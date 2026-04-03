"""
Phishing Detection REST API
=============================
Flask backend that serves phishing predictions via /predict endpoint.

Setup:
    pip install flask flask-cors scikit-learn joblib numpy flask-limiter
    python ../ml/train_model.py   # generate model first
    python app.py

Environment Variables:
    MODEL_PATH   - path to phishing_model.joblib (default: ../ml/models/phishing_model.joblib)
    PORT         - server port (default: 5000)
    SECRET_KEY   - Flask secret key (set in production)
"""

import os
import re
import logging
import hashlib
import time
from functools import wraps
from datetime import datetime
from urllib.parse import urlparse
from collections import Counter

import numpy as np
import joblib
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── App setup ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("phishing-api")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-in-production")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB max request

CORS(app, origins=[
    "http://localhost:3000",
    "http://localhost:5173",
    "https://phishing-detector.vercel.app",
    "https://phishing-detector-sello-bot.vercel.app",
])

# Rate limiting: 30 requests/minute per IP
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "30 per minute"],
    storage_uri="memory://",
)

# ── Load ML model ─────────────────────────────────────────────────────────────

MODEL_PATH = os.getenv(
    "MODEL_PATH",
    os.path.join(os.path.dirname(__file__), "..", "ml", "models", "phishing_model.joblib"),
)

_model_bundle = None


def get_model():
    global _model_bundle
    if _model_bundle is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Model not found at {MODEL_PATH}. "
                "Run `python ml/train_model.py` first."
            )
        _model_bundle = joblib.load(MODEL_PATH)
        logger.info(f"Model loaded from {MODEL_PATH}")
    return _model_bundle["model"]


# ── Feature extraction (mirrors ml/train_model.py) ───────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "update", "confirm", "banking",
    "secure", "webscr", "signin", "password", "credential", "billing",
    "paypal", "ebay", "amazon", "apple", "microsoft", "google",
    "urgent", "suspended", "limited", "click", "free", "winner",
    "prize", "congratulations", "validate", "expire", "unusual",
    "activity", "restore", "locked", "alert", "security", "access",
]

TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "amazon.com", "apple.com", "microsoft.com", "github.com",
    "stackoverflow.com", "wikipedia.org", "linkedin.com", "reddit.com",
    "netflix.com", "spotify.com", "dropbox.com", "slack.com",
]


def extract_features(text: str) -> np.ndarray:
    text = str(text).strip()
    text_lower = text.lower()

    try:
        parsed = urlparse(text if "://" in text else "http://" + text)
        domain = parsed.netloc.lower()
        path = parsed.path
    except Exception:
        domain, path = "", ""

    features = []

    features.append(len(text))
    features.append(len(domain))
    features.append(len(path))
    features.append(min(text.count("/"), 10))
    features.append(min(text.count("."), 10))
    features.append(min(text.count("@"), 5))
    features.append(min(text.count("-"), 10))
    features.append(min(text.count("_"), 5))
    features.append(min(text.count("?"), 5))
    features.append(min(text.count("="), 5))
    features.append(min(text.count("%"), 10))
    features.append(min(text.count("!"), 5))

    kw_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in text_lower)
    features.append(kw_hits)
    features.append(min(kw_hits, 5))

    is_trusted = any(td in domain for td in TRUSTED_DOMAINS)
    features.append(1 if is_trusted else 0)

    has_ip = bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text))
    features.append(1 if has_ip else 0)

    features.append(len(domain.split(".")) if domain else 0)
    features.append(1 if domain.count("-") >= 2 else 0)
    features.append(1 if "https" in text_lower else 0)
    features.append(1 if "@" in text and "." in text else 0)
    features.append(min(len(re.findall(r"[A-Z]", text)), 20))
    features.append(min(len(re.findall(r"\d", text)), 20))
    features.append(1 if len(text) > 75 else 0)
    features.append(1 if len(text) > 150 else 0)

    if domain:
        cnt = Counter(domain)
        total = len(domain)
        entropy = -sum((c / total) * np.log2(c / total) for c in cnt.values())
    else:
        entropy = 0.0
    features.append(round(entropy, 4))

    brand_in_path = any(b in path.lower() for b in ["paypal", "amazon", "apple", "google", "microsoft", "ebay"])
    brand_in_domain = any(b in domain for b in ["paypal", "amazon", "apple", "google", "microsoft", "ebay"])
    features.append(1 if brand_in_path and not brand_in_domain else 0)

    param_count = len(re.findall(r"[?&]\w+=", text))
    features.append(min(param_count, 10))

    domain_digits = len(re.findall(r"\d", domain))
    features.append(domain_digits)

    return np.array(features, dtype=np.float32)


# ── Input validation ──────────────────────────────────────────────────────────

MAX_INPUT_LENGTH = 2000
MIN_INPUT_LENGTH = 3
ALLOWED_TYPES = {"url", "email"}


def validate_input(data: dict) -> tuple[str | None, str | None]:
    """Returns (text, error_message). error_message is None if valid."""
    if not isinstance(data, dict):
        return None, "Request body must be JSON"

    text = data.get("text", "").strip()
    input_type = data.get("type", "url").lower()

    if not text:
        return None, "Field 'text' is required and cannot be empty"

    if len(text) < MIN_INPUT_LENGTH:
        return None, f"Input too short (minimum {MIN_INPUT_LENGTH} characters)"

    if len(text) > MAX_INPUT_LENGTH:
        return None, f"Input too long (maximum {MAX_INPUT_LENGTH} characters)"

    if input_type not in ALLOWED_TYPES:
        return None, f"Field 'type' must be one of: {ALLOWED_TYPES}"

    # Sanitize: strip null bytes and control characters
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

    return text, None


# ── API endpoints ─────────────────────────────────────────────────────────────

@app.before_request
def start_timer():
    g.start_time = time.time()


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    try:
        get_model()
        model_status = "loaded"
    except FileNotFoundError:
        model_status = "not_found"
    return jsonify({
        "status": "ok",
        "model": model_status,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@app.route("/predict", methods=["POST"])
@limiter.limit("20 per minute")
def predict():
    """
    POST /predict
    Body: { "text": "http://example.com", "type": "url" }
    Returns: { "label": "phishing"|"safe", "confidence": 0.97, "risk_level": "high"|"medium"|"low", ... }
    """
    start = time.time()

    # ── Parse body ────────────────────────────────────────────────────────────
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "Invalid JSON body"}), 400

    text, err = validate_input(data)
    if err:
        return jsonify({"error": err}), 422

    # ── Feature extraction ────────────────────────────────────────────────────
    try:
        features = extract_features(text).reshape(1, -1)
    except Exception as e:
        logger.error(f"Feature extraction failed: {e}")
        return jsonify({"error": "Feature extraction failed"}), 500

    # ── Prediction ────────────────────────────────────────────────────────────
    try:
        model = get_model()
        proba = model.predict_proba(features)[0]
        pred_class = int(np.argmax(proba))
        confidence = float(proba[pred_class])
        phishing_prob = float(proba[1])
        safe_prob = float(proba[0])
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        return jsonify({"error": "Prediction failed"}), 500

    # ── Risk level ────────────────────────────────────────────────────────────
    if phishing_prob >= 0.80:
        risk_level = "high"
    elif phishing_prob >= 0.50:
        risk_level = "medium"
    else:
        risk_level = "low"

    label = "phishing" if pred_class == 1 else "safe"
    elapsed_ms = round((time.time() - start) * 1000, 2)

    result = {
        "label": label,
        "confidence": round(confidence, 4),
        "phishing_probability": round(phishing_prob, 4),
        "safe_probability": round(safe_prob, 4),
        "risk_level": risk_level,
        "input_length": len(text),
        "elapsed_ms": elapsed_ms,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    logger.info(f"[{label.upper()}] conf={confidence:.3f} risk={risk_level} ms={elapsed_ms}")
    return jsonify(result), 200


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({
        "error": "Rate limit exceeded. Please slow down.",
        "retry_after": "60 seconds",
    }), 429


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def internal_error(e):
    logger.exception("Unhandled server error")
    return jsonify({"error": "Internal server error"}), 500


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    logger.info(f"Starting Phishing Detection API on port {port}")
    app.run(host="0.0.0.0", port=port, debug=debug)