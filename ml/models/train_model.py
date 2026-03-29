"""
Phishing Detection ML Model Trainer
=====================================
Trains a RandomForest classifier to detect phishing URLs and email text.
Run this script once to produce phishing_model.joblib before starting the API.

Usage:
    pip install scikit-learn joblib numpy pandas
    python train_model.py
"""

import re
import os
import numpy as np
from collections import Counter
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib


# ── Feature vocabulary ────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "update", "confirm", "banking",
    "secure", "webscr", "signin", "password", "credential", "billing",
    "paypal", "ebay", "amazon", "apple", "microsoft", "google",
    "urgent", "suspended", "limited", "click", "free", "winner",
    "prize", "congratulations", "validate", "expire", "unusual",
    "activity", "restore", "locked", "alert", "security", "access",
]

TRUSTED_TLDS = {".com", ".org", ".edu", ".gov", ".net", ".io"}
TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "amazon.com", "apple.com", "microsoft.com", "github.com",
    "stackoverflow.com", "wikipedia.org", "linkedin.com", "reddit.com",
    "netflix.com", "spotify.com", "dropbox.com", "slack.com",
]

FEATURE_COUNT = 28  # must match extract_features output length


# ── Feature extraction ────────────────────────────────────────────────────────

def extract_features(text: str) -> np.ndarray:
    """
    Extract 28 numerical features from a URL or email snippet.
    All features are interpretable and directly relevant to phishing signals.
    """
    text = str(text).strip()
    text_lower = text.lower()

    try:
        parsed = urlparse(text if "://" in text else "http://" + text)
        domain = parsed.netloc.lower()
        path = parsed.path
    except Exception:
        domain, path = "", ""

    features = []

    # ── Length signals ────────────────────────────────────────────────────────
    features.append(len(text))                               # [0] total length
    features.append(len(domain))                             # [1] domain length
    features.append(len(path))                               # [2] path length
    features.append(min(text.count("/"), 10))                # [3] slash count (capped)
    features.append(min(text.count("."), 10))                # [4] dot count (capped)

    # ── Special character signals ─────────────────────────────────────────────
    features.append(min(text.count("@"), 5))                 # [5] @ symbol
    features.append(min(text.count("-"), 10))                # [6] hyphens
    features.append(min(text.count("_"), 5))                 # [7] underscores
    features.append(min(text.count("?"), 5))                 # [8] query markers
    features.append(min(text.count("="), 5))                 # [9] equals signs
    features.append(min(text.count("%"), 10))                # [10] URL encoding
    features.append(min(text.count("!"), 5))                 # [11] exclamation

    # ── Keyword signals ────────────────────────────────────────────────────────
    kw_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in text_lower)
    features.append(kw_hits)                                 # [12] keyword hits
    features.append(min(kw_hits, 5))                         # [13] capped hits

    # ── Domain trust signals ──────────────────────────────────────────────────
    is_trusted = any(td in domain for td in TRUSTED_DOMAINS)
    features.append(1 if is_trusted else 0)                  # [14] trusted domain

    has_ip = bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text))
    features.append(1 if has_ip else 0)                      # [15] IP address URL

    subdomain_depth = len(domain.split(".")) if domain else 0
    features.append(subdomain_depth)                         # [16] subdomain depth

    features.append(1 if domain.count("-") >= 2 else 0)     # [17] multi-hyphen domain
    features.append(1 if "https" in text_lower else 0)       # [18] has HTTPS

    # ── Structural signals ────────────────────────────────────────────────────
    features.append(1 if "@" in text and "." in text else 0) # [19] email-like
    upper_count = len(re.findall(r"[A-Z]", text))
    features.append(min(upper_count, 20))                    # [20] uppercase letters
    digit_count = len(re.findall(r"\d", text))
    features.append(min(digit_count, 20))                    # [21] digit count
    features.append(1 if len(text) > 75 else 0)             # [22] long URL flag
    features.append(1 if len(text) > 150 else 0)            # [23] very long URL

    # ── Entropy (randomness in domain name) ───────────────────────────────────
    if domain:
        cnt = Counter(domain)
        total = len(domain)
        entropy = -sum((c / total) * np.log2(c / total) for c in cnt.values())
    else:
        entropy = 0.0
    features.append(round(entropy, 4))                       # [24] domain entropy

    # ── Mismatch signals ──────────────────────────────────────────────────────
    # Brand name in path but not in domain (e.g. domain=evil.com, path=/paypal/login)
    brand_in_path = any(b in path.lower() for b in ["paypal", "amazon", "apple", "google", "microsoft", "ebay"])
    brand_in_domain = any(b in domain for b in ["paypal", "amazon", "apple", "google", "microsoft", "ebay"])
    features.append(1 if brand_in_path and not brand_in_domain else 0)  # [25] brand mismatch

    # Many query parameters
    param_count = len(re.findall(r"[?&]\w+=", text))
    features.append(min(param_count, 10))                    # [26] param count

    # Numeric-heavy domain (e.g. 1nformat10n.com)
    domain_digits = len(re.findall(r"\d", domain))
    features.append(domain_digits)                           # [27] digits in domain

    assert len(features) == FEATURE_COUNT, f"Expected {FEATURE_COUNT}, got {len(features)}"
    return np.array(features, dtype=np.float32)


# ── Synthetic dataset ─────────────────────────────────────────────────────────

SAFE_URLS = [
    "https://www.google.com/search?q=machine+learning",
    "https://github.com/anthropics/anthropic-sdk-python",
    "https://stackoverflow.com/questions/tagged/python",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://www.amazon.com/Best-Sellers/zgbs",
    "https://twitter.com/home",
    "https://www.linkedin.com/feed/",
    "https://news.ycombinator.com/",
    "https://www.reddit.com/r/netsec",
    "https://developer.mozilla.org/en-US/docs/Web",
    "https://flask.palletsprojects.com/en/3.0.x/",
    "https://scikit-learn.org/stable/modules/ensemble.html",
    "https://www.nytimes.com/section/technology",
    "https://medium.com/topic/artificial-intelligence",
    "https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/",
    "https://stripe.com/docs/api",
    "https://hub.docker.com/_/python",
    "https://pypi.org/project/scikit-learn/",
]

PHISHING_URLS = [
    "http://paypal-secure-login.verify-account.com/signin?user=victim&token=abc123",
    "http://192.168.1.105/banking/update-credentials.php?redirect=true",
    "http://amazon-account-suspended.click-verify.com/restore?id=9823",
    "http://secure-apple-id-confirm.xyz/login?session=expired&action=verify",
    "http://microsoft-account-billing-update.info/confirm-payment",
    "http://ebay-account-login-verify.suspicious.net/restore?locked=true",
    "http://free-gift-card-winner.prize-now.click/validate?winner=you",
    "http://bank0famerica-online.com/verify-identity.php?urgent=1",
    "http://urgent-account-suspended.security-alert.net/restore",
    "http://google-account-unusual-activity.com/verify?email=user@gmail.com",
    "http://update-your-paypal-now.com/account/login?confirm=billing",
    "http://apple-id-locked-verify.com/unlock?token=xk91ms&ref=security",
    "http://win-amazon-gift-card-2024.free-click.xyz/claim?id=winner123",
    "http://netfl1x-payment-failed.com/update-billing?account=suspended",
    "http://secure-login-wellsfargo.phish-domain.com/verify",
    "http://chase-bank-verify-account.suspicious-tld.info/login",
    "http://verify-your-account-now.limited-access.net/restore?urgent=true",
    "http://dropbox-storage-full-upgrade.scam-host.com/billing",
    "http://linkedin-account-verify.fake-domain.xyz/login?from=email",
    "http://unusual-sign-in-activity-google.com/verify?device=new&action=confirm",
]


def generate_dataset(n_samples: int = 10000, noise: float = 0.05) -> tuple:
    """Generate balanced synthetic phishing/safe URL dataset with noise."""
    rng = np.random.default_rng(42)
    data, labels = [], []
    half = n_samples // 2

    for i in range(half):
        url = SAFE_URLS[i % len(SAFE_URLS)]
        if rng.random() > 0.6:
            url += f"&ref={rng.integers(10000)}"
        feats = extract_features(url)
        if rng.random() < noise:
            feats += rng.normal(0, 0.1, FEATURE_COUNT).astype(np.float32)
        data.append(feats)
        labels.append(0)

    for i in range(half):
        url = PHISHING_URLS[i % len(PHISHING_URLS)]
        if rng.random() > 0.5:
            rand_token = "".join(rng.choice(list("abcdef0123456789"), 12).tolist())
            url += f"?id={rng.integers(99999)}&token={rand_token}"
        feats = extract_features(url)
        if rng.random() < noise:
            feats += rng.normal(0, 0.1, FEATURE_COUNT).astype(np.float32)
        data.append(feats)
        labels.append(1)

    idx = rng.permutation(len(data))
    return np.array(data)[idx], np.array(labels)[idx]


# ── Train and save ─────────────────────────────────────────────────────────────

def train_and_save(output_dir: str = "./models") -> str:
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 60)
    print("  Phishing Detection Model Trainer")
    print("=" * 60)

    print("\n[1/4] Generating synthetic dataset (10,000 samples)...")
    X, y = generate_dataset(n_samples=10000)
    print(f"      Dataset shape: {X.shape}  |  Labels: {np.bincount(y)}")

    print("\n[2/4] Splitting into train/test sets (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"      Train: {len(X_train)}  |  Test: {len(X_test)}")

    print("\n[3/4] Training RandomForest pipeline...")
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=300,
            max_depth=20,
            min_samples_split=4,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )),
    ])
    model.fit(X_train, y_train)

    print("\n[4/4] Evaluating model...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n      Accuracy: {acc:.4f} ({acc*100:.2f}%)")
    print("\n" + classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

    model_path = os.path.join(output_dir, "phishing_model.joblib")
    joblib.dump({"model": model, "feature_count": FEATURE_COUNT}, model_path)
    print(f"  Model saved → {model_path}")
    print("=" * 60)
    return model_path


if __name__ == "__main__":
    train_and_save()