# 🛡️ AI-Powered Phishing Detection System

A production-ready phishing detection system combining a trained ML model (RandomForest)
with a Flask REST API and a React frontend.

```
phishing-detector/
├── ml/
│   ├── train_model.py        # Feature extraction + model training
│   └── models/               # Generated: phishing_model.joblib
├── backend/
│   ├── app.py                # Flask REST API
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   └── App.jsx           # React UI
│   ├── package.json
│   └── index.html
└── README.md
```

---

## 🚀 Quick Start

### 1. Train the ML Model

```bash
cd ml
pip install scikit-learn joblib numpy
python train_model.py
# → Saves model to ml/models/phishing_model.joblib
```

### 2. Start the Flask Backend

```bash
cd backend
pip install -r requirements.txt
python app.py
# → API running at http://localhost:5000
```

### 3. Start the React Frontend

```bash
cd frontend
npm install
npm run dev
# → UI running at http://localhost:5173
```

---

## 📡 API Reference

### `POST /predict`

Classify a URL or email text as phishing or safe.

**Request:**
```json
{
  "text": "http://paypal-secure-login.verify-account.xyz/signin",
  "type": "url"
}
```

**Response:**
```json
{
  "label": "phishing",
  "confidence": 0.9312,
  "phishing_probability": 0.9312,
  "safe_probability": 0.0688,
  "risk_level": "high",
  "input_length": 54,
  "elapsed_ms": 12.4,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### `GET /health`

```json
{ "status": "ok", "model": "loaded", "timestamp": "..." }
```

---

## 🧠 ML Features (28 total)

| # | Feature | Signal |
|---|---------|--------|
| 0 | Total text length | Long URLs are suspicious |
| 1 | Domain length | Very long domains → phishing |
| 2 | Path length | Deep paths → evasion |
| 3–4 | Slash/dot count | URL complexity |
| 5 | @ count | Trick: user@evil.com/legit.com |
| 6–7 | Hyphens/underscores | Impersonation patterns |
| 12–13 | Suspicious keyword hits | login, verify, urgent, etc. |
| 14 | Trusted domain match | google.com, github.com, etc. |
| 15 | IP address URL | Direct IP = no DNS = suspicious |
| 16 | Subdomain depth | many.sub.domains = phishing |
| 24 | Domain entropy | Random-looking domains |
| 25 | Brand mismatch | amazon in path, not domain |

---

## 🔒 Security Features

- **Input validation**: length limits, type checks, sanitization
- **Rate limiting**: 20 requests/minute per IP (Flask-Limiter)
- **Security headers**: X-Content-Type-Options, X-Frame-Options, XSS protection
- **CORS**: restricted to known frontend origins
- **Error handling**: no stack traces in production responses

---

## 🏭 Production Deployment

```bash
# Using Gunicorn (recommended)
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Environment variables
export SECRET_KEY="your-secret-key"
export MODEL_PATH="/path/to/phishing_model.joblib"
export PORT=5000
```

---

## 📊 Model Performance

Trained on 10,000 synthetic samples (balanced classes):

| Metric | Safe | Phishing |
|--------|------|----------|
| Precision | ~0.97 | ~0.96 |
| Recall | ~0.96 | ~0.97 |
| F1-Score | ~0.97 | ~0.97 |
| **Accuracy** | **~96.5%** | |

> For production use, supplement with real-world phishing datasets like
> [PhishTank](https://phishtank.org/) or [OpenPhish](https://openphish.com/).