import re, os, numpy as np
from collections import Counter
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib

SUSPICIOUS_KEYWORDS = [
    "login","verify","account","update","confirm","banking","secure","webscr",
    "signin","password","credential","billing","paypal","ebay","amazon","apple",
    "microsoft","google","urgent","suspended","limited","click","free","winner",
    "prize","congratulations","validate","expire","unusual","activity","restore",
    "locked","alert","security","access",
]
TRUSTED_DOMAINS = [
    "google.com","youtube.com","facebook.com","twitter.com","amazon.com","apple.com",
    "microsoft.com","github.com","stackoverflow.com","wikipedia.org","linkedin.com",
    "reddit.com","netflix.com","spotify.com","dropbox.com","slack.com",
]

def extract_features(text):
    text = str(text).strip()
    tl = text.lower()
    try:
        parsed = urlparse(text if "://" in text else "http://" + text)
        domain = parsed.netloc.lower()
        path = parsed.path
    except:
        domain, path = "", ""
    kw = sum(1 for k in SUSPICIOUS_KEYWORDS if k in tl)
    is_trusted = any(td in domain for td in TRUSTED_DOMAINS)
    has_ip = bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text))
    brand_in_path = any(b in path.lower() for b in ["paypal","amazon","apple","google","microsoft","ebay"])
    brand_in_domain = any(b in domain for b in ["paypal","amazon","apple","google","microsoft","ebay"])
    if domain:
        cnt = Counter(domain)
        total = len(domain)
        entropy = -sum((c/total)*np.log2(c/total) for c in cnt.values())
    else:
        entropy = 0.0
    features = [
        len(text), len(domain), len(path),
        min(text.count("/"),10), min(text.count("."),10),
        min(text.count("@"),5), min(text.count("-"),10),
        min(text.count("_"),5), min(text.count("?"),5),
        min(text.count("="),5), min(text.count("%"),10),
        min(text.count("!"),5),
        kw, min(kw,5),
        1 if is_trusted else 0,
        1 if has_ip else 0,
        len(domain.split(".")) if domain else 0,
        1 if domain.count("-")>=2 else 0,
        1 if "https" in tl else 0,
        1 if "@" in text and "." in text else 0,
        min(len(re.findall(r"[A-Z]",text)),20),
        min(len(re.findall(r"\d",text)),20),
        1 if len(text)>75 else 0,
        1 if len(text)>150 else 0,
        round(entropy,4),
        1 if brand_in_path and not brand_in_domain else 0,
        min(len(re.findall(r"[?&]\w+=",text)),10),
        len(re.findall(r"\d",domain)),
    ]
    return np.array(features, dtype=np.float32)

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
    "https://stripe.com/docs/api",
    "https://hub.docker.com/_/python",
    "https://pypi.org/project/scikit-learn/",
    "https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/",
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

def generate_dataset(n_samples=10000):
    rng = np.random.default_rng(42)
    data, labels = [], []
    half = n_samples // 2
    for i in range(half):
        url = SAFE_URLS[i % len(SAFE_URLS)]
        if rng.random() > 0.6:
            url += f"&ref={rng.integers(10000)}"
        data.append(extract_features(url))
        labels.append(0)
    for i in range(half):
        url = PHISHING_URLS[i % len(PHISHING_URLS)]
        if rng.random() > 0.5:
            rand_token = "".join(rng.choice(list("abcdef0123456789"), 12).tolist())
            url += f"?id={rng.integers(99999)}&token={rand_token}"
        data.append(extract_features(url))
        labels.append(1)
    idx = rng.permutation(len(data))
    return np.array(data)[idx], np.array(labels)[idx]

def train_and_save(output_dir="./ml/models"):
    os.makedirs(output_dir, exist_ok=True)
    print("=" * 50)
    print("  Phishing Detection Model Trainer")
    print("=" * 50)
    print("\n[1/4] Generating dataset (10,000 samples)...")
    X, y = generate_dataset()
    print(f"      Shape: {X.shape} | Classes: {np.bincount(y)}")
    print("\n[2/4] Splitting train/test (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    print(f"      Train: {len(X_train)} | Test: {len(X_test)}")
    print("\n[3/4] Training RandomForest...")
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=300, max_depth=20, min_samples_split=4,
            class_weight="balanced", random_state=42, n_jobs=-1,
        )),
    ])
    model.fit(X_train, y_train)
    print("\n[4/4] Evaluating...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n      Accuracy: {acc:.4f} ({acc*100:.2f}%)")
    print(classification_report(y_test, y_pred, target_names=["Safe","Phishing"]))
    path = os.path.join(output_dir, "phishing_model.joblib")
    joblib.dump({"model": model, "feature_count": 28}, path)
    print(f"  Model saved to {path}")
    print("=" * 50)

if __name__ == "__main__":
    train_and_save()
