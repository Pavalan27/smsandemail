"""
PhishShift - AI-Powered Message Risk Scanner
Flask Backend Application

Provides:
- Machine Learning classification (TF-IDF + Logistic Regression loaded via joblib)
- URL forensic heuristic analysis (static pattern inspection without visiting links)
- Content threat indicator extraction (urgency, credentials, financial coercion, prizes)
- Composite heuristic risk scoring (0-100)
- In-memory privacy preservation (messages are never persisted to disk or logged)
- REST API endpoints:
  - POST /api/scan
  - GET  /api/health
  - GET  /
"""

import os
import re
import time
import urllib.parse
import warnings
from collections import defaultdict
from flask import Flask, request, jsonify, render_template

# Suppress scikit-learn version mismatch warnings if environment slightly differs
warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')

try:
    import joblib
except ImportError:
    joblib = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static')
)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024  # 100 KB max payload

# Model loading state
MODEL = None
MODEL_LOAD_ERROR = None
MODEL_CLASSES = []

MODEL_CANDIDATE_PATHS = [
    os.path.join(BASE_DIR, 'phishshift_3class.joblib'),
    os.path.join(os.getcwd(), 'phishshift_3class.joblib'),
    os.path.join(BASE_DIR, '..', 'phishshift_3class.joblib'),
    os.path.join(os.path.dirname(__file__), 'phishshift_3class.joblib'),
    'phishshift_3class.joblib'
]

def load_ml_model():
    """Loads the pre-trained joblib model once during startup."""
    global MODEL, MODEL_LOAD_ERROR, MODEL_CLASSES
    if joblib is None:
        MODEL_LOAD_ERROR = "joblib package is not installed."
        return

    found_path = None
    for path in MODEL_CANDIDATE_PATHS:
        if os.path.exists(path):
            found_path = path
            break

    if not found_path:
        MODEL_LOAD_ERROR = (
            "Model file 'phishshift_3class.joblib' was not found in the workspace. "
            "Please place 'phishshift_3class.joblib' in the application root directory."
        )
        return

    try:
        loaded = joblib.load(found_path)
        MODEL = loaded
        if hasattr(loaded, 'classes_'):
            MODEL_CLASSES = list(loaded.classes_)
        MODEL_LOAD_ERROR = None
        print(f"[PhishShift] Model successfully loaded from '{found_path}'. Classes: {MODEL_CLASSES}")
    except Exception as exc:
        MODEL_LOAD_ERROR = f"Failed to load model file '{found_path}': {str(exc)}"
        MODEL = None
        print(f"[PhishShift ERROR] {MODEL_LOAD_ERROR}")

# Load model upon module initialization
load_ml_model()

# Basic in-memory rate limiter (per IP, max 60 requests per minute)
RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_PER_WINDOW = 60
_request_records = defaultdict(list)

def is_rate_limited(client_ip: str) -> bool:
    """Checks whether the client IP has exceeded the allowed request threshold."""
    now = time.time()
    timestamps = _request_records[client_ip]
    # Prune old records
    _request_records[client_ip] = [ts for ts in timestamps if now - ts < RATE_LIMIT_WINDOW]
    if len(_request_records[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
        return True
    _request_records[client_ip].append(now)
    return False

# Security response headers
@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response

# ---------------------------------------------------------------------------
# HEURISTIC ANALYSIS ENGINE
# ---------------------------------------------------------------------------

INDICATOR_PATTERNS = [
    {
        "type": "urgency",
        "label": "Artificial Urgency & Pressure",
        "description": "Urges immediate action with strict deadlines to prevent rational verification.",
        "severity": "high",
        "regex": re.compile(
            r'\b(urgent|immediately|act now|hurry|within 24 hours|within 12 hours|expires (soon|today)|'
            r'action required|time[- ]sensitive|instant access|dont wait|final (notice|warning))\b',
            re.IGNORECASE
        )
    },
    {
        "type": "account_threat",
        "label": "Account Suspension / Legal Threat",
        "description": "Threatens negative consequences such as account lockout, arrest, or penalties.",
        "severity": "high",
        "regex": re.compile(
            r'\b(suspended|locked|blocked|frozen|restricted|unauthorized access|compromised|'
            r'security breach|terminated|legal action|law enforcement|arrest warrant|irs penalty)\b',
            re.IGNORECASE
        )
    },
    {
        "type": "credential_harvesting",
        "label": "Credential & Sensitive Data Request",
        "description": "Attempts to solicit passwords, PINs, OTP codes, or personal identifiers.",
        "severity": "high",
        "regex": re.compile(
            r'\b(verify (your )?(account|identity|password|pin|ssn|credentials|details)|'
            r'confirm (your )?(password|pin|card|ssn)|enter (your )?(otp|passcode|code)|'
            r'update your (login|security|profile|payment method))\b',
            re.IGNORECASE
        )
    },
    {
        "type": "prize_lottery",
        "label": "Unsolicited Prize or Sweepstakes Claim",
        "description": "Claims you have won an unexpected reward, gift card, or lottery jackpot.",
        "severity": "medium",
        "regex": re.compile(
            r'\b(congratulations|you(\'ve| have) won|selected as (a|the) winner|claim your (prize|reward|gift card)|'
            r'free (voucher|gift|iphone|cash|\$\d+)|lottery jackpot|exclusive reward)\b',
            re.IGNORECASE
        )
    },
    {
        "type": "financial_coercion",
        "label": "Financial Demand or Bogus Refund",
        "description": "Prompts money transfer, cryptocurrency, gift cards, or fake invoice refunds.",
        "severity": "high",
        "regex": re.compile(
            r'\b(wire transfer|crypto|bitcoin|gift card payment|refund of \$\d+|unpaid invoice|'
            r'overdue bill|claim your refund|transaction (pending|declined)|cash prize)\b',
            re.IGNORECASE
        )
    },
    {
        "type": "delivery_scam",
        "label": "Fake Package Delivery Notice",
        "description": "Impersonates postal/shipping carriers claiming a delivery failed or needs fees.",
        "severity": "medium",
        "regex": re.compile(
            r'\b(package (delivery )?(failed|detained|stopped|pending|held)|'
            r'reschedule delivery|update (shipping|delivery) address|postal service|'
            r'customs fee|parcel tracking)\b',
            re.IGNORECASE
        )
    }
]

KNOWN_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'v.gd'
}

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'tk', 'buzz', 'rest', 'icu', 'cam', 'work', 'loan', 'cfd',
    'fit', 'gq', 'ml', 'ga', 'cf', 'click', 'link', 'press', 'bar', 'surf'
}

BRAND_KEYWORDS = [
    'paypal', 'apple', 'amazon', 'netflix', 'wellsfargo', 'chase', 'bankofamerica',
    'citi', 'usps', 'fedex', 'ups', 'dhl', 'microsoft', 'google', 'meta', 'whatsapp'
]

IP_PATTERN = re.compile(r'^(?:https?:\/\/)?(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:\/.*)?$', re.IGNORECASE)
RAW_URL_REGEX = re.compile(r'(?:https?:\/\/|www\.)[^\s<>"\'`()]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:\/[^\s<>"\'`]*)?', re.IGNORECASE)

def extract_and_analyze_urls(text: str):
    """
    Extracts URLs from message text and performs static heuristic inspection.
    NOTE: This inspection does NOT make any outbound network requests or visit the target.
    """
    found_urls = []
    seen = set()

    # Extract matching tokens
    candidates = RAW_URL_REGEX.findall(text)
    for raw in candidates:
        cleaned = raw.rstrip('.,;!?:)"\']')
        if not cleaned or cleaned in seen:
            continue
        # Filter false positives like plain abbreviations or filenames
        if '.' not in cleaned or len(cleaned) < 4:
            continue
        seen.add(cleaned)

        # Normalize with scheme if missing
        norm_url = cleaned
        if not norm_url.lower().startswith(('http://', 'https://')):
            norm_url = 'http://' + norm_url

        try:
            parsed = urllib.parse.urlparse(norm_url)
            host = parsed.netloc.lower()
            if not host and parsed.path:
                host = parsed.path.split('/')[0].lower()
            # Remove port if present
            hostname = host.split(':')[0]
        except Exception:
            hostname = cleaned

        flags = []
        risk_level = "Low"

        # Check for IP address as host
        is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname))
        if is_ip:
            flags.append({
                "severity": "high",
                "label": "Raw IP Address Host",
                "detail": f"Host '{hostname}' uses a numeric IP address instead of a standard domain name, often used to evade domain reputation filters."
            })
            risk_level = "High"

        # Check for known URL shorteners
        if hostname in KNOWN_SHORTENERS:
            flags.append({
                "severity": "medium",
                "label": "Obfuscating URL Shortener",
                "detail": f"Domain '{hostname}' masks the final destination URL."
            })
            if risk_level != "High":
                risk_level = "Medium"

        # Check for suspicious TLD
        tld = hostname.split('.')[-1] if '.' in hostname else ''
        if tld in SUSPICIOUS_TLDS:
            flags.append({
                "severity": "medium",
                "label": "High-Abuse Top-Level Domain",
                "detail": f"The '.{tld}' extension is frequently correlated with automated phishing infrastructure."
            })
            if risk_level != "High":
                risk_level = "Medium"

        # Check for brand impersonation in host
        for brand in BRAND_KEYWORDS:
            if brand in hostname and not (hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com")):
                flags.append({
                    "severity": "high",
                    "label": "Potential Brand Impersonation in Domain",
                    "detail": f"Domain '{hostname}' contains the brand keyword '{brand}' but appears to be an unofficial host."
                })
                risk_level = "High"
                break

        # Check for suspicious path/query keywords
        full_lower = norm_url.lower()
        suspicious_path_terms = ['login', 'signin', 'verify', 'update', 'banking', 'secure', 'confirm', 'wallet']
        detected_path_terms = [t for t in suspicious_path_terms if t in full_lower and t not in hostname]
        if detected_path_terms:
            flags.append({
                "severity": "medium",
                "label": "Credential Harvesting Path Patterns",
                "detail": f"URL path/parameters contain sensitive keywords: {', '.join(detected_path_terms[:3])}."
            })
            if risk_level == "Low":
                risk_level = "Medium"

        # Check protocol
        if norm_url.lower().startswith('http://') and not is_ip:
            flags.append({
                "severity": "low",
                "label": "Unencrypted HTTP Protocol",
                "detail": "Link uses plaintext HTTP instead of secure HTTPS."
            })

        found_urls.append({
            "original_url": cleaned,
            "display_host": hostname,
            "scheme": parsed.scheme if 'parsed' in locals() else 'unknown',
            "risk_level": risk_level,
            "flags": flags
        })

    return found_urls

def extract_indicators(text: str):
    """Identifies textual threat indicators using regex patterns and returns snippets."""
    indicators = []
    for item in INDICATOR_PATTERNS:
        matches = list(item["regex"].finditer(text))
        if matches:
            # Capture up to 2 distinct match snippets
            snippets = []
            for m in matches[:2]:
                snippet = m.group(0)
                if snippet not in snippets:
                    snippets.append(snippet)

            indicators.append({
                "type": item["type"],
                "label": item["label"],
                "description": item["description"],
                "severity": item["severity"],
                "snippets": snippets,
                "count": len(matches)
            })
    return indicators

def compute_composite_risk(prediction_class: str, probabilities: dict, indicators: list, urls: list):
    """
    Computes a transparent composite heuristic risk score (0-100) and risk level.
    
    Combines:
    - ML Model predicted class and confidence probabilities (if available)
    - Content threat indicators (urgency, credential harvest, threats)
    - URL forensic flags (IP hosts, shorteners, brand spoofing)
    """
    score = 10.0  # Baseline baseline

    phish_prob = probabilities.get("phishing", 0.0) if probabilities else 0.0
    spam_prob = probabilities.get("spam", 0.0) if probabilities else 0.0
    legit_prob = probabilities.get("legitimate", 0.0) if probabilities else 0.0

    if probabilities:
        # Base ML contribution up to 55 points
        score = (phish_prob * 55.0) + (spam_prob * 25.0) + (legit_prob * 5.0)
    else:
        if prediction_class == "phishing":
            score = 65.0
        elif prediction_class == "spam":
            score = 40.0
        else:
            score = 10.0

    # Indicator contributions
    high_sev_indicators = sum(1 for ind in indicators if ind["severity"] == "high")
    med_sev_indicators = sum(1 for ind in indicators if ind["severity"] == "medium")
    score += (high_sev_indicators * 12.0)
    score += (med_sev_indicators * 6.0)

    # URL contributions
    high_risk_urls = sum(1 for u in urls if u["risk_level"] == "High")
    med_risk_urls = sum(1 for u in urls if u["risk_level"] == "Medium")
    score += (high_risk_urls * 18.0)
    score += (med_risk_urls * 8.0)

    # Clamp to [0, 100]
    score = max(5.0, min(99.0, score))
    final_score = int(round(score))

    # Determine risk category
    if final_score >= 70:
        level = "High"
    elif final_score >= 40:
        level = "Medium"
    else:
        level = "Low"

    return final_score, level

def generate_recommendations(prediction: str, indicators: list, urls: list) -> list:
    """Generates specific, practical safety advice based on the detected risks."""
    recs = []

    if urls:
        recs.append("Do not click or tap any links in this message. Even if a link appears legitimate, it may lead to an attacker-controlled credential-harvesting portal.")
        if any(u["risk_level"] == "High" for u in urls):
            recs.append("Detected high-risk URL characteristics (e.g., numeric IP host or brand impersonation). Delete this message and do not interact with the sender.")

    if any(ind["type"] == "credential_harvesting" for ind in indicators):
        recs.append("Never submit passwords, one-time verification codes (OTP), PINs, or Social Security numbers via links received in unsolicited messages. Legitimate organizations never request secrets via text.")

    if any(ind["type"] == "urgency" for ind in indicators):
        recs.append("Beware of artificial urgency. Scammers fabricate immediate deadlines to make targets panic and bypass normal verification steps.")

    if any(ind["type"] in ("account_threat", "financial_coercion") for ind in indicators):
        recs.append("If this message claims to be from your bank, utility, or postal carrier, independently open their official app or type their known URL directly into your browser to check your account status.")

    if any(ind["type"] == "prize_lottery" for ind in indicators):
        recs.append("Legitimate lotteries and sweepstakes do not notify winners via unsolicited SMS or demand fees to claim prizes.")

    if prediction in ("phishing", "spam"):
        recs.append("Report this message as spam/phishing to your mobile carrier by forwarding it to 7726 (SPAM) where supported, then block the sender.")
    else:
        recs.append("Even though this message was classified as Legitimate by the SMS text model, always verify unexpected requests through trusted out-of-band channels before sharing sensitive information.")

    return recs

# ---------------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    """Serves the main PhishShift web dashboard."""
    return render_template('index.html')

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint exposing system & model status."""
    return jsonify({
        "status": "healthy" if MODEL is not None else "degraded",
        "model_loaded": MODEL is not None,
        "model_error": MODEL_LOAD_ERROR,
        "classes": MODEL_CLASSES,
        "version": "1.0.0",
        "service": "PhishShift Message Risk Scanner"
    }), 200

@app.route('/api/scan', methods=['POST'])
def scan_message():
    """
    Main risk analysis endpoint.
    Accepts JSON: { "message": "..." }
    Returns structured prediction, heuristic score, extracted indicators, and recommendations.
    """
    client_ip = request.remote_addr or '127.0.0.1'
    if is_rate_limited(client_ip):
        return jsonify({
            "success": False,
            "error": "Rate limit exceeded. Please wait a moment before submitting another message."
        }), 429

    # Model readiness check
    if MODEL is None:
        return jsonify({
            "success": False,
            "error": MODEL_LOAD_ERROR or "Model is not loaded on the server. Please verify 'phishshift_3class.joblib' is present."
        }), 503

    # Validate JSON payload
    if not request.is_json:
        return jsonify({
            "success": False,
            "error": "Invalid request format. Request body must be valid application/json."
        }), 400

    data = request.get_json(silent=True)
    if data is None or not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Malformed JSON payload."
        }), 400

    raw_message = data.get("message")
    if raw_message is None or not isinstance(raw_message, str):
        return jsonify({
            "success": False,
            "error": "Missing or invalid 'message' field in request body. Must be a non-empty string."
        }), 400

    cleaned_message = raw_message.strip()
    if not cleaned_message:
        return jsonify({
            "success": False,
            "error": "Message text cannot be empty or contain only whitespace."
        }), 400

    if len(cleaned_message) > 10000:
        return jsonify({
            "success": False,
            "error": f"Message length ({len(cleaned_message)} characters) exceeds the maximum allowed limit of 10,000 characters."
        }), 400

    # Execute ML Inference
    try:
        # Run prediction on the input message
        raw_pred = MODEL.predict([cleaned_message])[0]
        prediction_slug = str(raw_pred).lower().strip()

        # Human-friendly category label
        label_map = {
            "legitimate": "Legitimate",
            "spam": "Spam",
            "phishing": "Phishing"
        }
        category_label = label_map.get(prediction_slug, prediction_slug.capitalize())

        # Extract probabilities if model supports predict_proba
        probabilities = None
        confidence = None
        if hasattr(MODEL, "predict_proba"):
            try:
                proba_array = MODEL.predict_proba([cleaned_message])[0]
                classes = list(MODEL.classes_) if hasattr(MODEL, "classes_") else []
                if len(classes) == len(proba_array):
                    probabilities = {}
                    for cls_name, prob in zip(classes, proba_array):
                        key = str(cls_name).lower().strip()
                        probabilities[key] = round(float(prob), 4)

                    # Overall confidence is the probability assigned to the chosen class
                    if prediction_slug in probabilities:
                        confidence = probabilities[prediction_slug]
            except Exception as pe:
                print(f"[PhishShift Warning] predict_proba failed: {pe}")
                probabilities = None
                confidence = None

    except Exception as exc:
        print(f"[PhishShift Inference Error] {exc}")
        return jsonify({
            "success": False,
            "error": f"Machine learning inference failed: {str(exc)}"
        }), 500

    # Run Heuristic Inspection & URL Forensics
    extracted_urls = extract_and_analyze_urls(cleaned_message)
    detected_indicators = extract_indicators(cleaned_message)

    # Compute Composite Heuristic Risk Score (0-100)
    risk_score, risk_level = compute_composite_risk(
        prediction_slug,
        probabilities,
        detected_indicators,
        extracted_urls
    )

    # Synthesize plain-language explanation
    explanation_parts = []
    if prediction_slug == "phishing":
        explanation_parts.append(
            f"The machine learning model classified this message as Phishing"
            + (f" with {int(confidence * 100)}% model probability." if confidence is not None else ".")
        )
    elif prediction_slug == "spam":
        explanation_parts.append(
            f"The machine learning model classified this message as Spam"
            + (f" with {int(confidence * 100)}% model probability." if confidence is not None else ".")
        )
    else:
        explanation_parts.append(
            f"The machine learning model classified this message as Legitimate"
            + (f" with {int(confidence * 100)}% model probability." if confidence is not None else ".")
        )

    if detected_indicators:
        ind_names = [ind['label'] for ind in detected_indicators]
        explanation_parts.append(f"Heuristic pattern inspection detected {len(detected_indicators)} suspicious indicator(s): {', '.join(ind_names)}.")

    if extracted_urls:
        explanation_parts.append(f"Found {len(extracted_urls)} link(s) in message text.")
        flagged_urls = [u for u in extracted_urls if u['risk_level'] in ('Medium', 'High')]
        if flagged_urls:
            explanation_parts.append(f"{len(flagged_urls)} link(s) exhibited elevated risk characteristics during static forensic inspection.")

    if prediction_slug == "legitimate" and (detected_indicators or extracted_urls):
        explanation_parts.append("Note: While the statistical SMS model favored legitimate patterns, presence of external links or persuasive cues warrants caution.")

    full_explanation = " ".join(explanation_parts)
    recommendations = generate_recommendations(prediction_slug, detected_indicators, extracted_urls)

    # Sanitized logging: log only metadata, never full message text
    print(f"[PhishShift Audit] Scan completed | IP: {client_ip} | Len: {len(cleaned_message)} | Pred: {category_label} | Score: {risk_score} | URLs: {len(extracted_urls)}")

    return jsonify({
        "success": True,
        "prediction": prediction_slug,
        "label": category_label,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "confidence": confidence,
        "probabilities": probabilities,
        "explanation": full_explanation,
        "indicators": detected_indicators,
        "urls": extracted_urls,
        "recommendations": recommendations,
        "metadata": {
            "analyzed_characters": len(cleaned_message),
            "analyzed_words": len(cleaned_message.split()),
            "model_architecture": "TF-IDF (1-2 ngrams, sublinear TF) + Logistic Regression",
            "model_scope": "Trained on SMS dataset. Not validated for email headers, attachments, or malicious binaries.",
            "scoring_note": "Risk score is a heuristic synthesis combining model probabilities and rule-based forensic checks."
        }
    }), 200


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"==================================================")
    print(f" PhishShift - Message Risk Scanner Server")
    print(f" Running at: http://127.0.0.1:{port}")
    print(f" Health check: http://127.0.0.1:{port}/api/health")
    print(f"==================================================")
    app.run(host='0.0.0.0', port=port, debug=False)
