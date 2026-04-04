import pickle
import os
import sys

# Fix import path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.feature_extractor import extract_features

# ==============================
# LOAD MODEL
# ==============================

model_path = os.path.join(os.path.dirname(__file__), "model.pkl")

with open(model_path, "rb") as f:
    model = pickle.load(f)

# ==============================
# PREDICTION FUNCTION
# ==============================

def predict_phishing(text, url, work_hours, workdays):
    # Extract features
    features = extract_features(text, url, work_hours, workdays).reshape(1, -1)

    # Predict probability
    prob = model.predict_proba(features)[0][1]

    # ==============================
    # EXPLAINABILITY (WHY FLAGGED)
    # ==============================

    reasons = []

    text_lower = text.lower()

    # Content-based reasons
    if 'urgent' in text_lower:
        reasons.append("Contains urgent language")
    if 'verify' in text_lower:
        reasons.append("Requests verification")
    if 'click' in text_lower:
        reasons.append("Suspicious call-to-action")
    if 'password' in text_lower:
        reasons.append("Mentions password/security")

    # URL-based reasons
    if len(url) > 25:
        reasons.append("Long suspicious URL")
    if '-' in url:
        reasons.append("Hyphenated URL (common in phishing)")
    if 'https' not in url:
        reasons.append("Non-secure HTTP link")

    # Behavioral reasons
    if work_hours == 0:
        reasons.append("Sent outside work hours")
    if workdays == 0:
        reasons.append("Sent on weekend")

    # ==============================
    # FINAL OUTPUT
    # ==============================

    return {
        "phishing_probability": float(prob),
        "label": "Phishing" if prob > 0.5 else "Safe",
        "reasons": reasons
    }