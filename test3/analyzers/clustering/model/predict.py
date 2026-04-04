import pickle
import os
import sys

# Fix path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test3.analyzers.clustering.campaign import detect_campaign
from test3.analyzers.clustering.utils.feature_extractor import extract_features

model_path = os.path.join(os.path.dirname(__file__), "model.pkl")

with open(model_path, "rb") as f:
    model = pickle.load(f)

def predict_phishing(text, url, work_hours, workdays):
    features = extract_features(text, url, work_hours, workdays).reshape(1, -1)
    prob = model.predict_proba(features)[0][1]

    campaign_flag, similarity = detect_campaign(text)

    return {
    "phishing_probability": float(prob),
    "label": "Phishing" if prob > 0.5 else "Safe",
    "campaign_detected": campaign_flag,
    "similarity_score": similarity
    }