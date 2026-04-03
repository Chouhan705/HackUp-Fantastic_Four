import pandas as pd
import xgboost as xgb
import numpy as np
from sklearn.model_selection import train_test_split
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType
import re
from urllib.parse import urlparse
import os

# Set base directory to the root of the project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(BASE_DIR, 'NoPhishZone', 'dataset', 'top-1m.csv')

# 1. Load the Popularity Data
print("Loading Top-1M CSV...")
top_df = pd.read_csv(CSV_PATH, header=None, names=['rank', 'domain'])
# Create a set of the top 10,000 domains for O(1) lookup
top_10k = set(top_df.head(10000)['domain'])

# 2. Feature Extraction Function (Must match your JS exactly)
def extract_9_features(url, domain_age=30):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname if parsed.hostname else ""
        hostname_lower = hostname.lower()

        # Feature 8: The Popularity Check
        is_popular = 1 if hostname_lower in top_10k or any(hostname_lower.endswith('.' + d) for d in top_10k) else 0

        # Feature 9: Infrastructure Risk Score
        infra_risk_score = 0.0
        if hostname_lower.endswith('.tk') or hostname_lower.endswith('.ml') or '10minutemail' in hostname_lower or 'tempmail' in hostname_lower:
            infra_risk_score = 1.0
        elif 'herokuapp.com' in hostname_lower or 'vercel.app' in hostname_lower or 'firebaseapp.com' in hostname_lower or 'web.app' in hostname_lower:
            infra_risk_score = 0.7

        return [
            len(url),                                      # 1. url_length      
            url.count('.'),                                # 2. dot_count       
            1 if url.startswith('https') else 0,           # 3. has_https       
            1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname_lower) else 0, # 4. is_ip
            len(re.sub("[^0-9]", "", url)) / len(url) if len(url) > 0 else 0, # 5. digit_ratio
            len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', url)), # 6. special_char_count
            domain_age,                                    # 7. domain_age      
            is_popular,                                    # 8. is_popular
            infra_risk_score                               # 9. infra_risk_score
        ]
    except:
        return [0] * 9
# 3. Generate/Load Training Data
# We generate a better synthetic dataset to avoid 0.5 flat predictions
print("Preparing training dataset...")

import random
np.random.seed(42)
random.seed(42)

def generate_synthetic_data(n_samples=20000):
    X = []
    y = []
    for _ in range(n_samples // 2):
        # Safe URL mimic (popular domains or short realistic urls)
        domain = random.choice(list(top_10k))
        # Mix simple and complex paths
        path = "".join(random.choices("abcdefghijklmnopqrstuvwxyz/", k=10)) if random.random() > 0.5 else "login=1&user=test"
        url = f"https://{domain}/{path}"
        # Make safe features look safe
        feature_vector = extract_9_features(url, random.randint(500, 3000))     
        # Ensure has_https is overwhelmingly 1
        X.append(feature_vector)
        y.append(0)
    for _ in range(n_samples // 2):
        # Phish URL mimic (complex, IP, numbers, untrusted domains)
        path = f"verify/{random.randint(1000,9999)}?session={random.random()}&action=update"
        domain = f"secure-update-{random.randint(100,999)}.net" if random.random() > 0.2 else f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        protocol = "http" if random.random() > 0.5 else "https"
        url = f"{protocol}://{domain}/{path}"
        feature_vector = extract_9_features(url, random.randint(0, 30))
        # Enforce popular domain = 0 for most explicitly risky generated ones to teach it the distinction
        feature_vector[-2] = 0 # -2 is now is_popular
        X.append(feature_vector)
        y.append(1)

    return np.array(X, dtype=np.float32), np.array(y)

X, y = generate_synthetic_data(20000)

# 4. Train XGBoost
print("Training model...")
model = xgb.XGBClassifier(n_estimators=50, max_depth=3, learning_rate=0.1)      
model.fit(np.array(X), np.array(y))

# 5. Export to ONNX
print("Exporting to ONNX...")
initial_type = [('float_input', FloatTensorType([None, 9]))] # Note the 9 here! 
onnx_model = onnxmltools.convert_xgboost(model, initial_types=initial_type)     

onnx_out_path = os.path.join(BASE_DIR, 'NoPhishZone', 'phishing_prober.onnx')   
onnx_local_path = os.path.join(BASE_DIR, 'ml', 'phishing_prober.onnx')

with open(onnx_out_path, "wb") as f:
    f.write(onnx_model.SerializeToString())

# Also keep a copy in ml/ for reference
with open(onnx_local_path, "wb") as f:
    f.write(onnx_model.SerializeToString())

print("Done! 'phishing_prober.onnx' is ready with 9 features.")
