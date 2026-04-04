import sys
import os
import uuid
import time
from datetime import datetime

# Adjust path so we can import predict from this folder
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from predict import predict_phishing

class BehaviourAnalyzer:
    """
    Analyses behavioural patterns of the communication, extracting text/URL/time
    features to predict likelihood of phishing.
    Outputs a structured JSON event for the pipeline.
    """

    def analyze(self, text: str, url: str, work_hours: int = 1, workdays: int = 1) -> dict:
        start_time = time.time()
        
        # 1. Run the local ML prediction model + heuristics
        try:
            result = predict_phishing(text, url, work_hours, workdays)
        except Exception as e:
            result = {
                "phishing_probability": 0.0,
                "label": "Safe",
                "reasons": [f"Error running model: {e}"]
            }

        # 2. Convert prediction output to pipeline Signals
        prob = result.get("phishing_probability", 0.0)
        reasons = result.get("reasons", [])
        
        signals = []
        weight_per_reason = 10
        total_reason_weight = len(reasons) * weight_per_reason

        # High probability -> major signal
        if prob > 0.5:
            signals.append({
                "id": "ml_behaviour_phishing_detected",
                "category": "BEHAVIORAL",
                "severity": "HIGH" if prob > 0.8 else "MEDIUM",
                "weight": int(prob * 50),
                "confidence": float(prob),
                "evidence": f"Behaviour ML model predicted {prob*100:.1f}% phishing probability."
            })
            
        for r in reasons:
            signals.append({
                "id": r.lower().replace(" ", "_").replace("/", "_"),
                "category": "BEHAVIORAL",
                "severity": "MEDIUM",
                "weight": weight_per_reason,
                "confidence": 0.9,
                "evidence": r
            })

        score = min(sum(s["weight"] for s in signals), 100)
        verdict = (
            "CRITICAL" if score >= 80 else
            "DANGEROUS" if score >= 60 else
            "SUSPICIOUS" if score >= 30 else
            "LOW RISK" if score >= 10 else
            "CLEAN"
        )

        nodes = [
            {"id": "n1", "type": "behaviour", "entity_id": f"behaviour_profile:{uuid.uuid4().hex[:8]}"},
            {"id": "n_url", "type": "url", "entity_id": f"url:{url}"}
        ]
        edges = [{"source": "n1", "target": "n_url", "type": "observed_link"}]
        
        # 3. Output Event payload
        return {
            "id": str(uuid.uuid4()),
            "type": "behaviour",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "iocs": {
                "urls": [url],
                "domains": [],
                "ips": [],
                "emails": [],
                "hashes": [],
                "patterns": {"reasons": reasons}
            },
            "features": {
                "work_hours": work_hours,
                "workdays": workdays,
                "text_length": len(text)
            },
            "signals": signals,
            "graph": {"nodes": nodes, "edges": edges},
            "correlation_keys": {
                "urls": [url],
                "domains": [],
                "emails": [],
                "ips": [],
            },
            "score": score,
            "verdict": verdict,
            "attack_type": ["social_engineering"] if score >= 30 else ["benign_communication"],
            "prediction": result,
            "analysis_time_ms": round((time.time() - start_time) * 1000, 2)
        }

if __name__ == "__main__":
    analyzer = BehaviourAnalyzer()
    res = analyzer.analyze("Verify your password urgently click here!", "http://evil-bank-login.com", 0, 0)
    import json
    print(json.dumps(res, indent=2))