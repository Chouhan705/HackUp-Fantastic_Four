import sys
import os
import uuid
import time
from datetime import datetime

# Adjust path so we can import campaign detection
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from campaign import detect_campaign

class ClusteringAnalyzer:
    """
    Analyzes event text payloads (e.g. from an email body) and clusters them 
    against historically seen events using TF-IDF and Cosine Similarity 
    to detect organized phishing campaigns.
    Outputs a structured JSON event for the pipeline.
    """

    def analyze(self, text: str, source_id: str = None) -> dict:
        start_time = time.time()
        
        # 1. Run local campaign similarity clustering
        try:
            is_campaign, similarity_score = detect_campaign(text)
        except Exception as e:
            is_campaign, similarity_score = False, 0.0

        # 2. Build signals based on campaign detection
        signals = []
        if is_campaign:
            signals.append({
                "id": "campaign_cluster_matched",
                "category": "CAMPAIGN",
                "severity": "HIGH",
                "weight": int(similarity_score * 50),
                "confidence": similarity_score,
                "evidence": f"Text highly matches a known campaign cluster (Similarity: {similarity_score:.2f})."
            })

        score = min(sum(s["weight"] for s in signals), 100)
        verdict = (
            "DANGEROUS" if score >= 40 else
            "SUSPICIOUS" if score >= 20 else
            "CLEAN"
        )

        cluster_entity_id = f"campaign_cluster:{uuid.uuid4().hex[:8]}" if not is_campaign else "campaign_cluster:active_threat"
        source_id = source_id or f"text_source:{uuid.uuid4().hex[:8]}"

        nodes = [
            {"id": "c1", "type": "clustering", "entity_id": cluster_entity_id},
        ]
        edges = []

        # 3. Output Event payload
        return {
            "id": str(uuid.uuid4()),
            "type": "clustering",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "iocs": {
                "urls": [],
                "domains": [],
                "ips": [],
                "emails": [],
                "hashes": [],
                "patterns": {"campaign_match": is_campaign, "similarity": similarity_score}
            },
            "features": {
                "text_length": len(text),
                "is_campaign": is_campaign,
                "similarity_score": similarity_score
            },
            "signals": signals,
            "graph": {"nodes": nodes, "edges": edges},
            "correlation_keys": {
                "urls": [],
                "domains": [],
                "emails": [],
                "ips": [],
            },
            "score": score,
            "verdict": verdict,
            "attack_type": ["organized_campaign"] if is_campaign else ["isolated_event"],
            "analysis_time_ms": round((time.time() - start_time) * 1000, 2)
        }

if __name__ == "__main__":
    analyzer = ClusteringAnalyzer()
    print("--- Test 1 (Pops a new cluster) ---")
    res1 = analyzer.analyze("Hello, please update your bank account password at http://evil.com/login.")
    import json
    print(json.dumps(res1, indent=2))
    
    print("\n--- Test 2 (Should cluster with Test 1) ---")
    res2 = analyzer.analyze("Hello, please update your bank account password at http://evil.com/login now.")
    print(json.dumps(res2, indent=2))