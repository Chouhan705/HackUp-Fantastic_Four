import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import json
from pipeline.orchestrator import Orchestrator

def create_event_json(event_id, event_type, timestamp, score, verdict, domain, url=None, filename=None):
    nodes = []
    
    if event_type == "email":
        nodes.append({"id": "n1", "type": "email", "entity_id": f"email:attacker@{domain}"})
    elif event_type == "url":
        nodes.append({"id": "n1", "type": "url", "entity_id": f"url:{url}"})
        nodes.append({"id": "n2", "type": "domain", "entity_id": f"domain:{domain}"})
    elif event_type == "attachment":
        nodes.append({"id": "n1", "type": "file", "entity_id": f"file:{filename}"})
        nodes.append({"id": "n2", "type": "domain", "entity_id": f"domain:{domain}"})
    elif event_type == "behaviour":
        nodes.append({"id": "n1", "type": "behaviour", "entity_id": f"behaviour_profile:{domain}"}) # Just mapping to domain for testing context
        nodes.append({"id": "n2", "type": "url", "entity_id": f"url:{url}"})
    elif event_type == "clustering":
        nodes.append({"id": "n1", "type": "clustering", "entity_id": f"campaign_cluster:active_threat"})
        nodes.append({"id": "n2", "type": "url", "entity_id": f"url:{url}"})

    event_data = {
        "id": event_id,
        "type": event_type,
        "timestamp": timestamp,
        "iocs": {"domains": [domain]},
        "graph": {
            "nodes": nodes,
            "edges": []
        },
        "score": score,
        "verdict": verdict,
        "attack_type": ["phishing"],
        "correlation_keys": {"domains": [domain]}
    }
    
    if event_type in ["url", "behaviour", "clustering"]:
        event_data["graph"]["edges"].append({"source": "n1", "target": "n2", "type": "hosted_on"})
        
    return json.dumps(event_data)

def run_integration():
    # 1. Generate Raw JSON events mapping a coherent attack flow
    # Email -> URL -> Attachment
    raw_events = [
        create_event_json("ev_001", "email", "2026-04-04T10:00:00Z", 40, "MEDIUM", "evil.com"),
        create_event_json("ev_002", "url", "2026-04-04T10:05:00Z", 75, "HIGH", "evil.com", url="http://evil.com/payload"),
        create_event_json("ev_003", "attachment", "2026-04-04T10:10:00Z", 95, "CRITICAL", "evil.com", filename="malware.exe"),
        create_event_json("ev_004", "behaviour", "2026-04-04T10:12:00Z", 85, "CRITICAL", "evil.com", url="http://evil.com/payload"),
        create_event_json("ev_005", "clustering", "2026-04-04T10:15:00Z", 65, "HIGH", "evil.com", url="http://evil.com/payload")
    ]

    print("[*] Running Orchestrator Pipeline...")
    
    # Initialize and run
    orchestrator = Orchestrator()
    result = orchestrator.process_events(raw_events)

    print("\n========= ORCHESTRATOR OUTPUT =========")
    print(json.dumps(result["chains"], indent=2))

if __name__ == "__main__":
    run_integration()
