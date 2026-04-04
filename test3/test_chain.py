from datetime import datetime, timezone, timedelta
import json
from core.chain_builder import ChainBuilder

class DummyEvent:
    def __init__(self, id, type, timestamp_offset_minutes=0):
        self.id = id
        self.type = type
        self.timestamp = datetime.now(timezone.utc) + timedelta(minutes=timestamp_offset_minutes)

def run_dummy_test():
    # 1. Create dummy events
    e1 = DummyEvent(id="event_1", type="email", timestamp_offset_minutes=0)
    e2 = DummyEvent(id="event_2", type="url", timestamp_offset_minutes=5)
    e3 = DummyEvent(id="event_3", type="url", timestamp_offset_minutes=10) # Redirect
    e4 = DummyEvent(id="event_4", type="attachment", timestamp_offset_minutes=15)
    e5 = DummyEvent(id="event_5", type="email", timestamp_offset_minutes=20) # Unrelated
    
    events = [e1, e2, e3, e4, e5]

    # 2. Create dummy correlated links
    correlated_links = [
        {
            "event1": "event_1",
            "event2": "event_2",
            "score": 0.8,
            "reasons": ["shared_domain", "time_proximity"],
            "time_diff_seconds": 300.0
        },
        {
            "event1": "event_2",
            "event2": "event_3",
            "score": 0.9,
            "reasons": ["shared_domain", "graph_overlap"],
            "time_diff_seconds": 300.0
        },
        {
            "event1": "event_3",
            "event2": "event_4",
            "score": 0.95,
            "reasons": ["shared_hash", "time_proximity"],
            "time_diff_seconds": 300.0
        }
        # e5 has no connections
    ]

    # 3. Initialize ChainBuilder and run
    builder = ChainBuilder()
    chains = builder.build_chains(correlated_links, events)

    # 4. Print output
    print(json.dumps(chains, indent=2))

if __name__ == "__main__":
    run_dummy_test()
