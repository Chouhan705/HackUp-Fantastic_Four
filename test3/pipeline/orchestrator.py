import json
from typing import List, Dict, Any

# Assuming these modules are structured in a way that they can be imported from "core"
# You might need to adjust these paths based on your actual PYTHONPATH.
try:
    from models.event import Event
    from core.graph_store import GraphStore
    from core.correlator import Correlator
    from core.chain_builder import ChainBuilder
except ImportError:
    # Fallback to absolute or relative imports as per environment configuration
    pass

class Orchestrator:
    def __init__(self):
        # Initialize the pipeline components
        self.graph_store = GraphStore()
        self.correlator = Correlator()
        self.chain_builder = ChainBuilder()

    def process_events(self, raw_events_json: List[str]) -> Dict[str, Any]:
        """
        Main pipeline execution.
        1. Ingest event strings (JSON format)
        2. Convert to Event objects
        3. Add to GraphStore
        4. Run Correlator
        5. Build chains
        6. Compute qualitative risk
        """
        # 1 & 2: Ingest and convert to Event objects
        events = []
        for raw_json in raw_events_json:
            try:
                # Utilizing the previously built Event.from_json() logic
                event = Event.from_json(raw_json)
                events.append(event)
            except Exception as e:
                print(f"[Orchestrator] Error parsing event from JSON: {e}")
                continue

        # 3: Add to GraphStore for network merging and mapping
        for event in events:
            self.graph_store.add_event(event)
            
        # 4: Run Correlator (Detect temporal and structural overlaps)
        correlated_pairs = self.correlator.correlate(events)
        
        # 5: Build chains (Identify attack paths sequentially)
        chains = self.chain_builder.build_chains(correlated_pairs)
        
        # 6: Compute risk (Weighing chain confidence against internal event threat scores)
        # Create a quick lookup for event risk mapping
        event_map = {getattr(e, "id", None): e for e in events}
        
        for chain in chains:
            chain_events = [event_map[eid] for eid in chain.get("events", []) if eid in event_map]
            if not chain_events:
                chain["risk_score"] = 0.0
                chain["risk_level"] = "Low"
                continue
                
            # Heuristic calculation for chain risk
            # For instance, a weighted max score + compounding length factor
            max_score = max((getattr(e, "score", 0) for e in chain_events), default=0)
            confidence = chain.get("confidence", 0.5)
            
            # Simple algorithmic risk calculation logic
            base_risk = max_score * confidence
            length_amplifier = len(chain_events) * 5  # Add points for multi-staged attacks
            
            final_risk = base_risk + length_amplifier
            chain["risk_score"] = round(final_risk, 2)
            
            # Simple thresholding logic
            if final_risk > 80:
                chain["risk_level"] = "Critical"
            elif final_risk > 50:
                chain["risk_level"] = "High"
            elif final_risk > 20:
                chain["risk_level"] = "Medium"
            else:
                chain["risk_level"] = "Low"

        # Final structured payload mimicking standardized API responses
        return {
            "chains": chains,
            "global_graph": self.graph_store.export_graph()
        }
