import json
from typing import List, Dict, Any

from models.event import Event
from core.graph_store import GraphStore
from core.correlator import Correlator
from core.chain_builder import ChainBuilder
from core.risk_engine import RiskEngine

class Orchestrator:
    def __init__(self):
        # Initialize all the pipeline components correctly
        self.graph_store = GraphStore()
        self.correlator = Correlator()
        self.chain_builder = ChainBuilder()
        self.risk_engine = RiskEngine()

    def process_events(self, raw_events_json: List[str]) -> Dict[str, Any]:
        """
        Main pipeline execution.
        1. Ingest event strings (JSON format)
        2. Convert to Event objects
        3. Add to GraphStore
        4. Run Correlator
        5. Build chains
        6. Compute qualitative risk using RiskEngine
        """
        # 1 & 2: Ingest and convert to Event objects
        events = []
        for raw_json in raw_events_json:
            try:
                event = Event.from_json(raw_json)
                events.append(event)
            except Exception as e:
                print(f"[Orchestrator] Error parsing event from JSON: {e}")
                continue

        # 3: Add to GraphStore for network merging and mapping
        for event in events:
            self.graph_store.add_event(event)

        # 4: Run Correlator
        # It generates weighted, explainable links matching our robust correlator implementation
        correlated_pairs = self.correlator.correlate(events, graph_store=self.graph_store)

        # 5: Build chains
        chains = self.chain_builder.build_chains(correlated_pairs, events)

        # 6: Compute risk using RiskEngine
        for chain in chains:
            risk_result = self.risk_engine.compute(chain, events)

            # Append risk profiling data onto the chain logic output payload
            chain["risk_score"] = risk_result.get("risk_score", 0.0)
            chain["risk_level"] = risk_result.get("risk_level", "LOW")
            chain["reasoning"] = risk_result.get("reasoning", {})

        return {
            "chains": chains,
            "global_graph": self.graph_store.export_graph()
        }
