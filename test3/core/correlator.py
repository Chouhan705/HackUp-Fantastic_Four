from typing import List, Tuple, Any
from datetime import timedelta
from itertools import combinations

class Correlator:
    def __init__(self, time_threshold_hours: float = 24.0):
        # Configurable time threshold for linking events
        self.time_threshold = timedelta(hours=time_threshold_hours)

    def correlate(self, events: List[Any]) -> List[Tuple[Any, Any]]:
        """
        Link events based on shared properties and time constraints.
        Returns a list of linked event pairs (without duplicates or self-links).
        """
        linked_pairs = []

        # itertools.combinations ensures no self-links and no duplicate pairs (e.g., A,B and B,A)
        for event1, event2 in combinations(events, 2):
            if self._should_link(event1, event2):
                linked_pairs.append((event1, event2))

        return linked_pairs

    def _should_link(self, event1: Any, event2: Any) -> bool:
        """
        Determine if two events should be linked based on:
        1. Time difference < threshold
        2. AND (Shared correlation_keys OR Graph overlap)
        """
        # Feature 2: Time difference check
        if not hasattr(event1, "timestamp") or not hasattr(event2, "timestamp"):
            return False
            
        time_diff = abs(event1.timestamp - event2.timestamp)
        if time_diff >= self.time_threshold:
            return False

        # Feature 1: Shared correlation_keys (domain, ip, brand, hash)
        if self._has_shared_keys(event1, event2):
            return True

        # Feature 3: Graph overlap (shared entity_id)
        if self._has_graph_overlap(event1, event2):
            return True

        return False

    def _has_shared_keys(self, event1: Any, event2: Any) -> bool:
        """Check if events share any values in their correlation_keys."""
        keys1 = getattr(event1, "correlation_keys", {}) or {}
        keys2 = getattr(event2, "correlation_keys", {}) or {}
        
        for key, val1 in keys1.items():
            if key in keys2:
                val2 = keys2[key]
                
                # Normalize to sets for easy intersection, handling both lists and scalar values
                val1_set = set(val1) if isinstance(val1, list) else {val1}
                val2_set = set(val2) if isinstance(val2, list) else {val2}
                
                if val1_set.intersection(val2_set):
                    return True
        return False

    def _has_graph_overlap(self, event1: Any, event2: Any) -> bool:
        """Check if events share any nodes (by entity_id) in their graphs."""
        graph1 = getattr(event1, "graph", {}) or {}
        graph2 = getattr(event2, "graph", {}) or {}
        
        nodes1 = graph1.get("nodes", []) if isinstance(graph1, dict) else []
        nodes2 = graph2.get("nodes", []) if isinstance(graph2, dict) else []
        
        # Extract entity_ids from both graphs
        entity_ids1 = {n.get("entity_id") for n in nodes1 if isinstance(n, dict) and n.get("entity_id")}
        entity_ids2 = {n.get("entity_id") for n in nodes2 if isinstance(n, dict) and n.get("entity_id")}
        
        return bool(entity_ids1.intersection(entity_ids2))
