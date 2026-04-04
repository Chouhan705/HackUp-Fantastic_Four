from typing import List, Tuple, Any, Dict, Optional
from datetime import timedelta
from itertools import combinations

class Correlator:
    def __init__(self, time_threshold_hours: float = 24.0):
        # Configurable time threshold for linking events
        self.time_threshold = timedelta(hours=time_threshold_hours)
        
        self.key_weights = {
            "hashes": 1.0,
            "hash": 1.0,
            "ips": 0.9,
            "ip": 0.9,
            "domains": 0.7,
            "domain": 0.7,
            "emails": 0.6,
            "email": 0.6,
            "brands": 0.4,
            "brand": 0.4
        }
        
        self.reason_map = {
            "hashes": "shared_hash",
            "hash": "shared_hash",
            "ips": "shared_ip",
            "ip": "shared_ip",
            "domains": "shared_domain",
            "domain": "shared_domain",
            "emails": "shared_email",
            "email": "shared_email",
            "brands": "shared_brand",
            "brand": "shared_brand",
        }

    def correlate(self, events: List[Any], graph_store: Optional[Any] = None) -> List[Dict[str, Any]]:
        """
        Link events based on shared properties, time constraints, and graph proximity.
        Returns a list of linked event dictionaries.
        """
        linked_pairs = []

        for e1, e2 in combinations(events, 2):
            if not hasattr(e1, "timestamp") or not hasattr(e2, "timestamp"):
                continue
                
            # Ensure event1 is earlier, event2 is later (Direction logic)
            if e1.timestamp <= e2.timestamp:
                event1, event2 = e1, e2
            else:
                event1, event2 = e2, e1
                
            time_diff = abs(event1.timestamp - event2.timestamp)
            if time_diff >= self.time_threshold:
                continue
                
            score, reasons = self._evaluate_link(event1, event2, time_diff, graph_store)
            
            # Threshold constraint
            if score >= 0.5:
                linked_pairs.append({
                    "event1": getattr(event1, "id", str(id(event1))),
                    "event2": getattr(event2, "id", str(id(event2))),
                    "score": round(score, 3),
                    "reasons": reasons,
                    "time_diff_seconds": time_diff.total_seconds()
                })

        return linked_pairs

    def _evaluate_link(self, event1: Any, event2: Any, time_diff: timedelta, graph_store: Optional[Any]) -> Tuple[float, List[str]]:
        score = 0.0
        reasons = []
        
        # 1. Time proximity
        time_diff_sec = time_diff.total_seconds()
        max_sec = self.time_threshold.total_seconds()
        if max_sec > 0:
            time_score = max(0.0, 1.0 - (time_diff_sec / max_sec))
            # Weight proximity to push positive interactions higher
            score += time_score * 0.5
            if time_score > 0.5:
                reasons.append("time_proximity")

        # 2. Shared correlation_keys (weighted)
        shared_keys_score, shared_reasons = self._get_shared_keys_score(event1, event2)
        score += shared_keys_score
        reasons.extend(shared_reasons)

        # 3. Graph overlap
        if self._has_graph_overlap(event1, event2):
            score += 0.5
            reasons.append("graph_overlap")
            
        # 4. Optional GraphStore indirect relationships
        if graph_store:
            indirect_score, indirect_reasons = self._evaluate_indirect_graph_relationships(event1, event2, graph_store)
            score += indirect_score
            reasons.extend(indirect_reasons)

        # Deduplicate reasons while preserving order
        reasons = list(dict.fromkeys(reasons))
        
        return score, reasons

    def _should_link(self, event1: Any, event2: Any) -> bool:
        """Kept for backward compatibility. Checks basic linkage."""
        if not hasattr(event1, "timestamp") or not hasattr(event2, "timestamp"):
            return False
            
        time_diff = abs(event1.timestamp - event2.timestamp)
        if time_diff >= self.time_threshold:
            return False

        if self._has_shared_keys(event1, event2):
            return True

        if self._has_graph_overlap(event1, event2):
            return True

        return False

    def _get_shared_keys_score(self, event1: Any, event2: Any) -> Tuple[float, List[str]]:
        score = 0.0
        reasons = []
        
        keys1 = getattr(event1, "correlation_keys", {}) or {}
        keys2 = getattr(event2, "correlation_keys", {}) or {}
        
        for key, val1 in keys1.items():
            if key in keys2:
                val2 = keys2[key]
                val1_set = set(val1) if isinstance(val1, list) else {val1}
                val2_set = set(val2) if isinstance(val2, list) else {val2}
                
                if val1_set.intersection(val2_set):
                    weight = self.key_weights.get(key.lower(), 0.1)
                    score += weight
                    reason_str = self.reason_map.get(key.lower(), f"shared_{key}")
                    reasons.append(reason_str)
                    
        return score, reasons

    def _has_shared_keys(self, event1: Any, event2: Any) -> bool:
        """Check if events share any values in their correlation_keys."""
        score, _ = self._get_shared_keys_score(event1, event2)
        return score > 0

    def _has_graph_overlap(self, event1: Any, event2: Any) -> bool:
        """Check if events share any nodes (by entity_id) in their graphs."""
        graph1 = getattr(event1, "graph", {}) or {}
        graph2 = getattr(event2, "graph", {}) or {}
        
        nodes1 = graph1.get("nodes", []) if isinstance(graph1, dict) else []
        nodes2 = graph2.get("nodes", []) if isinstance(graph2, dict) else []
        
        entity_ids1 = {n.get("entity_id") for n in nodes1 if isinstance(n, dict) and n.get("entity_id")}
        entity_ids2 = {n.get("entity_id") for n in nodes2 if isinstance(n, dict) and n.get("entity_id")}
        
        return bool(entity_ids1.intersection(entity_ids2))

    def _evaluate_indirect_graph_relationships(self, event1: Any, event2: Any, graph_store: Any) -> Tuple[float, List[str]]:
        score = 0.0
        reasons = []
        
        graph1 = getattr(event1, "graph", {}) or {}
        graph2 = getattr(event2, "graph", {}) or {}
        
        nodes1 = graph1.get("nodes", []) if isinstance(graph1, dict) else []
        nodes2 = graph2.get("nodes", []) if isinstance(graph2, dict) else []
        
        entity_ids1 = {n.get("entity_id") for n in nodes1 if isinstance(n, dict) and n.get("entity_id")}
        entity_ids2 = {n.get("entity_id") for n in nodes2 if isinstance(n, dict) and n.get("entity_id")}
        
        for e_id1 in entity_ids1:
            neighbors = graph_store.get_neighbors(e_id1)
            neighbor_ids = {n.entity_id if hasattr(n, "entity_id") else n for n in neighbors}
            if neighbor_ids.intersection(entity_ids2):
                score += 0.3
                reasons.append("indirect_graph_overlap")
                break # Adding once per pair relation to avoid score explosion
                
        return score, reasons
