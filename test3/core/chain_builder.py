import uuid
import networkx as nx
from typing import List, Tuple, Dict, Any

class ChainBuilder:
    def build_chains(self, correlated_pairs: List[Tuple[Any, Any]]) -> List[Dict[str, Any]]:
        """
        Builds directed chains from correlated event pairs.
        Merges overlapping chains and orders events by timestamp.
        """
        if not correlated_pairs:
            return []

        # Using a Directed Graph to represent chronological chains
        G = nx.DiGraph()

        for e1, e2 in correlated_pairs:
            # Ensure directed edge goes from older to newer event
            if not hasattr(e1, "timestamp") or not hasattr(e2, "timestamp"):
                continue
                
            if e1.timestamp <= e2.timestamp:
                G.add_edge(e1, e2)
            else:
                G.add_edge(e2, e1)

        chains = []
        
        # Merge overlapping chains by finding weakly connected components
        # (Components where events are linked regardless of edge direction)
        for component_nodes in nx.weakly_connected_components(G):
            if len(component_nodes) < 2:
                continue

            # Order events by timestamp to ensure chronological output
            sorted_events = sorted(list(component_nodes), key=lambda x: x.timestamp)
            event_ids = [getattr(e, "id", str(id(e))) for e in sorted_events]

            # Detect sequences and build attack paths
            attack_path = []
            
            # Check directed edges in chronological order to build the logical path
            for i in range(len(sorted_events)):
                for j in range(i + 1, len(sorted_events)):
                    u = sorted_events[i]
                    v = sorted_events[j]
                    
                    if G.has_edge(u, v):
                        u_type = getattr(u, "type", "unknown")
                        v_type = getattr(v, "type", "unknown")
                        path_str = f"{u_type}->{v_type}"
                        attack_path.append(path_str)

            # Remove duplicate transition strings if any, preserving discovery order
            attack_path = list(dict.fromkeys(attack_path))

            # Calculate a heuristic confidence based on the presence of malicious sequences
            confidence = 0.5  # Base confidence for any correlation
            
            if "email->url" in attack_path:
                confidence += 0.2
            if "url->attachment" in attack_path:
                confidence += 0.2
            if len(event_ids) >= 3:
                 confidence += 0.1
                 
            # Ensure confidence sits safely between 0.0 and 1.0
            confidence = min(1.0, round(confidence, 2))

            chains.append({
                "chain_id": str(uuid.uuid4()),
                "events": event_ids,
                "attack_path": attack_path,
                "confidence": float(confidence)
            })

        return chains
