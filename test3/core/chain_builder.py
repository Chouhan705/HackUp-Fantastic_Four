import uuid
from typing import List, Dict, Any, Set, Optional
from collections import defaultdict, deque

class ChainBuilder:
    def __init__(self):
        # Defines what constitutes a strong signal for chain validation
        self.strong_signal_keywords = {"hash", "domain", "email", "graph_overlap"}

    def build_chains(self, correlated_links: List[Dict[str, Any]], events: List[Any]) -> List[Dict[str, Any]]:
        """
        Builds directed attack chains from a list of correlated event links.
        Returns a structured list of valid attack chains.
        """
        # Map events for quick O(1) lookup
        event_map = {getattr(e, "id"): e for e in events if hasattr(e, "id")}
        
        # adj: directed adjacency list for edges and their metadata
        # undirected_adj: undirected connectivity mapping for component discovery
        adj = defaultdict(dict)
        undirected_adj = defaultdict(set)
        
        for link in correlated_links:
            u = link.get("event1")
            v = link.get("event2")
            score = link.get("score", 0.0)
            reasons = link.get("reasons", [])
            
            if not u or not v or u not in event_map or v not in event_map:
                continue
                
            e1 = event_map[u]
            e2 = event_map[v]
            
            # Enforce directed chronological order
            t1 = getattr(e1, "timestamp", None)
            t2 = getattr(e2, "timestamp", None)
            
            if t1 and t2:
                if t1 > t2:
                    u, v = v, u
                elif t1 == t2:
                    # Break ties deterministically to avoid cycles
                    if u > v:
                        u, v = v, u
            
            # Support duplicate links by keeping the best score and merging reasons
            if v in adj[u]:
                adj[u][v]["score"] = max(score, adj[u][v]["score"])
                adj[u][v]["reasons"] = list(set(adj[u][v]["reasons"]).union(set(reasons)))
            else:
                adj[u][v] = {"score": score, "reasons": reasons}
            
            undirected_adj[u].add(v)
            undirected_adj[v].add(u)
            
        # Discover connected components denoting potential chains
        visited = set()
        chains = []
        
        for node in list(undirected_adj.keys()):
            if node not in visited:
                component = self._bfs_component(node, undirected_adj, visited)
                if len(component) >= 2:
                    chains.append(component)
                    
        # Extract and validate sequences from each component
        results = []
        for comp in chains:
            chain_result = self._process_chain_component(comp, adj, event_map)
            if chain_result:
                results.append(chain_result)
                
        return results

    def _bfs_component(self, start_node: str, undirected_adj: Dict[str, Set[str]], visited: Set[str]) -> Set[str]:
        """Runs standard BFS to extract a weakly connected component."""
        component = set()
        queue = deque([start_node])
        visited.add(start_node)
        
        while queue:
            curr = queue.popleft()
            component.add(curr)
            for neighbor in undirected_adj[curr]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        return component

    def _process_chain_component(self, component: Set[str], adj: Dict[str, Dict[str, Any]], event_map: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Processes, validates, and formats a single attack chain."""
        edges = []
        all_reasons = set()
        total_score = 0.0
        
        # Reconstruct all localized edges
        for u in component:
            for v in adj[u]:
                if v in component:
                    edge_data = adj[u][v]
                    edges.append((u, v, edge_data))
                    all_reasons.update(edge_data["reasons"])
                    total_score += edge_data["score"]
                    
        num_edges = len(edges)
        if num_edges == 0:
            return None
            
        avg_score = total_score / num_edges
        
        # VALIDATION 1: Average edge score must be >= 0.5
        if avg_score < 0.5:
            return None
            
        # VALIDATION 2: Must contain at least one strong signal
        has_strong_signal = any(
            any(keyword in reason for keyword in self.strong_signal_keywords) 
            for reason in all_reasons
        )
        if not has_strong_signal:
            return None
            
        # Ensure chronological ordering of the events
        sorted_nodes = sorted(list(component), key=lambda x: (getattr(event_map[x], "timestamp"), x))
        
        # Infer chronological attack path sequentially
        attack_path = []
        sorted_edges = sorted(edges, key=lambda e: getattr(event_map[e[0]], "timestamp"))
        
        for u, v, _ in sorted_edges:
            t1 = getattr(event_map[u], "type", "unknown")
            t2 = getattr(event_map[v], "type", "unknown")
            
            if t1 == "url" and t2 == "url":
                path_step = "redirect"
            else:
                path_step = f"{t1}->{t2}"
                
            attack_path.append(path_step)
                
        # Deduplicate sequential/matching steps to clean up complex paths
        clean_attack_path = list(dict.fromkeys(attack_path))
        
        # Compute dynamic confidence
        confidence = avg_score
        if len(component) >= 3:
            confidence += 0.15 # Stronger confidence with extended multi-stage links
            
        if any(key in reason for reason in all_reasons for key in ("hash", "domain")):
            confidence += 0.20 # Bonus for highly precise matches
            
        confidence = max(0.0, min(1.0, confidence))
        
        return {
            "chain_id": str(uuid.uuid4()),
            "events": sorted_nodes,
            "attack_path": clean_attack_path,
            "confidence": round(confidence, 3),
            "meta": {
                "event_count": len(component),
                "avg_score": round(avg_score, 3)
            }
        }
