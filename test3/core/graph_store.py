import networkx as nx
from typing import Dict, Any, List

class GraphStore:
    def __init__(self):
        # Using MultiDiGraph to allow different types of edges between the same nodes
        self.graph = nx.MultiDiGraph()

    def add_event(self, event: Any) -> None:
        """
        Merge nodes and edges from an Event into the graph.
        We expect event.graph to be a dictionary like:
        {
            "nodes": [{"entity_id": "...", "type": "..."}, ...],
            "edges": [{"source": "...", "target": "...", "type": "..."}, ...]
        }
        """
        if not event or not hasattr(event, "graph") or not event.graph:
            return

        event_id = getattr(event, "id", "unknown_event")
        event_graph = event.graph
        
        nodes = event_graph.get("nodes", [])
        edges = event_graph.get("edges", [])

        # Add or merge nodes using entity_id
        for node in nodes:
            entity_id = node.get("entity_id")
            if not entity_id:
                continue
                
            node_type = node.get("type", "unknown")
            
            if not self.graph.has_node(entity_id):
                # Create node with initial attributes
                self.graph.add_node(
                    entity_id, 
                    type=node_type, 
                    source_events=[event_id]
                )
            else:
                # Merge existing node attributes
                existing_sources = self.graph.nodes[entity_id].get("source_events", [])
                if event_id not in existing_sources:
                    existing_sources.append(event_id)
                self.graph.nodes[entity_id]["source_events"] = existing_sources

        # Add edges, avoiding duplication and invalid edges
        for edge in edges:
            source = edge.get("source")
            target = edge.get("target")
            edge_type = edge.get("type")
            
            # Avoid invalid edges
            if not source or not target or not edge_type:
                continue
                
            # Both ends of the edge must exist in the graph (no invalid edges)
            if not self.graph.has_node(source) or not self.graph.has_node(target):
                continue
                
            # Check for existing duplicate edge of the exact same type
            is_dupe = False
            if self.graph.has_edge(source, target):
                existing_edges = self.graph[source][target]
                for key, edge_data in existing_edges.items():
                    if edge_data.get("type") == edge_type:
                        is_dupe = True
                        break
            
            if not is_dupe:
                self.graph.add_edge(source, target, type=edge_type)

    def get_neighbors(self, node_id: str) -> List[str]:
        """Return a list of neighbor node IDs for a given node."""
        if not self.graph.has_node(node_id):
            return []
        
        successors = list(self.graph.successors(node_id))
        predecessors = list(self.graph.predecessors(node_id))
        
        # Deduplicate and return
        return list(set(successors + predecessors))

    def export_graph(self) -> Dict[str, Any]:
        """Export the graph back to a JSON-serializable dictionary format."""
        return nx.node_link_data(self.graph)
