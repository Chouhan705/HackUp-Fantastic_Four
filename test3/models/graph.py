from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Set

@dataclass
class GraphNode:
    id: str
    type: str # 'url', 'domain', 'subdomain', 'ip', 'email', 'file', 'brand'
    entity_id: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        allowed_types = {"url", "domain", "subdomain", "ip", "email", "file", "brand"}
        if not self.id:
            raise ValueError("id must not be empty")
        if self.type not in allowed_types:
            raise ValueError(f"Invalid type '{self.type}'. Must be one of: {allowed_types}")
        if not self.entity_id.startswith(f"{self.type}:"):
            raise ValueError(f"entity_id must start with '{self.type}:'")


@dataclass
class GraphEdge:
    from_node: str
    to_node: str
    type: str # 'hosted_on', 'belongs_to', 'trust_violation', 'contains_link', 'drops_file', 'sent_from'
    attributes: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        allowed_types = {"hosted_on", "belongs_to", "trust_violation", "contains_link", "drops_file", "sent_from"}
        if self.from_node == self.to_node:
            raise ValueError("Self-loops are not allowed (from_node == to_node)")
        if self.type not in allowed_types:
            raise ValueError(f"Invalid type '{self.type}'. Must be one of: {allowed_types}")


@dataclass
class Graph:
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    
    # Internal lookups for faster access and deduplication
    _node_by_entity_id: Dict[str, GraphNode] = field(init=False, default_factory=dict, repr=False)
    _node_ids: Set[str] = field(init=False, default_factory=set, repr=False)
    _edge_set: Set[str] = field(init=False, default_factory=set, repr=False) # stores "from_node:to_node:type"

    def __post_init__(self):
        # Build initial lookups from provided lists
        for node in self.nodes:
            self._node_by_entity_id[node.entity_id] = node
            self._node_ids.add(node.id)
            
        for edge in self.edges:
            edge_key = f"{edge.from_node}:{edge.to_node}:{edge.type}"
            self._edge_set.add(edge_key)

    def add_node(self, node: GraphNode) -> None:
        if node.entity_id not in self._node_by_entity_id:
            self.nodes.append(node)
            self._node_by_entity_id[node.entity_id] = node
            self._node_ids.add(node.id)

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.from_node not in self._node_ids or edge.to_node not in self._node_ids:
            raise ValueError(f"Edge nodes ({edge.from_node} -> {edge.to_node}) must exist in the graph")
            
        edge_key = f"{edge.from_node}:{edge.to_node}:{edge.type}"
        if edge_key not in self._edge_set:
            self.edges.append(edge)
            self._edge_set.add(edge_key)

    def get_node(self, entity_id: str) -> Optional[GraphNode]:
        return self._node_by_entity_id.get(entity_id)

    def validate(self) -> None:
        seen_entity_ids = set()
        node_ids = set()

        for node in self.nodes:
            if node.entity_id in seen_entity_ids:
                raise ValueError(f"Duplicate entity_id found: {node.entity_id}")
            seen_entity_ids.add(node.entity_id)
            node_ids.add(node.id)

        for edge in self.edges:
            if edge.from_node not in node_ids or edge.to_node not in node_ids:
                raise ValueError(f"Edge references invalid node ids: {edge.from_node} -> {edge.to_node}")
            if edge.from_node == edge.to_node:
                raise ValueError(f"Self-loop edge detected: {edge.from_node} -> {edge.to_node}")

    def get_neighbors(self, entity_id: str) -> List[GraphNode]:
        node = self.get_node(entity_id)
        if not node:
            return []
            
        target_id = node.id
        neighbor_ids = set()
        
        for edge in self.edges:
            if edge.from_node == target_id:
                neighbor_ids.add(edge.to_node)
            elif edge.to_node == target_id:
                neighbor_ids.add(edge.from_node)
                
        # Find GraphNode objects by id
        neighbors = [n for n in self.nodes if n.id in neighbor_ids]
        return neighbors

    def get_nodes_by_type(self, type: str) -> List[GraphNode]:
        return [node for node in self.nodes if node.type == type]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Graph":
        nodes = [GraphNode(**node_data) for node_data in data.get("nodes", [])]
        edges = [GraphEdge(**edge_data) for edge_data in data.get("edges", [])]
        return cls(nodes=nodes, edges=edges)
