from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Set
from datetime import datetime
import json

@dataclass
class Event:
    id: str
    type: str  # email, url, attachment
    timestamp: datetime
    iocs: Dict[str, Any]
    graph: Dict[str, Any]
    score: int
    verdict: str
    attack_type: List[str]
    correlation_keys: Dict[str, Any]

    def __post_init__(self):
        self._validate_types()
        self._check_safety()
        self._normalize_data()
        self._validate_graph()
        self._validate_correlation()
        self._validate_type_consistency()

    def _validate_types(self):
        if not isinstance(self.id, str) or not self.id:
            raise ValueError("id must be a non-empty string")
        if self.type not in {"email", "url", "attachment", "behaviour", "clustering"}:
            raise ValueError("type must be 'email', 'url', 'attachment', 'behaviour', or 'clustering'")
        if not isinstance(self.timestamp, datetime):
            raise TypeError("timestamp must be a datetime object")
        if not isinstance(self.iocs, dict):
            raise TypeError("iocs must be a dictionary")
        if not isinstance(self.graph, dict):
            raise TypeError("graph must be a dictionary")
        if not isinstance(self.score, int):
            raise TypeError("score must be an integer")
        if not isinstance(self.verdict, str):
            raise TypeError("verdict must be a string")
        if not isinstance(self.attack_type, list):
            raise TypeError("attack_type must be a list")
        if not isinstance(self.correlation_keys, dict):
            raise TypeError("correlation_keys must be a dictionary")

    def _check_safety(self):
        if not self.graph or not self.graph.get("nodes"):
            raise ValueError("event graph cannot be empty")
        if not self.correlation_keys:
            raise ValueError("correlation_keys cannot be empty")

    def _normalize_data(self):
        # Normalize and deduplicate IOCs
        for key, values in self.iocs.items():
            if isinstance(values, list):
                if key.lower() in ["domain", "domains", "url", "urls"]:
                    self.iocs[key] = list(set(str(v).lower() for v in values))
                else:
                    self.iocs[key] = list(set(values))
            elif isinstance(values, str) and key.lower() in ["domain", "domains", "url", "urls"]:
                self.iocs[key] = values.lower()

        # Normalize correlation_keys
        for key, values in self.correlation_keys.items():
            if isinstance(values, list):
                if key.lower() in ["domain", "domains"]:
                    self.correlation_keys[key] = list(set(str(v).lower() for v in values))
                else:
                    self.correlation_keys[key] = list(set(values))
            elif isinstance(values, str) and key.lower() in ["domain", "domains"]:
                self.correlation_keys[key] = values.lower()

    def _validate_graph(self):
        nodes = self.graph.get("nodes", [])
        edges = self.graph.get("edges", [])
        
        seen_entity_ids: Set[str] = set()
        node_ids: Set[str] = set()

        for node in nodes:
            node_id = node.get("id")
            node_type = node.get("type")
            entity_id = node.get("entity_id")

            if not node_id or not node_type or not entity_id:
                raise ValueError(f"Graph node missing required fields (id, type, entity_id): {node}")

            if not isinstance(entity_id, str) or not entity_id.strip():
                raise ValueError(f"Invalid entity_id format: {entity_id}")

            if entity_id in seen_entity_ids:
                raise ValueError(f"Duplicate node found by entity_id: {entity_id}")
            
            seen_entity_ids.add(entity_id)
            node_ids.add(node_id)

        for edge in edges:
            source = edge.get("source")
            target = edge.get("target")

            if not source or not target:
                raise ValueError(f"Edge missing source or target: {edge}")

            if source not in node_ids or target not in node_ids:
                raise ValueError(f"Edge references invalid node ids: source={source}, target={target}")

            if source == target:
                raise ValueError(f"Self-loop edge detected: {source} -> {target}")

    def _validate_correlation(self):
        # Domains in iocs must appear in correlation_keys.domains
        iocs_domains = self.iocs.get("domains", []) or self.iocs.get("domain", [])
        if isinstance(iocs_domains, str):
            iocs_domains = [iocs_domains]
            
        corr_domains = self.correlation_keys.get("domains", []) or self.correlation_keys.get("domain", [])
        if isinstance(corr_domains, str):
            corr_domains = [corr_domains]
            
        corr_domains_set = set(corr_domains)
        
        for domain in iocs_domains:
            if domain not in corr_domains_set:
                raise ValueError(f"Domain from IOCs '{domain}' is missing in correlation_keys")

    def _validate_type_consistency(self):
        nodes = self.graph.get("nodes", [])
        node_types = {str(node.get("type")).lower() for node in nodes}

        if self.type == "email":
            if "email" not in node_types:
                raise ValueError("Event type 'email' must contain 'email' nodes in the graph")
        elif self.type == "url":
            if "url" not in node_types and "domain" not in node_types:
                raise ValueError("Event type 'url' must contain 'url' or 'domain' nodes in the graph")
        elif self.type == "attachment":
            if "file" not in node_types and "hash" not in node_types:
                raise ValueError("Event type 'attachment' must contain 'file' or 'hash' nodes in the graph")

    def get_all_entities(self) -> List[str]:
        return [node.get("entity_id") for node in self.graph.get("nodes", []) if node.get("entity_id")]

    def get_primary_domain(self) -> str:
        domains = self.correlation_keys.get("domains", []) or self.correlation_keys.get("domain", [])
        if isinstance(domains, list) and domains:
            return domains[0]
        elif isinstance(domains, str):
            return domains
        return ""

    def get_event_summary(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "timestamp": self.timestamp.isoformat(),
            "verdict": self.verdict,
            "score": self.score,
            "node_count": len(self.graph.get("nodes", [])),
            "edge_count": len(self.graph.get("edges", [])),
            "primary_domain": self.get_primary_domain()
        }

    @classmethod
    def from_json(cls, json_str: str) -> "Event":
        data = json.loads(json_str)
        if "timestamp" in data and isinstance(data["timestamp"], str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
        return cls(**data)

    def to_json(self) -> str:
        data = asdict(self)
        if isinstance(data.get("timestamp"), datetime):
            data["timestamp"] = data["timestamp"].isoformat()
        return json.dumps(data)
