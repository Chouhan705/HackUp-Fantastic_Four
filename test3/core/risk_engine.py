from typing import List, Dict, Any, Set

# Constants for Risk Calculation Logic
MAX_SCORE_NORMALIZER = 100.0

# Boost coefficients for risk amplification
STAGE_BOOST_STRONG = 0.20
STAGE_BOOST_MODERATE = 0.10
CRITICAL_BOOST = 0.20
MULTIPLE_HIGH_BOOST = 0.15
DIVERSITY_DOMAIN_BOOST = 0.10
DIVERSITY_ATTACK_TYPE_BOOST = 0.10

# Thresholds for severity levels based on event scores
CRITICAL_SCORE_THRESHOLD = 90
HIGH_SCORE_THRESHOLD = 70

class RiskEngine:
    def compute(self, chain: Dict[str, Any], events: List[Any]) -> Dict[str, Any]:
        """
        Computes the qualitative risk for multi-stage attack chains.
        """
        # Filter global events to only those included in the provided chain
        chain_event_ids = set(chain.get("events", []))
        chain_events = [e for e in events if getattr(e, "id", None) in chain_event_ids]

        if not chain_events:
            return self._build_empty_response()

        # 2. Extract Features
        scores = [getattr(e, "score", 0) for e in chain_events]
        max_score = max(scores) if scores else 0
        
        num_events = len(chain_events)
        
        domains: Set[str] = set()
        attack_types: Set[str] = set()
        critical_count = 0
        high_count = 0

        for e in chain_events:
            # Extract unique domains
            corr_keys = getattr(e, "correlation_keys", {})
            event_domains = corr_keys.get("domains", []) or corr_keys.get("domain", [])
            if isinstance(event_domains, str):
                domains.add(event_domains)
            elif isinstance(event_domains, list):
                domains.update(event_domains)
            
            # Extract unique attack types
            e_attack_types = getattr(e, "attack_type", [])
            if isinstance(e_attack_types, str):
                attack_types.add(e_attack_types)
            elif isinstance(e_attack_types, list):
                attack_types.update(e_attack_types)

            # Check for CRITICAL and HIGH signals
            score = getattr(e, "score", 0)
            verdict = getattr(e, "verdict", "").upper()
            if score >= CRITICAL_SCORE_THRESHOLD or verdict == "CRITICAL":
                critical_count += 1
            elif score >= HIGH_SCORE_THRESHOLD or verdict == "HIGH":
                high_count += 1

        # 3. Risk Logic
        
        # A. Base Score (normalized based on max event score)
        base_score = min(max_score / MAX_SCORE_NORMALIZER, 1.0)
        boost = 0.0

        # B. Stage Amplification
        if num_events >= 3:
            boost += STAGE_BOOST_STRONG
        elif num_events == 2:
            boost += STAGE_BOOST_MODERATE

        # C. Severity Boost
        if critical_count > 0:
            boost += CRITICAL_BOOST
        if high_count > 1:
            boost += MULTIPLE_HIGH_BOOST

        # D. Diversity Boost
        if len(domains) > 1:
            boost += DIVERSITY_DOMAIN_BOOST
        if len(attack_types) > 1:
            boost += DIVERSITY_ATTACK_TYPE_BOOST

        # E. Confidence Weight
        raw_score = min(base_score + boost, 1.0)
        confidence = float(chain.get("confidence", 1.0))
        
        final_risk_score = raw_score * confidence
        final_risk_score = max(0.0, min(final_risk_score, 1.0))

        # 4. Risk Level Mapping
        if final_risk_score >= 0.85:
            risk_level = "CRITICAL"
        elif final_risk_score >= 0.60:
            risk_level = "HIGH"
        elif final_risk_score >= 0.30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # 5. Output Format
        return {
            "risk_score": round(final_risk_score, 4),
            "risk_level": risk_level,
            "reasoning": {
                "max_score": max_score,
                "event_count": num_events,
                "critical_present": critical_count > 0,
                "attack_types": list(attack_types),
                "domains": list(domains)
            }
        }

    def _build_empty_response(self) -> Dict[str, Any]:
        return {
            "risk_score": 0.0,
            "risk_level": "LOW",
            "reasoning": {
                "max_score": 0,
                "event_count": 0,
                "critical_present": False,
                "attack_types": [],
                "domains": []
            }
        }
