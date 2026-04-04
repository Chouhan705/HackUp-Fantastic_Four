from typing import List, Dict, Any

class RiskEngine:
    """
    Production-grade RiskEngine for multi-vector phishing detection chains.
    Computes cross-vector fusion, applies category caps, chain amplifications,
    and returns human-readable explainable attack summaries.
    """
    
    SEVERITY_WEIGHTS = {
        "CRITICAL": 1.0,
        "HIGH": 0.75,
        "MEDIUM": 0.5,
        "LOW": 0.25
    }

    def compute(self, chain: Dict[str, Any], events: List[Any]) -> Dict[str, Any]:
        chain_event_ids = set(chain.get("events", []))
        chain_events = [e for e in events if getattr(e, "id", None) in chain_event_ids]

        if not chain_events:
            return self._build_empty_response()

        confidence = float(chain.get("confidence", 1.0))
        attack_path = chain.get("attack_path", [])

        # 2. SIGNAL WEIGHTING
        all_signals = []
        critical_count = 0

        for e in chain_events:
            signals = getattr(e, "signals", [])
            # If no formal signals list is present, infer a generic signal from the verdict
            if not signals:
                verdict = getattr(e, "verdict", "LOW").upper()
                signals = [
                    {
                        "name": f"Inferred {verdict} activity on {getattr(e, 'type', 'event')}",
                        "severity": verdict,
                        "weight": 1.0
                    }
                ]
            
            for s in signals:
                sev = str(s.get("severity", "LOW")).upper()
                base_weight = self.SEVERITY_WEIGHTS.get(sev, 0.25)
                # Apply explicit input signal weights if provided
                s_weight = float(s.get("weight", 1.0))
                
                weighted_signal_score = (base_weight * s_weight) * confidence
                
                if sev == "CRITICAL":
                    critical_count += 1
                
                all_signals.append({
                    "name": s.get("name", "Unknown Signal"),
                    "severity": sev,
                    "weighted_score": weighted_signal_score
                })

        # Sort signals by their computed weighted score
        all_signals.sort(key=lambda x: x["weighted_score"], reverse=True)
        top_signals = [s["name"] for s in all_signals[:3]]

        # 3. VECTOR-LEVEL SCORING & 4. CATEGORY CAPS
        vectors = {"email": [], "url": [], "attachment": []}
        for e in chain_events:
            etype = getattr(e, "type", "unknown").lower()
            if etype in vectors:
                vectors[etype].append(e)

        caps = {"email": 0.3, "url": 0.4, "attachment": 0.4}
        vector_scores = {"email": 0.0, "url": 0.0, "attachment": 0.0}

        for vec, evs in vectors.items():
            if not evs:
                continue
                
            # Score adjusted based on the raw maximum score
            max_score = max((getattr(e, "score", 0) for e in evs), default=0)
            normalized_score = max_score / 100.0
            # Implement 4. Category Caps preventing specific vectors from dominating
            vector_scores[vec] = min(normalized_score, caps.get(vec, 0.0))

        # 5. CROSS-VECTOR FUSION
        base_score = sum(vector_scores.values())
        active_vectors = sum(1 for v in vector_scores.values() if v > 0)
        
        fusion_boost = 0.0
        if active_vectors == 3:
            fusion_boost = 0.2
        elif active_vectors >= 2:
            fusion_boost = 0.1
            
        fused_score = base_score + fusion_boost

        # 6. CHAIN AMPLIFICATION
        chain_boost_value = 0.0
        if len(chain_events) >= 3:
            fused_score *= 1.2
            chain_boost_value += 0.2
            
        if "email->url" in attack_path and "url->attachment" in attack_path:
            fused_score += 0.15
            chain_boost_value += 0.15

        # 7. CRITICAL OVERRIDE
        critical_override_applied = False
        if critical_count > 1:
            if fused_score < 0.85:
                fused_score = max(fused_score, 0.85)
                critical_override_applied = True
        elif critical_count >= 1:
            if fused_score < 0.70:
                fused_score = max(fused_score, 0.70)
                critical_override_applied = True

        # 8. NORMALIZATION
        final_score = max(0.0, min(fused_score, 1.0))

        # 9. FINAL VERDICT
        if final_score < 0.3:
            verdict = "CLEAN"
        elif final_score < 0.50:
            verdict = "LOW RISK"
        elif final_score < 0.75:
            verdict = "SUSPICIOUS"
        else:
            verdict = "DANGEROUS"

        # 11. ATTACK SUMMARY Generation
        summary = self._generate_summary(active_vectors, attack_path, top_signals, critical_count)

        # 10. EXPLAINABILITY Format Output
        return {
            "risk_score": round(final_score, 4),
            "verdict": verdict,
            "breakdown": {
                "email_score": round(vector_scores["email"], 4),
                "url_score": round(vector_scores["url"], 4),
                "attachment_score": round(vector_scores["attachment"], 4),
                "chain_boost": round(chain_boost_value, 4),
                "critical_override": critical_override_applied
            },
            "top_signals": top_signals,
            "attack_summary": summary
        }

    def _generate_summary(self, active_vectors: int, attack_path: List[str], top_signals: List[str], critical_count: int) -> str:
        parts = []
        
        if "email->url" in attack_path and ("url->attachment" in attack_path or "email->attachment" in attack_path):
            parts.append("This attack involves an email delivering a phishing URL which leads to a malicious payload.")
        elif "email->url" in attack_path:
            parts.append("This attack originates from an email routing to a suspicious URL.")
        elif "url->attachment" in attack_path:
            parts.append("This attack involves a URL downloading or directly linking to a suspicious attachment.")
        elif active_vectors == 1:
            parts.append("This is an isolated single-vector attack.")
        else:
            parts.append("This is a multi-stage attack involving across multiple vectors.")

        if top_signals:
            sig_str = ", ".join(top_signals[:2])
            parts.append(f"Critical signals include {sig_str}, resulting in a mapped multi-stage attack.")

        if critical_count > 0:
            parts.append(f"The presence of {critical_count} critical signal(s) escalates the threat level significantly.")

        return " ".join(parts)

    def _build_empty_response(self) -> Dict[str, Any]:
        return {
            "risk_score": 0.0,
            "verdict": "CLEAN",
            "breakdown": {
                "email_score": 0.0,
                "url_score": 0.0,
                "attachment_score": 0.0,
                "chain_boost": 0.0,
                "critical_override": False
            },
            "top_signals": [],
            "attack_summary": "No valid events were able to trigger risk profiling inside the chain."
        }
