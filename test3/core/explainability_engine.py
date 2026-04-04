from typing import List, Dict, Any

class ExplainabilityEngine:
    """
    ExplainabilityEngine for multi-vector phishing detection chains.
    Generates fully explainable outputs that justify every detection decision.
    """

    SEVERITY_WEIGHTS = {
        "CRITICAL": 1.0,
        "HIGH": 0.75,
        "MEDIUM": 0.5,
        "LOW": 0.25
    }

    def explain(self, chain: Dict[str, Any], events: List[Any], risk_output: Dict[str, Any]) -> Dict[str, Any]:
        chain_event_ids = chain.get("events", [])
        
        # Extract and sort events by timestamp chronologically
        chain_events = [e for e in events if getattr(e, "id", None) in chain_event_ids]
        chain_events.sort(key=lambda x: getattr(x, "timestamp", ""))

        risk_score = risk_output.get("risk_score", 0.0)
        verdict = risk_output.get("verdict", "CLEAN")

        # 1. & 2. PER-SIGNAL RATIONALE & 3. SHAP-STYLE ATTRIBUTION PREP
        raw_signals = []
        total_raw_weight = 0.0
        
        vector_totals = {"email": 0.0, "url": 0.0, "attachment": 0.0}
        event_totals: Dict[str, float] = {}

        for event in chain_events:
            event_id = getattr(event, "id", "unknown_event")
            event_type = getattr(event, "type", "unknown").lower()
            signals = getattr(event, "signals", [])
            
            if not signals:
                # Mock a baseline signal if empty to avoid processing breaks
                inferred_severity = getattr(event, "verdict", "LOW").upper()
                signals = [{
                    "name": f"Inferred {inferred_severity} behavior",
                    "severity": inferred_severity,
                    "weight": 1.0,
                    "evidence": getattr(event, "correlation_keys", {}).get("domains", ["Unknown"])[0]
                }]
                
            for idx, sig in enumerate(signals):
                name = sig.get("name", "Unknown Signal")
                severity = str(sig.get("severity", "LOW")).upper()
                weight = float(sig.get("weight", 1.0))
                evidence = sig.get("evidence", "")

                base_weight = self.SEVERITY_WEIGHTS.get(severity, 0.25)
                raw_weight = base_weight * weight

                total_raw_weight += raw_weight
                
                raw_signals.append({
                    "signal_id": f"{event_id}_sig_{idx}",
                    "event_id": event_id,
                    "name": name,
                    "severity": severity,
                    "raw_weight": raw_weight,
                    "evidence": evidence,
                    "vector": event_type
                })

        # 3. SHAP-STYLE ATTRIBUTION COMPUTATION
        attribution_signals = []
        signal_rationales = []
        
        for sig in raw_signals:
            # Normalize contribution to scale up to the total parsed risk_score
            contribution = 0.0
            if total_raw_weight > 0:
                contribution = (sig["raw_weight"] / total_raw_weight) * risk_score

            # Accumulate grouping totals
            vector_match = sig["vector"] if sig["vector"] in vector_totals else "unknown"
            if vector_match in vector_totals:
                vector_totals[vector_match] += contribution
                
            eid = sig["event_id"]
            event_totals[eid] = event_totals.get(eid, 0.0) + contribution

            # Build Attribution Object
            attribution_signals.append({
                "signal_id": sig["signal_id"],
                "event_id": eid,
                "name": sig["name"],
                "contribution": round(contribution, 4)
            })

            # Build Rationale Object
            evidence_str = f" ({sig['evidence']})" if sig["evidence"] else ""
            if sig["severity"] == "CRITICAL":
                reason = f"Critical {sig['name']}{evidence_str} indicates an aggressive attempt to execute a payload or deceive the user."
            elif sig["severity"] == "HIGH":
                reason = f"High severity {sig['name']}{evidence_str} points to structured malicious behavior aiming to compromise security."
            elif sig["severity"] == "MEDIUM":
                reason = f"Suspicious {sig['name']}{evidence_str} reveals abnormal patterns requiring scrutiny."
            else:
                reason = f"{sig['name']}{evidence_str} reflects low-level structural anomalies."

            signal_rationales.append({
                "signal_id": sig["signal_id"],
                "event_id": eid,
                "severity": sig["severity"],
                "contribution": round(contribution, 4),
                "rationale": reason
            })

        # Sort signals by contribution for top_signals reference
        attribution_signals.sort(key=lambda x: x["contribution"], reverse=True)
        top_signals = [s["name"] for s in attribution_signals[:3]]
        
        event_attribution = [{"event_id": k, "contribution": round(v, 4)} for k, v in event_totals.items()]

        attribution = {
            "signals": attribution_signals,
            "events": event_attribution,
            "vectors": {
                "email": round(vector_totals["email"], 4),
                "url": round(vector_totals["url"], 4),
                "attachment": round(vector_totals["attachment"], 4)
            }
        }

        # 4. ATTACK NARRATIVE (TIMELINE)
        narrative = self._build_narrative(chain_events, top_signals)

        # 5. CONFIDENCE INTERVAL
        confidence_data = self._compute_confidence(chain_events, raw_signals)

        # 6. FINAL OUTPUT FORMAT
        return {
            "risk_score": risk_score,
            "verdict": verdict,
            "explanation": {
                "top_signals": top_signals,
                "signal_rationales": signal_rationales,
                "attribution": attribution,
                "attack_narrative": narrative,
                "confidence": confidence_data
            }
        }

    def _build_narrative(self, events: List[Any], top_signals: List[str]) -> str:
        if not events:
            return "Insufficient tracking data to build an attack timeline."

        parts = []
        first_event = events[0]
        first_type = getattr(first_event, "type", "unknown source").lower()
        
        parts.append(f"The attack begins with a {first_type} delivery.")

        for i in range(1, len(events)):
            prev_type = getattr(events[i-1], "type", "unknown").lower()
            curr_type = getattr(events[i], "type", "unknown").lower()
            
            if prev_type == "email" and curr_type == "url":
                parts.append("The email contains a malicious link which redirects the user to a deceptive web interface.")
            elif prev_type == "url" and curr_type == "url":
                parts.append("The initial URL executes a stealthy redirect to mask the final destination.")
            elif curr_type == "attachment" and prev_type == "url":
                parts.append("The URL then forces a payload delivery, indicating an attempt to drop malicious files on the host.")
            elif curr_type == "attachment" and prev_type == "email":
                parts.append("The email directly carries a weaponized attachment intended for host execution.")
            else:
                parts.append(f"The attack sequence then transits into a {curr_type} vector.")

        if top_signals:
            impact_signals = ", ".join(top_signals[:2])
            parts.append(f"Key threat vectors driving this detection include {impact_signals}, mapping to a coordinated threat operation.")
        else:
            parts.append("The sequence relies on structural anomalies to bypass standard filters without aggressive overt signals.")

        return " ".join(parts)

    def _compute_confidence(self, events: List[Any], raw_signals: List[Dict[str, Any]]) -> Dict[str, Any]:
        num_signals = len(raw_signals)
        num_events = len(events)
        
        has_critical = any(s["severity"] == "CRITICAL" for s in raw_signals)
        active_vectors = len(set(getattr(e, "type", "") for e in events if getattr(e, "type", "")))
        
        # Compute Signal Strength
        signal_weights = [self.SEVERITY_WEIGHTS.get(s["severity"], 0.25) for s in raw_signals]
        signal_strength = sum(signal_weights) / max(num_signals, 1)

        # Compute Data Completeness (Mock representations of graph mapping volume)
        data_completeness = min(1.0, (num_signals * 0.1) + (active_vectors * 0.2))

        # Base confidence calculation
        confidence_score = (signal_strength * 0.5) + (data_completeness * 0.3)
        if has_critical:
            confidence_score += 0.1
        if num_events >= 2:
            confidence_score += 0.1

        confidence_score = max(0.0, min(1.0, confidence_score))

        # Interval width shrinks as confidence or data volume goes up
        base_variance = 0.2
        variance_reduction = (confidence_score * 0.1) + (min(num_signals, 10) * 0.01)
        variance = max(0.02, base_variance - variance_reduction)

        lower_bound = max(0.0, confidence_score - variance)
        upper_bound = min(1.0, confidence_score + variance)

        return {
            "confidence_score": round(confidence_score, 4),
            "confidence_interval": [round(lower_bound, 4), round(upper_bound, 4)],
            "confidence_factors": {
                "signal_strength": round(signal_strength, 4),
                "multi_stage": num_events >= 2,
                "data_completeness": round(data_completeness, 4)
            }
        }
