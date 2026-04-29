from __future__ import annotations

from ..schemas.events import EngineeredFeatures, ThreatDecision


class ThreatClassifier:
    def classify(
        self,
        event_id: str,
        features: EngineeredFeatures,
        action: str,
        confidence: float,
        reward: float,
        reasons: list[str],
    ) -> ThreatDecision:
        if action == "block":
            label = "attack"
        elif action == "allow_with_alert":
            label = "suspicious"
        else:
            label = "normal"

        return ThreatDecision(
            event_id=event_id,
            label=label,
            action=action,
            confidence=confidence,
            reward=reward,
            reasons=reasons,
            features=features,
        )
