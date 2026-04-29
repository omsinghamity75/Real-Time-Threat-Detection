from __future__ import annotations

from ..config import AppConfig
from ..schemas.events import EngineeredFeatures


class DQNAgent:
    """
    Deterministic baseline for a DQN-like policy layer.

    The interface is shaped so a trained model can replace the rule policy
    later without changing the surrounding pipeline contracts.
    """

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def evaluate(self, features: EngineeredFeatures) -> tuple[str, float, float, list[str]]:
        reasons: list[str] = []
        sensitive_port_targeted = features.destination_port in {22, 23, 3389, 5900}

        if features.packets_per_minute >= 1000:
            reasons.append("traffic frequency exceeded normal operating range")
        if sensitive_port_targeted:
            reasons.append("destination targeted a privileged or sensitive port")
        if features.protocol_risk >= 0.45:
            reasons.append("protocol profile carries elevated risk")

        if sensitive_port_targeted and features.packets_per_minute >= 1200:
            reasons.append("high-volume traffic hit a sensitive port pattern")
            return "block", 0.97, 1.0, reasons
        if features.risk_score >= self.config.block_threshold:
            reasons.append("aggregated risk score crossed block threshold")
            return "block", 0.96, 1.0, reasons
        if features.risk_score >= self.config.alert_threshold:
            reasons.append("aggregated risk score crossed alert threshold")
            return "allow_with_alert", 0.74, 0.68, reasons

        reasons.append("traffic profile remained within acceptable range")
        return "allow", 0.91, 0.9, reasons
