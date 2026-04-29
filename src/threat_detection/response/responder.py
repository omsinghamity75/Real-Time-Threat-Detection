from __future__ import annotations

from ..schemas.events import ThreatDecision


class ResponseCoordinator:
    def apply(self, decision: ThreatDecision) -> list[str]:
        actions: list[str] = []

        if decision.action == "block":
            actions.append(f"blocked source {decision.features.source_ip}")
            actions.append("generated critical alert")
            actions.append("notified administrator")
        elif decision.action == "allow_with_alert":
            actions.append(f"generated suspicious activity alert for {decision.features.source_ip}")
        else:
            actions.append(f"allowed traffic from {decision.features.source_ip}")

        for action in actions:
            print(f"[response] {action}")

        return actions
