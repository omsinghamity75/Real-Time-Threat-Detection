from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


@dataclass(slots=True)
class SecurityEvent:
    source_type: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    packet_size: int
    packets_per_minute: int
    raw_payload: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid4()))
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    device_id: str = "unknown"

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SecurityEvent":
        observed_at = payload.get("observed_at")
        if isinstance(observed_at, str):
            observed_at = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))

        return cls(
            source_type=payload["source_type"],
            source_ip=payload["source_ip"],
            destination_ip=payload["destination_ip"],
            source_port=int(payload["source_port"]),
            destination_port=int(payload["destination_port"]),
            protocol=str(payload["protocol"]).upper(),
            packet_size=int(payload["packet_size"]),
            packets_per_minute=int(payload["packets_per_minute"]),
            raw_payload=payload.get("raw_payload", {}),
            event_id=payload.get("event_id", str(uuid4())),
            observed_at=observed_at or datetime.now(timezone.utc),
            device_id=payload.get("device_id", "unknown"),
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["observed_at"] = self.observed_at.isoformat()
        return data


@dataclass(slots=True)
class EngineeredFeatures:
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int
    destination_port: int
    packet_size: int
    packets_per_minute: int
    risk_score: float
    protocol_risk: float
    port_risk: float
    traffic_ratio: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ThreatDecision:
    event_id: str
    label: str
    action: str
    confidence: float
    reward: float
    reasons: list[str]
    features: EngineeredFeatures
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "label": self.label,
            "action": self.action,
            "confidence": self.confidence,
            "reward": self.reward,
            "reasons": self.reasons,
            "created_at": self.created_at.isoformat(),
            "features": self.features.to_dict(),
        }


@dataclass(slots=True)
class PipelineSummary:
    total_events: int
    label_counts: dict[str, int]
    action_counts: dict[str, int]
    average_confidence: float
    blocked_sources: list[str]
    decisions: list[ThreatDecision]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_events": self.total_events,
            "label_counts": self.label_counts,
            "action_counts": self.action_counts,
            "average_confidence": self.average_confidence,
            "blocked_sources": self.blocked_sources,
            "decisions": [decision.to_dict() for decision in self.decisions],
        }
