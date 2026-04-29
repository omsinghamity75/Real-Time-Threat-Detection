from __future__ import annotations

from ..schemas.events import EngineeredFeatures, SecurityEvent


class FeatureEngineer:
    HIGH_RISK_PROTOCOLS = {"TELNET", "RDP"}
    MEDIUM_RISK_PROTOCOLS = {"SSH", "MQTT"}
    HIGH_RISK_PORTS = {22, 23, 3389, 5900}

    def transform(self, event: SecurityEvent) -> EngineeredFeatures:
        frequency_factor = min(event.packets_per_minute / 1000, 1.0)
        size_factor = min(event.packet_size / 1500, 1.0)
        protocol_risk = self._protocol_risk(event.protocol)
        port_risk = 0.25 if event.destination_port in self.HIGH_RISK_PORTS else 0.05
        traffic_ratio = round(event.packet_size / max(event.packets_per_minute, 1), 3)

        risk_score = round(
            (frequency_factor * 0.4)
            + (size_factor * 0.2)
            + (protocol_risk * 0.2)
            + (port_risk * 0.2),
            3,
        )

        return EngineeredFeatures(
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            protocol=event.protocol,
            source_port=event.source_port,
            destination_port=event.destination_port,
            packet_size=event.packet_size,
            packets_per_minute=event.packets_per_minute,
            risk_score=risk_score,
            protocol_risk=protocol_risk,
            port_risk=port_risk,
            traffic_ratio=traffic_ratio,
        )

    def _protocol_risk(self, protocol: str) -> float:
        protocol_name = protocol.upper()
        if protocol_name in self.HIGH_RISK_PROTOCOLS:
            return 0.9
        if protocol_name in self.MEDIUM_RISK_PROTOCOLS:
            return 0.45
        if protocol_name == "TCP":
            return 0.2
        return 0.1
