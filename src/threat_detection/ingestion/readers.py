from __future__ import annotations

import csv
import json
from pathlib import Path

from ..schemas.events import SecurityEvent


class EventReader:
    def read(self, path: Path) -> list[SecurityEvent]:
        suffix = path.suffix.lower()
        if suffix == ".csv":
            return self._read_csv(path)
        if suffix in {".json", ".jsonl"}:
            return self._read_jsonl(path)
        raise ValueError(f"Unsupported file format: {path.suffix}")

    def read_text(self, content: str, suffix: str) -> list[SecurityEvent]:
        normalized_suffix = suffix.lower()
        if normalized_suffix == ".csv":
            return self._read_csv_text(content)
        if normalized_suffix in {".json", ".jsonl"}:
            return self._read_jsonl_text(content)
        raise ValueError(f"Unsupported file format: {suffix}")

    def sample_events(self) -> list[SecurityEvent]:
        return [
            SecurityEvent(
                source_type="network_traffic",
                source_ip="10.0.0.5",
                destination_ip="172.16.0.10",
                source_port=51514,
                destination_port=443,
                protocol="TCP",
                packet_size=1480,
                packets_per_minute=920,
                device_id="edge-gateway-01",
                raw_payload={"message": "TLS session spike"},
            ),
            SecurityEvent(
                source_type="system_log",
                source_ip="192.168.1.20",
                destination_ip="192.168.1.1",
                source_port=49832,
                destination_port=22,
                protocol="TCP",
                packet_size=1350,
                packets_per_minute=1500,
                device_id="workstation-22",
                raw_payload={"message": "Repeated SSH attempts"},
            ),
            SecurityEvent(
                source_type="iot_device",
                source_ip="172.20.1.99",
                destination_ip="172.20.1.10",
                source_port=1883,
                destination_port=1883,
                protocol="MQTT",
                packet_size=220,
                packets_per_minute=80,
                device_id="sensor-99",
                raw_payload={"message": "Normal telemetry heartbeat"},
            ),
        ]

    def _read_csv(self, path: Path) -> list[SecurityEvent]:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            return [SecurityEvent.from_dict(row) for row in reader]

    def _read_jsonl(self, path: Path) -> list[SecurityEvent]:
        with path.open("r", encoding="utf-8") as handle:
            return self._read_jsonl_text(handle.read())

    def _read_csv_text(self, content: str) -> list[SecurityEvent]:
        reader = csv.DictReader(content.splitlines())
        return [SecurityEvent.from_dict(row) for row in reader]

    def _read_jsonl_text(self, content: str) -> list[SecurityEvent]:
        return [
            SecurityEvent.from_dict(json.loads(line))
            for line in content.splitlines()
            if line.strip()
        ]
