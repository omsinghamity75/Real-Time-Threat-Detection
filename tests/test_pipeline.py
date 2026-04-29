from pathlib import Path

from threat_detection.config import AppConfig
from threat_detection.ingestion.readers import EventReader
from threat_detection.processing.pipeline import ThreatDetectionPipeline


def test_simulation_produces_expected_summary(tmp_path: Path) -> None:
    config = AppConfig.from_path(tmp_path / "threats.db")
    pipeline = ThreatDetectionPipeline(config)
    reader = EventReader()

    summary = pipeline.handle_events(reader.sample_events())

    assert summary.total_events == 3
    assert summary.label_counts["normal"] >= 1
    assert summary.label_counts["suspicious"] >= 1
    assert summary.label_counts["attack"] >= 1
    assert len(summary.blocked_sources) == 1


def test_file_reader_supports_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"source_type":"network_traffic","source_ip":"1.1.1.1","destination_ip":"2.2.2.2","source_port":1111,"destination_port":23,"protocol":"TELNET","packet_size":1200,"packets_per_minute":1400,"device_id":"router-01"}\n',
        encoding="utf-8",
    )

    reader = EventReader()
    events = reader.read(path)

    assert len(events) == 1
    assert events[0].protocol == "TELNET"
