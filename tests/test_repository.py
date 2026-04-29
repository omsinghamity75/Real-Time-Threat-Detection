from pathlib import Path

from threat_detection.config import AppConfig
from threat_detection.processing.pipeline import ThreatDetectionPipeline
from threat_detection.schemas.events import SecurityEvent


def test_repository_report_and_feedback(tmp_path: Path) -> None:
    config = AppConfig.from_path(tmp_path / "threats.db")
    pipeline = ThreatDetectionPipeline(config)

    decision = pipeline.handle_event(
        SecurityEvent(
            source_type="system_log",
            source_ip="192.168.10.44",
            destination_ip="192.168.10.1",
            source_port=40000,
            destination_port=22,
            protocol="TCP",
            packet_size=1400,
            packets_per_minute=1600,
            device_id="host-44",
            raw_payload={"message": "burst authentication failures"},
        )
    )

    pipeline.repository.record_feedback(decision.event_id, "attack", "confirmed by analyst")
    report = pipeline.repository.build_report()

    assert report["total_events"] == 1
    assert report["feedback_items"] == 1
    assert report["labels"]["attack"] == 1
    assert report["actions"]["block"] == 1
    assert report["protocols"]["TCP"] == 1
    assert "192.168.10.44" in report["blocked_sources"]
    assert len(report["label_trend"]) >= 1
