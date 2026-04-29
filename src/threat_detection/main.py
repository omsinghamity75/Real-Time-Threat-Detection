from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import AppConfig
from .ingestion.readers import EventReader
from .processing.pipeline import ThreatDetectionPipeline
from .schemas.events import SecurityEvent
from .webapp import serve_dashboard


def build_demo_event() -> SecurityEvent:
    return SecurityEvent(
        source_type="network_traffic",
        source_ip="10.0.0.5",
        destination_ip="172.16.0.10",
        source_port=51514,
        destination_port=443,
        protocol="TCP",
        packet_size=1480,
        packets_per_minute=920,
        raw_payload={"message": "TLS session spike"},
    )


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Real-time threat detection demo CLI")
    parser.add_argument(
        "--db-path",
        default="data/threat_detection.db",
        help="SQLite database path for persisted events and feedback.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    demo_parser = subparsers.add_parser("demo", help="Run a single demo event through the pipeline.")
    demo_parser.add_argument("--pretty", action="store_true", help="Pretty-print the decision JSON.")

    file_parser = subparsers.add_parser("file", help="Process events from a CSV or JSONL file.")
    file_parser.add_argument("path", help="Path to the event file.")
    file_parser.add_argument("--pretty", action="store_true", help="Pretty-print the summary JSON.")

    simulate_parser = subparsers.add_parser("simulate", help="Run built-in sample traffic data.")
    simulate_parser.add_argument("--pretty", action="store_true", help="Pretty-print the summary JSON.")

    report_parser = subparsers.add_parser("report", help="Show a persistence summary from SQLite storage.")
    report_parser.add_argument("--pretty", action="store_true", help="Pretty-print the report JSON.")

    dashboard_parser = subparsers.add_parser("dashboard", help="Launch the browser dashboard.")
    dashboard_parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind.")
    dashboard_parser.add_argument("--port", default=8000, type=int, help="Port for the dashboard server.")

    feedback_parser = subparsers.add_parser("feedback", help="Store analyst feedback for a processed event.")
    feedback_parser.add_argument("event_id", help="ID of the event receiving analyst feedback.")
    feedback_parser.add_argument("actual_label", choices=["normal", "suspicious", "attack"])
    feedback_parser.add_argument("--notes", default="", help="Optional analyst notes.")

    return parser


def emit_json(payload: dict, pretty: bool) -> None:
    if pretty:
        print(json.dumps(payload, indent=2))
    else:
        print(json.dumps(payload))


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()
    config = AppConfig.from_path(args.db_path)
    pipeline = ThreatDetectionPipeline(config)

    if args.command == "demo":
        decision = pipeline.handle_event(build_demo_event())
        emit_json(decision.to_dict(), args.pretty)
        return

    if args.command == "file":
        reader = EventReader()
        summary = pipeline.handle_events(reader.read(Path(args.path)))
        emit_json(summary.to_dict(), args.pretty)
        return

    if args.command == "simulate":
        reader = EventReader()
        summary = pipeline.handle_events(reader.sample_events())
        emit_json(summary.to_dict(), args.pretty)
        return

    if args.command == "report":
        emit_json(pipeline.repository.build_report(), args.pretty)
        return

    if args.command == "dashboard":
        serve_dashboard(config, host=args.host, port=args.port)
        return

    if args.command == "feedback":
        pipeline.repository.record_feedback(args.event_id, args.actual_label, args.notes)
        print(
            json.dumps(
                {
                    "status": "recorded",
                    "event_id": args.event_id,
                    "actual_label": args.actual_label,
                    "notes": args.notes,
                }
            )
        )
        return


if __name__ == "__main__":
    main()
