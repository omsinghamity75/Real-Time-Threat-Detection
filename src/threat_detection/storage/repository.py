from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from ..schemas.events import SecurityEvent, ThreatDecision


class ThreatRepository:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    source_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    source_port INTEGER NOT NULL,
                    destination_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    packet_size INTEGER NOT NULL,
                    packets_per_minute INTEGER NOT NULL,
                    device_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    raw_payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS decisions (
                    event_id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    action TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    reward REAL NOT NULL,
                    reasons TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    features TEXT NOT NULL,
                    FOREIGN KEY(event_id) REFERENCES events(event_id)
                );

                CREATE TABLE IF NOT EXISTS responses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    action_text TEXT NOT NULL,
                    FOREIGN KEY(event_id) REFERENCES events(event_id)
                );

                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    actual_label TEXT NOT NULL,
                    notes TEXT NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(event_id) REFERENCES events(event_id)
                );
                """
            )

    def store(self, event: SecurityEvent, decision: ThreatDecision, responses: list[str]) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO events (
                    event_id, source_type, source_ip, destination_ip, source_port,
                    destination_port, protocol, packet_size, packets_per_minute,
                    device_id, observed_at, raw_payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.source_type,
                    event.source_ip,
                    event.destination_ip,
                    event.source_port,
                    event.destination_port,
                    event.protocol,
                    event.packet_size,
                    event.packets_per_minute,
                    event.device_id,
                    event.observed_at.isoformat(),
                    json.dumps(event.raw_payload),
                ),
            )
            connection.execute(
                """
                INSERT OR REPLACE INTO decisions (
                    event_id, label, action, confidence, reward, reasons, created_at, features
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.event_id,
                    decision.label,
                    decision.action,
                    decision.confidence,
                    decision.reward,
                    json.dumps(decision.reasons),
                    decision.created_at.isoformat(),
                    json.dumps(decision.features.to_dict()),
                ),
            )
            connection.execute("DELETE FROM responses WHERE event_id = ?", (event.event_id,))
            connection.executemany(
                "INSERT INTO responses (event_id, action_text) VALUES (?, ?)",
                [(event.event_id, action) for action in responses],
            )

        print(
            "[storage] persisted event",
            {
                "event_id": event.event_id,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "label": decision.label,
                "action": decision.action,
            },
        )

    def record_feedback(self, event_id: str, actual_label: str, notes: str = "") -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO feedback (event_id, actual_label, notes) VALUES (?, ?, ?)",
                (event_id, actual_label, notes),
            )

    def build_report(self) -> dict[str, object]:
        with self._connect() as connection:
            totals_row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total_events,
                    SUM(CASE WHEN label = 'attack' THEN 1 ELSE 0 END) AS attacks,
                    SUM(CASE WHEN label = 'suspicious' THEN 1 ELSE 0 END) AS suspicious,
                    SUM(CASE WHEN label = 'normal' THEN 1 ELSE 0 END) AS normal,
                    AVG(confidence) AS average_confidence
                FROM decisions
                """
            ).fetchone()
            feedback_row = connection.execute(
                "SELECT COUNT(*) AS feedback_count FROM feedback"
            ).fetchone()
            action_rows = connection.execute(
                """
                SELECT action, COUNT(*) AS total
                FROM decisions
                GROUP BY action
                """
            ).fetchall()
            protocol_rows = connection.execute(
                """
                SELECT e.protocol, COUNT(*) AS total
                FROM events e
                GROUP BY e.protocol
                ORDER BY total DESC, e.protocol ASC
                """
            ).fetchall()
            recent_rows = connection.execute(
                """
                SELECT
                    e.event_id,
                    e.source_type,
                    e.source_ip,
                    e.destination_ip,
                    e.protocol,
                    e.destination_port,
                    d.label,
                    d.action,
                    d.confidence,
                    d.reasons,
                    d.created_at
                FROM events e
                JOIN decisions d ON d.event_id = e.event_id
                ORDER BY d.created_at DESC
                LIMIT 10
                """
            ).fetchall()
            label_trend_rows = connection.execute(
                """
                SELECT substr(d.created_at, 1, 13) AS hour_bucket, d.label, COUNT(*) AS total
                FROM decisions d
                GROUP BY hour_bucket, d.label
                ORDER BY hour_bucket DESC
                LIMIT 18
                """
            ).fetchall()
            blocked_rows = connection.execute(
                """
                SELECT DISTINCT e.source_ip
                FROM events e
                JOIN decisions d ON d.event_id = e.event_id
                WHERE d.action = 'block'
                ORDER BY e.source_ip
                """
            ).fetchall()

        return {
            "total_events": totals_row["total_events"] or 0,
            "labels": {
                "attack": totals_row["attacks"] or 0,
                "suspicious": totals_row["suspicious"] or 0,
                "normal": totals_row["normal"] or 0,
            },
            "actions": {row["action"]: row["total"] for row in action_rows},
            "protocols": {row["protocol"]: row["total"] for row in protocol_rows},
            "average_confidence": round(float(totals_row["average_confidence"] or 0.0), 3),
            "feedback_items": feedback_row["feedback_count"] or 0,
            "blocked_sources": [row["source_ip"] for row in blocked_rows],
            "label_trend": [dict(row) for row in label_trend_rows],
            "recent_events": [
                {
                    **dict(row),
                    "reasons": json.loads(row["reasons"]),
                }
                for row in recent_rows
            ],
        }
