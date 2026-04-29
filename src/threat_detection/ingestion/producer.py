from __future__ import annotations

from collections.abc import Iterable

from ..schemas.events import SecurityEvent


class StreamProducer:
    """Kafka-style producer contract for emitting security events."""

    def publish(self, event: SecurityEvent) -> None:
        print(
            f"[ingestion] published event {event.event_id} "
            f"from {event.source_ip} to {event.destination_ip}"
        )

    def publish_batch(self, events: Iterable[SecurityEvent]) -> None:
        for event in events:
            self.publish(event)
