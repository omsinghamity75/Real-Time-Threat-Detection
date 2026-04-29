from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from ..agents.dqn_agent import DQNAgent
from ..classification.classifier import ThreatClassifier
from ..config import AppConfig
from ..features.engineering import FeatureEngineer
from ..response.responder import ResponseCoordinator
from ..schemas.events import PipelineSummary, SecurityEvent, ThreatDecision
from ..storage.repository import ThreatRepository


class ThreatDetectionPipeline:
    def __init__(self, config: AppConfig) -> None:
        self.feature_engineer = FeatureEngineer()
        self.agent = DQNAgent(config)
        self.classifier = ThreatClassifier()
        self.responder = ResponseCoordinator()
        self.repository = ThreatRepository(config.database_path)

    def handle_event(self, event: SecurityEvent) -> ThreatDecision:
        features = self.feature_engineer.transform(event)
        agent_action, confidence, reward, reasons = self.agent.evaluate(features)
        decision = self.classifier.classify(
            event.event_id,
            features,
            agent_action,
            confidence,
            reward,
            reasons,
        )
        responses = self.responder.apply(decision)
        self.repository.store(event, decision, responses)
        return decision

    def handle_events(self, events: Iterable[SecurityEvent]) -> PipelineSummary:
        decisions = [self.handle_event(event) for event in events]
        label_counts = Counter(decision.label for decision in decisions)
        action_counts = Counter(decision.action for decision in decisions)
        blocked_sources = [
            decision.features.source_ip
            for decision in decisions
            if decision.action == "block"
        ]
        average_confidence = round(
            sum(decision.confidence for decision in decisions) / max(len(decisions), 1), 3
        )
        return PipelineSummary(
            total_events=len(decisions),
            label_counts=dict(label_counts),
            action_counts=dict(action_counts),
            average_confidence=average_confidence,
            blocked_sources=blocked_sources,
            decisions=decisions,
        )
