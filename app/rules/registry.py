"""Rule registry for discovering, registering, and running static security rules."""

import logging

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding

logger = logging.getLogger(__name__)


class RuleRegistry:
    """Registry maintaining all active security audit rules."""

    def __init__(self):
        self._rules: dict[str, BaseRule] = {}

    def register(self, rule_class: type[BaseRule]) -> None:
        """Register a rule class."""
        rule_instance = rule_class()
        self._rules[rule_instance.id] = rule_instance

    def get_rule(self, rule_id: str) -> BaseRule | None:
        """Get a registered rule by its ID."""
        return self._rules.get(rule_id)

    def list_rules(self) -> list[BaseRule]:
        """Return all registered rules."""
        return list(self._rules.values())

    def evaluate_all(self, workflow: Workflow) -> list[Finding]:
        """Run all registered rules against a parsed workflow and return aggregated findings."""
        findings: list[Finding] = []
        for rule_id, rule in self._rules.items():
            try:
                rule_findings = rule.evaluate(workflow)
                findings.extend(rule_findings)
            except Exception as exc:
                logger.error("Error evaluating rule %s: %s", rule_id, exc)
        return findings


# Global default registry
default_registry = RuleRegistry()
