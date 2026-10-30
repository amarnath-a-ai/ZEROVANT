"""Optional Anthropic Claude LLM client with strict safety limits and fallback."""

import logging
from typing import Any

from app.explain.templates import Explanation

logger = logging.getLogger(__name__)


class LLMExplainer:
    """Uses Anthropic API to enrich explanations without whole-repo exposure or score setting."""

    def __init__(self, api_key: str | None = None, model: str = "claude-3-5-sonnet-20241022"):
        self.api_key = api_key
        self.model = model

    def enrich(self, finding: Any, template_explanation: Explanation) -> Explanation:
        """Enrich a template explanation using LLM if configured; fallback on error.

        (Detailed implementation in Phase 4)
        """
        if not self.api_key:
            return template_explanation
        return template_explanation

