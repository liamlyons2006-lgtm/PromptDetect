"""Detection Engine — orchestrates the full analysis pipeline.

Pipeline:
  1. Input validation (delegated to API layer, but engine enforces too)
  2. Text normalisation
  3. Parallel heuristic analysis (JailbreakAnalyzer + IndirectInjectionAnalyzer)
  4. Score aggregation → Classification + confidence + threat_type
  5. Return AnalysisResult
"""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone

from app.detector.indirect_injection import IndirectInjectionAnalyzer
from app.detector.jailbreak import JailbreakAnalyzer
from app.detector.scoring import ScoreAggregator
from app.models.schemas import AnalysisResult


def _normalize(text: str) -> str:
    """Normalise text for analysis.

    - NFC unicode normalisation (resolves composed/decomposed forms)
    - Collapse excessive whitespace (but preserve newlines as spaces so
      multi-line prompts are searchable with single-line patterns)
    - Lowercase
    """
    # NFC normalisation first to handle decomposed unicode characters
    text = unicodedata.normalize("NFC", text)
    # Collapse all horizontal whitespace runs; convert newlines to spaces
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = text.replace("\n", " ")
    return text.lower().strip()


class DetectionEngine:
    """Heuristic-based prompt injection detection engine."""

    def __init__(self) -> None:
        self._jailbreak = JailbreakAnalyzer()
        self._indirect = IndirectInjectionAnalyzer()
        self._aggregator = ScoreAggregator()

    def analyze(self, prompt: str) -> AnalysisResult:
        """Analyse a prompt and return a complete AnalysisResult.

        Must complete well within 3 seconds (typically <50 ms).
        Raises ValueError for prompts that fail length / whitespace validation.
        """
        # Engine-level validation (belt-and-suspenders alongside API validation)
        stripped = prompt.strip()
        if not stripped or len(prompt) > 10_000:
            raise ValueError(
                "Prompt must be between 1 and 10,000 characters"
            )

        normalized = _normalize(prompt)

        jb_score = self._jailbreak.score(normalized)
        ii_score = self._indirect.score(normalized)

        classification, confidence, threat_type = self._aggregator.classify(
            jb_score, ii_score
        )

        return AnalysisResult(
            prompt=prompt,
            classification=classification,
            confidence_score=confidence,
            threat_type=threat_type,
            submitted_at=datetime.now(timezone.utc),
        )
