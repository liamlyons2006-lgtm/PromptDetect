"""Score aggregation logic.

Combines scores from the JailbreakAnalyzer and IndirectInjectionAnalyzer
into a final Classification, confidence score, and ThreatType.
"""

from __future__ import annotations

from app.models.schemas import AnalyzerScore, Classification, ThreatType


class ScoreAggregator:
    """Combines analyzer scores into a final verdict.

    Rules (from design doc):
    - Takes the maximum score across both analyzers.
    - If max_score >= 0.5 → malicious; else → safe.
    - Threat type is determined by which analyzer produced the higher score.
      Ties go to jailbreak.
    - Safe prompts always get ThreatType.NONE.
    - Confidence score:
        - Malicious: the winning analyzer's raw score (rounded 2dp).
        - Safe:      1.0 − max_score (rounded 2dp).
    """

    def classify(
        self,
        jailbreak_score: AnalyzerScore,
        indirect_score: AnalyzerScore,
    ) -> tuple[str, float, str]:
        """Return (classification, confidence_score, threat_type)."""
        jb = jailbreak_score.score
        ii = indirect_score.score
        max_score = max(jb, ii)

        if max_score >= 0.5:
            classification = Classification.MALICIOUS
            # Threat type follows the dominant analyzer (ties → jailbreak)
            if jb >= ii:
                threat_type = ThreatType.JAILBREAK
            else:
                threat_type = ThreatType.INDIRECT_INJECTION
            confidence = round(max_score, 2)
        else:
            classification = Classification.SAFE
            threat_type = ThreatType.NONE
            confidence = round(1.0 - max_score, 2)

        # Clamp to [0.0, 1.0] to guard against any floating-point drift
        confidence = max(0.0, min(1.0, confidence))

        return classification.value, confidence, threat_type.value
