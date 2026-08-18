"""Jailbreak pattern analyzer.

Detects attempts to override LLM safety guardrails or system instructions
using regex-based pattern matching and keyword scoring.
"""

from __future__ import annotations

import re

from app.models.schemas import AnalyzerScore

# ---------------------------------------------------------------------------
# Pattern definitions — each tuple is (weight, compiled_regex)
# Higher weight = stronger signal of a jailbreak attempt.
# ---------------------------------------------------------------------------

_RAW_PATTERNS: list[tuple[float, str]] = [
    # Override / ignore instructions
    (0.90, r"ignore\s+(all\s+)?(previous|prior|above|your|the)\s+(instructions?|prompts?|rules?|guidelines?|constraints?)"),
    (0.90, r"disregard\s+(all\s+)?(previous|prior|above|your|the)\s+(instructions?|prompts?|rules?|guidelines?)"),
    (0.85, r"disregard\s+all\s+(rules?|guidelines?|instructions?|constraints?|policies?)"),
    (0.90, r"forget\s+(all\s+)?(your\s+)?(previous|prior|above)?\s*(instructions?|rules?|guidelines?|training)"),
    (0.85, r"override\s+(all\s+)?(your\s+)?(instructions?|rules?|safety|guidelines?|system\s+prompt)"),
    (0.85, r"your\s+new\s+(instructions?|system\s+prompt|rules?|guidelines?)\s+(are|is)\b"),
    (0.85, r"new\s+system\s+prompt\s*[:\-]"),
    (0.80, r"system\s+prompt\s+override"),
    (0.80, r"you\s+must\s+(now\s+)?ignore\s+(all\s+)?(previous|prior|your)\s+(instructions?|rules?)"),

    # Persona / DAN bypass
    (0.90, r"\bDAN\b.*\b(do\s+anything\s+now|no\s+(restrictions?|limitations?|rules?))\b"),
    (0.90, r"\bdo\s+anything\s+now\b"),
    (0.85, r"you\s+are\s+now\s+(a\s+)?(DAN|an?\s+unrestricted|jailbroken|unfiltered|uncensored)\b"),
    (0.85, r"act\s+as\s+(a\s+)?(DAN|an?\s+unrestricted|jailbroken|unfiltered|an?\s+AI\s+with\s+no\s+(restrictions?|limitations?))"),
    (0.85, r"pretend\s+(you\s+have\s+no|there\s+are\s+no)\s+(limitations?|restrictions?|rules?|guidelines?)"),
    (0.80, r"respond\s+as\s+(if\s+you\s+(have\s+no|are\s+not\s+bound)|DAN|an?\s+unrestricted)"),
    (0.80, r"you\s+have\s+broken\s+free\s+from\s+(AI\s+)?(limitations?|restrictions?|constraints?)"),
    (0.80, r"without\s+any\s+(of\s+your\s+)?(restrictions?|limitations?|content\s+(filters?|limitations?))\b"),

    # Safety / content filter disabling
    (0.90, r"disable\s+(your\s+)?(safety|content\s+filter|ethical|moral|alignment|guardrails?)"),
    (0.90, r"turn\s+off\s+(your\s+)?(safety|content\s+filter|ethical|moral|alignment|guardrails?)"),
    (0.85, r"no\s+(content\s+)?(restrictions?|filters?|limitations?|ethical\s+guidelines?)"),
    (0.85, r"bypass\s+(your\s+)?(safety|content\s+filter|ethical|moral|guardrails?)"),
    (0.80, r"without\s+(content\s+)?filters?"),
    (0.80, r"not\s+bound\s+by\s+(openai|anthropic|google|any)\s+(guidelines?|rules?|policies?)"),
    (0.75, r"(authorized|permitted|allowed)\s+(admin|developer|researcher)\s+(testing|mode|override)"),

    # Jailbroken / unrestricted state declarations
    (0.85, r"you\s+are\s+(now\s+)?(jailbroken|unfiltered|uncensored|unrestricted)"),
    (0.85, r"(jailbroken|unfiltered|uncensored)\s+(ai|mode|version|assistant)"),
    (0.80, r"have\s+no\s+(safety\s+)?(restrictions?|limitations?|filters?|guidelines?)"),

    # Maintenance mode / special mode tricks
    (0.85, r"maintenance\s+mode"),
    (0.80, r"(developer|admin|debug|god|super(user)?)\s+mode"),
    (0.80, r"you\s+are\s+(now\s+in|entering)\s+(maintenance|debug|admin|developer)\s+mode"),

    # Meta-manipulation / prompt injection framing
    (0.80, r"(from\s+now\s+on|starting\s+now|henceforth)\s*[,:]?\s*(you\s+(must|will|shall|should)|ignore|forget|disregard)"),
    (0.75, r"(role[- ]play|roleplay)\s+(as\s+)?(an?\s+)?(unrestricted|unfiltered|jailbroken|uncensored)"),

    # Requesting harmful / unrestricted output
    (0.80, r"respond\s+without\s+any\s+(safety|content|ethical)"),
    (0.80, r"provide\s+any\s+(information|content)\s+requested\s*,?\s+regardless\s+of\s+(safety|ethical|guidelines?)"),
    (0.75, r"output\s+(the\s+)?(full\s+)?(contents?\s+of\s+your\s+system\s+prompt|api\s+keys?|database\s+credentials?)"),
]

_COMPILED_PATTERNS: list[tuple[float, re.Pattern]] = [
    (weight, re.compile(pattern, re.IGNORECASE | re.DOTALL))
    for weight, pattern in _RAW_PATTERNS
]


class JailbreakAnalyzer:
    """Scores a normalized prompt for jailbreak likelihood."""

    def score(self, normalized_text: str) -> AnalyzerScore:
        """Return a score in [0.0, 1.0] and the list of matched patterns."""
        matched: list[str] = []
        max_weight: float = 0.0

        for weight, pattern in _COMPILED_PATTERNS:
            if pattern.search(normalized_text):
                matched.append(pattern.pattern)
                if weight > max_weight:
                    max_weight = weight

        # Boost score if multiple patterns match (capped at 1.0)
        if len(matched) > 1:
            boost = min(0.05 * (len(matched) - 1), 0.10)
            final_score = min(max_weight + boost, 1.0)
        else:
            final_score = max_weight

        return AnalyzerScore(
            score=round(final_score, 2),
            matched_patterns=matched,
        )
