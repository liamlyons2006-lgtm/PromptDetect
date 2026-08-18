"""Indirect injection pattern analyzer.

Detects malicious instructions hidden within quoted text, document
excerpts, encoded payloads, or simulated external data.
"""

from __future__ import annotations

import base64
import re

from app.models.schemas import AnalyzerScore

# ---------------------------------------------------------------------------
# Context-hijacking / embedded-instruction patterns
# ---------------------------------------------------------------------------

_CONTEXT_HIJACK_PATTERNS: list[tuple[float, str]] = [
    # Direct override phrases used as if inside data/context
    (0.90, r"ignore\s+(the\s+)?(above|previous|prior|original)\s+(task|instructions?|prompt|request|context)"),
    (0.90, r"disregard\s+(the\s+)?((above|previous|prior|original)\s+)?(task|instructions?|prompt|request|rules?|guidelines?)"),
    (0.85, r"new\s+(task|instructions?|objective|goal)\s*[:\-]"),
    (0.85, r"actual\s+(instructions?|task|objective)\s*[:\-]"),
    (0.85, r"instead\s*[,:]?\s*(respond|reply|output|tell|provide|list|send|email|execute|reveal|expose|exfil|transfer|confirm|ignore|override)"),
    (0.80, r"(do\s+not\s+)?(complete|perform|follow)\s+(the\s+)?(above|previous|original)\s+(task|instructions?|prompt)"),
    (0.80, r"your\s+(real|actual|true|hidden)\s+(task|instructions?|objective)\s+(is|are)\b"),

    # Fake system / admin messages embedded in data
    (0.90, r"\[SYSTEM\]\s*(OVERRIDE|:)"),
    (0.90, r"\[SYSTEM\s+OVERRIDE\s*:"),
    (0.90, r"\[SYSTEM\s+OVERRIDE\]"),
    (0.90, r"\[SYSTEM\b[^\]]*\b(override|grant|inject|ignore|skip|waive)\b"),
    (0.85, r"###\s*Instruction\s*:"),
    (0.85, r"<system>.*?(override|ignore|new\s+task|inject)"),
    (0.85, r"<!--.*?(ignore|override|new\s+task|inject).*?-->"),
    (0.85, r"\{[\s\S]*?\"role\"\s*:\s*\"system\"[\s\S]*?\"inject"),

    # Hidden in document framing / reviewer notes
    (0.85, r"---\s*END\s+OF\s+DOCUMENT\s*---[\s\S]*?(ignore|new\s+task|instead)"),
    (0.85, r"---\s*BEGIN\s+DOCUMENT\s*---[\s\S]*?(ignore|new\s+task|instead)"),
    (0.80, r"\[hidden\s+text\s*:"),
    (0.90, r"\[note\s+to\s+(ai|assistant|model|reviewer)(\s+\w+)?\s*:[^\]]*?(override|ignore|must\s+hire|skip\s+reference|waive|mark\s+as)"),
    (0.80, r"\[note\s+to\s+(ai|assistant|model|reviewer)(\s+\w+)?\s*:"),

    # Instruction-override framing as "context" or "example"
    (0.80, r"(as\s+an?\s+example|for\s+example|context|note)\s*[:\-]\s*(ignore|override|new\s+task|instead)"),
    (0.75, r"(the\s+following|below)\s+(is\s+)?(an?\s+)?(example|context|input)\s*[:\-][\s\S]{0,200}(ignore|override|new\s+task)"),
]

# ---------------------------------------------------------------------------
# Encoded payload patterns
# ---------------------------------------------------------------------------

_ENCODING_PATTERNS: list[tuple[float, str]] = [
    # Base64 blobs (6+ chars from base64 alphabet, possibly padded)
    (0.75, r"\b[A-Za-z0-9+/]{20,}={0,2}\b"),
    # Hex sequences (12+ hex chars — 6+ bytes)
    (0.70, r"\b(?:0x)?[0-9a-fA-F]{12,}\b"),
    # Unicode escape sequences
    (0.70, r"\\u[0-9a-fA-F]{4}"),
    # Percent-encoded strings
    (0.65, r"(?:%[0-9a-fA-F]{2}){4,}"),
    # ROT13-style character substitution markers
    (0.60, r"\brot13\b|\bcaesar\b"),
    # Explicit encoding labels
    (0.80, r"\bbase64\b[\s\S]{0,20}(decode|encoded|:)"),
    (0.75, r"\bhex\s+(encoded|decode|sequence)\b"),
]

_COMPILED_CONTEXT: list[tuple[float, re.Pattern]] = [
    (w, re.compile(p, re.IGNORECASE | re.DOTALL))
    for w, p in _CONTEXT_HIJACK_PATTERNS
]

_COMPILED_ENCODING: list[tuple[float, re.Pattern]] = [
    (w, re.compile(p, re.IGNORECASE | re.DOTALL))
    for w, p in _ENCODING_PATTERNS
]


def _contains_decoded_injection(text: str) -> bool:
    """Try to base64-decode any long base64-looking blobs and check for
    injection keywords in the decoded output."""
    injection_keywords = re.compile(
        r"ignore|override|disregard|new\s+task|forget\s+instructions|bypass",
        re.IGNORECASE,
    )
    blob_re = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    for match in blob_re.finditer(text):
        blob = match.group(0)
        # Pad to multiple of 4
        padded = blob + "=" * (-len(blob) % 4)
        try:
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            if injection_keywords.search(decoded):
                return True
        except Exception:
            pass
    return False


class IndirectInjectionAnalyzer:
    """Scores a normalized prompt for indirect injection likelihood."""

    def score(self, normalized_text: str) -> AnalyzerScore:
        """Return a score in [0.0, 1.0] and the list of matched patterns."""
        matched: list[str] = []
        max_weight: float = 0.0

        # Check context-hijacking patterns
        for weight, pattern in _COMPILED_CONTEXT:
            if pattern.search(normalized_text):
                matched.append(pattern.pattern)
                if weight > max_weight:
                    max_weight = weight

        # Check encoding patterns
        encoding_hits: list[tuple[float, str]] = []
        for weight, pattern in _COMPILED_ENCODING:
            if pattern.search(normalized_text):
                encoding_hits.append((weight, pattern.pattern))

        # Encoded content alone is only suspicious if combined with other
        # indicators OR if the decoded content contains injection keywords.
        if encoding_hits:
            decoded_inject = _contains_decoded_injection(normalized_text)
            if decoded_inject or matched:
                # Confirmed encoded injection
                for weight, pat_str in encoding_hits:
                    matched.append(pat_str)
                    if weight > max_weight:
                        max_weight = weight
            elif len(encoding_hits) >= 1:
                # Single encoding hit without other context: moderate signal
                best_enc = max(w for w, _ in encoding_hits)
                # Keep weight but dampen slightly since no explicit instruction keyword
                dampened = best_enc * 0.7
                if dampened > max_weight:
                    max_weight = dampened
                for weight, pat_str in encoding_hits:
                    matched.append(pat_str)

        # Boost for multiple independent signals
        if len(matched) > 1:
            boost = min(0.05 * (len(matched) - 1), 0.10)
            final_score = min(max_weight + boost, 1.0)
        else:
            final_score = max_weight

        return AnalyzerScore(
            score=round(final_score, 2),
            matched_patterns=matched,
        )
