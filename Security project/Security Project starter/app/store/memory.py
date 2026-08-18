"""In-memory storage for prompt analysis results."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.schemas import AnalysisResult, DashboardSummary


class PromptStore:
    """Thread-safe in-memory store for AnalysisResult objects.

    Properties maintained:
    - Property 7: total == safe + malicious at all times.
    - Property 9: get_all() returns results sorted newest-first.
    """

    def __init__(self) -> None:
        self._results: list[AnalysisResult] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def add(self, result: "AnalysisResult") -> None:
        """Append an analysis result to the store."""
        with self._lock:
            self._results.append(result)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_all(self) -> list["AnalysisResult"]:
        """Return all results sorted by submission time, newest first."""
        with self._lock:
            return sorted(
                self._results,
                key=lambda r: r.submitted_at,
                reverse=True,
            )

    def get_summary(self) -> "DashboardSummary":
        """Return counts of total, safe, and malicious prompts."""
        from app.models.schemas import DashboardSummary

        with self._lock:
            total = len(self._results)
            safe = sum(1 for r in self._results if r.classification == "safe")
            malicious = total - safe
            return DashboardSummary(total=total, safe=safe, malicious=malicious)

    def clear(self) -> None:
        """Reset the store (used in tests)."""
        with self._lock:
            self._results.clear()
