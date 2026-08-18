"""Core Pydantic data models for the Prompt Injection Detector."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Classification(str, Enum):
    SAFE = "safe"
    MALICIOUS = "malicious"


class ThreatType(str, Enum):
    NONE = "none"
    JAILBREAK = "jailbreak"
    INDIRECT_INJECTION = "indirect_injection"


class ConfidenceLevel(str, Enum):
    HIGH = "High Confidence"    # score > 0.8
    MEDIUM = "Medium Confidence"  # 0.5 <= score <= 0.8
    LOW = "Low Confidence"      # score < 0.5


# ---------------------------------------------------------------------------
# Analysis domain models
# ---------------------------------------------------------------------------

class AnalysisResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    prompt: str
    classification: Classification
    confidence_score: float = Field(ge=0.0, le=1.0)
    threat_type: ThreatType
    submitted_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def confidence_level(self) -> ConfidenceLevel:
        if self.confidence_score > 0.8:
            return ConfidenceLevel.HIGH
        elif self.confidence_score >= 0.5:
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW

    @property
    def truncated_prompt(self) -> str:
        if len(self.prompt) > 200:
            return self.prompt[:200] + "\u2026"
        return self.prompt

    model_config = {"use_enum_values": True}


class DashboardSummary(BaseModel):
    total: int = 0
    safe: int = 0
    malicious: int = 0


# ---------------------------------------------------------------------------
# Scenario / demo models
# ---------------------------------------------------------------------------

class ScenarioPrompt(BaseModel):
    id: str
    label: str
    prompt: str
    expected_category: Literal["safe", "jailbreak", "indirect_injection"]
    explanation: str


class DemoScenario(BaseModel):
    id: str
    name: str
    description: str
    prompts: list[ScenarioPrompt]


# ---------------------------------------------------------------------------
# Detection internal models
# ---------------------------------------------------------------------------

class AnalyzerScore(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    matched_patterns: list[str] = Field(default_factory=list)


class DetectionResult(BaseModel):
    classification: Classification
    confidence_score: float
    threat_type: ThreatType
    jailbreak_score: AnalyzerScore
    indirect_injection_score: AnalyzerScore


# ---------------------------------------------------------------------------
# API request / response schemas
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=10000)


class PromptsResponse(BaseModel):
    prompts: list[dict]
    summary: DashboardSummary


class ScenariosResponse(BaseModel):
    scenarios: list[DemoScenario]


class RunDemoResponse(BaseModel):
    status: Literal["started", "already_running"]
    total: int


class RunAllScenariosResponse(BaseModel):
    status: Literal["started", "already_running"]
    total: int


# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------

class AppState:
    """Singleton managing mutable application state."""

    def __init__(self) -> None:
        from app.store.memory import PromptStore  # avoid circular at module level
        import asyncio

        self.store: PromptStore = PromptStore()
        self.demo_in_progress: bool = False
        self.demo_mode: str = ""          # "full_demo" | "all_scenarios"
        self.demo_current: int = 0
        self.demo_total: int = 0
        self.sse_clients: list[asyncio.Queue] = []


# Module-level singleton — imported by routes and events
state = AppState()
