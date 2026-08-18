"""REST API routes for the Prompt Injection Detector."""

from __future__ import annotations

import asyncio
import logging
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator

from app.api.events import broadcaster
from app.detector.engine import DetectionEngine
from app.models.schemas import (
    AnalysisResult,
    RunAllScenariosResponse,
    RunDemoResponse,
    state,
)
from app.samples.provider import ScenarioProvider

logger = logging.getLogger(__name__)

router = APIRouter()
_engine = DetectionEngine()
_scenarios = ScenarioProvider()

# ---------------------------------------------------------------------------
# Request schema
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=10000)

    @field_validator("prompt")
    @classmethod
    def not_whitespace_only(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Prompt must be between 1 and 10,000 characters")
        return v


# ---------------------------------------------------------------------------
# Helper: run the synchronous engine with a wall-clock timeout guard
# ---------------------------------------------------------------------------

def _run_engine(prompt: str) -> AnalysisResult:
    """Call the detection engine directly (it completes in <5ms)."""
    t0 = time.perf_counter()
    result = _engine.analyze(prompt)
    elapsed = time.perf_counter() - t0
    if elapsed > 3.0:
        raise TimeoutError("Analysis exceeded 3 second limit")
    return result


# ---------------------------------------------------------------------------
# Helper: serialise AnalysisResult to a plain dict for JSON responses
# ---------------------------------------------------------------------------

def _result_dict(r: AnalysisResult) -> dict:
    return {
        "id": r.id,
        "prompt": r.prompt,
        "truncated_prompt": r.truncated_prompt,
        "classification": r.classification,
        "confidence_score": r.confidence_score,
        "confidence_level": r.confidence_level.value
            if hasattr(r.confidence_level, "value") else r.confidence_level,
        "threat_type": r.threat_type,
        "submitted_at": r.submitted_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/")
async def dashboard(request: Request) -> FileResponse:
    """Serve the dashboard HTML."""
    import os
    static_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "static", "index.html"
    )
    return FileResponse(os.path.abspath(static_path))


@router.post("/api/analyze")
async def analyze_prompt(body: AnalyzeRequest) -> dict:
    """Analyse a prompt and return the classification result."""
    try:
        result = _run_engine(body.prompt)
    except TimeoutError:
        raise HTTPException(
            status_code=504,
            detail="Analysis timed out. Please try again.",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected engine error: %s", exc)
        raise HTTPException(
            status_code=500,
            detail="Analysis could not be completed. Please try again.",
        )

    state.store.add(result)
    summary = state.store.get_summary()

    await broadcaster.broadcast("result", {
        "result": _result_dict(result),
        "summary": summary.model_dump(),
    })

    return _result_dict(result)


@router.get("/api/prompts")
async def get_prompts() -> dict:
    """Return all analysed prompts with summary counts."""
    results = state.store.get_all()
    summary = state.store.get_summary()
    return {
        "prompts": [_result_dict(r) for r in results],
        "summary": summary.model_dump(),
    }


@router.get("/api/scenarios")
async def get_scenarios() -> dict:
    """Return all demo scenario categories."""
    scenarios = _scenarios.get_all_scenarios()
    return {"scenarios": [s.model_dump() for s in scenarios]}


@router.get("/api/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str) -> dict:
    """Return a single scenario by ID."""
    scenario = _scenarios.get_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return scenario.model_dump()


@router.post("/api/run-demo")
async def run_demo() -> dict:
    """Run one prompt per scenario sequentially with 2-second pauses."""
    if state.demo_in_progress:
        return RunDemoResponse(status="already_running", total=0).model_dump()

    sequence = _scenarios.get_demo_sequence()
    state.demo_in_progress = True
    state.demo_mode = "full_demo"
    state.demo_current = 0
    state.demo_total = len(sequence)

    asyncio.create_task(_run_sequence(sequence, mode="full_demo", pause=2.0))

    return RunDemoResponse(status="started", total=len(sequence)).model_dump()


@router.post("/api/run-all-scenarios")
async def run_all_scenarios() -> dict:
    """Run every scenario prompt sequentially."""
    if state.demo_in_progress:
        return RunAllScenariosResponse(status="already_running", total=0).model_dump()

    all_prompts = _scenarios.get_all_prompts()
    state.demo_in_progress = True
    state.demo_mode = "all_scenarios"
    state.demo_current = 0
    state.demo_total = len(all_prompts)

    asyncio.create_task(_run_sequence(all_prompts, mode="all_scenarios", pause=1.0))

    return RunAllScenariosResponse(status="started", total=len(all_prompts)).model_dump()


@router.get("/api/events")
async def sse_stream(request: Request) -> StreamingResponse:
    """Server-Sent Events stream for real-time dashboard updates."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    await broadcaster.add_client(queue)

    results = state.store.get_all()
    summary = state.store.get_summary()
    initial = {
        "prompts": [_result_dict(r) for r in results],
        "summary": summary.model_dump(),
        "demo_in_progress": state.demo_in_progress,
        "demo_mode": state.demo_mode,
        "demo_current": state.demo_current,
        "demo_total": state.demo_total,
    }

    async def stream_with_disconnect():
        async for chunk in broadcaster.sse_generator(queue, initial_state=initial):
            if await request.is_disconnected():
                break
            yield chunk

    return StreamingResponse(
        stream_with_disconnect(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ---------------------------------------------------------------------------
# Internal: demo sequence runner
# ---------------------------------------------------------------------------

async def _run_sequence(prompts: list, mode: str, pause: float) -> None:
    """Run a list of ScenarioPrompts sequentially, broadcasting progress."""
    total = len(prompts)
    try:
        for i, scenario_prompt in enumerate(prompts, start=1):
            try:
                result = _run_engine(scenario_prompt.prompt)
                state.store.add(result)
                summary = state.store.get_summary()
                await broadcaster.broadcast("result", {
                    "result": _result_dict(result),
                    "summary": summary.model_dump(),
                })
            except Exception as exc:
                logger.error("Demo prompt %d/%d failed: %s", i, total, exc)
                await broadcaster.broadcast("error", {
                    "message": f"Prompt {i}/{total} could not be analysed.",
                    "prompt_index": i,
                })

            state.demo_current = i
            await broadcaster.broadcast("progress", {
                "current": i,
                "total": total,
                "mode": mode,
            })

            if i < total:
                await asyncio.sleep(pause)
    finally:
        state.demo_in_progress = False
        state.demo_mode = ""
        await broadcaster.broadcast("demo_complete", {"mode": mode})
