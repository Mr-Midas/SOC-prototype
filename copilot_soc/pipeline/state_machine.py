"""Pipeline state machine — deterministic, enum-backed transitions with retry.

States mirror the database pipeline_state enum. Every transition is validated
at runtime so we never skip a step or double-process an alert.

Why not LangGraph?
  We only have a linear 3-agent chain (Manager → Triage → Containment).
  A 70-line enum + transition map is easier to debug, deploy, and understand
  than a full graph framework. If the chain becomes non-linear in Phase 2
  we can swap in a proper DAG without changing the agent logic.
"""

from __future__ import annotations

import asyncio
from enum import Enum
from typing import Any, Callable, Optional


class PipelineState(str, Enum):
    QUEUED = "queued"
    CLASSIFYING = "classifying"
    CLASSIFYING_FAILED = "classifying_failed"
    TRIAGING = "triaging"
    TRIAGING_FAILED = "triaging_failed"
    PLANNING = "planning"
    PLANNING_FAILED = "planning_failed"
    COMPLETED = "completed"
    FAILED = "failed"


TRANSITIONS: dict[PipelineState, list[PipelineState]] = {
    PipelineState.QUEUED: [PipelineState.CLASSIFYING, PipelineState.FAILED],
    PipelineState.CLASSIFYING: [PipelineState.TRIAGING, PipelineState.CLASSIFYING_FAILED],
    PipelineState.CLASSIFYING_FAILED: [PipelineState.TRIAGING, PipelineState.FAILED],
    PipelineState.TRIAGING: [PipelineState.PLANNING, PipelineState.TRIAGING_FAILED],
    PipelineState.TRIAGING_FAILED: [PipelineState.PLANNING, PipelineState.FAILED],
    PipelineState.PLANNING: [PipelineState.COMPLETED, PipelineState.PLANNING_FAILED],
    PipelineState.PLANNING_FAILED: [PipelineState.COMPLETED, PipelineState.FAILED],
    PipelineState.COMPLETED: [],
    PipelineState.FAILED: [],
}


class StateMachine:
    def __init__(self) -> None:
        self._current = PipelineState.QUEUED

    @property
    def current(self) -> PipelineState:
        return self._current

    def can_transition_to(self, target: PipelineState) -> bool:
        return target in TRANSITIONS.get(self._current, [])

    def transition_to(self, target: PipelineState) -> None:
        if not self.can_transition_to(target):
            raise ValueError(
                f"Cannot transition from {self._current.value} to {target.value}"
            )
        self._current = target

    def is_terminal(self) -> bool:
        return self._current in (PipelineState.COMPLETED, PipelineState.FAILED)


async def run_with_retry(
    agent_fn: Callable[..., Any],
    args: tuple,
    kwargs: dict[str, Any],
    max_retries: int = 3,
    base_delay: float = 2.0,
) -> tuple[Any, bool]:
    last_exc: Optional[Exception] = None
    for attempt in range(1, max_retries + 1):
        try:
            result = await agent_fn(*args, **kwargs)
            return result, True
        except Exception as exc:
            last_exc = exc
            if attempt < max_retries:
                delay = base_delay * (2 ** (attempt - 1))
                await asyncio.sleep(delay)
    return last_exc, False
