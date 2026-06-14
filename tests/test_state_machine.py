"""Tests for the pipeline state machine â€” transition validation and retry logic."""

from __future__ import annotations

import pytest

from arbiterion.pipeline.state_machine import (
    PipelineState,
    StateMachine,
    run_with_retry,
)


class TestPipelineState:
    def test_enum_values_match_db(self):
        assert PipelineState.QUEUED.value == "queued"
        assert PipelineState.CLASSIFYING.value == "classifying"
        assert PipelineState.CLASSIFYING_FAILED.value == "classifying_failed"
        assert PipelineState.TRIAGING.value == "triaging"
        assert PipelineState.TRIAGING_FAILED.value == "triaging_failed"
        assert PipelineState.PLANNING.value == "planning"
        assert PipelineState.PLANNING_FAILED.value == "planning_failed"
        assert PipelineState.COMPLETED.value == "completed"
        assert PipelineState.FAILED.value == "failed"


class TestStateMachine:
    def test_starts_at_queued(self):
        sm = StateMachine()
        assert sm.current == PipelineState.QUEUED

    def test_not_terminal_at_start(self):
        sm = StateMachine()
        assert not sm.is_terminal()

    def test_completed_is_terminal(self):
        sm = StateMachine()
        sm.transition_to(PipelineState.CLASSIFYING)
        sm.transition_to(PipelineState.TRIAGING)
        sm.transition_to(PipelineState.PLANNING)
        sm.transition_to(PipelineState.COMPLETED)
        assert sm.is_terminal()

    def test_failed_is_terminal(self):
        sm = StateMachine()
        sm.transition_to(PipelineState.FAILED)
        assert sm.is_terminal()

    def test_valid_transition(self):
        sm = StateMachine()
        assert sm.can_transition_to(PipelineState.CLASSIFYING)
        sm.transition_to(PipelineState.CLASSIFYING)
        assert sm.current == PipelineState.CLASSIFYING

    def test_invalid_transition_raises(self):
        sm = StateMachine()
        with pytest.raises(ValueError, match="Cannot transition from queued to completed"):
            sm.transition_to(PipelineState.COMPLETED)

    def test_full_happy_path(self):
        sm = StateMachine()
        path = [
            PipelineState.CLASSIFYING,
            PipelineState.TRIAGING,
            PipelineState.PLANNING,
            PipelineState.COMPLETED,
        ]
        for state in path:
            assert sm.can_transition_to(state)
            sm.transition_to(state)
        assert sm.is_terminal()

    def test_full_failed_path(self):
        sm = StateMachine()
        sm.transition_to(PipelineState.FAILED)
        assert sm.is_terminal()
        assert sm.current == PipelineState.FAILED

    def test_failed_transition_allows_retry(self):
        sm = StateMachine()
        sm.transition_to(PipelineState.CLASSIFYING)
        sm.transition_to(PipelineState.CLASSIFYING_FAILED)
        assert sm.can_transition_to(PipelineState.TRIAGING)
        assert sm.can_transition_to(PipelineState.FAILED)

    def test_terminal_states_have_no_transitions(self):
        for terminal in (PipelineState.COMPLETED, PipelineState.FAILED):
            sm = StateMachine()
            # jump directly to terminal
            sm._current = terminal
            assert sm.is_terminal()
            # no outgoing transitions
            from arbiterion.pipeline.state_machine import TRANSITIONS
            assert TRANSITIONS[terminal] == []


class TestRunWithRetry:
    @pytest.mark.asyncio
    async def test_success_on_first_attempt(self):
        async def fn():
            return "ok"

        result, ok = await run_with_retry(fn, args=(), kwargs={})
        assert ok is True
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_retry_then_success(self):
        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("not yet")
            return "ok"

        result, ok = await run_with_retry(fn, args=(), kwargs={}, max_retries=3, base_delay=0.01)
        assert ok is True
        assert result == "ok"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_exhaust_retries(self):
        async def fn():
            raise ValueError("always fails")

        result, ok = await run_with_retry(fn, args=(), kwargs={}, max_retries=2, base_delay=0.01)
        assert ok is False
        assert isinstance(result, ValueError)

    @pytest.mark.asyncio
    async def test_backoff_increases_delay(self):
        import time

        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            raise ValueError("fail")

        t0 = time.monotonic()
        await run_with_retry(fn, args=(), kwargs={}, max_retries=3, base_delay=0.05)
        elapsed = time.monotonic() - t0
        # At least the first delay (0.05s) should have elapsed
        assert elapsed >= 0.04

