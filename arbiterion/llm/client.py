from __future__ import annotations

import json
import os
from typing import Any, Optional

import structlog

logger = structlog.get_logger()

MODEL_MAP = {
    "gpt-4o": "openai/gpt-4o",
    "gpt-4o-mini": "openai/gpt-4o-mini",
    "claude-sonnet-4": "anthropic/claude-sonnet-4-20250514",
    "claude-3-opus": "anthropic/claude-3-opus-20240229",
    "gemini-2.5-flash": "gemini/gemini-2.5-flash",
    "gemini-2.5-pro": "gemini/gemini-2.5-pro",
    "ollama/llama3.1:8b": "ollama/llama3.1:8b",
    "ollama/mistral": "ollama/mistral",
}


def resolve_model_key(user_provider: str, user_model: str) -> str:
    if user_provider == "ollama":
        return f"ollama/{user_model}"
    key = MODEL_MAP.get(user_model)
    if key:
        return key
    return f"{user_provider}/{user_model}"


def _build_litellm_kwargs(
    model_key: str,
    system_prompt: str,
    user_payload: dict[str, Any],
    api_key: Optional[str] = None,
) -> dict[str, Any]:
    # For Ollama, we need to set the base_url
    kwargs: dict[str, Any] = {
        "model": model_key,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload, indent=2)},
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }
    if "ollama/" in model_key:
        from arbiterion.config import settings
        kwargs["api_base"] = settings.ollama_base_url
    
    if api_key:
        kwargs["api_key"] = api_key
    return kwargs


async def call_llm(
    model_key: str,
    system_prompt: str,
    user_payload: dict[str, Any],
    api_key: Optional[str] = None,
    timeout_seconds: int = 60,
) -> str:
    try:
        from litellm import acompletion

        kwargs = _build_litellm_kwargs(model_key, system_prompt, user_payload, api_key)
        response = await acompletion(**kwargs, timeout=timeout_seconds)
        raw = response.choices[0].message.content or ""
        logger.info("llm_call_success", model=model_key, response_length=len(raw))
        return raw
    except ImportError:
        logger.warning("litellm_not_installed_falling_back")
        return ""
    except Exception as exc:
        logger.error("llm_call_failed", model=model_key, error=str(exc))
        return ""
