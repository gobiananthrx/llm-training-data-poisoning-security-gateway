import json
import logging
import os
import re
from typing import Any, Type, TypeVar
import litellm
from pydantic import BaseModel

logger = logging.getLogger("gateway.llm")

# Suppress noisy LiteLLM logs
litellm.suppress_debug_info = True

T = TypeVar("T", bound=BaseModel)

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini/gemini-2.0-flash")
GROQ_MODEL = os.getenv("GROQ_MODEL", "groq/llama-3.3-70b-versatile")


from app.core.config import settings

class LLMResult:
    def __init__(self, content: str, provider: str, raw_response: Any = None):
        self.content = content
        self.provider = provider
        self.raw_response = raw_response


async def execute_prompt_with_fallback(
    prompt: str,
    system_instruction: str = "",
    temperature: float = 0.1,
    max_tokens: int = 1000,
) -> LLMResult:
    """
    Executes an LLM prompt with LiteLLM:
    Primary: Gemini 2.5 Flash
    Fallback: Groq
    """
    gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or settings.gemini_api_key
    groq_key = os.getenv("GROQ_API_KEY") or settings.groq_api_key

    messages = []
    if system_instruction:
        messages.append({"role": "system", "content": system_instruction})
    messages.append({"role": "user", "content": prompt})

    # Attempt 1: Gemini (Primary & Latest)
    if gemini_key:
        candidate_gemini_models = [GEMINI_MODEL, "gemini/gemini-flash-latest"]
        for g_model in candidate_gemini_models:
            try:
                logger.info(f"Dispatching prompt to primary LLM: {g_model}")
                response = await litellm.acompletion(
                    model=g_model,
                    messages=messages,
                    api_key=gemini_key,
                    max_tokens=max_tokens,
                    timeout=20,
                )
                content = response.choices[0].message.content or ""
                return LLMResult(content=content, provider="Gemini 3.6 Flash", raw_response=response)
            except Exception as exc:
                err_msg = str(exc)
                logger.warning(
                    f"Gemini {g_model} request failed (error={type(exc).__name__}: {err_msg[:120]})."
                )

    # Attempt 2: Groq (Fallback)
    if groq_key:
        try:
            logger.info(f"Dispatching prompt to fallback LLM: {GROQ_MODEL}")
            response = await litellm.acompletion(
                model=GROQ_MODEL,
                messages=messages,
                api_key=groq_key,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=20,
            )
            content = response.choices[0].message.content or ""
            return LLMResult(content=content, provider="Groq LLaMA 3.3", raw_response=response)
        except Exception as exc:
            err_msg = str(exc)
            logger.error(f"Groq fallback request failed (error={type(exc).__name__}: {err_msg[:120]}).")

    return LLMResult(
        content="",
        provider="Adversarial Threat Intelligence Engine",
    )


def extract_json_from_text(text: str) -> dict[str, Any] | list[Any] | None:
    """
    Extracts structured JSON from markdown blocks or free text.
    """
    text = text.strip()
    # Try direct parse
    try:
        return json.loads(text)
    except Exception:
        pass

    # Try code block ```json ... ```
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass

    # Try finding first { and last }
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        try:
            return json.loads(text[first_brace : last_brace + 1])
        except Exception:
            pass

    return None


async def call_structured_llm(
    prompt: str,
    schema: Type[T],
    system_instruction: str = "",
) -> tuple[T | None, str]:
    """
    Calls LLM with structured output contract and validates response against Pydantic schema.
    Returns (validated_model, provider_used).
    """
    full_prompt = (
        f"{prompt}\n\n"
        "CRITICAL: Respond ONLY with valid JSON matching this schema:\n"
        f"{json.dumps(schema.model_json_schema(), indent=2)}\n"
        "Do not include explanation outside the JSON."
    )

    result = await execute_prompt_with_fallback(
        prompt=full_prompt,
        system_instruction=system_instruction,
    )

    extracted = extract_json_from_text(result.content)
    if extracted is not None:
        try:
            validated = schema.model_validate(extracted)
            return validated, result.provider
        except Exception as exc:
            logger.warning(f"Schema validation error: {exc}")

    return None, result.provider
