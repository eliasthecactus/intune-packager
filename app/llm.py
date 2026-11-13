"""Provider-neutral chat sessions with tool calling.

* OpenRouter                     -> OpenAI-compatible /chat/completions
* Microsoft Foundry, OpenAI API  -> {endpoint}/openai/v1/chat/completions
* Microsoft Foundry, Claude      -> Anthropic Messages API via the official SDK (AsyncAnthropicFoundry)
"""
from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from urllib.parse import urlparse

import anthropic
import httpx

from .config import settings

log = logging.getLogger(__name__)


class LLMError(Exception):
    pass


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict
    parse_error: str | None = None


@dataclass
class StepResult:
    text: str
    tool_calls: list[ToolCall]
    truncated: bool = False


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    requests: int = 0
    cost_usd: float = 0.0

    def as_dict(self) -> dict:
        return dict(self.__dict__)


class ChatSession(ABC):
    def __init__(self, system: str, tools: list[dict]):
        self.system = system
        self.tools = tools  # neutral: {"name", "description", "parameters"}
        self.usage = Usage()

    @abstractmethod
    async def step(self) -> StepResult: ...

    @abstractmethod
    def add_tool_results(self, results: list[tuple[ToolCall, str, bool]], note: str | None = None) -> None: ...

    @abstractmethod
    def add_user_message(self, text: str) -> None: ...


# ======================================================================= OpenAI
class OpenAICompatSession(ChatSession):
    def __init__(self, system: str, tools: list[dict], *, base_url: str, headers: dict, model: str,
                 params: dict | None = None, token_param: str = "max_tokens", cache_system: bool = False):
        super().__init__(system, tools)
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.headers = headers
        self.model = model
        self.params = params or {}
        self.token_param = token_param
        sys_content: object = system
        if cache_system:  # Anthropic models via OpenRouter honour cache_control on content parts
            sys_content = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
        self.messages: list[dict] = [{"role": "system", "content": sys_content}]
        self.oa_tools = [{"type": "function", "function": t} for t in tools]

    async def step(self) -> StepResult:
        body = {
            "model": self.model,
            "messages": self.messages,
            "tools": self.oa_tools,
            "tool_choice": "auto",
            self.token_param: settings.llm_max_tokens,
        }
        if "openrouter.ai" in self.url:
            body["usage"] = {"include": True}
        data = await self._post(body)
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        usage = data.get("usage") or {}
        self.usage.requests += 1
        self.usage.input_tokens += usage.get("prompt_tokens", 0) or 0
        self.usage.output_tokens += usage.get("completion_tokens", 0) or 0
        self.usage.cached_tokens += (usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0) or 0
        self.usage.cost_usd += float(usage.get("cost") or 0)

        assistant = {k: v for k, v in msg.items() if v is not None}
        assistant["role"] = "assistant"
        assistant.setdefault("content", "")
        self.messages.append(assistant)

        calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            raw = fn.get("arguments") or "{}"
            try:
                args, err = (json.loads(raw) if raw.strip() else {}), None
                if not isinstance(args, dict):
                    args, err = {}, "arguments must be a JSON object"
            except json.JSONDecodeError as exc:
                args, err = {}, f"invalid JSON arguments: {exc}"
            calls.append(ToolCall(id=tc.get("id") or f"call_{len(calls)}", name=fn.get("name", ""), arguments=args, parse_error=err))
        text = msg.get("content") or ""
        if isinstance(text, list):
            text = "".join(p.get("text", "") for p in text if isinstance(p, dict))
        return StepResult(text=text, tool_calls=calls, truncated=choice.get("finish_reason") == "length")

    async def _post(self, body: dict) -> dict:
        delay = 3.0
        async with httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=20.0)) as client:
            for attempt in range(5):
                try:
                    resp = await client.post(self.url, headers=self.headers, params=self.params, json=body)
                except httpx.HTTPError as exc:
                    if attempt == 4:
                        raise LLMError(f"connection to AI provider failed: {exc}") from exc
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                if resp.status_code in (408, 409, 429, 500, 502, 503, 504) and attempt < 4:
                    retry_after = resp.headers.get("retry-after")
                    await asyncio.sleep(float(retry_after) if retry_after and retry_after.isdigit() else delay)
                    delay *= 2
                    continue
                if resp.status_code >= 400:
                    raise LLMError(f"AI provider returned HTTP {resp.status_code}: {resp.text[:1500]}")
                data = resp.json()
                if "error" in data and not data.get("choices"):
                    raise LLMError(f"AI provider error: {json.dumps(data['error'])[:1500]}")
                return data
        raise LLMError("AI provider request failed")

    def add_tool_results(self, results, note=None):
        for call, content, _is_error in results:
            self.messages.append({"role": "tool", "tool_call_id": call.id, "content": content})
        if note:
            self.messages.append({"role": "user", "content": note})

    def add_user_message(self, text):
        self.messages.append({"role": "user", "content": text})


# ==================================================================== Anthropic
class AnthropicSession(ChatSession):
    def __init__(self, system: str, tools: list[dict], *, client: anthropic.AsyncAnthropicFoundry, model: str,
                 fallback_state: anthropic.BetaFallbackState | None = None):
        super().__init__(system, tools)
        self.client = client
        self.model = model
        self.fallback_state = fallback_state
        self.messages: list[dict] = []
        self.a_tools = [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in tools]

    async def step(self) -> StepResult:
        kwargs: dict = {
            "model": self.model,
            "max_tokens": settings.llm_max_tokens,
            "system": self.system,
            "tools": self.a_tools,
            "messages": self.messages,
            "cache_control": {"type": "ephemeral"},
        }
        if settings.claude_effort:
            kwargs["output_config"] = {"effort": settings.claude_effort}
        try:
            if self.fallback_state is not None:
                with self.fallback_state:
                    resp = await self.client.beta.messages.create(**kwargs)
            else:
                resp = await self.client.beta.messages.create(**kwargs)
        except anthropic.RateLimitError as exc:
            raise LLMError(f"Foundry rate limit reached: {exc}") from exc
        except anthropic.APIStatusError as exc:
            raise LLMError(f"Foundry returned HTTP {exc.status_code}: {str(exc)[:1500]}") from exc
        except anthropic.APIConnectionError as exc:
            raise LLMError(f"connection to Foundry failed: {exc}") from exc

        u = resp.usage
        self.usage.requests += 1
        self.usage.input_tokens += (u.input_tokens or 0) + (u.cache_read_input_tokens or 0) + (u.cache_creation_input_tokens or 0)
        self.usage.cached_tokens += u.cache_read_input_tokens or 0
        self.usage.output_tokens += u.output_tokens or 0

        if resp.stop_reason == "refusal":
            details = getattr(resp, "stop_details", None)
            raise LLMError(f"The model declined the request (refusal: {getattr(details, 'category', None)}). "
                           "Set FOUNDRY_FALLBACK_MODEL to a deployed fallback model or rephrase the request.")

        self.messages.append({"role": "assistant", "content": resp.content})
        calls = [ToolCall(id=b.id, name=b.name, arguments=b.input if isinstance(b.input, dict) else {})
                 for b in resp.content if b.type == "tool_use"]
        text = "".join(b.text for b in resp.content if b.type == "text")
        return StepResult(text=text, tool_calls=calls, truncated=resp.stop_reason == "max_tokens")

    def add_tool_results(self, results, note=None):
        content: list[dict] = [
            {"type": "tool_result", "tool_use_id": call.id, "content": text, "is_error": is_error}
            for call, text, is_error in results
        ]
        if note:
            content.append({"type": "text", "text": note})
        self.messages.append({"role": "user", "content": content})

    def add_user_message(self, text):
        self.messages.append({"role": "user", "content": [{"type": "text", "text": text}]})


# ====================================================================== factory
def _foundry_style() -> str:
    style = settings.foundry_api_style
    if style == "auto":
        return "anthropic" if settings.foundry_model.lower().startswith("claude") else "openai"
    return style


def _foundry_host() -> str:
    if settings.foundry_endpoint:
        return urlparse(settings.foundry_endpoint).netloc
    return f"{settings.foundry_resource}.services.ai.azure.com"


def create_session(system: str, tools: list[dict]) -> ChatSession:
    errors = settings.config_errors()
    if errors:
        raise LLMError("AI provider not configured: " + "; ".join(errors))

    if settings.llm_provider == "openrouter":
        return OpenAICompatSession(
            system, tools,
            base_url=settings.openrouter_base_url,
            headers={
                "Authorization": f"Bearer {settings.openrouter_api_key}",
                "HTTP-Referer": "https://github.com/eliasthecactus/intune-packager",
                "X-Title": "Intune Packager",
            },
            model=settings.openrouter_model,
            cache_system=settings.openrouter_model.startswith("anthropic/"),
        )

    # Microsoft Foundry
    if _foundry_style() == "anthropic":
        endpoint = settings.foundry_endpoint
        base_url = None
        if endpoint:
            base_url = endpoint if "/anthropic" in endpoint else f"https://{_foundry_host()}/anthropic/"
        middleware = None
        state = None
        if settings.foundry_fallback_model:
            middleware = [anthropic.BetaRefusalFallbackMiddleware(fallbacks=[{"model": settings.foundry_fallback_model}])]
            state = anthropic.BetaFallbackState()
        client = anthropic.AsyncAnthropicFoundry(
            api_key=settings.foundry_api_key,
            resource=None if base_url else settings.foundry_resource,
            base_url=base_url,
            max_retries=4,
            timeout=600,
            middleware=middleware,
        )
        return AnthropicSession(system, tools, client=client, model=settings.foundry_model, fallback_state=state)

    endpoint = settings.foundry_endpoint or f"https://{_foundry_host()}"
    endpoint = endpoint.rstrip("/")
    if not endpoint.endswith("/openai/v1") and "/models" not in endpoint and "/openai/deployments" not in endpoint:
        endpoint += "/openai/v1"
    headers = ({"Authorization": f"Bearer {settings.foundry_api_key}"} if settings.foundry_auth_header == "bearer"
               else {"api-key": settings.foundry_api_key or ""})
    params = {"api-version": settings.foundry_api_version} if settings.foundry_api_version else {}
    return OpenAICompatSession(system, tools, base_url=endpoint, headers=headers, model=settings.foundry_model,
                               params=params, token_param="max_completion_tokens")
