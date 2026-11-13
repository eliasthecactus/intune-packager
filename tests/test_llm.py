import asyncio
import json
from dataclasses import replace

import httpx

from app import llm


def _mock(monkeypatch, handler):
    real = httpx.AsyncClient
    monkeypatch.setattr(llm.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))


def _with_settings(monkeypatch, **kw):
    monkeypatch.setattr(llm, "settings", replace(llm.settings, **kw))


def test_foundry_style_routing(monkeypatch):
    cases = {"claude-opus-5-5": "anthropic", "gpt-5.1": "responses", "GPT-5-codex": "responses",
             "o4-mini": "responses", "codex-mini": "responses", "DeepSeek-V3.2": "chat",
             "Llama-4-Maverick": "chat", "grok-4": "chat", "mistral-large": "chat"}
    for model, style in cases.items():
        _with_settings(monkeypatch, foundry_model=model, foundry_api_style="auto")
        assert llm._foundry_style() == style, model
    _with_settings(monkeypatch, foundry_model="my-gpt", foundry_api_style="openai")
    assert llm._foundry_style() == "chat"
    _with_settings(monkeypatch, foundry_model="my-gpt", foundry_api_style="responses")
    assert llm._foundry_style() == "responses"


def test_responses_session_roundtrip(monkeypatch):
    _with_settings(monkeypatch, llm_provider="foundry", foundry_resource="res", foundry_endpoint=None,
                   foundry_api_key="k", foundry_model="gpt-5.1", foundry_api_style="auto",
                   openai_reasoning_effort="high")
    bodies = []

    def handler(request: httpx.Request):
        assert str(request.url) == "https://res.services.ai.azure.com/openai/v1/responses"
        assert request.headers["api-key"] == "k"
        bodies.append(json.loads(request.content))
        if len(bodies) == 1:
            return httpx.Response(200, json={"status": "completed", "error": None, "output": [
                {"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": "ENC"},
                {"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "list_files",
                 "arguments": '{"path": "."}', "status": "completed"},
            ], "usage": {"input_tokens": 100, "output_tokens": 20, "input_tokens_details": {"cached_tokens": 40}}})
        return httpx.Response(200, json={"status": "completed", "error": None, "output": [
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "done"}]},
        ], "usage": {"input_tokens": 150, "output_tokens": 5}})

    _mock(monkeypatch, handler)
    tool = {"name": "list_files", "description": "list", "parameters": {"type": "object", "properties": {}}}
    session = llm.create_session("system prompt", [tool])
    assert isinstance(session, llm.ResponsesSession)
    session.add_user_message("package this")

    first = asyncio.run(session.step())
    assert [(c.id, c.name, c.arguments) for c in first.tool_calls] == [("call_1", "list_files", {"path": "."})]
    assert bodies[0]["instructions"] == "system prompt"
    assert bodies[0]["store"] is False and bodies[0]["reasoning"] == {"effort": "high"}
    assert bodies[0]["tools"][0] == {"type": "function", **tool}

    session.add_tool_results([(first.tool_calls[0], "a.exe", False)], note="keep going")
    second = asyncio.run(session.step())
    assert second.text == "done" and not second.tool_calls and not second.truncated
    sent = bodies[1]["input"]
    assert sent[0] == {"role": "user", "content": "package this"}
    assert sent[1]["type"] == "reasoning" and sent[1]["encrypted_content"] == "ENC"
    assert sent[2]["type"] == "function_call"
    assert sent[3] == {"type": "function_call_output", "call_id": "call_1", "output": "a.exe"}
    assert sent[4] == {"role": "user", "content": "keep going"}
    assert session.usage.input_tokens == 250 and session.usage.cached_tokens == 40 and session.usage.requests == 2


def test_deepseek_uses_chat_completions(monkeypatch):
    _with_settings(monkeypatch, llm_provider="foundry", foundry_resource="res", foundry_endpoint=None,
                   foundry_api_key="k", foundry_model="DeepSeek-V3.2", foundry_api_style="auto")

    def handler(request: httpx.Request):
        assert str(request.url) == "https://res.services.ai.azure.com/openai/v1/chat/completions"
        body = json.loads(request.content)
        assert "max_completion_tokens" in body
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "hi"},
                                                       "finish_reason": "stop"}], "usage": {}})

    _mock(monkeypatch, handler)
    session = llm.create_session("sys", [])
    assert isinstance(session, llm.OpenAICompatSession)
    session.add_user_message("hello")
    assert asyncio.run(session.step()).text == "hi"


def test_responses_truncated(monkeypatch):
    def handler(request):
        return httpx.Response(200, json={"status": "incomplete", "error": None,
                                         "incomplete_details": {"reason": "max_output_tokens"}, "output": []})
    _mock(monkeypatch, handler)
    s = llm.ResponsesSession("sys", [], base_url="https://x/openai/v1", headers={}, model="gpt-5.1")
    assert asyncio.run(s.step()).truncated
