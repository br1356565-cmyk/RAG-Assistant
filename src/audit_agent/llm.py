"""Model access: the LiteLLM gateway's OpenAI-compatible API (default), or Bedrock's
Converse API directly for accounts that don't have the gateway.

The harness depends only on the `LLM` protocol and speaks OpenAI-style messages; the
Bedrock client translates them. Tests use a scripted fake.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol


RAW_KEY = "_converse_content"   # never sent to the gateway; see BedrockLLM


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: str  # raw JSON string from the model


@dataclass
class LLMResponse:
    text: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    # Bedrock only: the assistant turn exactly as returned, including reasoning blocks.
    # Claude 5.x thinks by default and rejects a tool result unless the thinking blocks
    # of that turn are sent back complete and unmodified.
    raw_content: list | None = None

    def as_message(self) -> dict:
        msg: dict[str, Any] = {"role": "assistant", "content": self.text}
        if self.tool_calls:
            msg["tool_calls"] = [
                {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": c.arguments}}
                for c in self.tool_calls
            ]
        if self.raw_content is not None:
            msg[RAW_KEY] = self.raw_content
        return msg


class LLM(Protocol):
    def complete(
        self, *, model: str, messages: list[dict], tools: list[dict], tool_choice: Any,
        max_tokens: int, user: str, tags: list[str], temperature: float | None = None,
    ) -> LLMResponse: ...


class GatewayLLM:
    def __init__(self, base_url: str, api_key: str, timeout_s: float = 60.0, http_client=None):
        from openai import OpenAI

        self._client = OpenAI(base_url=base_url, api_key=api_key, timeout=timeout_s, max_retries=2,
                              http_client=http_client)

    def complete(self, *, model, messages, tools, tool_choice, max_tokens, user, tags,
                 temperature: float | None = None) -> LLMResponse:
        messages = [{k: v for k, v in m.items() if k != RAW_KEY} for m in messages]
        kwargs: dict[str, Any] = dict(
            model=model, messages=messages, max_tokens=max_tokens, user=user,
            extra_body={"metadata": {"tags": tags}},  # LiteLLM spend tracking
        )
        if temperature is not None:   # None: leave it to the model (reasoning models reject it)
            kwargs["temperature"] = temperature
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = tool_choice
        resp = self._client.chat.completions.create(**kwargs)
        msg = resp.choices[0].message
        calls = [
            ToolCall(id=c.id, name=c.function.name, arguments=c.function.arguments or "{}")
            for c in (msg.tool_calls or [])
        ]
        usage = resp.usage
        return LLMResponse(
            text=msg.content,
            tool_calls=calls,
            tokens_in=getattr(usage, "prompt_tokens", 0) or 0,
            tokens_out=getattr(usage, "completion_tokens", 0) or 0,
        )


class GatewayKeys:
    """Per-team LiteLLM virtual keys, so cost is attributed to the team that asked."""

    def __init__(self, keys: dict[str, str]):
        if "default" not in keys:
            raise ValueError("gateway keys secret needs a 'default' entry")
        self._keys = keys

    def for_teams(self, team_ids: tuple[str, ...]) -> str:
        for t in sorted(team_ids):
            if t in self._keys:
                return self._keys[t]
        return self._keys["default"]


class BedrockLLM:
    """Calls Bedrock's Converse API with the Lambda role's credentials.

    Translation from the OpenAI-style messages the harness builds:
      system messages      -> `system`
      assistant tool_calls -> `toolUse` blocks
      role "tool" messages -> `toolResult` blocks in a user turn
    Converse needs strictly alternating user/assistant turns, so consecutive messages with
    the same role (several tool results, then a harness note) are merged into one turn.
    There are no per-team keys here: cost shows up per model in the AWS bill and the
    token counts in the audit log.
    """

    def __init__(self, region: str, client=None):
        if client is None:
            import boto3
            from botocore.config import Config

            client = boto3.client("bedrock-runtime", region_name=region, config=Config(
                read_timeout=60, connect_timeout=5, retries={"max_attempts": 4, "mode": "adaptive"}))
        self._client = client

    def complete(self, *, model, messages, tools, tool_choice, max_tokens, user, tags,
                 temperature: float | None = None) -> LLMResponse:
        system, turns = to_converse(messages)
        kwargs: dict[str, Any] = {"modelId": model, "messages": turns,
                                  "inferenceConfig": {"maxTokens": max_tokens}}
        if temperature is not None:
            kwargs["inferenceConfig"]["temperature"] = temperature
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["toolConfig"] = {"tools": [_tool_spec(t) for t in tools],
                                    "toolChoice": _tool_choice(tool_choice)}
        try:
            resp = self._client.converse(**kwargs)
        except Exception as exc:  # noqa: BLE001
            # Some models (e.g. Sonnet 5.5) reject forced tool use; ask with "auto" instead.
            # The harness still requires the terminal tool, so nothing is lost but certainty.
            forced = tools and "auto" not in kwargs["toolConfig"]["toolChoice"]
            if not (forced and _is_validation_error(exc)):
                raise
            kwargs["toolConfig"]["toolChoice"] = {"auto": {}}
            resp = self._client.converse(**kwargs)
        texts, calls = [], []
        for block in (resp.get("output", {}).get("message", {}).get("content") or []):
            if "text" in block:
                texts.append(block["text"])
            elif "toolUse" in block:
                u = block["toolUse"]
                calls.append(ToolCall(id=u["toolUseId"], name=u["name"], arguments=json.dumps(u.get("input") or {})))
        usage = resp.get("usage") or {}
        raw = list(resp.get("output", {}).get("message", {}).get("content") or [])
        return LLMResponse(text="".join(texts) or None, tool_calls=calls,
                           tokens_in=usage.get("inputTokens", 0), tokens_out=usage.get("outputTokens", 0),
                           raw_content=raw)


def to_converse(messages: list[dict]) -> tuple[list[dict], list[dict]]:
    system: list[dict] = []
    turns: list[dict] = []

    def add(role: str, blocks: list[dict]) -> None:
        if not blocks:
            return
        if turns and turns[-1]["role"] == role:
            turns[-1]["content"].extend(blocks)
        else:
            turns.append({"role": role, "content": blocks})

    for m in messages:
        role, content = m["role"], m.get("content")
        if role == "system":
            if content:
                system.append({"text": content})
        elif role == "user":
            add("user", [{"text": content}] if content else [])
        elif role == "assistant" and m.get(RAW_KEY):
            add("assistant", list(m[RAW_KEY]))   # verbatim, so reasoning blocks survive
        elif role == "assistant":
            blocks = [{"text": content}] if content else []
            for c in m.get("tool_calls") or []:
                fn = c["function"]
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                if not isinstance(args, dict):
                    args = {}
                blocks.append({"toolUse": {"toolUseId": c["id"], "name": fn["name"], "input": args}})
            add("assistant", blocks)
        elif role == "tool":
            add("user", [{"toolResult": {"toolUseId": m["tool_call_id"],
                                         "content": [{"text": content or "(empty)"}]}}])
        else:
            raise ValueError(f"unsupported message role {role!r}")
    return system, turns


def _is_validation_error(exc: Exception) -> bool:
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "") if hasattr(exc, "response") else ""
    return code == "ValidationException" or type(exc).__name__ == "ValidationException"


def _tool_spec(tool: dict) -> dict:
    fn = tool["function"]
    return {"toolSpec": {"name": fn["name"], "description": fn.get("description") or fn["name"],
                         "inputSchema": {"json": fn.get("parameters") or {"type": "object", "properties": {}}}}}


def _tool_choice(choice: Any) -> dict:
    if isinstance(choice, dict) and choice.get("type") == "function":
        return {"tool": {"name": choice["function"]["name"]}}
    if choice == "required":
        return {"any": {}}
    return {"auto": {}}
