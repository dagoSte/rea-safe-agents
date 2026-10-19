"""Text/tool-history-only provider requests; no cloud integrations or file URLs."""

import re

from tunnel import require

FIELDS = {
    "codex": {"model", "input", "instructions", "tools", "tool_choice", "parallel_tool_calls", "reasoning",
              "store", "stream", "include", "prompt_cache_key", "client_metadata", "max_output_tokens", "background"},
    "claude": {"model", "messages", "system", "tools", "tool_choice", "max_tokens", "stream", "metadata", "thinking",
               "context_management", "output_config", "temperature", "top_p", "top_k", "stop_sequences"},
}
CLAUDE_BETAS = {
    "claude-code-20250219", "interleaved-thinking-2025-05-14", "thinking-token-count-2026-05-13",
    "context-management-2025-06-27", "prompt-caching-scope-2026-01-05", "per-turn-control-2026-07-01",
    "effort-2025-11-24", "thinking-display-updates-2026-08-18", "token-counting-2024-11-01",
    # Sent by the subscription (non-bare) profile.
    "oauth-2025-04-20", "mid-conversation-tool-changes-2026-07-01", "extended-cache-ttl-2025-04-11",
}


def fields(item, allowed):
    require(isinstance(item, dict) and set(item) <= allowed, "Unapproved provider request fields")


def text_blocks(content, client):
    if isinstance(content, str):
        return
    require(isinstance(content, list), "Expected text content")
    for block in content:
        allowed = {"type", "text", "cache_control"} if client == "claude" else {"type", "text", "annotations", "logprobs"}
        fields(block, allowed)
        require(isinstance(block.get("logprobs", []), list), "Invalid output logprobs")
        require(block.get("type") in ({"text"} if client == "claude" else {"input_text", "output_text"})
                and isinstance(block.get("text"), str), "Remote media and file references are forbidden")
        # Output annotations are data; permit no remote-resource descriptors.
        require(not block.get("annotations"), "Provider output annotations are outside the text profile")


def claude_content(content):
    if isinstance(content, str):
        return
    require(isinstance(content, list), "Expected Claude content")
    for block in content:
        require(isinstance(block, dict), "Invalid Claude content block")
        kind = block.get("type")
        if kind == "text":
            text_blocks([block], "claude")
        elif kind == "tool_use":
            fields(block, {"type", "id", "name", "input"})
        elif kind == "tool_result":
            fields(block, {"type", "tool_use_id", "content", "is_error", "cache_control"})
            text_blocks(block.get("content", ""), "claude")
        elif kind == "thinking":
            fields(block, {"type", "thinking", "signature"})
        elif kind == "redacted_thinking":
            fields(block, {"type", "data"})
        else:
            require(False, "Claude content outside the text/tool-history profile")


def tool_fields(tools, client):
    require(isinstance(tools, list), "Invalid provider tool list")
    for tool in tools:
        require(isinstance(tool, dict), "Invalid provider tool declaration")
        if client == "codex" and tool.get("type") == "namespace":
            fields(tool, {"type", "name", "description", "tools"})
            tool_fields(tool.get("tools"), client)
        else:
            fields(tool, ({"type", "name", "description", "parameters", "strict"} if client == "codex"
                          else {"type", "name", "description", "input_schema", "cache_control"}))


def validate_body(client, body, beta):
    fields(body, FIELDS[client])
    requested = beta.split(",") if beta else []
    require(not requested if client == "codex" else len(requested) == len(set(requested)) and set(requested) <= CLAUDE_BETAS,
            "Provider beta outside the pinned client profile")
    tool_fields(body.get("tools", []), client)
    if client == "codex":
        if "reasoning" in body:
            fields(body["reasoning"], {"effort", "summary"})
        require(body.get("include", []) in ([], ["reasoning.encrypted_content"]), "Provider include outside the text profile")
        require(body.get("tool_choice", "auto") in ("auto", "none", "required"), "Unapproved provider tool choice")
        source = body.get("input", [])
        if isinstance(source, str):
            return
        require(isinstance(source, list), "Invalid Responses input")
        for item in source:
            require(isinstance(item, dict), "Invalid Responses item")
            kind = item.get("type", "message")
            if kind == "message":
                # Real models label assistant messages with a short phase such as "commentary".
                fields(item, {"type", "id", "role", "content", "status", "phase"})
                require(item.get("phase") is None or isinstance(item["phase"], str) and re.fullmatch(r"[a-z_]{1,32}", item["phase"]) is not None,
                        "Invalid message phase")
                text_blocks(item.get("content", ""), client)
            elif kind == "function_call":
                fields(item, {"type", "id", "name", "namespace", "arguments", "call_id", "status"})
            elif kind == "function_call_output":
                fields(item, {"type", "id", "call_id", "output", "status"})
                text_blocks(item.get("output", ""), client)
            elif kind == "reasoning":
                fields(item, {"type", "id", "summary", "encrypted_content", "status"})
                require(all(isinstance(part, dict) and set(part) <= {"type", "text"}
                            and part.get("type") == "summary_text" for part in item.get("summary", [])), "Invalid reasoning summary")
            else:
                require(False, "Responses item outside the text/tool-history profile")
    else:
        if "tool_choice" in body:
            choice = body["tool_choice"]
            fields(choice, {"type", "name", "disable_parallel_tool_use"})
            require(choice.get("type") in {"auto", "any", "tool", "none"}, "Unapproved tool selection")
        if "thinking" in body:
            fields(body["thinking"], {"type", "budget_tokens", "display"})
            require(body["thinking"].get("type") in {"adaptive", "enabled", "disabled"}, "Unapproved thinking mode")
        if "context_management" in body:
            require(body["context_management"] == {"edits": [{"type": "clear_thinking_20251015", "keep": "all"}]},
                    "Unapproved server context integration")
        if "output_config" in body:
            fields(body["output_config"], {"effort"})
        text_blocks(body.get("system", ""), client)
        require(isinstance(body.get("messages", []), list), "Invalid Messages input")
        for message in body.get("messages", []):
            fields(message, {"role", "content", "output_config"})
            if "output_config" in message:
                fields(message["output_config"], {"effort"})
            claude_content(message.get("content", ""))
