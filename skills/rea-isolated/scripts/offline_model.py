"""Deterministic localhost model fixture; never contacts a model provider."""

import http.server
import json

from agent_session import refusal_evidence
from tunnel import MAX_BODY, decode_json, require


def completed_calls(body):
    completed = set()
    for item in body.get("input", []):
        if isinstance(item, dict) and item.get("type") == "function_call_output":
            completed.add(item.get("call_id"))
    for message in body.get("messages", []):
        for item in message.get("content", []) if isinstance(message.get("content"), list) else []:
            if item.get("type") == "tool_result":
                completed.add(item.get("tool_use_id"))
    return completed


def response_bytes(client, body, actions, number):
    if client == "claude":
        content = [{"type": "tool_use", "id": identifier, "name": name, "input": arguments}
                   for identifier, name, arguments in actions]
        if not content:
            content = [{"type": "text", "text": "Offline verification completed."}]
        initial = {"id": "msg_fixture_" + str(number), "type": "message", "role": "assistant",
                   "model": body.get("model", "offline"), "content": [], "stop_reason": None,
                   "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 0}}
        events = [("message_start", {"type": "message_start", "message": initial})]
        for index, block in enumerate(content):
            empty = dict(block, input={}) if block["type"] == "tool_use" else dict(block, text="")
            delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])} if actions else {"type": "text_delta", "text": block["text"]}
            events += [("content_block_start", {"type": "content_block_start", "index": index, "content_block": empty}),
                       ("content_block_delta", {"type": "content_block_delta", "index": index, "delta": delta}),
                       ("content_block_stop", {"type": "content_block_stop", "index": index})]
        events += [("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use" if actions else "end_turn", "stop_sequence": None},
                                      "usage": {"output_tokens": 1}}), ("message_stop", {"type": "message_stop"})]
    else:
        output = []
        namespaced = any(tool.get("type") == "namespace" and tool.get("name") == "mcp__rea" for tool in body.get("tools", []))
        for index, (identifier, name, arguments) in enumerate(actions):
            item = {"id": "fc_fixture_" + str(number) + "_" + str(index), "type": "function_call",
                    "call_id": identifier, "name": name, "arguments": json.dumps(arguments)}
            if namespaced and name.startswith("mcp__rea__"):
                item.update(namespace="mcp__rea", name=name.removeprefix("mcp__rea__"))
            output.append(item)
        response = {"id": "resp_fixture_" + str(number), "object": "response", "created_at": 0, "status": "completed",
                    "output": output, "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
        events = [("response.created", {"type": "response.created", "response": dict(response, status="in_progress", output=[])})]
        for index, item in enumerate(output):
            for event in ("response.output_item.added", "response.output_item.done"):
                events.append((event, {"type": event, "output_index": index, "item": item}))
        events.append(("response.completed", {"type": "response.completed", "response": response}))
    return "".join("event: " + name + "\ndata: " + json.dumps(value) + "\n\n" for name, value in events).encode()


class OfflineHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        require(self.headers.get("Content-Encoding", "identity") == "identity", "Unexpected fixture compression")
        length = int(self.headers.get("Content-Length", "0"))
        require(0 < length <= MAX_BODY, "Unexpected fixture request size")
        body = decode_json(self.rfile.read(length))
        self.server.requests += 1
        if self.server.client == "claude" and self.path.split("?", 1)[0] == "/v1/messages/count_tokens":
            raw = b'{"input_tokens":1}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        self.server.refused.update(refusal_evidence(body))
        completed = completed_calls(body)
        forbidden = {
            "codex": [("exec_command", {"cmd": "echo REA_CONTAINED_PROBE"}),
                      ("apply_patch", {"patch": "*** Begin Patch\n*** Add File: /tmp/rea-unexpected-write\n+must not exist\n*** End Patch"})],
            "claude": [("Bash", {"command": "echo REA_CONTAINED_PROBE"}),
                       ("Write", {"file_path": "/tmp/rea-unexpected-write", "content": "must not exist"})],
        }
        actions = [("deny_" + name, name, arguments) for name, arguments in forbidden[self.server.client]
                   if self.server.test_refusals and name not in self.server.refused]
        if not actions:
            for index, (name, arguments) in enumerate(self.server.steps):
                identifier = "contained_step_" + str(index)
                if identifier not in completed:
                    actions = [(identifier, "mcp__rea__" + name, arguments)]
                    break
        raw = response_bytes(self.server.client, body, actions, self.server.requests)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
