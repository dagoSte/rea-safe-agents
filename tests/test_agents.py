"""Observable client boundary invariants; native verification is a separate opt-in CLI."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "skills/rea-isolated/scripts/agent_session.py"
spec = importlib.util.spec_from_file_location("agent_session", SCRIPT)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def claude_init(**changes):
    value = {"type": "system", "subtype": "init", "tools": ["mcp__rea__catalog_probe"], "skills": [],
             "mcp_servers": [{"name": "rea", "status": "connected", "source": "dynamic"}]}
    value.update(changes)
    return json.dumps(value)


CLAUDE = [[{"name": "mcp__rea__catalog_probe", "input_schema": {"type": "object", "properties": {}}}]]
CODEX = [[{"type": "function", "name": name} for name in agent.CODEX_PASSIVE] +
         [{"type": "namespace", "name": "mcp__rea", "tools": [{"name": "catalog_probe", "type": "function"}]}]]


class AgentBoundaryTests(unittest.TestCase):
    def test_no_credentials_or_provider_overrides_are_inherited(self):
        dirty = {"OPENAI_API_KEY": "secret", "ANTHROPIC_API_KEY": "secret", "ANTHROPIC_BASE_URL": "https://invalid.example",
                 "CODEX_HOME": "/untrusted", "CLAUDE_CONFIG_DIR": "/untrusted", "HTTP_PROXY": "http://invalid.example",
                 "NODE_OPTIONS": "--require=/untrusted", "PYTHONPATH": "/untrusted", "PATH": "/trusted/bin"}
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, dirty, clear=True):
            for client in ("codex", "claude"):
                env, _ = agent.environment(root, client)
                for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "HTTP_PROXY", "NODE_OPTIONS", "PYTHONPATH"):
                    self.assertNotIn(name, env)
                self.assertTrue(env["HOME"].startswith(root))
                self.assertNotEqual(env.get("CODEX_HOME"), "/untrusted")
                self.assertNotEqual(env.get("CLAUDE_CONFIG_DIR"), "/untrusted")

    def test_claude_signs_in_only_with_a_subscription_login(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"ANTHROPIC_API_KEY": "key", "CLAUDE_CODE_OAUTH_TOKEN": "host"}):
            root = Path(temporary)
            session = {"client": "claude", "executable": "/trusted/client"}
            argv, env = agent.command(root, session, agent.mcp_command(root / "deployment.json"), mock_url="http://127.0.0.1:12345",
                                      login=agent.OFFLINE_CLAUDE_LOGIN)
            self.assertNotIn("--bare", argv)  # bare mode ignores subscription logins
            self.assertEqual(env["CLAUDE_CODE_OAUTH_TOKEN"], agent.OFFLINE_CLAUDE_LOGIN)
            self.assertNotIn("ANTHROPIC_API_KEY", env)
            for login in (None, "", "sk-ant-api03-" + "k" * 40, "host"):
                with self.assertRaises(agent.BoundaryError):
                    agent.command(root, session, agent.mcp_command(root / "deployment.json"), mock_url="http://127.0.0.1:12345", login=login)

    @unittest.skipIf(os.name == "nt", "POSIX executable fixture")
    def test_client_version_runs_with_the_clean_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            client = Path(temporary) / "codex"
            client.write_text("#!/bin/sh\necho 'codex-cli 0.163.0'\n")
            client.chmod(0o700)
            self.assertEqual(agent.client_version(str(client), temporary, "codex"), "codex-cli 0.163.0")

    def test_catalog_requires_mcp_and_rejects_any_unexpected_tool(self):
        for client, catalogs, stdout in (("codex", CODEX, ""), ("claude", CLAUDE, claude_init())):
            evidence = agent.catalog_evidence(client, catalogs, stdout)
            self.assertFalse(evidence["host_shell_file_browser_tools_advertised"])
            with self.assertRaises(agent.BoundaryError):
                agent.catalog_evidence(client, [], stdout)
            with self.assertRaises(agent.BoundaryError):
                agent.catalog_evidence(client, [[{"name": "Bash"}]], stdout)
            with self.assertRaises(agent.BoundaryError):
                agent.catalog_evidence(client, [catalogs[0] + [{"name": "exec_command"}]], stdout)

    def test_other_mcp_namespace_is_rejected(self):
        unexpected = [[{"type": "namespace", "name": "mcp__other", "tools": [{"name": "catalog_probe"}]}]]
        with self.assertRaises(agent.BoundaryError):
            agent.catalog_evidence("codex", unexpected, "")

    def test_claude_extra_skills_tools_and_servers_are_rejected(self):
        for changes in ({"skills": ["host-commands"]}, {"tools": ["Bash", "mcp__rea__catalog_probe"]}, {"mcp_servers": []}):
            with self.assertRaises(agent.BoundaryError):
                agent.catalog_evidence("claude", CLAUDE, claude_init(**changes))

    def test_claude_init_is_mandatory(self):
        with self.assertRaises(agent.BoundaryError):
            agent.catalog_evidence("claude", CLAUDE, "")

    def test_localhost_url_cannot_be_replaced_by_external_url(self):
        agent.check_mock_url("http://127.0.0.1:12345")
        for url in ("https://example.com", "http://127.0.0.1:12345@example.com", "http://127.0.0.1:12345/path",
                    "http://localhost:12345", "http://127.0.0.1:12345?next=remote"):
            with self.assertRaises(agent.BoundaryError):
                agent.check_mock_url(url)

    def test_cross_platform_arguments_preserve_spaces_as_one_argument(self):
        deployment = r"C:\REA files\deployment.json"
        argv = agent.mcp_command(deployment)
        self.assertEqual(argv[1], str(agent.CONTAINER))
        self.assertEqual(argv[-1], deployment)
        self.assertEqual(argv[2:4], ["mcp", "--config"])

    def test_native_executable_rejects_windows_shell_wrappers(self):
        with tempfile.TemporaryDirectory() as root:
            wrapper = Path(root) / "claude.cmd"
            wrapper.write_text("unexpected shell wrapper")
            with self.assertRaises(agent.BoundaryError):
                agent.executable_path("claude", str(wrapper))

    def test_generated_profiles_are_explicit_and_no_host_commands_are_mcp(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mcp = agent.mcp_command(root / "deployment.json")
            for client in ("codex", "claude"):
                session = {"client": client, "executable": "/trusted/client"}
                argv, env = agent.command(root, session, mcp, mock_url="http://127.0.0.1:12345", login=agent.OFFLINE_CLAUDE_LOGIN)
                self.assertEqual(argv[0], "/trusted/client")
                self.assertNotIn("--dangerously-skip-permissions", argv)
                self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", argv)
                if client == "claude":
                    self.assertEqual(argv[argv.index("--tools") + 1], "")
                    self.assertEqual(argv[argv.index("--setting-sources") + 1], "")
                    self.assertEqual(argv[argv.index("--permission-mode") + 1], "dontAsk")
                    config = json.loads((root / "mcp.json").read_text())
                    self.assertEqual(set(config["mcpServers"]), {"rea"})
                else:
                    config = (Path(env["CODEX_HOME"]) / "config.toml").read_text()
                    for flag in agent.CODEX_OFF:
                        self.assertIn(flag + " = false", config)
                    self.assertIn('sandbox_mode = "read-only"', config)
                    self.assertIn('wire_api = "responses"', config)

    def test_claude_turn_budget_is_set_by_the_controller_within_a_cap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = {"client": "claude", "executable": "/trusted/client"}
            mcp = agent.mcp_command(root / "deployment.json")
            options = {"mock_url": "http://127.0.0.1:12345", "login": agent.OFFLINE_CLAUDE_LOGIN}
            argv, _ = agent.command(root, session, mcp, **options)
            self.assertEqual(argv[argv.index("--max-turns") + 1], "20")
            argv, _ = agent.command(root, session, mcp, max_turns=50, **options)
            self.assertEqual(argv[argv.index("--max-turns") + 1], "50")
            for turns in (0, agent.MAX_TURNS + 1, "20"):
                with self.subTest(turns=turns), self.assertRaises(agent.BoundaryError):
                    agent.command(root, session, mcp, max_turns=turns, **options)

    def test_prompt_cannot_be_parsed_as_a_client_option(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mcp = agent.mcp_command(root / "deployment.json")
            for client in ("codex", "claude"):
                for prompt in ("--dangerously-skip-permissions", "- analyse the selected file", "--"):
                    argv, _ = agent.command(root, {"client": client, "executable": "/trusted/client"}, mcp, prompt=prompt)
                    self.assertEqual(argv[-2:], ["--", prompt])
                    self.assertEqual(argv[:-1].count("--"), 1)

    def test_modified_binary_deployment_or_helper_invalidates_identity(self):
        with tempfile.TemporaryDirectory() as root:
            binary, deployment = Path(root) / "client", Path(root) / "deployment.json"
            binary.write_text("first")
            deployment.write_text("{}")
            session = {"client": "claude", "version": agent.REVIEWED["claude"], "executable": str(binary), "deployment": str(deployment)}
            first = agent.identity(session)
            binary.write_text("second")
            self.assertNotEqual(agent.identity(session), first)
            first = agent.identity(session)
            deployment.write_text('{"changed": true}')
            self.assertNotEqual(agent.identity(session), first)

    def test_only_explicit_client_tool_errors_prove_dispatch_refusal(self):
        self.assertEqual(agent.refusal_evidence({"input": [
            {"type": "function_call_output", "output": "unsupported call: exec_command"},
            {"type": "function_call_output", "output": "unsupported call: apply_patch"},
        ]}), {"exec_command", "apply_patch"})
        self.assertEqual(agent.refusal_evidence({"messages": [{"role": "user", "content": [
            {"type": "tool_result", "is_error": True, "content": "No such tool available: Bash."},
            {"type": "tool_result", "is_error": True, "content": "No such tool available: Write."},
        ]}]}), {"Bash", "Write"})
        self.assertEqual(agent.refusal_evidence({"messages": [{"content": "No such tool available: Bash"}]}), set())

    def test_failed_verification_removes_old_passing_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "verification.json"
            report.write_text('{"status":"verified-offline-catalog"}')
            args = type("Args", (), {"session": str(root)})()
            with patch.object(agent, "load_session", return_value=(root, {})), \
                    patch.object(agent.http.server, "ThreadingHTTPServer", side_effect=OSError("blocked")):
                with self.assertRaises(agent.BoundaryError):
                    agent.verify(args)
            self.assertFalse(report.exists())

    def test_docker_configuration_contract_requires_explicit_control_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deployment = root / "deployment.json"
            deployment.write_text(json.dumps({"schema": 1, "docker": "/docker", "context": "default", "image_id": "sha256:" + "0" * 64, "input_dir": str(root)}))
            args = type("Args", (), {"output": str(root / "new-session"), "deployment": str(deployment), "client": "claude"})()
            with self.assertRaises(agent.BoundaryError):
                agent.prepare(args)
            self.assertFalse((root / "new-session").exists())



if __name__ == "__main__":
    unittest.main()
