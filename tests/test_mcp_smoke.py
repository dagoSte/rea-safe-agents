"""Exercise MCP framing and cleanup using inert local Python fixtures only."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "skills/rea-isolated/scripts/mcp_smoke.py"
spec = importlib.util.spec_from_file_location("mcp_smoke", SCRIPT)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

BASE = '''import json,sys,time,signal
for line in sys.stdin.buffer:
 request=json.loads(line)
 if request.get("method")=="initialize":
  result={"serverInfo":{"name":"inert-fixture","version":"1.0"}}
 elif request.get("method")=="tools/list":
  result={"tools":[{"name":"inert_probe","description":DESCRIPTION}]}
 else:continue
 sys.stdout.buffer.write((json.dumps({"jsonrpc":"2.0","id":request["id"],"result":result},ensure_ascii=False)+"\\n").encode("utf-8"));sys.stdout.buffer.flush()
'''


class McpSmokeTests(unittest.TestCase):
    def fixture(self, source):
        process = subprocess.Popen([sys.executable, "-u", "-c", source], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, shell=False)
        def cleanup():
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            for stream in (process.stdin, process.stdout):
                if stream and not stream.closed:
                    stream.close()
        self.addCleanup(cleanup)
        return process

    def test_realistic_catalog_larger_than_two_mib_is_accepted(self):
        process = self.fixture(BASE.replace("DESCRIPTION", '"x"*(2*1024*1024+100)'))
        with patch.object(smoke.subprocess, "Popen", return_value=process):
            evidence = smoke.verify("fixture-deployment.json")
        self.assertEqual(evidence["tool_names"], ["inert_probe"])
        self.assertGreater(evidence["largest_message_bytes"], 2 * 1024 * 1024)
        self.assertEqual(process.returncode, 0)

    def test_oversized_response_is_drained_and_primary_error_survives(self):
        process = self.fixture(BASE.replace("DESCRIPTION", '"x"*10000'))
        with patch.object(smoke, "MAX_MESSAGE_BYTES", 256), patch.object(smoke.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(ValueError, "message exceeded the probe limit"):
                smoke.verify("fixture-deployment.json")
        self.assertEqual(process.returncode, 0)

    def test_utf8_budget_counts_bytes_instead_of_characters(self):
        process = self.fixture(BASE.replace("DESCRIPTION", '"\\U0001f512"*60'))
        with patch.object(smoke, "MAX_MESSAGE_BYTES", 256), patch.object(smoke.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(ValueError, "message exceeded the probe limit"):
                smoke.verify("fixture-deployment.json")
        self.assertEqual(process.returncode, 0)

    def test_nonresponsive_server_retains_identified_timeout(self):
        process = self.fixture("import sys\nfor line in sys.stdin.buffer:pass\n")
        with patch.object(smoke, "RESPONSE_TIMEOUT", 0.05), patch.object(smoke.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(RuntimeError, "MCP response 1 timed out"):
                smoke.verify("fixture-deployment.json")
        self.assertEqual(process.returncode, 0)

    @unittest.skipIf(os.name == "nt", "Native Windows console signals need their own runner")
    def test_shutdown_interrupt_does_not_hide_the_primary_timeout(self):
        process = self.fixture('import sys,signal,time\nsignal.signal(signal.SIGINT,lambda *args:sys.exit(0))\nfor line in sys.stdin.buffer:pass\ntime.sleep(20)\n')
        with patch.object(smoke, "RESPONSE_TIMEOUT", 0.1), patch.object(smoke, "SHUTDOWN_TIMEOUT", 0.1), \
                patch.object(smoke.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(RuntimeError, "MCP response 1 timed out; cleanup also failed: MCP required an interrupt"):
                smoke.verify("fixture-deployment.json")
        self.assertEqual(process.returncode, 0)


if __name__ == "__main__":
    unittest.main()
