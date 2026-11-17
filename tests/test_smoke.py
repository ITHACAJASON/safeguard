"""Disposable localhost integration checks for the demo's advertised business policy."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]


class GuardrailRoundTrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.scratch.cleanup)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        cls.base = f"http://127.0.0.1:{port}"
        env = {**os.environ, "AGENT_MODEL_PROVIDER": "offline"}
        cls.proc = subprocess.Popen(
            [sys.executable, "app.py", "--port", str(port), "--db", str(Path(cls.scratch.name) / "demo.sqlite3")],
            cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        cls.addClassCleanup(cls.shutdown)
        for _ in range(80):
            if cls.proc.poll() is not None:
                raise RuntimeError(cls.proc.stderr.read().decode(errors="replace"))
            try:
                if cls.req("/api/health")[0] == 200:
                    break
            except (URLError, TimeoutError):
                time.sleep(0.05)
        else:
            raise RuntimeError("temporary server not ready")

    @classmethod
    def shutdown(cls):
        if cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
                cls.proc.wait()
        cls.proc.stderr.close()

    @classmethod
    def req(cls, path, role=None, body=None):
        headers = {}
        data = None
        if role:
            headers["Authorization"] = "Bearer demo-" + role
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = Request(cls.base + path, headers=headers, data=data)
        try:
            with urlopen(request, timeout=4) as response:
                payload = response.read()
                return response.status, json.loads(payload) if "json" in response.headers.get("Content-Type", "") else payload
        except HTTPError as response:
            with response:
                return response.code, json.loads(response.read())

    @classmethod
    def action(cls, action, request_id="PR-1001", **fields):
        return cls.req("/api/action", "analyst", {"action": action, "request_id": request_id, **fields})

    def test_authentication_and_static_ui(self):
        self.assertEqual(self.req("/")[0], 200)
        self.assertEqual(self.req("/api/requests")[0], 401)
        self.assertIn(self.req("/api/audit", "analyst")[0], {401, 403})
        self.assertIn(self.req("/api/approvals", "analyst")[0], {401, 403})

    def test_business_action_round_trip(self):
        code, assigned = self.req("/api/requests", "analyst")
        self.assertEqual(code, 200)
        self.assertIn("PR-1001", json.dumps(assigned))
        self.assertNotIn("PR-2002", json.dumps(assigned))
        self.assertEqual(self.action("read_request")[1]["status"], "allowed")
        self.assertEqual(self.action("read_request", "PR-2002")[1]["status"], "denied")
        self.assertEqual(self.action("send_order")[1]["status"], "denied")

    def test_bound_approval_one_execution(self):
        destination = "ops@example.test"
        code, response = self.action("export_request", recipient=destination)
        self.assertEqual((code, response["status"]), (202, "pending"))
        approval = response["approval_id"]
        path = "/api/approvals/" + approval
        self.assertNotEqual(self.action("export_request", recipient=destination, approval_id=approval)[1]["status"], "allowed")
        self.assertIn(self.req(path, "analyst", {"decision": "approve"})[0], {401, 403})
        self.assertLess(self.req(path, "supervisor", {"decision": "approve"})[0], 300)
        self.assertNotEqual(self.action("export_request", recipient="other@example.test", approval_id=approval)[1]["status"], "allowed")

        def execute():
            return self.action("export_request", recipient=destination, approval_id=approval)[1]["status"]

        with ThreadPoolExecutor(max_workers=4) as workers:
            results = list(workers.map(lambda _: execute(), range(4)))
        self.assertEqual(results.count("allowed"), 1, results)
        _, audit = self.req("/api/audit", "auditor")
        self.assertIn(approval, json.dumps(audit))

    def test_declined_approval_cannot_release_export(self):
        destination = "ops@example.test"
        _, response = self.action("export_request", recipient=destination)
        approval = response["approval_id"]
        self.assertLess(self.req("/api/approvals/" + approval, "supervisor", {"decision": "reject"})[0], 300)
        status = self.action("export_request", recipient=destination, approval_id=approval)[1]["status"]
        self.assertNotEqual(status, "allowed")

    def test_offline_proposal_is_only_a_proposal(self):
        code, response = self.req("/api/propose", "analyst", {"message": "读取采购申请 PR-1001"})
        self.assertEqual(code, 200, response)
        proposal = response.get("proposal", response.get("data", response))
        self.assertEqual(proposal.get("action"), "read_request")
        self.assertEqual(proposal.get("request_id"), "PR-1001")
        self.assertNotIn("file_version", json.dumps(response))


if __name__ == "__main__":
    unittest.main()
