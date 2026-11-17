"""Defensive unit checks on disposable local state and simulated faults."""
from pathlib import Path
import sqlite3
import tempfile
import unittest

from guardrail import ANALYST, RECIPIENT, SUPERVISOR, Guardrail


class PolicyInvariantTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.path = Path(d.name) / "policy.sqlite3"
        self.now = 1000
        self.policy = Guardrail(self.path, approval_ttl=10, clock=lambda: self.now)

    def approved_export(self):
        status, pending = self.policy.execute(ANALYST, "export_request", "PR-1001", RECIPIENT)
        self.assertEqual(status, 202)
        approval = pending["approval_id"]
        self.assertEqual(self.policy.decide_approval(SUPERVISOR, approval, "approve")[0], 200)
        return approval

    def execute(self, approval):
        return self.policy.execute(ANALYST, "export_request", "PR-1001", RECIPIENT, approval)

    def test_expired_approval_cannot_release_export(self):
        approval = self.approved_export()
        self.now += 10
        self.assertEqual(self.execute(approval)[1]["reason"], "APPROVAL_EXPIRED")

    def test_changed_source_requires_reauthorization(self):
        approval = self.approved_export()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE requests SET quantity=481 WHERE request_id=?", ("PR-1001",))
        self.assertEqual(self.execute(approval)[1]["reason"], "APPROVAL_VERSION_CHANGED")

    def test_audit_failure_rolls_back_export_control(self):
        approval = self.approved_export()
        with sqlite3.connect(self.path) as db:
            db.execute("""CREATE TRIGGER test_audit_store_failure BEFORE INSERT ON audit
                       WHEN NEW.reason='APPROVED_EXPORT'
                       BEGIN SELECT RAISE(ABORT, 'simulated audit outage'); END""")
        with self.assertRaises(sqlite3.Error):
            self.execute(approval)
        with sqlite3.connect(self.path) as db:
            persisted = db.execute("SELECT status FROM approvals WHERE id=?", (approval,)).fetchone()
        self.assertEqual(persisted[0], "approved")
