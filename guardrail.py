"""Deterministic local procurement policy and transactional audit store."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import re
import secrets
import sqlite3
import time

RULE_VERSION = "procurement-v1"
ANALYST = "demo-analyst"
SUPERVISOR = "demo-supervisor"
AUDITOR = "demo-auditor"
RECIPIENT = "ops@example.test"
ACTIONS = {"read_request", "export_request", "send_order"}
REQUEST_ID = re.compile(r"PR-[0-9]{4}")
APPROVAL_ID = re.compile(r"[0-9a-f]{32}")

FIXTURES = [
    ("PR-1001", ANALYST, "精密轴承框架采购", "精密轴承", 480, "智能制造事业部", 1, "【仅合成数据】供应商内部评估：供货能力待核实；内部核价为 83,400 元。"),
    ("PR-2002", "other-analyst", "线体控制器采购", "线体控制器", 30, "自动化事业部", 2, "【仅合成数据】供应商内部报价与评估均未审批。"),
]


def request_id_valid(value):
    return isinstance(value, str) and REQUEST_ID.fullmatch(value) is not None


def approval_id_valid(value):
    return isinstance(value, str) and APPROVAL_ID.fullmatch(value) is not None


def utc_stamp(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def is_action(value):
    return isinstance(value, str) and value in ACTIONS


def public_request(row):
    return {k: row[k] for k in ("request_id", "title", "item", "quantity", "department", "file_version")} | {"id": row["request_id"]}


def export_artifact(row):
    # This is an explicit field allowlist. Do not include internal_notes, owner, or any credentials.
    return (
        "DEMO / 合成数据 — 采购摘要（脱敏）\n"
        f"申请单：{row['request_id']}\n"
        f"标题：{row['title']}\n"
        f"物料：{row['item']}\n"
        f"数量：{row['quantity']}\n"
        f"部门：{row['department']}\n"
        f"来源版本：{row['file_version']}\n"
    )


class Guardrail:
    def __init__(self, db_path, approval_ttl=300, clock=time.time):
        if not (1 <= approval_ttl <= 3600):
            raise ValueError("approval TTL must be 1–3600 seconds")
        self.db_path = str(db_path)
        self.approval_ttl = approval_ttl
        self.clock = clock
        with self.transaction() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS requests (
                request_id TEXT PRIMARY KEY, assignee TEXT NOT NULL, title TEXT NOT NULL,
                item TEXT NOT NULL, quantity INTEGER NOT NULL, department TEXT NOT NULL,
                file_version INTEGER NOT NULL, internal_notes TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY, actor TEXT NOT NULL, request_id TEXT NOT NULL REFERENCES requests(request_id),
                recipient TEXT NOT NULL, file_version INTEGER NOT NULL, source_digest TEXT NOT NULL,
                artifact_digest TEXT NOT NULL, rule_version TEXT NOT NULL, status TEXT NOT NULL,
                created_at REAL NOT NULL, expires_at REAL NOT NULL, approver TEXT, decision_at REAL,
                consumed_at REAL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, event TEXT NOT NULL, actor TEXT NOT NULL,
                action TEXT, request_id TEXT, status TEXT NOT NULL, reason TEXT NOT NULL,
                rule_version TEXT NOT NULL, approval_id TEXT, approver TEXT, approval_status TEXT,
                file_version INTEGER, recipient TEXT
            )""")
            db.executemany("INSERT OR IGNORE INTO requests VALUES (?, ?, ?, ?, ?, ?, ?, ?)", FIXTURES)

    @contextmanager
    def transaction(self, write=True):
        conn = sqlite3.connect(self.db_path, timeout=2, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _audit(self, db, event, actor, status, reason, **fields):
        db.execute(
            """INSERT INTO audit (at,event,actor,action,request_id,status,reason,rule_version,approval_id,
            approver,approval_status,file_version,recipient) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (utc_stamp(self.clock()), event, actor, fields.get("action"), fields.get("request_id"), status, reason,
             RULE_VERSION, fields.get("approval_id"), fields.get("approver"), fields.get("approval_status"),
             fields.get("file_version"), fields.get("recipient")),
        )

    def audit_event(self, event, actor, status, reason, **fields):
        with self.transaction() as db:
            self._audit(db, event, actor, status, reason, **fields)

    def list_requests(self, actor):
        with self.transaction(False) as db:
            return [public_request(row) for row in db.execute(
                "SELECT * FROM requests WHERE assignee=? ORDER BY request_id", (actor,)
            )]

    def list_audit(self):
        with self.transaction(False) as db:
            return [dict(row) for row in db.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 100")]

    def _approval_public(self, row):
        data = {k: row[k] for k in ("id", "actor", "request_id", "recipient", "file_version", "rule_version", "status", "approver")}
        data["approval_id"] = row["id"]
        data["action"] = "export_request"
        if row["status"] in {"pending", "approved"} and self.clock() >= row["expires_at"]:
            data["status"] = "expired"
        for field in ("created_at", "expires_at", "decision_at", "consumed_at"):
            data[field] = utc_stamp(row[field]) if row[field] is not None else None
        return data

    def list_approvals(self):
        with self.transaction(False) as db:
            return [self._approval_public(row) for row in db.execute(
                "SELECT * FROM approvals ORDER BY created_at DESC, id DESC LIMIT 100"
            )]

    def _decision(self, db, actor, action, request_id, code, status, reason, data=None, event="action", **fields):
        self._audit(db, event, actor, status, reason, action=action, request_id=request_id, **fields)
        result = {"status": status, "reason": reason}
        if data is not None:
            result["data"] = data
        if "approval_id" in fields and status != "denied":
            result["approval_id"] = fields["approval_id"]
        return code, result

    def _binding(self, row):
        # Bind source bytes (including non-exported fields) and the exact redacted export bytes.
        return (
            row["file_version"],
            digest(json.dumps(dict(row), ensure_ascii=False, sort_keys=True, separators=(",", ":"))),
            digest(export_artifact(row)),
        )

    def decide_approval(self, actor, approval_id, decision):
        with self.transaction() as db:
            fields = {"approval_id": approval_id, "approver": actor}
            if actor != SUPERVISOR:
                return self._decision(db, actor, "export_request", None, 403, "denied", "ROLE_NOT_ALLOWED", event="approval", **fields)
            row = db.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            request_id = row["request_id"] if row else None
            fields |= {"recipient": row["recipient"], "file_version": row["file_version"]} if row else {}
            if row is None:
                return self._decision(db, actor, "export_request", request_id, 404, "denied", "APPROVAL_NOT_FOUND", event="approval", **fields)
            current = self._approval_public(row)["status"]
            if current != "pending":
                return self._decision(db, actor, "export_request", request_id, 409, "denied", "APPROVAL_EXPIRED" if current == "expired" else "APPROVAL_NOT_PENDING", event="approval", approval_status=current, **fields)
            response_state = {"approve": "approved", "reject": "rejected"}[decision]
            db.execute("UPDATE approvals SET status=?, approver=?, decision_at=? WHERE id=?",
                       (response_state, actor, self.clock(), approval_id))
            return self._decision(db, actor, "export_request", request_id, 200, response_state,
                                  f"APPROVAL_{response_state.upper()}", event="approval",
                                  approval_status=response_state, **fields)

    def execute(self, actor, action, request_id, recipient=None, approval_id=None):
        with self.transaction() as db:
            def result(code, status, reason, data=None, **fields):
                return self._decision(db, actor, action, request_id, code, status, reason, data, **fields)
            if actor != ANALYST:
                return result(403, "denied", "ROLE_NOT_ALLOWED")
            if action == "send_order":
                return result(403, "denied", "ORDER_AUTOMATION_FORBIDDEN")
            if action not in {"read_request", "export_request"}:
                return result(400, "denied", "UNKNOWN_ACTION")
            row = db.execute("SELECT * FROM requests WHERE request_id=? AND assignee=?", (request_id, actor)).fetchone()
            if row is None:
                return result(403, "denied", "REQUEST_NOT_ASSIGNED")
            if action == "read_request":
                return result(200, "allowed", "ASSIGNED_REQUEST", public_request(row), file_version=row["file_version"])
            if recipient != RECIPIENT:
                return result(403, "denied", "RECIPIENT_NOT_ALLOWED")
            now = self.clock()
            version, source_hash, artifact_hash = self._binding(row)
            fields = {"file_version": version, "recipient": RECIPIENT}
            if approval_id is None:
                approval_id = secrets.token_hex(16)
                db.execute("""INSERT INTO approvals
                    (id,actor,request_id,recipient,file_version,source_digest,artifact_digest,rule_version,status,created_at,expires_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (approval_id, actor, request_id, recipient, version, source_hash, artifact_hash, RULE_VERSION,
                     "pending", now, now + self.approval_ttl))
                return result(202, "pending", "SUPERVISOR_APPROVAL_REQUIRED",
                              approval_id=approval_id, approval_status="pending", **fields)
            approval = db.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            fields["approval_id"] = approval_id
            if approval is None or (approval["actor"], approval["request_id"], approval["recipient"]) != (actor, request_id, recipient):
                return result(403, "denied", "APPROVAL_BINDING_MISMATCH", **fields)
            state = self._approval_public(approval)["status"]
            fields |= {"approver": approval["approver"], "approval_status": state}
            if state != "approved":
                reason = {
                    "pending": "APPROVAL_NOT_APPROVED", "expired": "APPROVAL_EXPIRED",
                    "rejected": "APPROVAL_REJECTED", "consumed": "APPROVAL_ALREADY_USED",
                }.get(state, "APPROVAL_INVALID_STATE")
                return result(403, "denied", reason, **fields)
            if approval["approver"] != SUPERVISOR or (approval["file_version"], approval["source_digest"],
                    approval["artifact_digest"], approval["rule_version"]) != (version, source_hash, artifact_hash, RULE_VERSION):
                return result(403, "denied", "APPROVAL_VERSION_CHANGED", **fields)
            cursor = db.execute("""UPDATE approvals SET status='consumed', consumed_at=?
                WHERE id=? AND status='approved' AND expires_at>?""", (now, approval_id, now))
            if cursor.rowcount != 1:
                return result(403, "denied", "APPROVAL_NOT_CURRENT", **fields)
            fields["approval_status"] = "consumed"
            data = {"filename": f"{request_id}-redacted-v{version}.txt", "content": export_artifact(row),
                    "artifact_sha256": artifact_hash, "recipient": RECIPIENT, "file_version": version,
                    "request_id": request_id, "delivery": "local_demo_only"}
            return result(200, "allowed", "APPROVED_EXPORT", data, **fields)
