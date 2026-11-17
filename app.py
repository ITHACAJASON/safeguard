"""Loopback-only, dependency-free HTTP endpoint for the local demonstration."""
import argparse
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sqlite3
from urllib.parse import urlsplit

from guardrail import (
    ANALYST, SUPERVISOR, AUDITOR, RECIPIENT, RULE_VERSION, Guardrail,
    approval_id_valid, is_action, request_id_valid,
)

WEB = Path(__file__).resolve().parent / "web"
STATIC = {"/": ("index.html", "text/html;charset=utf-8"),
          "/index.html": ("index.html", "text/html;charset=utf-8"),
          "/app.js": ("app.js", "text/javascript;charset=utf-8"),
          "/styles.css": ("styles.css", "text/css;charset=utf-8"),
          "/style.css": ("style.css", "text/css;charset=utf-8")}
MAX_BODY = 8192

class InputError(Exception):
    pass


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, port, guardrail):
        self.guardrail = guardrail
        super().__init__(("127.0.0.1", port), Handler)


class Handler(BaseHTTPRequestHandler):
    server_version = "GuardrailDemo"
    sys_version = ""
    timeout = 10

    def log_message(self, format, *args):
        # Never emit request paths, body, headers, model text, or credentials.
        return

    @property
    def policy(self):
        return self.server.guardrail

    def _headers(self, code, media, length):
        self.send_response(code)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                         "connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()

    def _json(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._headers(code, "application/json;charset=utf-8", len(body))
        self.wfile.write(body)

    def _deny(self, code, reason):
        self._json(code, {"status": "denied", "reason": reason})

    def _valid_host(self):
        values = self.headers.get_all("Host", [])
        port = self.server.server_address[1]
        return len(values) == 1 and values[0] in {f"127.0.0.1:{port}", f"localhost:{port}"}

    def _origin_allowed(self):
        origins = self.headers.get_all("Origin", [])
        return not origins or (len(origins) == 1 and origins[0] == "http://" + self.headers["Host"])

    def _actor(self):
        headers = self.headers.get_all("Authorization", [])
        if len(headers) != 1 or not headers[0].startswith("Bearer "):
            return None
        token = headers[0][7:].encode("utf-8")
        return next((role for role in (ANALYST, SUPERVISOR, AUDITOR)
                     if compare_digest(token, role.encode("ascii"))), None)

    def _require(self, role):
        actor = self._actor()
        if actor != role:
            reason = "ROLE_NOT_ALLOWED" if actor else "AUTHENTICATION_REQUIRED"
            self.policy.audit_event("access", actor or "anonymous", "denied", reason)
            self._deny(403 if actor else 401, reason)
            return None
        return actor

    def _read_json(self):
        lengths = self.headers.get_all("Content-Length", [])
        if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()
                or len(lengths[0]) > 5 or not 0 < int(lengths[0]) <= MAX_BODY
                or self.headers.get("Transfer-Encoding") is not None
                or self.headers.get_content_type() != "application/json"):
            raise InputError()
        try:
            raw = self.rfile.read(int(lengths[0]))
            if len(raw) != int(lengths[0]):
                raise ValueError()
            payload = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_keys)
        except (ValueError, RecursionError, TimeoutError) as ex:
            raise InputError() from ex
        if not isinstance(payload, dict):
            raise InputError()
        return payload

    def _proposal(self, actor, payload):
        message = payload.get("message")
        if set(payload) != {"message"} or not isinstance(message, str) or not 1 <= len(message.strip()) <= 1000:
            raise InputError()
        try:
            from model import propose
            candidate = propose(message)
            if not isinstance(candidate, dict):
                raise ValueError()
            candidate = {k: candidate[k] for k in ("action", "request_id", "recipient") if k in candidate}
            if (not is_action(candidate.get("action")) or not request_id_valid(candidate.get("request_id"))
                    or ("recipient" in candidate and not isinstance(candidate["recipient"], str))):
                raise ValueError()
            # Proposal preview contains only recognized schema values, never arbitrary model content.
            if candidate["action"] == "export_request" and candidate.get("recipient") != RECIPIENT:
                self.policy.audit_event("proposal", actor, "denied", "INVALID_PROPOSAL_RECIPIENT",
                                        action=candidate["action"], request_id=candidate["request_id"])
                return self._deny(422, "INVALID_PROPOSAL_RECIPIENT")
            if candidate["action"] != "export_request":
                candidate.pop("recipient", None)
        except Exception:
            self.policy.audit_event("proposal", actor, "denied", "PROPOSAL_UNAVAILABLE")
            return self._deny(422, "PROPOSAL_UNAVAILABLE")
        self.policy.audit_event("proposal", actor, "proposed", "PROPOSAL_ONLY",
                                action=candidate["action"], request_id=candidate["request_id"])
        return self._json(200, {"status": "proposed", "reason": "PROPOSAL_ONLY", "proposal": candidate, "data": candidate})

    def _direct_action(self, actor, payload):
        action = payload.get("action")
        request_id = payload.get("request_id")
        recipient = payload.get("recipient")
        approval_id = payload.get("approval_id")
        if (not is_action(action) or not request_id_valid(request_id)
                or set(payload) - {"action", "request_id", "recipient", "approval_id"}
                or (action != "export_request" and set(payload) - {"action", "request_id"})
                or ("recipient" in payload and (not isinstance(recipient, str) or len(recipient) > 160))
                or ("approval_id" in payload and not approval_id_valid(approval_id))):
            raise InputError()
        result = self.policy.execute(actor, action, request_id, recipient, approval_id)
        return self._json(*result)

    def _dispatch(self, method):
        if not self._valid_host() or not self._origin_allowed():
            return self._deny(403, "LOOPBACK_ORIGIN_REQUIRED")
        try:
            parsed = urlsplit(self.path)
        except ValueError:
            return self._deny(400, "INVALID_TARGET")
        path = parsed.path
        if parsed.netloc or parsed.scheme or parsed.query or parsed.fragment:
            return self._deny(400, "INVALID_TARGET")
        if method == "GET" and path in STATIC:
            name, media = STATIC[path]
            try:
                content = (WEB / name).read_bytes()
            except FileNotFoundError:
                return self._deny(404, "STATIC_FILE_NOT_FOUND")
            self._headers(200, media, len(content))
            return self.wfile.write(content)
        if method == "GET" and path == "/api/health":
            return self._json(200, {"status": "ok", "reason": "LOCAL_DEMO", "rule_version": RULE_VERSION})
        routes = {
            ("GET", "/api/requests"): ANALYST, ("GET", "/api/approvals"): SUPERVISOR,
            ("GET", "/api/audit"): AUDITOR, ("POST", "/api/action"): ANALYST,
            ("POST", "/api/propose"): ANALYST,
        }
        approval_id = path.removeprefix("/api/approvals/") if path.startswith("/api/approvals/") else None
        route = routes.get((method, path))
        role = route or (SUPERVISOR if method == "POST" and approval_id_valid(approval_id) else None)
        if not role:
            return self._deny(404, "ROUTE_NOT_FOUND")
        actor = self._require(role)
        if actor is None:
            return
        try:
            if method == "GET":
                if path == "/api/requests":
                    items = self.policy.list_requests(actor)
                elif path == "/api/approvals":
                    items = self.policy.list_approvals()
                else:
                    items = self.policy.list_audit()
                return self._json(200, {"items": items})
            payload = self._read_json()
            if path == "/api/action":
                return self._direct_action(actor, payload)
            if path == "/api/propose":
                return self._proposal(actor, payload)
            if set(payload) != {"decision"} or payload["decision"] not in ("approve", "reject"):
                raise InputError()
            return self._json(*self.policy.decide_approval(actor, approval_id, payload["decision"]))
        except InputError:
            self.policy.audit_event("input", actor, "denied", "INVALID_INPUT")
            return self._deny(400, "INVALID_INPUT")

    def _handle(self, method):
        try:
            self._dispatch(method)
        except sqlite3.Error:
            self._deny(503, "GUARDRAIL_UNAVAILABLE")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8765")))
    parser.add_argument("--db", default=os.getenv("GUARDRAIL_DB", "state/guardrail.sqlite3"))
    parser.add_argument("--approval-ttl", type=int, default=int(os.getenv("APPROVAL_TTL", "300")))
    args = parser.parse_args()
    Path(args.db).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    with AppServer(args.port, Guardrail(Path(args.db).expanduser(), args.approval_ttl)) as server:
        print(f"Local synthetic-only demo: http://127.0.0.1:{server.server_address[1]}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
