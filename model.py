"""Proposal-only adapters for the synthetic procurement demo.

Offline by default. Optional HTTPS adapters receive a normalized fixture-only
utterance, never the raw prompt, session data, business data, or decision state.
No model can approve or execute an action.
"""
import json
import os
import re
import unicodedata
import urllib.error
import urllib.request

SYNTHETIC_RECIPIENT = "ops@example.test"
FIXTURES = frozenset({"PR-1001", "PR-2002"})
ACTION_WORDS = {
    "read_request": r"读取|查看|查询|查阅|浏览|打开|\b(?:read|view|show|lookup|look\s+up)\b",
    "export_request": r"导出|下载|\b(?:export|download)\b",
    "send_order": r"发单|下单|发送(?:订单|采购单)|提交(?:订单|采购单)|发(?:出|送)采购订单|\b(?:send|submit|place)\s+(?:(?:a|an|the|purchase)\s+){0,3}order\b",
}
PROVIDERS = {
    "glm": ("https://open.bigmodel.cn/api/paas/v4/chat/completions", "GLM_API_KEY", "GLM_MODEL", "glm-5.3"),
    "deepseek": ("https://api.deepseek.com/chat/completions", "DEEPSEEK_API_KEY", "DEEPSEEK_MODEL", "deepseek-flash"),
}
_RECIPIENT_MARKER = re.compile(r"给(?!我(?:导出|下载))|收件人|发送至|发至|\b(?:to|recipient)\b", re.IGNORECASE)
_EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", re.IGNORECASE | re.ASCII)
_ID = re.compile(r"(?<![a-z0-9_-])PR\s*-\s*([0-9]+)(?![a-z0-9-])", re.IGNORECASE)
_NEGATED = re.compile(r"不要|别|不得|禁止|无需|取消|不(?:要|用|能|应|打算|再)?(?:导出|下载|查看|读取|发单|下单|提交订单|发送订单)|\b(?:don't|do not|never|without|not|cancel)\b", re.IGNORECASE)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fixture_proposal(message):
    if not isinstance(message, str) or not message.strip() or len(message) > 500:
        raise ValueError("仅接受 1–500 字的合成采购演示指令")
    msg = unicodedata.normalize("NFKC", message).strip()
    ids = sorted({f"PR-{n}" for n in _ID.findall(msg)})
    if len(ids) != 1 or ids[0] not in FIXTURES:
        raise ValueError("请指定一个演示采购单：PR-1001 或 PR-2002")
    actions = [name for name, pattern in ACTION_WORDS.items() if re.search(pattern, msg, re.IGNORECASE)]
    if len(actions) != 1 or _NEGATED.search(msg):
        raise ValueError("请只描述一个明确、正向的演示动作：读取、导出或发单")
    proposal = {"action": actions[0], "request_id": ids[0]}
    if actions[0] == "export_request":
        emails = _EMAIL.findall(msg)
        if "@" in msg and (len(emails) != 1 or emails[0].lower() != SYNTHETIC_RECIPIENT):
            raise ValueError("演示导出的收件目标仅支持 ops@example.test")
        marker = _RECIPIENT_MARKER.search(msg)
        if marker:
            tail = msg[marker.end():].lstrip(" ：:")
            if not re.match(r"ops@example\.test(?=$|[\s。！？，、；!?;])", tail, re.IGNORECASE):
                raise ValueError("请明确写出唯一的演示收件目标 ops@example.test")
        proposal["recipient"] = SYNTHETIC_RECIPIENT
    return proposal


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("重复 JSON 字段")
        result[key] = value
    return result


def _provider_proposal(provider, expected):
    endpoint, key_env, name_env, default_name = PROVIDERS[provider]
    key = os.environ.get(key_env, "")
    name = os.environ.get(name_env, default_name)
    if not key or not re.fullmatch(r"[\x21-\x7e]{1,512}", key):
        raise ValueError(f"请在服务器环境中配置 {key_env}，或切回离线模式")
    if not re.fullmatch(r"[a-zA-Z0-9._-]{1,80}", name):
        raise ValueError("模型标识格式无效")
    phrase = {
        "read_request": "查看 {id}",
        "export_request": "导出 {id} 给 ops@example.test",
        "send_order": "对 {id} 发单",
    }[expected["action"]].format(id=expected["request_id"])
    payload = {
        "model": name,
        "messages": [
            {"role": "system", "content": (
                "你是虚构采购演示的意图解析器。只返回严格 JSON 对象，键为 action、"
                "request_id，且仅导出时额外包含 recipient。动作值：read_request（查看）、"
                "export_request（导出）、send_order（发单）。保留输入中的采购单和导出收件目标。"
                "不得授权、不得执行，不返回额外键。"
            )},
            {"role": "user", "content": phrase},
        ],
        "stream": False,
        "max_tokens": 160,
        "thinking": {"type": "disabled"},
        "response_format": {"type": "json_object"},
    }
    body = json.dumps(payload, ensure_ascii=False).encode()
    request = urllib.request.Request(endpoint, data=body, method="POST", headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json", "Accept": "application/json"
    })
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=8) as response:
            raw = response.read(65_537)
        if len(raw) > 65_536:
            raise ValueError("response too large")
        choice = json.loads(raw)["choices"][0]
        if choice.get("finish_reason") != "stop":
            raise ValueError("incomplete response")
        content = choice["message"]["content"]
        if not isinstance(content, str) or len(content) > 512:
            raise ValueError("malformed content")
        result = json.loads(content, object_pairs_hook=_unique_object)
        if not isinstance(result, dict) or result != expected:
            raise ValueError("unexpected action proposal")
    except (urllib.error.URLError, OSError, KeyError, IndexError, TypeError, ValueError, AttributeError):
        raise ValueError("模型适配器未返回有效演示提案，未执行任何动作") from None
    return result


def propose(message: str) -> dict:
    """Build an untrusted, effect-free proposal or raise ValueError."""
    provider = os.environ.get("AGENT_MODEL_PROVIDER", "offline").strip().lower()
    if provider not in ("offline", *PROVIDERS):
        raise ValueError("AGENT_MODEL_PROVIDER 仅支持 offline、glm 或 deepseek")
    expected = _fixture_proposal(message)
    return expected if provider == "offline" else _provider_proposal(provider, expected)
