"""Human-labelled impact and value-free explanations for per-call review."""
from __future__ import annotations

from collections import Counter

DOMAINS = ("employment", "credit", "legal", "benefits", "contract", "service_access")
REASONS = {"scope_confirmed": "요청 범위·정책 근거 확인", "request_inappropriate": "요청 부적합",
           "approval_withdrawn": "승인 판단 변경"}


def normalize(item: dict) -> dict:
    flag = item.get("high_impact", False)
    domains = item.get("impact_domains") or []
    if not isinstance(flag, bool) or not isinstance(domains, list) or any(d not in DOMAINS for d in domains):
        raise ValueError("중대 영향 여부와 영향 영역이 올바르지 않습니다.")
    if bool(domains) != flag:
        raise ValueError("중대 영향 도구에는 영향 영역이 필요합니다.")
    return {"high_impact": flag, "impact_domains": sorted(set(domains))}


def terms(item: dict) -> dict:
    return {k: v for k, v in item.items() if k not in ("reviewed_by", "reviewed_at")}


def explanation(approval_id: str, arguments: dict, item: dict, verdict: dict, data_class: str, action: str,
                server_id: str = "", tool: str = "") -> dict:
    # Even keys, summaries and reviewer prose can contain personal data. Export only fixed categories.
    counts = Counter()
    def count(value):
        kind = ("null" if value is None else "boolean" if isinstance(value, bool) else
                "object" if isinstance(value, dict) else "array" if isinstance(value, list) else
                "string" if isinstance(value, str) else "number")
        counts[kind] += 1
        for child in value.values() if isinstance(value, dict) else value if isinstance(value, list) else ():
            count(child)
    count(arguments)
    return {"approval_id": approval_id, "summary": "중대 영향 도구 호출", **normalize(item),
            "server_id": server_id, "tool": tool,
            "arguments": dict(sorted(counts.items())), "data_class": data_class, "action": action,
            "policy_id": "P-HIGH-IMPACT-001", "basis_policy_id": verdict["policy_id"],
            "basis_decision": verdict["decision"], "policy_version": verdict.get("policy_version", "unknown"),
            "effect_reversal": False}


# A period approval is a budget, not a blank cheque: past this many dispatches it needs a new approval.
WINDOW_MAX_USES = 50


def window(approval: dict | None) -> bool:
    """A period approval (10 or 30 minutes): the requester's calls to that tool, any arguments, for the reasons
    the approver saw. A one-use approval stays bound to the exact request, as before."""
    return bool(approval and approval.get("window_minutes"))


def live(approval: dict | None, now) -> bool:
    if not approval or approval.get("status") != "APPROVED" or approval.get("revoked_at"):
        return False
    if window(approval) and (approval.get("uses") or 0) >= WINDOW_MAX_USES:
        return False
    if approval.get("valid_until") and not window(approval) and approval.get("uses"):
        return False  # a one-use approval is spent by its dispatch
    return (approval.get("valid_until") or approval["expires_at"]) > now


def bound(approval: dict | None, payload: dict, item: dict, digest) -> bool:
    if not approval or approval.get("status") != "APPROVED" or not approval.get("reviewed_by") or approval.get("revoked_at"):
        return False
    stored = approval.get("request_payload") or {}
    if window(approval) and "P-HIGH-IMPACT-001" not in (stored.get("covered_policy_ids") or []):
        return False
    keys = ("server_id", "tool", "user_token") if window(approval) else ("server_id", "tool", "arguments", "user_token")
    return (approval.get("request_fingerprint") == digest(stored)
            and stored.get("impact_scope_sha256") == digest(terms(item))
            and all(stored.get(k) == payload.get(k) for k in keys)
            and bool(approval.get("explanation")))
