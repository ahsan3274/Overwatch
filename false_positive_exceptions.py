#!/usr/bin/env python3
"""Structured, auditable exceptions for confirmed Overwatch false positives."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


MODULE_DIR = Path(__file__).resolve().parent
BASE_DIR = Path.home() / "velociraptor-triage"
DEFAULT_RULES_PATH = MODULE_DIR / "false_positive_exceptions.json"
DEFAULT_AUDIT_PATH = BASE_DIR / "false_positive_audit.jsonl"


def _expand(value: object) -> object:
    if isinstance(value, str):
        return value.replace("{home}", str(Path.home()))
    return value


def _parse_timestamp(value: object) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def signing_identity(event: dict) -> tuple[str, str]:
    """Return FileMonitor's computed team and signing identifiers."""
    raw = event.get("raw", {})
    process = raw.get("file", {}).get("process", {})
    if not process:
        process = raw.get("process", {})

    computed = process.get("signing info (computed)", {})
    reported = process.get("signing info (reported)", {})
    team_id = computed.get("teamID") or reported.get("teamID") or ""
    signing_id = (
        computed.get("signatureID")
        or computed.get("signingID")
        or reported.get("signatureID")
        or reported.get("signingID")
        or ""
    )
    return str(team_id), str(signing_id)


def validate_rule(rule: object) -> list[str]:
    """Validate a rule and reject broad identity-free exceptions."""
    if not isinstance(rule, dict):
        return ["rule must be an object"]

    errors = []
    if not rule.get("id"):
        errors.append("id is required")
    if not rule.get("reason"):
        errors.append("reason is required")
    if not rule.get("source"):
        errors.append("source is required")
    if not rule.get("event_types"):
        errors.append("event_types must not be empty")

    process_constraints = (
        "process_exact", "process_prefix", "process_suffix", "process_name"
    )
    destination_constraints = (
        "path_exact", "path_prefix", "path_suffix", "remote_ip", "remote_port"
    )
    if not any(rule.get(key) for key in process_constraints):
        errors.append("at least one process identity constraint is required")
    if not any(rule.get(key) for key in destination_constraints):
        errors.append("at least one destination constraint is required")

    if rule.get("signing_status") == "signed":
        if not rule.get("team_id") or not rule.get("signing_id"):
            errors.append(
                "signed file exceptions require both team_id and signing_id"
            )

    expires_at = rule.get("expires_at")
    if expires_at and _parse_timestamp(expires_at) is None:
        errors.append("expires_at must be an ISO-8601 timestamp")
    return errors


def load_rules(path: Path = DEFAULT_RULES_PATH) -> list[dict]:
    if not path.exists():
        return []
    with open(path) as stream:
        document = json.load(stream)
    if document.get("version") != 1:
        raise ValueError("unsupported false-positive exception file version")

    rules = document.get("exceptions", [])
    errors = []
    for index, rule in enumerate(rules):
        errors.extend(
            f"exceptions[{index}]: {message}"
            for message in validate_rule(rule)
        )
    if errors:
        raise ValueError("; ".join(errors))
    return rules


def _string_match(rule: dict, event: dict, field: str) -> bool:
    value = str(event.get(field, ""))
    exact = _expand(rule.get(f"{field}_exact"))
    prefix = _expand(rule.get(f"{field}_prefix"))
    suffix = _expand(rule.get(f"{field}_suffix"))
    if exact is not None and value != exact:
        return False
    if prefix is not None and not value.startswith(str(prefix)):
        return False
    if suffix is not None and not value.endswith(str(suffix)):
        return False
    return True


def rule_matches(
    rule: dict,
    event: dict,
    now: Optional[datetime] = None,
) -> bool:
    if not rule.get("enabled", True):
        return False

    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    expiry = _parse_timestamp(rule.get("expires_at"))
    if expiry and reference.astimezone(timezone.utc) >= expiry:
        return False

    if event.get("source") != rule.get("source"):
        return False
    if event.get("event_type") not in rule.get("event_types", []):
        return False
    if not _string_match(rule, event, "process"):
        return False
    if not _string_match(rule, event, "path"):
        return False

    process_name = rule.get("process_name")
    if process_name:
        raw_name = (
            event.get("raw", {})
            .get("file", {})
            .get("process", {})
            .get("name", "")
        )
        if raw_name != process_name:
            return False

    signing_status = rule.get("signing_status")
    if signing_status and event.get("signing_status") != signing_status:
        return False

    team_id, signing_id = signing_identity(event)
    if rule.get("team_id") and team_id != rule["team_id"]:
        return False
    if rule.get("signing_id") and signing_id != rule["signing_id"]:
        return False

    network = event.get("network", {})
    if rule.get("remote_ip") and network.get("remote_ip") != rule["remote_ip"]:
        return False
    if rule.get("remote_port") is not None:
        if network.get("remote_port") != rule["remote_port"]:
            return False
    return True


def match_event(
    event: dict,
    rules: Optional[list[dict]] = None,
    now: Optional[datetime] = None,
) -> Optional[dict]:
    candidates = load_rules() if rules is None else rules
    for rule in candidates:
        if rule_matches(rule, event, now=now):
            return rule
    return None


def exception_score(rule: dict) -> dict:
    return {
        "risk_score": 1,
        "risk_level": "LOW",
        "category": "confirmed_false_positive",
        "explanation": rule["reason"],
        "recommended_action": (
            "No alert; retain the original event and exception match for audit."
        ),
        "confidence": 1.0,
        "deterministic_fast_path": True,
        "false_positive_exception": True,
        "exception_rule_id": rule["id"],
        "exception_expires_at": rule.get("expires_at"),
    }


def append_audit(
    event: dict,
    assessment: dict,
    path: Path = DEFAULT_AUDIT_PATH,
) -> None:
    record = {
        "suppressed_at": datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        ),
        "rule_id": assessment["exception_rule_id"],
        "rule_expires_at": assessment.get("exception_expires_at"),
        "event": event,
    }
    with open(path, "a") as stream:
        stream.write(json.dumps(record) + "\n")


if __name__ == "__main__":
    loaded = load_rules()
    print(json.dumps({
        "path": str(DEFAULT_RULES_PATH),
        "valid": True,
        "rules": [
            {
                "id": rule["id"],
                "enabled": rule.get("enabled", True),
                "expires_at": rule.get("expires_at"),
                "reason": rule["reason"],
            }
            for rule in loaded
        ],
    }, indent=2))
