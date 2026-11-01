"""Load and validate detection rules before any log is read."""
import re
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from .models import SEVERITIES

COMMON = {"id", "title", "severity", "attack", "source", "type"}
OPTIONAL = {"filter", "group_by", "window"}
EXTRA = {
    "match": {"pattern"},
    "threshold": {"count"},
    "distinct": {"field", "count"},
    "sequence": {"then", "count"},
}
SOURCES = ("ssh", "web")
WINDOW = re.compile(r"(\d+)([smh])")
UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600}
ATTACK = re.compile(r"T\d{4}(\.\d{3})?")
MATCH_DEDUP_WINDOW = "5m"


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    attack: str
    source: str
    type: str
    window: timedelta
    group_by: str = "src_ip"
    count: int = 1
    filter: dict[str, str] = field(default_factory=dict)
    pattern: dict[str, re.Pattern] = field(default_factory=dict)
    distinct_on: str | None = None
    then: dict[str, str] = field(default_factory=dict)


def _window(value: Any, where: str) -> timedelta:
    m = WINDOW.fullmatch(str(value))
    if not m or int(m[1]) == 0:
        raise RuleError(f"{where}: invalid window {value!r}, use e.g. 30s, 5m, 1h")
    return timedelta(seconds=int(m[1]) * UNIT_SECONDS[m[2]])


def _strings(value: Any, where: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RuleError(f"{where}: expected a mapping, got {value!r}")
    return {str(k): str(v) for k, v in value.items()}


def _patterns(value: Any, where: str) -> dict[str, re.Pattern]:
    try:
        return {k: re.compile(v, re.IGNORECASE | re.DOTALL) for k, v in _strings(value, where).items()}
    except re.error as e:
        raise RuleError(f"{where}: invalid regex: {e}") from e


def _count(value: Any, where: str) -> int:
    if type(value) is not int or value < 1:
        raise RuleError(f"{where}: count must be a positive integer, got {value!r}")
    return value


def _build(raw: Any, origin: str) -> Rule:
    if not isinstance(raw, dict):
        raise RuleError(f"{origin}: a rule must be a mapping")
    where = f"{origin}:{raw.get('id', '?')}"
    kind = raw.get("type")
    if not isinstance(kind, str) or kind not in EXTRA:
        raise RuleError(f"{where}: unknown type {kind!r}")
    required = COMMON | EXTRA[kind] | ({"window"} if kind != "match" else set())
    unknown = raw.keys() - COMMON - OPTIONAL - EXTRA[kind]
    if unknown:
        raise RuleError(f"{where}: unknown keys {sorted(unknown)}")
    missing = required - raw.keys()
    if missing:
        raise RuleError(f"{where}: missing {sorted(missing)}")
    if raw["severity"] not in SEVERITIES:
        raise RuleError(f"{where}: invalid severity {raw['severity']!r}")
    if raw["source"] not in SOURCES:
        raise RuleError(f"{where}: invalid source {raw['source']!r}")
    if not ATTACK.fullmatch(str(raw["attack"])):
        raise RuleError(f"{where}: invalid attack id {raw['attack']!r}")
    return Rule(
        id=str(raw["id"]),
        title=str(raw["title"]),
        severity=raw["severity"],
        attack=raw["attack"],
        source=raw["source"],
        type=kind,
        window=_window(raw.get("window", MATCH_DEDUP_WINDOW), where),
        group_by=str(raw.get("group_by", "src_ip")),
        count=_count(raw["count"], where) if "count" in EXTRA[kind] else 1,
        filter=_strings(raw.get("filter", {}), where),
        pattern=_patterns(raw["pattern"], where) if kind == "match" else {},
        distinct_on=str(raw["field"]) if kind == "distinct" else None,
        then=_strings(raw["then"], where) if kind == "sequence" else {},
    )


def load_rules(directory: str | Path) -> list[Rule]:
    files = sorted(Path(directory).glob("*.yml"))
    if not files:
        raise RuleError(f"no rule files in {directory}")
    rules: dict[str, Rule] = {}
    for path in files:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise RuleError(f"{path.name}: {e}") from e
        if not isinstance(data, list):
            raise RuleError(f"{path.name}: expected a list of rules")
        for raw in data:
            rule = _build(raw, path.name)
            if rule.id in rules:
                raise RuleError(f"{path.name}: duplicate rule id {rule.id!r}")
            rules[rule.id] = rule
    return list(rules.values())
