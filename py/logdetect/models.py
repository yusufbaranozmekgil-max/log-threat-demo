"""Data shared by parsers, the rule engine and reporters."""
from dataclasses import dataclass, field
from datetime import datetime

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    source: str  # "ssh" or "web"
    action: str
    raw: str
    src_ip: str | None = None
    user: str | None = None
    fields: dict[str, str] = field(default_factory=dict)
    repeat: int = 1  # syslog "message repeated N times"

    def get(self, name: str) -> str | None:
        if name in ("source", "action", "src_ip", "user"):
            return getattr(self, name)
        return self.fields.get(name)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    attack: str
    key: str
    first_seen: datetime
    last_seen: datetime
    evidence: tuple[str, ...]
    suppressed: int = 0  # related events seen while muted


@dataclass
class ParseStats:
    lines: int = 0
    events: int = 0
    ignored: int = 0
    malformed: int = 0
    late: int = 0  # arrived after the reorder buffer had moved on
