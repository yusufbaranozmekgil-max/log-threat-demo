"""Run rules over a time-ordered event stream."""
from collections import Counter, defaultdict, deque
from collections.abc import Iterable
from dataclasses import replace

from .models import Event, Finding
from .rules import Rule

MAX_EVIDENCE = 5
SWEEP_EVERY = 100_000  # events between evictions of idle keys


def _passes(event: Event, conditions: dict[str, str]) -> bool:
    for name, value in conditions.items():
        if event.get(name) != value:
            return False
    return True


def _evidence(hits: list[Event]) -> tuple[str, ...]:
    """Earliest events plus the one that fired: in a sequence the last line is the proof."""
    kept = hits if len(hits) <= MAX_EVIDENCE else [*hits[:MAX_EVIDENCE - 1], hits[-1]]
    return tuple(e.raw for e in kept)


class Detector:
    """Per-rule state. feed() must receive events in time order."""

    def __init__(self, rule: Rule):
        self.rule = rule
        self.windows: dict[str, deque[Event]] = defaultdict(deque)
        self.values: dict[str, Counter] = defaultdict(Counter)  # distinct rules only
        self.fed = 0
        self.muted_until = {}
        self.open: dict[str, int] = {}  # key -> index of its latest finding
        self.findings: list[Finding] = []
        self.check = getattr(self, f"_check_{rule.type}")

    def feed(self, event: Event) -> None:
        self.fed += 1
        if self.fed % SWEEP_EVERY == 0:
            self._sweep(event)
        rule = self.rule
        key = event.get(rule.group_by)
        if event.source != rule.source or key is None:
            return
        if key in self.muted_until and event.timestamp < self.muted_until[key]:
            if self._relevant(event):
                self._extend(key, event)
            return
        hits = self.check(event, key)
        if hits is None:
            return
        self.muted_until[key] = event.timestamp + rule.window
        self.windows.pop(key, None)
        self.values.pop(key, None)
        self.open[key] = len(self.findings)
        self.findings.append(Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            attack=rule.attack,
            key=key,
            first_seen=hits[0].timestamp,
            last_seen=hits[-1].timestamp,
            evidence=_evidence(hits),
        ))

    def _relevant(self, event: Event) -> bool:
        if self.rule.type == "sequence":
            return _passes(event, self.rule.filter) or _passes(event, self.rule.then)
        return self._check_match(event, "") is not None

    def _extend(self, key: str, event: Event) -> None:
        index = self.open[key]
        finding = self.findings[index]
        self.findings[index] = replace(
            finding,
            last_seen=max(finding.last_seen, event.timestamp),
            suppressed=finding.suppressed + 1,
        )

    def _prune(self, key: str, event: Event) -> deque[Event]:
        window = self.windows[key]
        cutoff = event.timestamp - self.rule.window
        while window and window[0].timestamp < cutoff:
            self._count(key, window.popleft(), -1)
        return window

    def _count(self, key: str, event: Event, change: int) -> None:
        if self.rule.distinct_on is None:
            return
        value = event.get(self.rule.distinct_on)
        if value is None:
            return
        self.values[key][value] += change
        if self.values[key][value] <= 0:
            del self.values[key][value]

    def _sweep(self, event: Event) -> None:
        """Forget keys with nothing left in their window, so unique attacker keys cannot grow state forever."""
        for key in list(self.windows):
            if not self._prune(key, event):
                del self.windows[key]
                self.values.pop(key, None)
        for key in [k for k, until in self.muted_until.items() if event.timestamp >= until]:
            del self.muted_until[key]
            del self.open[key]

    def _push(self, key: str, event: Event) -> deque[Event]:
        self.windows[key].append(event)
        self._count(key, event, 1)
        return self._prune(key, event)

    def _check_match(self, event: Event, key: str) -> list[Event] | None:
        rule = self.rule
        if not _passes(event, rule.filter):
            return None
        for name, pattern in rule.pattern.items():
            if not pattern.search(event.get(name) or ""):
                return None
        return [event]

    def _check_threshold(self, event: Event, key: str) -> list[Event] | None:
        if not _passes(event, self.rule.filter):
            return None
        window = self._push(key, event)
        return list(window) if len(window) >= self.rule.count else None

    def _check_distinct(self, event: Event, key: str) -> list[Event] | None:
        if not _passes(event, self.rule.filter):
            return None
        window = self._push(key, event)
        return list(window) if len(self.values[key]) >= self.rule.count else None

    def _check_sequence(self, event: Event, key: str) -> list[Event] | None:
        if _passes(event, self.rule.filter):
            self._push(key, event)
            return None
        if not _passes(event, self.rule.then):
            return None
        window = self._prune(key, event)
        return [*window, event] if len(window) >= self.rule.count else None


def scan(events: Iterable[Event], rules: list[Rule]) -> list[Finding]:
    detectors = [Detector(rule) for rule in rules]
    by_source: dict[str, list[Detector]] = {}
    for detector in detectors:
        by_source.setdefault(detector.rule.source, []).append(detector)
    for event in events:
        for detector in by_source.get(event.source, ()):
            detector.feed(event)
    return sorted((f for d in detectors for f in d.findings), key=lambda f: f.first_seen)
