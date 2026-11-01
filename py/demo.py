"""Bridge between the page and the unchanged logdetect package."""
import json
from datetime import timezone

from logdetect.engine import scan
from logdetect.models import ParseStats
from logdetect.parsers import parse_lines, reorder
from logdetect.reports import sort_findings
from logdetect.rules import load_rules

RULES = load_rules("/demo/rules")
BUCKETS = 360
MAX_EVIDENCE_CHARS = 600


def run(text: str, year: int) -> str:
    stats = ParseStats()
    events = list(reorder(parse_lines(text.splitlines(), year, timezone.utc, stats), stats))
    findings = sort_findings(scan(iter(events), RULES))
    result = {
        "stats": vars(stats),
        "rules": len(RULES),
        "findings": [
            {
                "rule": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "attack": f.attack,
                "key": f.key,
                "first": f.first_seen.timestamp(),
                "last": f.last_seen.timestamp(),
                "suppressed": f.suppressed,
                "evidence": [line[:MAX_EVIDENCE_CHARS] for line in f.evidence],
            }
            for f in findings
        ],
        "trace": None,
    }
    if events:
        start = min(e.timestamp for e in events).timestamp()
        end = max(e.timestamp for e in events).timestamp()
        span = max(end - start, 1.0)
        counts = [0] * BUCKETS
        for e in events:
            counts[min(int((e.timestamp.timestamp() - start) / span * BUCKETS), BUCKETS - 1)] += 1
        result["trace"] = {"start": start, "end": end, "counts": counts}
    return json.dumps(result)
