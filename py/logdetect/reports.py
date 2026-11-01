"""Render findings. Evidence is attacker-controlled: escape it, and keep it out of the terminal."""
import json
from collections import Counter
from dataclasses import asdict
from html import escape

from .models import SEVERITIES, Finding, ParseStats


def _rank(severity: str) -> int:
    return SEVERITIES.index(severity)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-_rank(f.severity), f.first_seen))


def reaches(findings: list[Finding], severity: str) -> bool:
    return any(_rank(f.severity) >= _rank(severity) for f in findings)


def render_text(findings: list[Finding], stats: ParseStats) -> str:
    out = [
        f"lines: {stats.lines}  events: {stats.events}  "
        f"ignored: {stats.ignored}  malformed: {stats.malformed}  late: {stats.late}",
        f"findings: {len(findings)}",
    ]
    for f in findings:
        out.append(
            f"{f.severity.upper():<8} {f.rule_id:<28} {f.attack:<10} {ascii(f.key)[1:-1]:<16} "
            f"{f.first_seen.isoformat()}"
        )
    return "\n".join(out)


def render_json(findings: list[Finding], stats: ParseStats) -> str:
    return json.dumps(
        {"stats": asdict(stats), "findings": [asdict(f) for f in findings]},
        indent=2,
        default=lambda value: value.isoformat(),
    )


CSS = """
:root {
  color-scheme: light dark;
  --paper: oklch(97% 0.008 95);
  --ink: oklch(25% 0.02 95);
  --muted: oklch(48% 0.02 95);
  --line: oklch(86% 0.012 95);
  --critical: oklch(48% 0.19 28);
  --high: oklch(55% 0.16 50);
  --medium: oklch(52% 0.11 95);
  --low: oklch(50% 0.07 230);
}
@media (prefers-color-scheme: dark) {
  :root {
    --paper: oklch(21% 0.012 95);
    --ink: oklch(91% 0.012 95);
    --muted: oklch(71% 0.015 95);
    --line: oklch(36% 0.012 95);
    --critical: oklch(72% 0.17 28);
    --high: oklch(76% 0.14 55);
    --medium: oklch(82% 0.12 95);
    --low: oklch(76% 0.08 230);
  }
}
body { margin: 0 auto; max-width: 62rem; padding: 2rem 1rem; background: var(--paper);
  color: var(--ink); font: 15px/1.5 ui-monospace, "Cascadia Mono", Consolas, monospace; }
h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
.stats { color: var(--muted); margin: 0 0 2rem; }
article { border-top: 1px solid var(--line); padding: 1rem 0; }
h2 { font-size: 1rem; margin: 0; }
.meta { color: var(--muted); margin: .25rem 0 .75rem; overflow-wrap: anywhere; }
.critical { color: var(--critical); } .high { color: var(--high); }
.medium { color: var(--medium); } .low { color: var(--low); }
pre { margin: 0; overflow-x: auto; color: var(--muted); font: inherit; font-size: .85em; }
"""


def _span(f: Finding) -> str:
    first, last = f.first_seen, f.last_seen
    zone = last.strftime("%z")
    start = first.strftime("%Y-%m-%d %H:%M:%S")
    if first == last:
        return f"{start} {zone}"
    end = last.strftime("%H:%M:%S" if first.date() == last.date() else "%Y-%m-%d %H:%M:%S")
    return f"{start} to {end} {zone}"


def _article(f: Finding) -> str:
    evidence = escape("\n".join(f.evidence))
    more = f" · {f.suppressed} more events" if f.suppressed else ""
    return (
        "<article>"
        f'<h2><span class="{escape(f.severity)}">{escape(f.severity.upper())}</span> '
        f"{escape(f.title)}</h2>"
        f'<p class="meta">{escape(f.rule_id)} · {escape(f.attack)} · {escape(f.key)}<br>'
        f"{_span(f)}{more}</p>"
        f"<pre>{evidence}</pre></article>"
    )


def render_html(findings: list[Finding], stats: ParseStats) -> str:
    counts = Counter(f.severity for f in findings)
    summary = " · ".join(f"{counts[s]} {s}" for s in reversed(SEVERITIES) if counts[s])
    body = "".join(_article(f) for f in findings) or "<p>No findings.</p>"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        """<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">"""
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>Log Threat Report</title><style>{CSS}</style></head><body>"
        f"<h1>Log Threat Report</h1>"
        f'<p class="stats">{escape(summary or "0 findings")}<br>'
        f"{stats.lines} lines · {stats.events} events · "
        f"{stats.ignored} ignored · {stats.malformed} malformed · {stats.late} late</p>"
        f"{body}</body></html>"
    )
