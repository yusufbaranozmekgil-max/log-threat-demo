"""Turn raw log lines into Events. Log content is untrusted input."""
import heapq
import ipaddress
import re
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, tzinfo
from functools import lru_cache
from itertools import count
from pathlib import Path
from urllib.parse import unquote_plus

from .models import Event, ParseStats

MAX_LINE = 65536  # room for 8 KB each of URL, referer and user agent, so padding cannot drop a line
MAX_REPEAT = 1000
# Web servers stamp a request when it starts but log it when it ends, so files drift out of order.
REORDER_SLACK = timedelta(minutes=2)
REORDER_LIMIT = 200_000  # events, so a flood within the slack cannot exhaust memory
URL_DECODE_ROUNDS = 3
MIN_YEAR, MAX_YEAR = 1970, 2200  # outside this a timestamp is forged, and date arithmetic could overflow

SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+) "
    r"\S+ (?P<proc>[\w./-]+)(?:\[\d+\])?: (?P<msg>.*)$"
)
# Greedy user + anchored tail: the real IP is always the last "from".
# A username containing " from 9.9.9.9 port 22" cannot spoof the source.
SSH_MESSAGES = (
    ("login_failed", re.compile(r"^Failed \S+ for (?:invalid user )?(?P<user>.*) from (?P<ip>\S+) port \d+(?: ssh2)?$")),
    ("login_success", re.compile(r"^Accepted \S+ for (?P<user>.*) from (?P<ip>\S+) port \d+(?: ssh2)?(?:: .*)?$")),
    # Key-only servers log this but never "Failed password", so probing would otherwise be invisible.
    ("invalid_user", re.compile(r"^Invalid user (?P<user>.*) from (?P<ip>\S+)(?: port \d+)?$")),
)

REPEATED = re.compile(r"^message repeated (?P<n>\d+) times: \[ ?(?P<msg>.*?) ?\]$")

_QUOTED = r'"((?:[^"\\]|\\.)*)"'  # linear: no nested quantifier to backtrack on
WEB = re.compile(
    rf'^(?P<ip>\S+) \S+ (?P<user>.*?) \[(?P<ts>[^\]]+)\] {_QUOTED} (?P<status>\d{{3}}) \S+ {_QUOTED} {_QUOTED}$'
)


@lru_cache(maxsize=65536)  # busy logs repeat a few addresses; bounded so unique IPs cannot grow it
def _ip(text: str) -> str:
    return str(ipaddress.ip_address(text))


def _plausible(ts: datetime) -> datetime:
    if not MIN_YEAR <= ts.year <= MAX_YEAR:
        raise ValueError("implausible timestamp")
    return ts


def _syslog_time(text: str, year: int, tz: tzinfo) -> datetime:
    if text[0].isdigit():
        ts = datetime.fromisoformat(text)
        return _plausible(ts if ts.tzinfo else ts.replace(tzinfo=tz))
    # ponytail: one year for the whole file, a log spanning New Year needs splitting
    return datetime.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S").replace(tzinfo=tz)


def _parse_syslog(m: re.Match, line: str, year: int, tz: tzinfo) -> Event | None:
    ts = _syslog_time(m["ts"], year, tz)
    if m["proc"] not in ("sshd", "sshd-session"):
        return None
    text, repeat = m["msg"], 1
    repeated = REPEATED.match(text)
    if repeated:
        text, repeat = repeated["msg"], min(int(repeated["n"]), MAX_REPEAT)
    for action, pattern in SSH_MESSAGES:
        msg = pattern.match(text)
        if msg:
            return Event(ts, "ssh", action, line, src_ip=_ip(msg["ip"]), user=msg["user"], repeat=repeat)
    return None


@lru_cache(maxsize=4096)  # strptime is the slowest step and busy logs repeat each second
def _web_time(text: str) -> datetime:
    return _plausible(datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z"))


def _decode(target: str) -> str:
    """Undo layered URL encoding so %25252e cannot hide a pattern."""
    for _ in range(URL_DECODE_ROUNDS):
        decoded = unquote_plus(target)
        if decoded == target:
            break
        target = decoded
    return target


def _split_request(request: str) -> tuple[str, str]:
    tokens = request.split()
    if len(tokens) < 2:
        return "", ""
    end = -1 if len(tokens) > 2 and tokens[-1].startswith("HTTP/") else len(tokens)
    return tokens[0], " ".join(tokens[1:end])


def _parse_web(m: re.Match, line: str) -> Event:
    ts = _web_time(m["ts"])
    ip = _ip(m["ip"])
    request, agent = m.group(4), m.group(7)  # 6 is the referer
    method, target = _split_request(request)
    fields = {
        "method": method,
        "target": target,
        "target_decoded": _decode(target),
        "status": m["status"],
        "user_agent": agent,
    }
    user = None if m["user"] == "-" else m["user"]
    return Event(ts, "web", "http_request", line, src_ip=ip, user=user, fields=fields)


def parse_line(line: str, year: int, tz: tzinfo) -> Event | None:
    """Return an Event, None for a valid but irrelevant line; raise ValueError if malformed."""
    if len(line) > MAX_LINE:
        raise ValueError("line too long")
    m = SYSLOG.match(line)
    if m:
        return _parse_syslog(m, line, year, tz)
    m = WEB.match(line)
    if m:
        return _parse_web(m, line)
    raise ValueError("unrecognised line")


def parse_lines(lines: Iterable[str], year: int, tz: tzinfo, stats: ParseStats) -> Iterator[Event]:
    for line in lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        stats.lines += 1
        try:
            event = parse_line(line, year, tz)
        except ValueError:
            stats.malformed += 1
            continue
        if event is None:
            stats.ignored += 1
            continue
        stats.events += event.repeat
        for _ in range(event.repeat):
            yield event


def reorder(
    events: Iterable[Event],
    stats: ParseStats,
    slack: timedelta = REORDER_SLACK,
    limit: int = REORDER_LIMIT,
) -> Iterator[Event]:
    """Fix local disorder with a heap holding at most `slack` of events, and never more than `limit`."""
    heap: list[tuple[datetime, int, Event]] = []
    order = count()  # tie-break, Events are not comparable
    newest = released = None
    for event in events:
        if released is not None and event.timestamp < released:
            stats.late += 1
        newest = event.timestamp if newest is None else max(newest, event.timestamp)
        heapq.heappush(heap, (event.timestamp, next(order), event))
        while heap and (heap[0][0] < newest - slack or len(heap) > limit):
            released = heap[0][0]
            yield heapq.heappop(heap)[2]
    while heap:
        yield heapq.heappop(heap)[2]


def parse_file(path: str | Path, year: int, tz: tzinfo, stats: ParseStats) -> Iterator[Event]:
    # newline="\n": a bare CR inside a field must not start a forged line.
    with open(path, encoding="utf-8", errors="replace", newline="\n") as lines:
        yield from reorder(parse_lines(lines, year, tz, stats), stats)


def merge_events(streams: Iterable[Iterable[Event]]) -> Iterator[Event]:
    """Merge per-file streams by time without loading them. parse_file has already ordered each one."""
    return heapq.merge(*streams, key=lambda e: e.timestamp)
