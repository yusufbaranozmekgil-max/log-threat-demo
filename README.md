# Log Threat Detector

An SSH and web log attack detector, written in Python, running live in your browser through Pyodide.

**[Open the live demo](https://yusufbaranozmekgil-max.github.io/log-threat-demo/)**

Pick a sample log or paste your own, and the detector records it as a seismograph-style trace, marks each finding's time window and maps it to a MITRE ATT&CK technique. Your logs never leave the page: there is no server.

This repository holds the demo page plus the runtime package and rules it executes (`py/`), which are readable here. Tests, benchmarks and history live in a private repository, available on request. `py/SOURCE_REV` names the private revision the package was copied from.

Sample logs are synthetic; attacker addresses come from documentation ranges.

## How it works

Parsers normalise OpenSSH `auth.log` and nginx/Apache combined log lines into one event shape. Twelve YAML rules of four types run as sliding windows over time:

| Type | Fires when | Example | ATT&CK |
|---|---|---|---|
| `match` | one line carries the attack | SQL injection in a URL | T1190 |
| `threshold` | an address repeats inside a window | SSH brute force | T1110.001 |
| `distinct` | an address touches many values | Password spraying | T1110.003 |
| `sequence` | one event follows many others | Login after failures | T1078 |

## Measured results

| Test | Result |
|---|---|
| SecLists SQL injection strings | 165 / 268 (61.6%), 23.9% before tuning |
| SecLists XSS strings | 110 / 110 (100%), 67.3% before tuning |
| SecLists path traversal strings | 589 / 930 (63.3%), 23.3% before tuning |
| Elastic nginx and Apache logs, 61,461 events | 0 findings |
| Loghub OpenSSH log, 646 events | 15 findings |
| Labelled synthetic logs | 13 of 13 attacks found, 1 deliberate false positive |

The rules were tuned against the same SecLists lists, so those rates are an upper estimate.

## Limits

- It detects; it does not block.
- Web logs hold no request bodies, so POST payloads are invisible.
- Slow or widely distributed attacks stay below the thresholds.
- Anyone who can write whole log lines can forge events.

## Updating

`sh sync.sh <path-to-private-repo>` copies the runtime package, rules and samples.

Built by Yusuf Baran Ozmakgil.
