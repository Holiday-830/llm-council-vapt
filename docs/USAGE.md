# Usage Reference

Full command reference for both ways of running the council. For setup, see
the main [README](../README.md#installation).

---

## Mode 1 — Chat (manual Chairman mode)

No keys needed. Works in claude.ai, the Claude app, or Claude Code.

### Syntax
```
/llm-council [depth] [input] [flags]
```

### Depth (choose one)
| Flag | Long form | Members | Use case |
|---|---|---|---|
| `-q` | `quick` | 3 (Red-teamer, CVSS Auditor, Evidence Auditor) | Fast in-engagement sanity check |
| `-m` | `medium` | 5 (+ Attack Chain Analyst, Remediation Critic) | Findings you intend to report |
| `-f` | `full` | 8 (+ Threat Intel Analyst, False Negative Hunter, Business Impact Translator) | Pre-delivery gate; default for High/Critical |

### Input (choose one)
| Flag | Meaning |
|---|---|
| `-u` | Finding is an uploaded file attached to the message |
| `-p` | Finding content is pasted directly in the message |

### Optional flags
| Flag | Meaning |
|---|---|
| `-vN` | Version number, e.g. `-v2` for the second draft of this finding |
| `-s <tier>` | Severity being validated: `low`, `medium`, `high`, `critical` |

### Examples
```
/llm-council -q -u
```
Quick check, 3 members, on an uploaded file.

```
/llm-council medium validation -p
```
Medium depth, 5 members, on pasted content.

```
/llm-council -f -u -v2 -s high
```
Full council, uploaded file, second version, validating a claimed High severity.

---

## Mode 2 — CLI (parallel cross-vendor mode)

Requires API keys in `.env`. Runs on your machine via Claude Code, fans the
finding out to Claude + ChatGPT + Gemini as real concurrent calls.

### Syntax
```bash
python3 scripts/council_direct.py [required] [optional]
```

### Required flags
| Flag | Meaning |
|---|---|
| `--mode <quick\|medium\|full>` | Depth (same tiers as chat mode) |
| `--finding <path>` | Path to the finding file (`.md`, `.txt`, `.json`, `.csv`, `.yaml`) or raw text |

### Optional flags
| Flag | Default | Meaning |
|---|---|---|
| `--severity <tier>` | — | Severity being validated |
| `--version <N>` | — | Version/draft number |
| `--finding-id <id>` | — | Your own tracking ID for this finding |
| `--engagement <vdp\|pentest>` | `vdp` | Severity-floor context — see below |
| `--findings-dir <path>` | finding's own directory | Directory to scan for related/sibling findings |
| `--project <prefix>` | none | Filename-prefix tag to filter which siblings count as "related" |

### Examples

Quick check, VDP context (default):
```bash
python3 scripts/council_direct.py --mode quick --finding ./finding.md
```

Full council, paid pentest context, with tracking metadata:
```bash
python3 scripts/council_direct.py \
    --mode full \
    --finding ./finding.md \
    --severity high \
    --version 2 \
    --finding-id FINDING-001 \
    --engagement pentest > council_run.json
```

Medium depth, checking against sibling findings in a specific folder:
```bash
python3 scripts/council_direct.py \
    --mode medium \
    --finding ./finding.md \
    --findings-dir ~/engagements/client-x/findings \
    --project client-x > council_run.json
```

### After running
The script prints JSON (per-member assessments, blind rankings, aggregate,
any failures) to stdout. Redirect it to a file, then ask Claude Code to read
that JSON and perform **Stage 3 (Chairman synthesis)** to get the final verdict.

---

## `--engagement` explained

Controls the severity floor the council applies:

- **`vdp`** (default) — bug-bounty/VDP context. Vendor-accepted-by-design
  behavior or third-party infrastructure may land as Informational/Low even
  with a working PoC, unless real impact to the in-scope target is shown.
- **`pentest`** — paid penetration test context. Severity floors are higher;
  a confirmed issue with a working PoC does not get downgraded to
  Informational just because the component is "vendor-accepted architecture."

Never assumed automatically from the finding content — always explicit via
this flag (CLI) or by stating it in your message (chat mode).

---

## Reading the verdict

Every run ends in this format:

```
VERDICT [<finding-id> | v<N>] → Worth reporting / Needs revision / Not worth reporting
SEVERITY → Confirmed <tier> / Inflated (should be <tier>) / Understated (should be <tier>)
```

Followed by numbered **Fixes before delivery** and a short **Council notes**
summary (agreement, the one real disagreement + which side won, aggregate
ranking). Ask to "show the work" if you want every member's full assessment
instead of the condensed summary.

If the Red-teamer flags a false positive, it leads with:
```
⚠ Red-teamer has flagged this as a FALSE POSITIVE.
```
