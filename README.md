# LLM Council — VAPT Finding Validation

A blind peer-review pipeline that validates a penetration-test finding before it
reaches a client. Independent expert lenses assess the finding, blind-review each
other, and a Chairman synthesizes one vetted verdict — is it worth reporting, and
is the severity calibrated?

Two ways to run it:

| Mode | Where | What happens |
|---|---|---|
| **Manual Chairman** | claude.ai / Claude app chat | One Claude reasons through each lens in isolation, then synthesizes. Zero cost, no keys. |
| **Parallel (cross-vendor)** | Claude Code on your machine | `council_direct.py` fans the lenses across Claude + ChatGPT + Gemini as real concurrent calls. Costs provider tokens. Catches blind spots a single vendor shares. |

This repo is the **source of truth**. Edit here, commit with git. The Claude
Project knowledge base is a read-only mirror — re-upload changed files when they
materially change. Don't two-way sync.

---

## Repo layout

```
llm-council-vapt/
├── README.md                      # this file
├── requirements.txt               # python deps
├── .env.template                  # key names, no values
├── .gitignore                     # ignores .env (keys never committed)
├── skills/
│   └── llm-council/
│       └── SKILL.md               # the skill (8 members, protocols, modes)
├── scripts/
│   └── council_direct.py          # parallel cross-vendor engine
└── docs/
    └── project_system_prompt.md   # paste into Claude Project settings
```

---

## Installation

```bash
# 1. clone / place the repo
git clone <your-repo-url> llm-council-vapt
cd llm-council-vapt

# 2. make the skill discoverable by Claude Code (symlink, so edits stay live)
mkdir -p ~/.claude/skills
ln -s ~/llm-council-vapt/skills/llm-council ~/.claude/skills/llm-council

# 3. keys
cp .env.template .env
nano .env        # paste the three keys, save
```

Edit `.env` and add your Anthropic, OpenAI, and Google API keys.

### Option A — venv (recommended)

Keeps dependencies isolated from your system Python.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Option B — system-wide install

```bash
pip install -r requirements.txt
```

> **Note (Kali / Debian-based systems):** PEP 668 blocks system-wide `pip install` by default. If you hit `externally-managed-environment`, use Option A or force it:
> ```bash
> pip install -r requirements.txt --break-system-packages
> ```

### Verify install

```bash
python scripts/council_direct.py --help
ls -l ~/.claude/skills/llm-council/SKILL.md   # should resolve via the symlink
```

If both run clean, you're set.

## Usage

### In chat (manual Chairman mode)

Just type a command — no keys, no scripts:

```
/llm-council -q -u                 # quick, upload file
/llm-council medium validation -p  # medium, paste content
/llm-council -f -u -v2 -s high     # full, upload, version 2, validate High claim
```

Flags: mode `-q|-m|-f` (or `quick|medium|full validation`), input `-u` (upload) /
`-p` (paste), version `-vN`, severity `-s low|medium|high|critical`.

### On your machine (parallel cross-vendor mode)

```bash
python3 scripts/council_direct.py \
    --mode full \
    --finding ./finding.md \
    --severity high \
    --version 2 \
    --finding-id <YOUR-FINDING-ID> \
    --project <PREFIX> > council_run.json
```

`--finding` accepts a file path or raw text. The script prints JSON
(assessments + blind rankings + aggregate + any failures). Then ask Claude Code
to read `council_run.json` and run the council's Stage 3 (Chairman synthesis)
to produce the final verdict.

---

## Modes → members

```
quick  (-q) → Red-teamer · CVSS Auditor · Evidence Auditor                 (3)
medium (-m) → + Attack Chain Analyst · Remediation Critic                  (5)
full   (-f) → + Threat Intel Analyst · False Negative Hunter ·
              Business Impact Translator                                    (8)
```

Quick = fast in-engagement sanity check. Medium = findings you intend to report.
Full = pre-delivery gate; default for any High/Critical.

---

## Model IDs

Verified against official provider docs (June 2026). **Not evergreen** — update
`MODELS` at the top of `scripts/council_direct.py` when providers ship new
flagships.

| Seat | Provider | Model ID | Key |
|---|---|---|---|
| Claude | Anthropic | `claude-opus-4-8` | `ANTHROPIC_API_KEY` |
| ChatGPT | OpenAI | `gpt-5.5` | `OPENAI_API_KEY` |
| Gemini | Google | `gemini-3.1-pro-preview` | `GEMINI_API_KEY` |

---

## Security notes

- **`.env` is gitignored.** Real keys never get committed. Verify with
  `git status` before your first `git add` — `.env` must not appear.
- Keys are read at runtime from the environment via `python-dotenv`. They are
  never written to logs or the output JSON.
- The council validates report *claims* against the evidence you supply — it does
  not test live endpoints. Ground truth stays with your curl / nmap / Burp work.

---

## Input formats

The script reads **text-based findings** directly: `.md`, `.txt`, `.json`, `.csv`,
`.yaml`, or raw text passed inline. Binary/document formats (`.pdf`, `.docx`,
`.xlsx`, etc.) are **not** supported — the script detects them and exits with a
message telling you to convert to `.md`/`.txt` first. Since findings are authored
in markdown, this is normally a non-issue.

## Related-finding (chain) analysis

In full/medium mode the Attack Chain Analyst can consider sibling findings:

- `--findings-dir <path>` — directory to scan (defaults to the finding file's own
  directory).
- `--project <prefix>` — optional filename-prefix tag to filter which siblings
  count as related. If omitted, all readable text siblings are considered. The tag
  is supplied at runtime; no client names or prefixes are baked into the code.

Keep your real finding files **outside** this repo (anywhere on your machine). Point
`--findings-dir` at that location per run.

---

## Known gaps (tracked, not yet built)

1. **False-positive report template** — a dedicated output template for findings
   the council rejects, separate from the standard verdict format.

---

## Author

Built by [Holiday](https://github.com/Holiday-830)
