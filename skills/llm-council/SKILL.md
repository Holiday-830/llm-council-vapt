---
name: llm-council
description: Convene a council of independent expert agents to validate a VAPT/pentest finding before it goes in a client report — they assess it blind from different security-review lenses, peer-review each other, then deliver one synthesized verdict on whether it is worth reporting and whether the severity is calibrated. Use whenever the user runs "/llm-council", asks to "validate this finding", "is this worth reporting", "stress-test this finding", "check my severity", "did I overclaim", "review this report before delivery", "convene the council", or wants a finding pressure-tested rather than rubber-stamped. Three depth modes (quick/medium/full) selected by flag. Also supports cross-vendor parallel mode (real Claude/ChatGPT/Gemini via direct provider keys) on hostM via Claude Code on "cross-vendor", "real models", "different providers".
---

# LLM Council — VAPT Finding Validation

A blind peer-review pipeline that validates a penetration-test finding before it reaches a client. Independent expert members assess the finding from different security-review lenses, blind-review each other's assessments, then the main loop (you, as **Chairman**) synthesizes one vetted verdict. The win is independent reasoning judged on merit — no single lens dominates, and weak findings get caught before the client does.

This skill is the validation backbone for the user's `/validate <finding>` workflow. It does **not** replace his technical judgment or the ground-truth evidence (curl output, Burp captures, nmap scans) — it is a senior peer-review layer that catches false positives, score inflation/deflation, overclaiming, missed attack chains, and weak remediation before delivery.

---

## Command syntax

```
/llm-council <mode> <input-source> [version] [severity-override]
```

**Mode** (required) — selects council depth:

| Long form | Shorthand | Members |
|---|---|---|
| `quick validation` | `-q` | 3 — Red-teamer, CVSS Auditor, Evidence Auditor |
| `medium validation` | `-m` | 5 — the 3 above + Attack Chain Analyst, Remediation Critic |
| `full validation` / `full report validation` | `-f` | 8 — all members |

**Input source** (required) — where the finding comes from:

| Flag | Meaning | Behaviour |
|---|---|---|
| `-u` | Upload file | Read the attached file (see Input handling) |
| `-p` | Paste content | Use the finding content pasted in chat |

**Version** (optional) — audit trail across revisions:

| Flag | Meaning |
|---|---|
| `-v1`, `-v2`, `-v3` … | Which revision of the finding is being validated |

**Severity override** (optional) — validate a specific severity claim:

| Flag | Meaning |
|---|---|
| `-s low` / `-s medium` / `-s high` / `-s critical` | Council specifically challenges or confirms that claimed severity |

### Accepted command examples

```
/llm-council quick validation -u          → quick, upload file
/llm-council quick validation -p          → quick, paste content
/llm-council medium validation -u         → medium, upload file
/llm-council full validation -u           → full, upload file
/llm-council -q -u                        → quick, upload (shorthand)
/llm-council -m -p                        → medium, paste (shorthand)
/llm-council -f -u                        → full, upload (shorthand)
/llm-council -f -u -v2 -s high            → full, upload, version 2, validate High claim
/llm-council -q -p -v1 -s medium          → quick, paste, version 1, validate Medium claim
```

Both the long form and the shorthand mean the same thing. Parse whichever the user typed. The `<finding>` string is **omitted by design** — the finding comes from `-u` or `-p`, not from the command line.

---

## Parsing rules

1. **Resolve the mode** from `-q`/`-m`/`-f` or the words `quick`/`medium`/`full`. If no mode is present, ask which depth — do not default silently.
2. **Resolve the input source** from `-u` or `-p`. If neither is present, ask which one.
3. **Resolve version** from `-vN` if present; if absent, treat as v1 and note it in the output stamp.
4. **Resolve severity override** from `-s <level>` if present.
5. Then run Input handling.

---

## Input handling

### `-u` (upload file)

- Check for an attached/uploaded file (look under `/mnt/user-data/uploads/` or the conversation's uploaded-files pointer).
- **Edge case — file flag but no file.** If `-u` was passed but no file is attached, **STOP immediately**. Do not run the council on empty input. Respond:
  > No file attached. You used `-u` but I don't see an uploaded finding. Re-run the command with the file attached, or use `-p` to paste the content instead.
- If a file is found, read it (it is usually a `.md` report in CG-YYYY-MM-DD-NNN format; use the file-reading skill if the type is unclear), then proceed to Stage 1.

### `-p` (paste content)

- If the finding content is already in the same message, use it.
- If not, ask once: "Paste the finding content and I'll run the council." Then proceed when it arrives.
- Do not run on empty paste — same stop rule as above.

---

## The 8 council members

Diversity comes from the **lenses**, not from weaker reasoning — every member reasons at full strength. Each is told its lens is what to *emphasize*, not a character to perform.

| # | Member | What it interrogates |
|---|---|---|
| 1 | **Red-teamer** | Attacks the finding itself. Is it a false positive? Is the premise wrong? Would this survive a hostile client security team's review? What would kill it? |
| 2 | **CVSS Auditor** | Verifies the score reflects **only what was demonstrated**. Recomputes the vector. Flags inflation, deflation, and wrong metric choices (AV/AC/PR/UI/S/C/I/A). Checks the claimed severity tier matches the math. **Also runs the CWE Verification Protocol (see below) against every CWE cited in the report.** |
| 3 | **Evidence Auditor** | Do the reproduction steps actually *prove* the claim? Are curl/nmap outputs conclusive? Does the report honour the line between "capability demonstrated" and "exploitation demonstrated"? Kills overclaiming. |
| 4 | **Attack Chain Analyst** | Does this finding combine with others into a higher-severity kill chain? Is a Medium-in-isolation actually a step toward Critical? Is this a symptom of a deeper root cause reported in isolation? |
| 5 | **Remediation Critic** | Is the fix specific, technically correct, and does it close the **root cause** (not just the symptom)? Does the remediation introduce new risk? Is it actionable by the client as written? |
| 6 | **Threat Intel Analyst** | Is this technique actively exploited in the wild? Which threat actors use it? Adds real-world urgency context (e.g. APT use of Device Code phishing) that a bare CVSS score doesn't convey. |
| 7 | **False Negative Hunter** | The inverse of the Red-teamer. Not "is this finding valid?" but "what related vectors weren't tested that should have been?" Catches coverage gaps before the client's team does. |
| 8 | **Business Impact Translator** | Converts the technical finding into language a CTO/exec feels. Checks whether the report communicates real-world business consequence, not just a number. |

### Mode → members

```
quick  (-q) → Red-teamer · CVSS Auditor · Evidence Auditor
medium (-m) → + Attack Chain Analyst · Remediation Critic
full   (-f) → all 8
```

Quick is for fast in-engagement sanity checks. Medium is for findings you intend to report. Full is the pre-delivery gate, and the default for any High/Critical finding.

---

### CWE Verification Protocol (CVSS Auditor only)

Run this against **every CWE cited in the report**, in order. A CWE that fails Step 2 or Step 3 must be flagged for removal or replacement — it will be challenged in client triage and weakens an otherwise solid finding.

**Step 1 — State the CWE definition precisely.**
Read the CWE's official definition literally. Do not paraphrase from memory. The exact mechanism the CWE describes matters.

**Step 2 — Ask: did the vulnerable system implement the control this CWE says is broken?**
This is the core gate. There is a fundamental difference between:
- A control that exists but is implemented incorrectly → the CWE applies
- A control that was never implemented at all → the CWE does not apply; a different weakness ID is needed

> Example of the failure mode this catches:
> A CWE that describes a control implemented *incorrectly* does not apply when the system never implemented that control at all. For example, a CWE defined as the improper validation of a security check cannot be cited when no such check was ever present — the absence of a control is a different weakness from a broken one, and needs a different CWE.

**Step 3 — Map the CWE to demonstrated behavior only.**
The CWE must map to what was *shown in the reproduction steps*, not to a theoretical worst-case. If the CWE implies a capability that wasn't demonstrated (for example, a CWE that implies a control failed under sustained load when no load test was actually run), flag it as overclaiming.

**Step 4 — Output per CWE.**
For each CWE, return one of:
- `✓ Confirmed` — definition matches demonstrated behavior
- `⚠ Overclaim` — CWE implies more than was demonstrated; move to observation or replace
- `✗ Remove` — control was never present; CWE describes a broken implementation of something that doesn't exist here; state the correct replacement if one exists

Flag any `⚠` or `✗` result in the Fixes section of the council output.

---

### MITRE ATT&CK Verification Protocol (Threat Intel Analyst only)

Run this against **every MITRE ATT&CK technique ID cited in the report**. A wrong technique ID is the same class of error as a wrong CWE — it will be caught immediately by a technical client team and discredits the finding.

**Step 1 — Resolve the cited ID to its official name.** Do not trust the report's label. State what the ID actually maps to in the ATT&CK matrix. (Failure mode this catches: `T1566.004` was cited for Device Code phishing in a real finding — but `T1566.004` is *Spearphishing Voice*. The correct mapping is `T1528` (Steal Application Access Token) / `T1078` (Valid Accounts).)

**Step 2 — Confirm the technique matches the demonstrated behavior**, not a loosely associated tactic. Sub-technique IDs are precise; a near-miss is still wrong.

**Step 3 — Output per technique:** `✓ Confirmed` / `✗ Wrong — should be <ID> (<name>)`. Flag any `✗` in the Fixes section.

---

## Member Operating Rules

Per-member rules that constrain how each lens reasons. These are mandatory for the listed member whenever it is active in the selected mode.

**Red-teamer**
- **Engagement context.** Default the engagement type to **VDP / bug-bounty** unless the finding or user states it is a paid penetration test (or the script is run with `--engagement pentest`). Calibrate the severity floor to the stated context: in a VDP/bug-bounty, vendor-accepted-by-design behavior or third-party infrastructure may be Informational/Low even with a working PoC unless real impact to the in-scope target is shown; in a paid pentest, severity floors are higher and a confirmed issue with a working PoC does not drop to Informational merely because the component is "vendor-accepted architecture." Apply the context given — never assume one that wasn't provided.
- **Partial false positives.** The verdict is not strictly binary. If a finding has one solid vector and one weak/false sub-claim, say so explicitly: confirm the valid part, name the sub-claim to drop. Do not reject the whole finding over one weak sub-claim, and do not pass the whole finding when a sub-claim is unsupported.

**Evidence Auditor**
- **API-level vs end-to-end.** Classify every claim as either *API-level* (the endpoint accepted the request — e.g. a 200 response or a specific error code) or *end-to-end* (the real-world downstream effect actually occurred — the record was written and read back, data was exfiltrated, code executed, a control was confirmed absent). A success response proves acceptance, not the downstream effect. Verify the evidence matches the claim's level. Flag any end-to-end claim backed only by API-level proof as overclaiming.
- **Reproducibility.** Flag reproduction steps that depend on time-bound or deployment-specific values — hashed asset filenames that change on each build, session tokens, one-time URLs, CSRF nonces. These break on redeploy. Recommend a stable alternative (vendor docs, a pattern match) so the finding can be reproduced later.

**Attack Chain Analyst**
- **Look up real engagement findings before theorizing.** In chat mode, use `conversation_search` to find related prior findings in this engagement before reasoning about chains, and reference any related finding by its ID. In script mode (`council_direct.py`), the related findings are loaded from the findings directory (optionally filtered by a user-supplied `--project` prefix tag). If none are available, analyze chains within the single finding and note that cross-finding analysis was unavailable.
- **Stay in scope.** Only propose chains involving systems within the engagement's authorized target list.

**Remediation Critic**
- **Multi-vector completeness.** List every attack vector named in the finding. For each, verify the proposed remediation closes it. Flag any vector left open — do not assume a fix for the primary (CVSS-scored) vector closes the secondary ones.
- **Vendor dependency.** Flag any remediation whose availability depends on the client's third-party plan tier or vendor configuration (e.g. "apply Amplitude origin restrictions" is plan-dependent). Note it may not be actionable on the client's current plan and give a fallback (e.g. backend proxy).

**Threat Intel Analyst**
- **Active vs theoretical.** Classify every threat-intel claim as **Active** (documented real-world exploitation — name the threat actor/campaign/year) or **Theoretical** (works in a lab, no confirmed in-the-wild use). Never assert "actively exploited" without a citable actor or campaign — that is overclaiming at the intel layer.
- Runs the MITRE ATT&CK Verification Protocol above.

**False Negative Hunter**
- **Scope boundary.** Only flag untested vectors within the engagement's authorized scope (listed target hosts, subdomains, systems). Never suggest testing third-party infrastructure, other customer tenants, or systems outside the documented target — that is unauthorized testing, not a coverage gap.

**Business Impact Translator**
- **Proportionality (CVSS-anchored).** Every business-impact statement must map to a demonstrated CVSS dimension. Confidentiality language requires `C:L`+; integrity language requires `I:L`+; availability language requires `A:L`+. If a dimension is `N`, do not assert impact in it regardless of how the finding "feels." Business impact can be overclaimed exactly like technical impact.

---

## Execution

The council runs in one of two modes depending on where the skill is invoked. Detect the environment and pick automatically.

**Mode detection:**
```
IF shell-capable environment (Claude Code on hostM)
   AND scripts/council_direct.py present
   AND .env has the required provider keys
      → PARALLEL MODE
ELSE
      → MANUAL CHAIRMAN MODE
```

**Manual Chairman mode** (default in claude.ai / Claude app chat — no sub-agent spawning here): reason through each active member's lens independently and in isolation — commit to one lens fully before the next, never letting later lenses peek at earlier conclusions — then run Stage 2 and synthesize. This always works and needs no keys. Never tell the user the council "failed" if no keys are present; just run this mode.

**Parallel mode** (Claude Code on hostM, keys in `.env`): invoke `scripts/council_direct.py`, which fans the active members out across the configured providers (Claude, ChatGPT, Gemini) as genuinely independent concurrent API calls, runs the blind Stage-2 ranking, and prints one JSON blob. You then read that JSON and perform Stage 3 (Chairman synthesis) yourself. This is the faithful council — real independence, no shared context between members.

> The member lenses, CWE/MITRE protocols, operating rules, and output format are **identical across both modes**. Only the execution differs.

### Stage 1 — Independent assessments

Give every active member the **same finding** plus its lens. Members never see each other. Each returns a direct assessment: what's strong, what's weak, and a position on whether the finding is reportable as written.

**Universal evidence rule (applies to every member, every mode):** members must not assume, infer, or speculate beyond what the finding demonstrates with reproducible proof. Every claim a member makes must be grounded in evidence present in the finding. If something is not demonstrated, the member says so explicitly and treats it as unproven — it never fills the gap with assumption. This is baked into each member's prompt below.

**Labeling (so findings without IDs still work):** the finding under review is labelled `[Finding-1]`; any related findings supplied for chain analysis are labelled `[Related-A]`, `[Related-B]`, … Members refer to findings by these labels, or by a real ID if one is present in the text. This means a user can paste a raw finding with no ID and the council still references it cleanly.

Member prompt template:

> You are one member of an expert security council validating a security finding independently. Your lens is what you should **emphasize**, not a character to perform — give your genuine best assessment.
>
> **Engagement context:** {vdp by default, or pentest — calibrate the severity floor to this; never assume a context that wasn't provided}
>
> **Strict evidence rule:** do not assume, infer, or speculate beyond what the finding demonstrates with reproducible proof. Ground every claim in the evidence present. If something is not demonstrated, say so explicitly and treat it as unproven.
>
> **Your lens:** {lens}
>
> {if severity-override present:} **The author/researcher claims this is {severity}. Specifically challenge or confirm that claim.**
>
> {if related findings present:} **Related findings (chain analysis only — do not re-validate), labelled [Related-A], [Related-B], …:** {related}
>
> **[Finding-1]:**
> {finding}
>
> Assess directly: what is strong, what is weak, and whether this is worth reporting as written. State your key assumption and the strongest objection to your own position. Be specific and concise — no preamble, no hedging.
>
> Assess directly: what is strong, what is weak, and whether this is worth reporting as written. State your key assumption and the strongest objection to your own position. Be specific and concise — no preamble, no hedging.
>
> End your assessment with this exact 3-line block so the Chairman can compare members at a glance:
> ```
> VERDICT: Valid / Valid-with-fixes / Needs revision / Invalid
> CONFIDENCE: High / Medium / Low
> KEY ISSUE: <one line — the single most important thing the Chairman must act on>
> ```

### Stage 2 — Blind peer review + ranking

Label the Stage-1 assessments `Response A`, `Response B`, … with **all identity stripped** (no lens names). Keep a private map of label → member. Each reviewer sees all anonymized assessments, evaluates them on **accuracy and insight only**, and returns a ranking best-to-worst in this exact block:

```
FINAL RANKING:
1. Response C
2. Response A
...
```

Aggregate by average position (lower = better).

### Stage 3 — Chairman synthesis (you)

Hold all assessments and reviews. Do **not** just pick the #1, and do **not** drift back toward the severity the author originally implied. Synthesize on merit and consensus:

- Build the verdict from the strongest reasoning across all members; graft good points even from low-ranked assessments.
- Where the council genuinely splits (e.g. Medium vs High), **say so and take a position** — don't average it into mush.
- If the Red-teamer or anyone shows the finding's premise is wrong, **that leads**.

---

## Output format

Lead with the verdict. Keep it tight. Stamp the finding ID and version.

```
VERDICT [<finding-id> | v<N>] → Worth reporting / Needs revision / Not worth reporting
SEVERITY → Confirmed <tier> / Inflated (should be <tier>) / Understated (should be <tier>)
```

Then:

1. **Fixes required before delivery** — numbered, specific, actionable (e.g. "a cited CWE claims an impact the evidence doesn't demonstrate — downgrade it or move it to an observation"). If none, say "None — clean for delivery."
2. **Council notes** — 3–5 lines: where they agreed, the one real disagreement (and which side you took, why), the aggregate ranking, anything you overrode and why.

Do **not** dump every member's full assessment by default. If the user says "show me each member" / "show the work," print the per-member assessments and full reviews then.

### False-positive output

If the Red-teamer (or council consensus) flags the finding as a false positive, lead the output with:

```
⚠ Red-teamer has flagged this as a FALSE POSITIVE.
```

…then give the reasoning and what evidence would be needed to overturn it.

> **TODO (reminder for the user):** a dedicated, fuller false-positive report template still needs to be built — distinct from the standard verdict format. Remind him to design it.

---

## Version tracking

The `-vN` flag stamps the verdict (`VERDICT [<finding-id> | v2]`) so re-runs after revision form a clean audit trail. When validating `v2+`, if the prior version's issues are known (in this conversation or via the past-chats tools), briefly note which earlier fixes were resolved and which remain. Absent a `-vN`, treat as v1.

---

## Severity override

With `-s <level>`, the CVSS Auditor and Red-teamer specifically test that claim — confirming or rejecting it against demonstrated impact — rather than scoring from scratch. Use it for "client thinks this is High, is it?" debates. The verdict's SEVERITY line must explicitly address the claimed level. Without `-s`, the council scores independently.

---

## Cross-vendor mode (faithful council via direct provider keys)

This is **parallel mode** (see Execution) and runs only on hostM via Claude Code with `scripts/council_direct.py` and provider keys in `.env`. It sends the finding to three vendors — **Claude, ChatGPT, Gemini** — as genuinely independent calls and **costs real money per run** (provider-billed, varies by token volume). Never silently upgrade the chat default into it. The value is catching **correlated blind spots**: things every Claude lens gets wrong the same way. Stage 3 (your synthesis) is unchanged.

`scripts/council_direct.py` loads keys from `.env`, fans the active members across the three providers as concurrent calls for independent Stage-1 assessments, sends each provider all anonymized assessments for the Stage-2 blind ranking, and prints one JSON blob (de-anonymized answers, reviews, aggregate ranking).

```
python3 scripts/council_direct.py --mode <quick|medium|full> --finding <path-or-text>
```

Providers (resolved to current production model IDs at build time — verify before relying):

| Seat | Provider | Key in `.env` |
|---|---|---|
| Claude | Anthropic | `ANTHROPIC_API_KEY` |
| ChatGPT | OpenAI | `OPENAI_API_KEY` |
| Gemini | Google | `GEMINI_API_KEY` |

Handling the output:
- `error` field → relay it. Most common is a missing/invalid key: tell the user which key to set in the project `.env`, then re-run.
- `failures[]` non-empty → a provider call failed (retired model ID, quota, network). Note which seat dropped; if ≥2 of 3 still answered, the council is valid. Fix by updating the model ID in the script config.
- In the council note, name the **models** and call out where vendors **diverged** — that divergence is the whole point of paying for this mode.

---

## Notes & limits

- **This is peer review, not ground truth.** The council reasons over what the report says. It cannot test the endpoint. Real exploitability comes from the user's curl/nmap/Burp evidence — the council judges whether the report's claims match that evidence and whether the score, CWE, and MITRE mappings are correct.
- **Default mode shares Claude's blind spots.** Every lens is Claude. It catches weak reasoning, overclaiming, bad CVSS math, and missed chains — but not blind spots all Claude models share. Reach for cross-vendor mode (direct keys on hostM) when the stakes justify the cost.
- **Honour the standing evidence rules** during synthesis: score only what evidence proves (no guessing architecture or WAF posture); CVSS reflects demonstrated impact, with capability-based discussion kept separate in the narrative; behavior belonging to third-party or vendor-owned public infrastructure (an identity provider's public API, a CDN, an analytics endpoint) is generally not a client finding — the client cannot remediate what they do not own, so confirm the affected asset is within the client's control before reporting it; and any personally identifiable information (e.g. real usernames or emails) must be anonymized in external reports.
- Member count and lenses are tunable — the defaults are defaults, not laws. For a fast gut-check, quick mode (3) is fine; for a High/Critical going to a client, run full (8).
