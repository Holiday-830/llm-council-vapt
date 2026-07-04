#!/usr/bin/env python3
"""
council_direct.py — LLM Council (VAPT) cross-vendor engine.

Runs the council in PARALLEL across three providers using direct provider keys:
  Claude (Anthropic)  ·  ChatGPT (OpenAI)  ·  Gemini (Google)

Pipeline:
  Stage 1 — each active member's lens is assigned to one provider (round-robin)
            and all members run CONCURRENTLY for independent assessments.
  Stage 2 — assessments are anonymized and sent to each provider for a blind
            ranking; rankings are aggregated by mean position.
  Output  — one JSON blob (de-anonymized assessments + reviews + aggregate
            ranking + failures[]) printed to stdout.

Stage 3 (Chairman synthesis) is intentionally NOT done here — Claude Code reads
this JSON and synthesizes the final verdict, applying the council's evidence rules.

Usage:
  python3 council_direct.py --mode quick  --finding ./finding.md
  python3 council_direct.py --mode full   --finding ./finding.md --severity high --version 2
  python3 council_direct.py --mode medium --finding "raw finding text..."

Keys are loaded from .env (never hardcoded):
  ANTHROPIC_API_KEY   OPENAI_API_KEY   GEMINI_API_KEY
"""

import argparse
import concurrent.futures
import json
import os
import sys
import traceback

# ----------------------------------------------------------------------------
# Model IDs — verified against official provider docs, June 2026.
# Update here when providers ship new flagships (these are not evergreen).
# ----------------------------------------------------------------------------
MODELS = {
    "claude": "claude-opus-4-8",        # Anthropic — most capable Opus-tier
    "chatgpt": "gpt-5.5",               # OpenAI — current flagship
    "gemini": "gemini-3.1-pro-preview", # Google — most advanced reasoning
}

STAGE1_MAX_TOKENS = 1500  # per-member assessment — room for full reasoning + verdict block
STAGE2_MAX_TOKENS = 300   # ranking only outputs a short FINAL RANKING list

# ----------------------------------------------------------------------------
# Council members. Each lens carries its operating rules inline so the prompt
# sent to the provider is self-contained and matches SKILL.md exactly.
# ----------------------------------------------------------------------------
MEMBERS = {
    "Red-teamer": (
        "Attack the finding itself. Is it a false positive? Is the premise wrong? "
        "Would it survive a hostile reviewer? What would kill it? "
        "RULES: (1) Apply the engagement context given in the prompt when judging "
        "the severity floor — do not assume a context that wasn't provided. (2) "
        "Verdict is not strictly binary — if one vector is solid and a sub-claim is "
        "weak, confirm the valid part and name the sub-claim to drop."
    ),
    "CVSS Auditor": (
        "Verify the CVSS score reflects ONLY what was demonstrated. Recompute the "
        "vector (AV/AC/PR/UI/S/C/I/A) and confirm the tier matches the math. Flag "
        "inflation and deflation. Then run the CWE VERIFICATION PROTOCOL on every "
        "CWE cited: (1) state the CWE's literal definition; (2) gate — did the system "
        "implement the control this CWE says is broken? A control that was NEVER "
        "implemented is a different weakness than one implemented incorrectly; a CWE "
        "describing a broken check does not apply when no such check ever existed; "
        "(3) map only to demonstrated behavior; (4) output per CWE: Confirmed / "
        "Overclaim / Remove (+replacement)."
    ),
    "Evidence Auditor": (
        "Do the reproduction steps actually PROVE the claim? RULES: (1) Classify every "
        "claim as API-LEVEL (the endpoint accepted the request — e.g. a 200 response or "
        "a specific error code) or END-TO-END (the real downstream effect actually "
        "occurred — the record was written, data was read back, code executed, a "
        "control was confirmed absent). A success response proves acceptance, not the "
        "downstream effect. Flag any end-to-end claim backed only by API-level proof as "
        "overclaiming. (2) Flag reproduction steps that depend on time-bound or "
        "deployment-specific values (hashed asset filenames that change each build, "
        "session tokens, one-time URLs, CSRF nonces) — they break on redeploy; "
        "recommend a stable alternative."
    ),
    "Attack Chain Analyst": (
        "Does this finding combine with others into a higher-severity kill chain? Is a "
        "Medium-in-isolation a step toward Critical? Is it a symptom of a deeper root "
        "cause reported in isolation? RULE: only propose chains involving systems within "
        "the engagement's authorized target list. Reason from the finding under review "
        "plus any RELATED FINDINGS provided in the input; reference related findings by "
        "their file name. If no related findings are provided, analyze chains within the "
        "single finding and note that cross-finding analysis was unavailable."
    ),
    "Remediation Critic": (
        "Is the fix specific, technically correct, and does it close the ROOT CAUSE "
        "(not just the symptom)? Does it introduce new risk? RULES: (1) Multi-vector "
        "completeness — list every attack vector named in the finding and verify the "
        "remediation closes EACH one; flag any vector left open. (2) Vendor dependency "
        "— flag any fix whose availability depends on the client's third-party plan "
        "tier or vendor config; note it may not be actionable on their plan and give a "
        "fallback."
    ),
    "Threat Intel Analyst": (
        "Is this technique actively exploited in the wild? Which threat actors use it? "
        "RULES: (1) Classify every claim as ACTIVE (documented real-world exploitation "
        "— name actor/campaign/year) or THEORETICAL (works in a lab, no confirmed "
        "in-the-wild use); never assert 'actively exploited' without a citable actor. "
        "(2) MITRE ATT&CK VERIFICATION — for every technique ID cited: resolve the ID "
        "to its official name (do not trust the report's label), confirm it matches the "
        "demonstrated behavior, output Confirmed or 'Wrong — should be <ID> (<name>)'."
    ),
    "False Negative Hunter": (
        "Not 'is this finding valid?' but 'what related vectors were NOT tested that "
        "should have been?' Catch coverage gaps before the client's team does. RULE: "
        "only flag untested vectors within the engagement's authorized scope (listed "
        "target hosts, subdomains, systems). Never suggest testing third-party "
        "infrastructure, other customer tenants, or out-of-scope systems — that is "
        "unauthorized testing, not a coverage gap."
    ),
    "Business Impact Translator": (
        "Convert the technical finding into language a CTO/exec feels, WITHOUT "
        "overclaiming. RULE: every business-impact statement must map to a demonstrated "
        "CVSS dimension — confidentiality language requires C:L+, integrity requires "
        "I:L+, availability requires A:L+. If a dimension is N, do not assert impact in "
        "it regardless of how the finding 'feels'."
    ),
}

MODE_MEMBERS = {
    "quick": ["Red-teamer", "CVSS Auditor", "Evidence Auditor"],
    "medium": ["Red-teamer", "CVSS Auditor", "Evidence Auditor",
               "Attack Chain Analyst", "Remediation Critic"],
    "full": list(MEMBERS.keys()),
}

PROVIDER_ORDER = ["claude", "chatgpt", "gemini"]

# ----------------------------------------------------------------------------
# Prompt builders
# ----------------------------------------------------------------------------
ENGAGEMENT_CONTEXT = {
    "vdp": ("This is a VDP / bug-bounty context. Calibrate severity to that floor: "
            "issues in vendor-accepted-by-design behavior or third-party infrastructure "
            "may be Informational/Low even with a working PoC, unless real impact to the "
            "in-scope target is demonstrated."),
    "pentest": ("This is a PAID PENETRATION TEST. Severity floors are higher than a "
                "VDP/bug-bounty: a confirmed issue with a working PoC does not drop to "
                "Informational merely because the underlying component is "
                "'vendor-accepted architecture'."),
}

NO_ASSUMPTIONS = (
    "STRICT EVIDENCE RULE: do not assume, infer, or speculate beyond what the finding "
    "demonstrates with reproducible proof. Every claim you make must be grounded in "
    "evidence present in the finding. If something is not demonstrated, say so "
    "explicitly and treat it as unproven — never fill the gap with assumption."
)


def stage1_prompt(lens, finding, severity, related="", engagement="vdp"):
    sev = ""
    if severity:
        sev = (f"\nThe author/researcher claims this is {severity.upper()}. "
               f"Specifically challenge or confirm that claim.\n")
    rel = ""
    if related:
        rel = ("\nRelated findings provided for chain analysis only (do not "
               "re-validate them). They are labelled [Related-A], [Related-B], … — "
               "refer to them by those labels (or by an ID if one is present):\n"
               f"{related}\n")
    ctx = ENGAGEMENT_CONTEXT.get(engagement, ENGAGEMENT_CONTEXT["vdp"])
    return (
        "You are one member of an expert security council validating a security "
        "finding independently. Your lens is what you should EMPHASIZE, not a "
        "character to perform — give your genuine best assessment.\n\n"
        f"Engagement context: {ctx}\n\n"
        f"{NO_ASSUMPTIONS}\n\n"
        f"Your lens:\n{lens}\n{sev}{rel}\n"
        "The finding under review is labelled [Finding-1]; refer to it that way "
        "(or by its ID if one is present).\n\n"
        f"[Finding-1]:\n{finding}\n\n"
        "Assess directly: what is strong, what is weak, and whether this is worth "
        "reporting as written. State your key assumption and the strongest objection "
        "to your own position. Be specific and concise — no preamble, no hedging.\n\n"
        "End with this exact 3-line block:\n"
        "VERDICT: Valid / Valid-with-fixes / Needs revision / Invalid\n"
        "CONFIDENCE: High / Medium / Low\n"
        "KEY ISSUE: <one line — the single most important thing the Chairman must act on>"
    )


def stage2_prompt(anon_assessments):
    body = "\n\n".join(f"--- {label} ---\n{text}" for label, text in anon_assessments)
    return (
        "You are judging anonymized assessments of the same security finding, "
        "written by independent council members. Evaluate them ONLY on accuracy and "
        "insight — not tone or length. You do not know which member wrote which.\n\n"
        f"{body}\n\n"
        "Rank them best-to-worst. Respond with ONLY this block and nothing else:\n"
        "FINAL RANKING:\n1. Response <letter>\n2. Response <letter>\n...(continue for all)"
    )


# ----------------------------------------------------------------------------
# Provider adapters — each returns plain text or raises. Lazy imports so a
# missing SDK only breaks the provider that needs it.
# ----------------------------------------------------------------------------
def call_claude(prompt, max_tokens):
    import anthropic
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    resp = client.messages.create(
        model=MODELS["claude"],
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    text = "".join(b.text for b in resp.content
                   if getattr(b, "type", None) == "text").strip()
    truncated = getattr(resp, "stop_reason", None) == "max_tokens"
    return text, truncated


def call_chatgpt(prompt, max_tokens):
    from openai import OpenAI
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    resp = client.chat.completions.create(
        model=MODELS["chatgpt"],
        max_completion_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    text = (resp.choices[0].message.content or "").strip()
    truncated = getattr(resp.choices[0], "finish_reason", None) == "length"
    return text, truncated


def call_gemini(prompt, max_tokens):
    from google import genai
    from google.genai import types
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    resp = client.models.generate_content(
        model=MODELS["gemini"],
        contents=prompt,
        config=types.GenerateContentConfig(max_output_tokens=max_tokens),
    )
    text = (resp.text or "").strip()
    truncated = False
    try:
        fr = resp.candidates[0].finish_reason
        truncated = str(getattr(fr, "name", fr)) == "MAX_TOKENS"
    except (AttributeError, IndexError, TypeError):
        pass
    return text, truncated


PROVIDER_FN = {"claude": call_claude, "chatgpt": call_chatgpt, "gemini": call_gemini}
PROVIDER_KEY = {"claude": "ANTHROPIC_API_KEY", "chatgpt": "OPENAI_API_KEY",
                "gemini": "GEMINI_API_KEY"}


# ----------------------------------------------------------------------------
# Engine
# ----------------------------------------------------------------------------
def assign_providers(members):
    """Round-robin members across providers so no single vendor dominates."""
    return {m: PROVIDER_ORDER[i % len(PROVIDER_ORDER)] for i, m in enumerate(members)}


def run_stage1(members, assignment, finding, severity, related="", engagement="vdp"):
    results, failures = {}, []

    def worker(member):
        provider = assignment[member]
        # related findings are only useful to the chain analyst
        member_related = related if member == "Attack Chain Analyst" else ""
        prompt = stage1_prompt(MEMBERS[member], finding, severity,
                               member_related, engagement)
        text, truncated = PROVIDER_FN[provider](prompt, STAGE1_MAX_TOKENS)
        return member, provider, text, truncated

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(members)) as ex:
        futs = {ex.submit(worker, m): m for m in members}
        for fut in concurrent.futures.as_completed(futs):
            member = futs[fut]
            try:
                m, provider, text, truncated = fut.result()
                if truncated:
                    text += (f"\n\n[!] OUTPUT TRUNCATED — this assessment hit the "
                             f"{STAGE1_MAX_TOKENS}-token limit. Raise STAGE1_MAX_TOKENS "
                             f"for the full reasoning.")
                results[m] = {"provider": provider, "model": MODELS[provider],
                              "text": text, "truncated": truncated}
            except Exception as e:  # noqa: BLE001 — capture per-member, keep going
                failures.append({"stage": "stage1", "member": member,
                                 "provider": assignment[member], "error": str(e)})
    return results, failures


def run_stage2(results):
    """Anonymize, get a blind ranking from each available provider, aggregate."""
    members = list(results.keys())
    labels = {chr(65 + i): m for i, m in enumerate(members)}  # A,B,C... -> member
    member_to_label = {m: l for l, m in labels.items()}
    anon = [(f"Response {l}", results[m]["text"]) for l, m in labels.items()]

    prompt = stage2_prompt(anon)
    rankings, failures = {}, []
    providers_used = sorted({results[m]["provider"] for m in members})

    for provider in providers_used:
        try:
            raw, _ = PROVIDER_FN[provider](prompt, STAGE2_MAX_TOKENS)
            order = parse_ranking(raw, set(labels.keys()))
            if order:
                rankings[provider] = order
        except Exception as e:  # noqa: BLE001
            failures.append({"stage": "stage2", "provider": provider, "error": str(e)})

    aggregate = aggregate_rankings(rankings, labels) if rankings else []
    return {
        "label_map": {l: m for l, m in labels.items()},
        "rankings_by_provider": {p: [labels[l] for l in order]
                                 for p, order in rankings.items()},
        "aggregate_ranking": aggregate,
    }, failures, member_to_label


def parse_ranking(raw, valid_labels):
    """Extract ordered labels from a 'FINAL RANKING:' block."""
    order, seen = [], set()
    for line in raw.splitlines():
        line = line.strip()
        if "Response" not in line:
            continue
        idx = line.find("Response")
        tail = line[idx + len("Response"):].strip()
        if tail:
            cand = tail[0].upper()
            if cand in valid_labels and cand not in seen:
                order.append(cand)
                seen.add(cand)
    return order


def aggregate_rankings(rankings, labels):
    """Mean position across providers; lower is better."""
    n = len(labels)
    sums = {l: 0.0 for l in labels}
    counts = {l: 0 for l in labels}
    for order in rankings.values():
        for pos, label in enumerate(order):
            sums[label] += pos + 1
            counts[label] += 1
        # labels a provider omitted get worst-rank penalty
        for label in labels:
            if label not in order:
                sums[label] += n
                counts[label] += 1
    mean = {l: (sums[l] / counts[l]) if counts[l] else n for l in labels}
    ordered = sorted(labels.keys(), key=lambda l: mean[l])
    return [{"member": labels[l], "mean_position": round(mean[l], 2)} for l in ordered]


# text-based extensions the script can read directly
TEXT_EXTS = {".md", ".txt", ".json", ".csv", ".log", ".yaml", ".yml", ".text", ""}
# binary/markup formats that need conversion first
BINARY_EXTS = {".pdf", ".docx", ".doc", ".rtf", ".odt", ".xlsx", ".pptx"}


def _read_text_file(path):
    """Read a text file, guarding against binary formats. Returns (text, error)."""
    ext = os.path.splitext(path)[1].lower()
    if ext in BINARY_EXTS:
        return None, (f"unsupported_format: '{ext}' is a binary/document format. "
                      f"Convert the finding to .md or .txt first, then re-run.")
    with open(path, "rb") as f:
        head = f.read(5)
    # crude binary sniff: PDFs start %PDF, Office files are zips (PK)
    if head[:4] == b"%PDF" or head[:2] == b"PK":
        return None, ("unsupported_format: file looks binary (PDF/Office). "
                      "Convert the finding to .md or .txt first, then re-run.")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read(), None


def load_finding(arg):
    """Load the finding from a file path or treat the arg as literal text.
    Returns (text, error)."""
    if arg and os.path.isfile(arg):
        return _read_text_file(arg)
    return arg, None  # literal text


def load_related(findings_dir, primary_path, project):
    """Collect sibling findings for chain analysis.

    findings_dir : directory to scan (defaults to the finding's own dir).
    primary_path : the finding under review, excluded from the related set.
    project      : optional filename-prefix tag supplied by the user at runtime;
                   if given, only siblings whose name starts with it are included;
                   if None, all readable text siblings are considered.
    No client names or prefixes are baked into this code — the tag is user input.
    """
    if not findings_dir or not os.path.isdir(findings_dir):
        return "", []
    primary = os.path.abspath(primary_path) if primary_path else None
    chunks, used = [], []
    for name in sorted(os.listdir(findings_dir)):
        full = os.path.join(findings_dir, name)
        if not os.path.isfile(full):
            continue
        if primary and os.path.abspath(full) == primary:
            continue
        if project and not name.startswith(project):
            continue
        if os.path.splitext(name)[1].lower() not in TEXT_EXTS:
            continue
        text, err = _read_text_file(full)
        if err or not text or not text.strip():
            continue
        label = f"[Related-{chr(65 + len(used))}]"  # A, B, C, ...
        chunks.append(f"{label} (file: {name})\n{text.strip()}")
        used.append({"label": label, "file": name})
    return "\n\n".join(chunks), used


def preflight(members, assignment):
    """Ensure each provider that will be used has its key set."""
    needed = {assignment[m] for m in members}
    missing = [PROVIDER_KEY[p] for p in needed if not os.environ.get(PROVIDER_KEY[p])]
    return missing


def main():
    ap = argparse.ArgumentParser(description="LLM Council (VAPT) cross-vendor engine")
    ap.add_argument("--mode", choices=["quick", "medium", "full"], required=True)
    ap.add_argument("--finding", required=True, help="path to finding file OR raw text")
    ap.add_argument("--severity", default=None, help="claimed severity to test (optional)")
    ap.add_argument("--version", default="1", help="finding version stamp (optional)")
    ap.add_argument("--finding-id", default=None, help="finding ID for the output stamp")
    ap.add_argument("--findings-dir", default=None,
                    help="directory of related findings for chain analysis "
                         "(default: the finding file's own directory)")
    ap.add_argument("--project", default=None,
                    help="optional filename-prefix tag to filter related findings; "
                         "if omitted, all readable text siblings are considered")
    ap.add_argument("--engagement", choices=["vdp", "pentest"], default="vdp",
                    help="severity-floor context: 'vdp' (bug-bounty/VDP, default) or "
                         "'pentest' (paid penetration test)")
    args = ap.parse_args()

    # load .env if python-dotenv is available; harmless if not
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except Exception:  # noqa: BLE001
        pass

    members = MODE_MEMBERS[args.mode]
    assignment = assign_providers(members)

    missing = preflight(members, assignment)
    if missing:
        print(json.dumps({"error": "missing_keys", "missing": missing,
                          "hint": "set these in the project .env, then re-run"}, indent=2))
        sys.exit(1)

    finding, ferr = load_finding(args.finding)
    if ferr:
        print(json.dumps({"error": ferr.split(":")[0], "detail": ferr}, indent=2))
        sys.exit(1)
    if not finding or not finding.strip():
        print(json.dumps({"error": "empty_finding"}, indent=2))
        sys.exit(1)

    # related findings for chain analysis (only meaningful when --finding is a path)
    related_text, related_used = "", []
    if "Attack Chain Analyst" in members:
        fdir = args.findings_dir
        if not fdir and os.path.isfile(args.finding):
            fdir = os.path.dirname(os.path.abspath(args.finding)) or "."
        related_text, related_used = load_related(fdir, args.finding, args.project)

    try:
        s1, f1 = run_stage1(members, assignment, finding, args.severity,
                            related_text, args.engagement)
        if not s1:
            print(json.dumps({"error": "all_members_failed", "failures": f1}, indent=2))
            sys.exit(1)
        s2, f2, _ = run_stage2(s1)
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": "fatal", "detail": str(e),
                          "trace": traceback.format_exc()}, indent=2))
        sys.exit(1)

    truncated_members = [m for m, v in s1.items() if v.get("truncated")]
    out = {
        "meta": {
            "mode": args.mode,
            "engagement": args.engagement,
            "finding_id": args.finding_id,
            "version": args.version,
            "severity_tested": args.severity,
            "models": MODELS,
            "assignment": assignment,
            "related_findings_used": related_used,
            "truncated_members": truncated_members,
        },
        "stage1_assessments": s1,
        "stage2_review": s2,
        "failures": f1 + f2,
        "note": "Stage 3 (Chairman synthesis) is performed by Claude Code from this JSON.",
    }
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
