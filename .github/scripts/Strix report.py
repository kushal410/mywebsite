#!/usr/bin/env python3
"""
Render Strix scan output as a single self-contained HTML report.

Standard library only, so it runs on a bare GitHub runner with no pip install.

Usage:
    python3 strix_report.py \
        --run-dir agent_runs \
        --log strix-output.log \
        --out strix-report/report.html \
        --repo owner/name --commit abc123 --target ./ --model anthropic/...

Design note: Strix's report schema is not pinned down, so findings are
discovered structurally (any JSON object carrying a recognisable severity plus
a title-ish field) rather than by a fixed path. If nothing matches, the report
still renders and falls back to the raw transcript. It must never come out
blank, because a blank report reads like a clean scan.
"""

import argparse
import html
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------
# Severity handling
# --------------------------------------------------------------------------

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_ALIASES = {
    "critical": "critical", "crit": "critical", "severe": "critical", "5": "critical",
    "high": "high", "important": "high", "major": "high", "4": "high",
    "medium": "medium", "moderate": "medium", "med": "medium", "3": "medium",
    "low": "low", "minor": "low", "2": "low",
    "info": "info", "informational": "info", "none": "info",
    "note": "info", "negligible": "info", "1": "info", "0": "info",
}

SEVERITY_KEYS = ("severity", "risk", "risk_level", "riskLevel",
                 "criticality", "impact", "level")

TITLE_KEYS = ("title", "name", "summary", "issue", "vulnerability",
              "vuln", "finding", "headline")

DESC_KEYS = ("description", "details", "detail", "explanation",
             "analysis", "body", "summary")

LOCATION_KEYS = ("file", "file_path", "filepath", "path", "location",
                 "url", "endpoint", "component", "module")

LINE_KEYS = ("line", "line_number", "lineno", "start_line")

EVIDENCE_KEYS = ("evidence", "poc", "proof_of_concept", "reproduction",
                 "steps_to_reproduce", "request", "payload", "snippet")

FIX_KEYS = ("recommendation", "remediation", "fix", "mitigation",
            "suggested_fix", "solution")

REF_KEYS = ("cwe", "cve", "cvss", "owasp", "references", "reference")


def normalise_severity(value):
    """Map an arbitrary severity value onto our five-point scale, or None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    if text in SEVERITY_ALIASES:
        return SEVERITY_ALIASES[text]
    # Handle things like "High (7.5)" or "severity: high"
    for token in re.split(r"[^a-z0-9]+", text):
        if token in SEVERITY_ALIASES:
            return SEVERITY_ALIASES[token]
    return None


# --------------------------------------------------------------------------
# Secret redaction
#
# GitHub masks secrets in *logs*, but not inside uploaded artifacts. A pentest
# agent's output is exactly the kind of place a key or token can end up, so
# scrub before writing anything to disk.
# --------------------------------------------------------------------------

REDACT_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{12,}"),
    re.compile(r"sk-[A-Za-z0-9]{24,}"),
    re.compile(r"pplx-[A-Za-z0-9]{12,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
]

# Exact values from the environment, longest first so partial overlaps are safe.
ENV_SECRETS = sorted(
    (v for v in (os.environ.get(k) for k in
                 ("LLM_API_KEY", "ANTHROPIC_API_KEY", "PERPLEXITY_API_KEY"))
     if v and len(v) >= 8),
    key=len,
    reverse=True,
)


def redact(text):
    if not text:
        return text
    for secret in ENV_SECRETS:
        text = text.replace(secret, "[redacted]")
    for pattern in REDACT_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text


# --------------------------------------------------------------------------
# Finding discovery
# --------------------------------------------------------------------------

def iter_dicts(obj):
    """Yield every dict nested anywhere inside obj."""
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from iter_dicts(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from iter_dicts(value)


def first_value(source, keys):
    """Return the first non-empty scalar value for any of keys."""
    for key in keys:
        for candidate in (key, key.lower(), key.upper()):
            if candidate in source:
                value = source[candidate]
                if value is None or isinstance(value, (dict, list)):
                    continue
                text = str(value).strip()
                if text:
                    return text
    return ""


def flatten_refs(source):
    parts = []
    for key in REF_KEYS:
        if key in source:
            value = source[key]
            if isinstance(value, list):
                parts.extend(str(v).strip() for v in value if str(v).strip())
            elif value not in (None, ""):
                parts.append(str(value).strip())
    # Deduplicate, keep order
    seen, out = set(), []
    for part in parts:
        if part not in seen:
            seen.add(part)
            out.append(part)
    return out


def extract_finding(source):
    """Turn a dict into a normalised finding, or return None if it isn't one."""
    severity = None
    for key in SEVERITY_KEYS:
        if key in source:
            severity = normalise_severity(source[key])
            if severity:
                break
    if not severity:
        return None

    title = first_value(source, TITLE_KEYS)
    if not title:
        return None

    description = ""
    for key in DESC_KEYS:
        if key in source:
            value = source[key]
            # "summary" can serve as either title or description depending on
            # the schema, so reject anything that just repeats the title.
            if isinstance(value, str) and value.strip() and value.strip() != title:
                description = value.strip()
                break

    location = first_value(source, LOCATION_KEYS)
    line = first_value(source, LINE_KEYS)
    if location and line:
        location = "{}:{}".format(location, line)

    return {
        "severity": severity,
        "title": title,
        "description": description,
        "location": location,
        "evidence": first_value(source, EVIDENCE_KEYS),
        "fix": first_value(source, FIX_KEYS),
        "refs": flatten_refs(source),
    }


def parse_file(path, run_dir):
    """Pull findings out of one JSON/JSONL file."""
    findings = []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    documents = []
    if path.suffix.lower() == ".jsonl":
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                documents.append(json.loads(line))
            except ValueError:
                continue
    else:
        try:
            documents.append(json.loads(raw))
        except ValueError:
            return findings

    for document in documents:
        for candidate in iter_dicts(document):
            finding = extract_finding(candidate)
            if finding:
                finding["source"] = str(path.relative_to(run_dir))
                findings.append(finding)
    return findings


def dedupe_and_sort(findings):
    seen, unique = set(), []
    for finding in findings:
        key = (finding["severity"], finding["title"], finding["location"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    unique.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["title"].lower()))
    return unique


# Files whose names suggest they hold the actual report, rather than the agent's
# internal trajectory. Trajectory logs contain plenty of objects with
# severity-ish keys, and mining those would invent findings that don't exist.
REPORT_NAME_HINT = re.compile(
    r"(report|finding|vuln|result|summary|issue|scan)", re.IGNORECASE)


def load_findings(run_dir):
    """Scan run_dir for JSON/JSONL files and pull findings out of them.

    Report-shaped filenames are tried first. Only if those yield nothing does
    this fall back to every JSON file, which is noisier but better than
    silently reporting zero findings because the naming differed.
    """
    if not run_dir.is_dir():
        return []

    candidates = [p for p in sorted(run_dir.rglob("*"))
                  if p.is_file() and p.suffix.lower() in (".json", ".jsonl")]

    preferred = [p for p in candidates if REPORT_NAME_HINT.search(p.name)]

    findings = []
    for path in preferred:
        findings.extend(parse_file(path, run_dir))

    if not findings:
        for path in candidates:
            if path in preferred:
                continue
            findings.extend(parse_file(path, run_dir))

    return dedupe_and_sort(findings)


def collect_notes(run_dir):
    """Gather markdown/text output so a human-written summary isn't lost."""
    notes = []
    if not run_dir.is_dir():
        return notes
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in (".md", ".markdown", ".txt"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if text:
            notes.append((str(path.relative_to(run_dir)), text))
    return notes


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

CSS = """
:root {
  color-scheme: light;
  --paper: #eff0ec;
  --sheet: #f8f8f5;
  --ink: #16191a;
  --ink-soft: #4c5250;
  --ink-faint: #797f7c;
  --rule: #d3d5ce;
  --critical: #6e1420;
  --high: #a8431c;
  --medium: #7e6410;
  --low: #3b5c6b;
  --info: #6a6f6b;
  --mono: ui-monospace, "SF Mono", SFMono-Regular, "Cascadia Mono", Menlo, Consolas, monospace;
  --serif: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font-family: var(--serif);
  font-size: 16px;
  line-height: 1.6;
}
.wrap { max-width: 60rem; margin: 0 auto; padding: 2.5rem 1.5rem 5rem; }

/* Labels and structural type are monospace; prose is serif. */
.label {
  font-family: var(--mono);
  font-size: 0.625rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--ink-faint);
}

/* ---- masthead: laid out like the header block of a case file ---- */
.masthead { border-top: 3px solid var(--ink); padding-top: 1.25rem; }
.masthead h1 {
  font-family: var(--mono);
  font-size: clamp(1.5rem, 4.5vw, 2.25rem);
  font-weight: 600;
  letter-spacing: -0.02em;
  margin: 0.5rem 0 0.25rem;
}
.masthead .strap {
  font-family: var(--serif);
  font-style: italic;
  color: var(--ink-soft);
  margin: 0 0 1.75rem;
}
.facts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
  gap: 1rem 1.5rem;
  border-top: 1px solid var(--rule);
  border-bottom: 1px solid var(--rule);
  padding: 1.125rem 0;
}
.fact div { font-family: var(--mono); font-size: 0.8125rem; margin-top: 0.3rem; word-break: break-word; }

/* ---- signature element: the severity ribbon ----
   A single solid bar segmented in proportion to the severity mix, set as
   blocks of ink rather than a chart. Reads as a redaction bar, which is the
   visual vocabulary this subject actually lives in. */
.ribbon-head { display: flex; justify-content: space-between; align-items: baseline; margin: 2.5rem 0 0.6rem; }
.ribbon {
  display: flex;
  width: 100%;
  height: 2.75rem;
  overflow: hidden;
  background: var(--sheet);
  border: 1px solid var(--rule);
}
.seg {
  display: flex;
  align-items: center;
  justify-content: center;
  min-width: 0;
  font-family: var(--mono);
  font-size: 0.75rem;
  font-weight: 600;
  color: #f4f4f0;
  white-space: nowrap;
  overflow: hidden;
  animation: grow 0.7s cubic-bezier(0.2, 0.8, 0.2, 1) both;
}
@keyframes grow { from { flex-basis: 0; } }
.seg-critical { background: var(--critical); }
.seg-high { background: var(--high); }
.seg-medium { background: var(--medium); }
.seg-low { background: var(--low); }
.seg-info { background: var(--info); }
.seg-empty { background: var(--sheet); color: var(--ink-faint); flex: 1; }

.legend { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.75rem; }
.chip {
  font-family: var(--mono);
  font-size: 0.6875rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 0.3rem 0.6rem;
  border: 1px solid var(--rule);
  background: var(--sheet);
  color: var(--ink-soft);
  cursor: pointer;
}
.chip[aria-pressed="true"] { background: var(--ink); color: var(--paper); border-color: var(--ink); }
.chip:focus-visible, details:focus-visible > summary { outline: 2px solid var(--ink); outline-offset: 2px; }
.dot { display: inline-block; width: 0.5rem; height: 0.5rem; margin-right: 0.4rem; vertical-align: baseline; }

/* ---- findings ---- */
h2.section {
  font-family: var(--mono);
  font-size: 0.6875rem;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--ink-faint);
  font-weight: 600;
  margin: 3rem 0 1rem;
  padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--rule);
}
.finding {
  background: var(--sheet);
  border: 1px solid var(--rule);
  border-left: 5px solid var(--info);
  margin-bottom: 0.6rem;
}
.finding[data-sev="critical"] { border-left-color: var(--critical); }
.finding[data-sev="high"] { border-left-color: var(--high); }
.finding[data-sev="medium"] { border-left-color: var(--medium); }
.finding[data-sev="low"] { border-left-color: var(--low); }
.finding > summary {
  cursor: pointer;
  padding: 0.9rem 1.1rem;
  display: grid;
  grid-template-columns: 5.5rem 1fr;
  gap: 0.25rem 1rem;
  align-items: baseline;
  list-style: none;
}
.finding > summary::-webkit-details-marker { display: none; }
.sev {
  font-family: var(--mono);
  font-size: 0.625rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}
.sev-critical { color: var(--critical); }
.sev-high { color: var(--high); }
.sev-medium { color: var(--medium); }
.sev-low { color: var(--low); }
.sev-info { color: var(--info); }
.finding .headline { font-size: 1.0625rem; }
.finding .where {
  grid-column: 2;
  font-family: var(--mono);
  font-size: 0.75rem;
  color: var(--ink-faint);
  word-break: break-all;
}
.finding .panel { padding: 0 1.1rem 1.2rem; border-top: 1px solid var(--rule); }
.finding .panel h3 {
  font-family: var(--mono);
  font-size: 0.625rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--ink-faint);
  font-weight: 600;
  margin: 1.2rem 0 0.4rem;
}
.finding .panel p { margin: 0; }
pre {
  font-family: var(--mono);
  font-size: 0.75rem;
  line-height: 1.55;
  background: #eceee7;
  border: 1px solid var(--rule);
  padding: 0.8rem;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  margin: 0;
}
.refs { display: flex; flex-wrap: wrap; gap: 0.35rem; }
.ref {
  font-family: var(--mono);
  font-size: 0.6875rem;
  padding: 0.15rem 0.45rem;
  border: 1px solid var(--rule);
  background: var(--paper);
  color: var(--ink-soft);
}
.empty {
  background: var(--sheet);
  border: 1px solid var(--rule);
  border-left: 5px solid var(--medium);
  padding: 1.25rem;
}
.empty p { margin: 0.5rem 0 0; }
.empty p:first-of-type { margin-top: 0; }
footer {
  margin-top: 3.5rem;
  padding-top: 1.25rem;
  border-top: 1px solid var(--rule);
  font-family: var(--mono);
  font-size: 0.6875rem;
  line-height: 1.7;
  color: var(--ink-faint);
}
a { color: var(--ink); text-decoration-thickness: 1px; text-underline-offset: 2px; }
.hidden { display: none !important; }
@media (prefers-reduced-motion: reduce) {
  .seg { animation: none; }
}
@media (max-width: 34rem) {
  .finding > summary { grid-template-columns: 1fr; }
  .finding .where { grid-column: 1; }
}
"""

JS = """
(function () {
  var chips = Array.prototype.slice.call(document.querySelectorAll('.chip[data-sev]'));
  var findings = Array.prototype.slice.call(document.querySelectorAll('.finding'));
  if (!chips.length || !findings.length) { return; }

  function apply() {
    var active = chips.filter(function (c) { return c.getAttribute('aria-pressed') === 'true'; })
                      .map(function (c) { return c.getAttribute('data-sev'); });
    findings.forEach(function (f) {
      var show = active.length === 0 || active.indexOf(f.getAttribute('data-sev')) !== -1;
      f.classList.toggle('hidden', !show);
    });
    var shown = findings.filter(function (f) { return !f.classList.contains('hidden'); }).length;
    var counter = document.getElementById('shown-count');
    if (counter) {
      counter.textContent = shown === findings.length
        ? findings.length + ' shown'
        : shown + ' of ' + findings.length + ' shown';
    }
  }

  chips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      chip.setAttribute('aria-pressed', chip.getAttribute('aria-pressed') === 'true' ? 'false' : 'true');
      apply();
    });
  });
})();
"""

SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>__TITLE__</title>
<style>__CSS__</style>
</head>
<body>
<div class="wrap">
__BODY__
</div>
<script>__JS__</script>
</body>
</html>
"""


def esc(text):
    return html.escape(str(text if text is not None else ""), quote=True)


def fact(label, value):
    return ('<div class="fact"><span class="label">{}</span>'
            '<div>{}</div></div>').format(esc(label), esc(value) or "&mdash;")


def render_ribbon(counts, total):
    parts = ['<div class="ribbon-head">',
             '<span class="label">Severity mix</span>',
             '<span class="label" id="shown-count">{} finding{}</span>'.format(
                 total, "" if total == 1 else "s"),
             '</div>', '<div class="ribbon">']
    if total == 0:
        parts.append('<div class="seg seg-empty">no structured findings parsed</div>')
    else:
        for index, severity in enumerate(SEVERITY_ORDER):
            count = counts.get(severity, 0)
            if not count:
                continue
            share = count / total * 100
            # Narrow segments would clip their label, so only label wider ones.
            caption = "{} {}".format(count, severity.upper()) if share >= 14 else str(count)
            parts.append(
                '<div class="seg seg-{sev}" style="flex: 0 0 {share:.4f}%; animation-delay: {delay}ms"'
                ' title="{count} {sev}">{caption}</div>'.format(
                    sev=severity, share=share, delay=index * 70,
                    count=count, caption=esc(caption)))
    parts.append("</div>")

    parts.append('<div class="legend">')
    for severity in SEVERITY_ORDER:
        count = counts.get(severity, 0)
        if not count:
            continue
        parts.append(
            '<button type="button" class="chip" data-sev="{sev}" aria-pressed="false">'
            '<span class="dot" style="background: var(--{sev})"></span>{sev} {count}'
            "</button>".format(sev=severity, count=count))
    parts.append("</div>")
    return "\n".join(parts)


def render_finding(finding):
    parts = ['<details class="finding" data-sev="{}">'.format(esc(finding["severity"]))]
    parts.append("<summary>")
    parts.append('<span class="sev sev-{s}">{s}</span>'.format(s=esc(finding["severity"])))
    parts.append('<span class="headline">{}</span>'.format(esc(finding["title"])))
    if finding["location"]:
        parts.append('<span class="where">{}</span>'.format(esc(finding["location"])))
    parts.append("</summary>")

    parts.append('<div class="panel">')
    if finding["description"]:
        parts.append("<h3>What was found</h3>")
        parts.append("<p>{}</p>".format(esc(finding["description"])))
    if finding["evidence"]:
        parts.append("<h3>Evidence</h3>")
        parts.append("<pre>{}</pre>".format(esc(finding["evidence"])))
    if finding["fix"]:
        parts.append("<h3>Suggested fix</h3>")
        parts.append("<p>{}</p>".format(esc(finding["fix"])))
    if finding["refs"]:
        parts.append("<h3>References</h3>")
        parts.append('<div class="refs">{}</div>'.format(
            "".join('<span class="ref">{}</span>'.format(esc(r)) for r in finding["refs"])))
    if finding.get("source"):
        parts.append("<h3>Parsed from</h3>")
        parts.append('<p><span class="where">{}</span></p>'.format(esc(finding["source"])))
    parts.append("</div></details>")
    return "\n".join(parts)


def build_report(args, findings, notes, log_text):
    counts = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    total = len(findings)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    is_url = str(args.target).startswith(("http://", "https://"))

    body = ['<div class="masthead">',
            '<span class="label">Strix &middot; automated security assessment</span>',
            "<h1>{}</h1>".format(esc(args.repo or "Security scan")),
            '<p class="strap">{}</p>'.format(
                "Black-box assessment of a live target."
                if is_url else
                "Code-level assessment of the repository at this commit."),
            '<div class="facts">',
            fact("Target", args.target),
            fact("Mode", "live URL" if is_url else "source tree"),
            fact("Commit", (args.commit or "")[:12]),
            fact("Depth", args.depth),
            fact("Model", args.model),
            fact("Generated", generated),
            "</div></div>"]

    body.append(render_ribbon(counts, total))

    if findings:
        body.append('<h2 class="section">Findings</h2>')
        body.extend(render_finding(f) for f in findings)
    else:
        body.append('<h2 class="section">Findings</h2>')
        body.append(
            '<div class="empty">'
            "<p><strong>No findings could be parsed from this run.</strong></p>"
            "<p>That is not the same as a clean result. It means no JSON object "
            "in the run output carried a recognisable severity field &mdash; the "
            "scan may have found nothing, or the report format may differ from "
            "what this page knows how to read. Check the transcript below before "
            "drawing a conclusion.</p></div>")

    for name, text in notes:
        body.append('<h2 class="section">{}</h2>'.format(esc(name)))
        body.append("<pre>{}</pre>".format(esc(redact(text))))

    if log_text:
        body.append('<h2 class="section">Run transcript</h2>')
        body.append('<details class="finding" data-sev="info">')
        body.append('<summary><span class="sev sev-info">log</span>'
                    '<span class="headline">Full scan output</span></summary>')
        body.append('<div class="panel"><pre>{}</pre></div>'.format(esc(redact(log_text))))
        body.append("</details>")

    footer = ["<footer>"]
    if args.run_url:
        footer.append('Workflow run: <a href="{u}">{u}</a><br>'.format(u=esc(args.run_url)))
    footer.append("Generated {} &middot; findings discovered structurally from run output "
                  "&middot; credentials matching known key formats are redacted"
                  .format(esc(generated)))
    footer.append("</footer>")
    body.extend(footer)

    title = "Strix report — {}".format(args.repo or args.target)
    return (SHELL
            .replace("__CSS__", CSS)
            .replace("__JS__", JS)
            .replace("__TITLE__", esc(title))
            .replace("__BODY__", "\n".join(body)))


def main():
    parser = argparse.ArgumentParser(description="Render Strix output as HTML.")
    parser.add_argument("--run-dir", default="agent_runs")
    parser.add_argument("--log", default="strix-output.log")
    parser.add_argument("--out", default="strix-report/report.html")
    parser.add_argument("--repo", default="")
    parser.add_argument("--commit", default="")
    parser.add_argument("--target", default="./")
    parser.add_argument("--model", default="")
    parser.add_argument("--depth", default="")
    parser.add_argument("--run-url", default="")
    parser.add_argument("--summary-out", default="",
                        help="Optional path to write a one-line severity tally.")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    findings = load_findings(run_dir)
    notes = collect_notes(run_dir)

    log_text = ""
    log_path = Path(args.log)
    if log_path.is_file():
        try:
            log_text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            log_text = ""
        # Keep the page usable if the agent was chatty.
        limit = 200_000
        if len(log_text) > limit:
            log_text = ("[transcript truncated to the last {} characters]\n\n".format(limit)
                        + log_text[-limit:])

    # Redact inside findings too, not just free text.
    for finding in findings:
        for key in ("title", "description", "location", "evidence", "fix"):
            finding[key] = redact(finding[key])

    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(build_report(args, findings, notes, log_text), encoding="utf-8")

    counts = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    tally = " ".join("{}={}".format(s, counts.get(s, 0)) for s in SEVERITY_ORDER)

    print("Report written to {}".format(output))
    print("Findings parsed: {} ({})".format(len(findings), tally))

    if args.summary_out:
        Path(args.summary_out).write_text(
            json.dumps({"total": len(findings), "counts": counts}), encoding="utf-8")

    # Exit code communicates gate state: 2 means blocking severities present.
    if counts.get("critical") or counts.get("high"):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
