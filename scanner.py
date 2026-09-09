import argparse
import html
import os
import sys
from datetime import datetime

from dotenv import load_dotenv

from controls import SEVERITY_ORDER
from rules import check_manifest

load_dotenv()

MODEL = "claude-sonnet-4-6"


def get_client():
    import anthropic

    return anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


def build_ai_summary(manifest_text, findings, file_path):
    """Ask Claude for a short narrative synthesis of the findings.

    The model is deliberately NOT asked to decide severity or compliance
    mapping -- those come from the deterministic rule table in controls.py.
    Its only job here is to write plain-English context for a human reader.
    """
    if not findings:
        finding_lines = "(no deterministic findings were triggered)"
    else:
        finding_lines = "\n".join(
            f"- [{f.severity}] {f.title} ({f.resource_kind}/{f.resource_name}, {f.location})"
            for f in findings
        )

    prompt = f"""You are a security-focused DevOps engineer with a compliance background.

A rule-based scanner already analyzed the Kubernetes manifest below and produced
the findings listed. Do NOT invent new findings, change severities, or cite
compliance control numbers -- that has already been done deterministically.

Your only job: write a short (3-6 sentence) plain-English executive summary
that explains, in context, how these specific findings combine to create risk
for someone reviewing this manifest for the first time.

File: {file_path}

Findings:
{finding_lines}

Manifest:
{manifest_text}"""

    message = get_client().messages.create(
        model=MODEL,
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )

    return message.content[0].text.strip()


def severity_counts(findings):
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] += 1
    return counts


def save_text_report(findings, summary, manifest_path, report_path="report.txt"):
    counts = severity_counts(findings)
    timestamp = datetime.now().strftime("%B %d, %Y at %H:%M")

    lines = [
        "K8s Compliance Scan Report",
        f"Manifest: {manifest_path}",
        f"Generated: {timestamp}",
        "",
        "SUMMARY",
        summary,
        "",
        f"FINDINGS ({len(findings)} total: {counts['HIGH']} High, "
        f"{counts['MEDIUM']} Medium, {counts['LOW']} Low)",
        "",
    ]

    for f in findings:
        meta = f.meta
        lines.append(f"[{f.severity}] {f.title}")
        lines.append(f"  Resource: {f.resource_kind}/{f.resource_name} ({f.location})")
        if f.detail:
            lines.append(f"  Detail: {f.detail}")
        lines.append(f"  CIS: {meta['cis']}")
        lines.append(f"  NIST 800-53: {meta['nist_800_53']}")
        lines.append(f"  PCI DSS: {meta['pci_dss']}")
        lines.append(f"  SOC 2: {meta['soc2']}")
        lines.append(f"  Remediation: {meta['remediation']}")
        if meta.get("note"):
            lines.append(f"  Note: {meta['note']}")
        lines.append("-" * 60)

    output = "\n".join(lines)
    with open(report_path, "w") as f:
        f.write(output)
    print(f"Text report saved to {report_path}")


def _finding_card_html(f):
    meta = f.meta
    detail_html = (
        f'<div class="finding-detail">{html.escape(f.detail)}</div>' if f.detail else ""
    )
    note_html = (
        f'<div class="finding-note">Note: {html.escape(meta["note"])}</div>'
        if meta.get("note")
        else ""
    )
    return f"""
        <div class="finding-card {f.severity.lower()}">
            <div class="finding-head">
                <span class="badge {f.severity.lower()}">{f.severity}</span>
                <span class="finding-title">{html.escape(f.title)}</span>
            </div>
            <div class="finding-resource">{html.escape(f.resource_kind)}/{html.escape(f.resource_name)} &middot; {html.escape(f.location)}</div>
            {detail_html}
            <div class="control-grid">
                <div><span class="control-label">CIS</span>{html.escape(meta['cis'])}</div>
                <div><span class="control-label">NIST 800-53</span>{html.escape(meta['nist_800_53'])}</div>
                <div><span class="control-label">PCI DSS</span>{html.escape(meta['pci_dss'])}</div>
                <div><span class="control-label">SOC 2</span>{html.escape(meta['soc2'])}</div>
            </div>
            <div class="remediation"><span class="control-label">Remediation</span>{html.escape(meta['remediation'])}</div>
            {note_html}
        </div>"""


def save_html_report(findings, summary, manifest_text, manifest_path, report_path="report.html"):
    timestamp = datetime.now().strftime("%B %d, %Y at %H:%M")
    counts = severity_counts(findings)

    findings_html = (
        "\n".join(_finding_card_html(f) for f in findings)
        if findings
        else '<p class="no-findings">No deterministic findings were triggered against the current rule set.</p>'
    )

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>K8s Compliance Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0d1117;
            color: #e6edf3;
            line-height: 1.7;
            min-height: 100vh;
        }}

        .header {{
            background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
            border-bottom: 1px solid #30363d;
            padding: 40px 60px;
        }}

        .header-top {{
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 24px;
        }}

        .logo {{
            width: 42px;
            height: 42px;
            background: linear-gradient(135deg, #58a6ff, #3fb950);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
        }}

        .header h1 {{
            font-size: 28px;
            font-weight: 700;
            color: #f0f6fc;
            letter-spacing: -0.5px;
        }}

        .header .subtitle {{
            font-size: 14px;
            color: #8b949e;
            margin-top: 4px;
        }}

        .meta-bar {{
            display: flex;
            gap: 32px;
            flex-wrap: wrap;
        }}

        .meta-item {{ display: flex; flex-direction: column; gap: 2px; }}

        .meta-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #8b949e;
            font-weight: 600;
        }}

        .meta-value {{
            font-size: 13px;
            color: #e6edf3;
            font-family: 'Courier New', monospace;
        }}

        .summary-bar {{
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 20px 60px;
            display: flex;
            gap: 16px;
            align-items: center;
            flex-wrap: wrap;
        }}

        .summary-label {{ font-size: 13px; color: #8b949e; font-weight: 600; margin-right: 8px; }}

        .severity-pill {{
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 0.5px;
        }}

        .severity-pill.high {{ background: rgba(248, 81, 73, 0.15); border: 1px solid rgba(248, 81, 73, 0.4); color: #f85149; }}
        .severity-pill.medium {{ background: rgba(210, 153, 34, 0.15); border: 1px solid rgba(210, 153, 34, 0.4); color: #d29922; }}
        .severity-pill.low {{ background: rgba(63, 185, 80, 0.15); border: 1px solid rgba(63, 185, 80, 0.4); color: #3fb950; }}

        .dot {{ width: 8px; height: 8px; border-radius: 50%; }}
        .high .dot {{ background: #f85149; }}
        .medium .dot {{ background: #d29922; }}
        .low .dot {{ background: #3fb950; }}

        .container {{
            max-width: 1100px;
            margin: 0 auto;
            padding: 40px 60px;
            display: grid;
            grid-template-columns: 1fr 320px;
            gap: 40px;
        }}

        .report-content {{ min-width: 0; }}

        .exec-summary {{
            background: #161b22;
            border: 1px solid #30363d;
            border-left: 3px solid #58a6ff;
            border-radius: 0 8px 8px 0;
            padding: 20px 24px;
            margin-bottom: 32px;
            font-size: 14px;
            color: #c9d1d9;
        }}

        .exec-summary h2 {{ font-size: 13px; text-transform: uppercase; letter-spacing: 1px; color: #58a6ff; margin-bottom: 10px; }}

        .finding-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-left: 3px solid #30363d;
            border-radius: 0 8px 8px 0;
            padding: 20px 24px;
            margin-bottom: 16px;
        }}

        .finding-card.high {{ border-left-color: #f85149; }}
        .finding-card.medium {{ border-left-color: #d29922; }}
        .finding-card.low {{ border-left-color: #3fb950; }}

        .finding-head {{ display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }}
        .finding-title {{ font-size: 15px; font-weight: 600; color: #f0f6fc; }}
        .finding-resource {{ font-size: 12px; color: #8b949e; font-family: 'Courier New', monospace; margin-bottom: 12px; }}
        .finding-detail {{ font-size: 12px; color: #8b949e; font-family: 'Courier New', monospace; margin-bottom: 12px; }}
        .finding-note {{ font-size: 12px; color: #8b949e; font-style: italic; margin-top: 8px; }}

        .control-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px 24px;
            font-size: 13px;
            color: #c9d1d9;
            margin-bottom: 12px;
        }}

        .control-label {{
            display: block;
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: #8b949e;
            font-weight: 600;
            margin-bottom: 2px;
        }}

        .remediation {{ font-size: 13px; color: #c9d1d9; }}

        .no-findings {{ color: #3fb950; font-size: 14px; }}

        .badge {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.8px;
            text-transform: uppercase;
        }}

        .badge.high {{ background: rgba(248, 81, 73, 0.15); color: #f85149; border: 1px solid rgba(248, 81, 73, 0.3); }}
        .badge.medium {{ background: rgba(210, 153, 34, 0.15); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.3); }}
        .badge.low {{ background: rgba(63, 185, 80, 0.15); color: #3fb950; border: 1px solid rgba(63, 185, 80, 0.3); }}

        .sidebar {{ position: sticky; top: 24px; align-self: start; }}

        .sidebar-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }}

        .sidebar-card h4 {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #8b949e;
            font-weight: 600;
            margin-bottom: 16px;
        }}

        .manifest-preview {{
            font-family: 'Courier New', monospace;
            font-size: 11px;
            color: #8b949e;
            line-height: 1.6;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 300px;
            overflow-y: auto;
        }}

        .stat-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid #21262d;
            font-size: 13px;
        }}

        .stat-row:last-child {{ border-bottom: none; }}
        .stat-label {{ color: #8b949e; }}
        .stat-value {{ font-weight: 600; color: #e6edf3; }}

        .footer {{
            text-align: center;
            padding: 40px 60px;
            border-top: 1px solid #30363d;
            font-size: 12px;
            color: #484f58;
        }}

        @media (max-width: 768px) {{
            .container {{ grid-template-columns: 1fr; padding: 24px; }}
            .header, .summary-bar {{ padding: 24px; }}
            .sidebar {{ position: static; }}
            .control-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>

    <div class="header">
        <div class="header-top">
            <div class="logo">🛡️</div>
            <div>
                <h1>K8s Compliance Scanner</h1>
                <div class="subtitle">Rule-based Kubernetes security analysis with AI-generated narrative</div>
            </div>
        </div>
        <div class="meta-bar">
            <div class="meta-item">
                <span class="meta-label">File Scanned</span>
                <span class="meta-value">{html.escape(manifest_path)}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Generated</span>
                <span class="meta-value">{timestamp}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Model</span>
                <span class="meta-value">{MODEL}</span>
            </div>
        </div>
    </div>

    <div class="summary-bar">
        <span class="summary-label">FINDINGS:</span>
        <div class="severity-pill high"><div class="dot"></div>{counts['HIGH']} High</div>
        <div class="severity-pill medium"><div class="dot"></div>{counts['MEDIUM']} Medium</div>
        <div class="severity-pill low"><div class="dot"></div>{counts['LOW']} Low</div>
    </div>

    <div class="container">
        <div class="report-content">
            <div class="exec-summary">
                <h2>Executive Summary</h2>
                {html.escape(summary)}
            </div>
            {findings_html}
        </div>

        <div class="sidebar">
            <div class="sidebar-card">
                <h4>Scan Summary</h4>
                <div class="stat-row"><span class="stat-label">Total Issues</span><span class="stat-value">{len(findings)}</span></div>
                <div class="stat-row"><span class="stat-label">High Severity</span><span class="stat-value" style="color: #f85149">{counts['HIGH']}</span></div>
                <div class="stat-row"><span class="stat-label">Medium Severity</span><span class="stat-value" style="color: #d29922">{counts['MEDIUM']}</span></div>
                <div class="stat-row"><span class="stat-label">Low Severity</span><span class="stat-value" style="color: #3fb950">{counts['LOW']}</span></div>
            </div>

            <div class="sidebar-card">
                <h4>Manifest Preview</h4>
                <div class="manifest-preview">{html.escape(manifest_text[:800])}{"..." if len(manifest_text) > 800 else ""}</div>
            </div>
        </div>
    </div>

    <div class="footer">
        Generated by K8s Compliance Scanner &nbsp;·&nbsp; Compliance mappings are rule-based, not AI-generated &nbsp;·&nbsp; {timestamp}
    </div>

</body>
</html>"""

    with open(report_path, "w") as f:
        f.write(html_doc)
    print(f"HTML report saved to {report_path}")


def run_scan(manifest_path, offline=False):
    with open(manifest_path, "r") as f:
        manifest_text = f.read()

    findings = check_manifest(manifest_text)
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])

    if offline or not os.getenv("ANTHROPIC_API_KEY"):
        summary = (
            "AI summary skipped (offline mode or no ANTHROPIC_API_KEY set). "
            "Findings below are from the deterministic rule engine only."
        )
    else:
        summary = build_ai_summary(manifest_text, findings, manifest_path)

    return findings, summary, manifest_text


def main():
    parser = argparse.ArgumentParser(description="Scan a Kubernetes manifest for compliance issues.")
    parser.add_argument("manifest", nargs="?", default="sample.yaml", help="Path to the manifest to scan")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip the AI narrative call and use rule-based findings only",
    )
    args = parser.parse_args()

    print(f"Scanning {args.manifest}...\n")
    findings, summary, manifest_text = run_scan(args.manifest, offline=args.offline)

    counts = severity_counts(findings)
    print(f"{len(findings)} findings ({counts['HIGH']} High, {counts['MEDIUM']} Medium, {counts['LOW']} Low)\n")
    print(summary, "\n")

    save_text_report(findings, summary, args.manifest)
    save_html_report(findings, summary, manifest_text, args.manifest)


if __name__ == "__main__":
    sys.exit(main())
