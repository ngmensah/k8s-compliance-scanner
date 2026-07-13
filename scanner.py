from dotenv import load_dotenv
import os
import anthropic
from datetime import datetime

load_dotenv()

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


def scan_manifest(file_path):
    with open(file_path, "r") as f:
        manifest = f.read()

    prompt = f"""You are a security-focused DevOps engineer with a compliance background.

Review the following Kubernetes manifest for security misconfigurations.

For each issue found:
- Give it a severity level: HIGH, MEDIUM, or LOW
- Explain what the problem is in plain English
- Explain why it matters from a compliance perspective
- Suggest how to fix it

Manifest:
{manifest}"""

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    return message.content[0].text, manifest


def save_text_report(output, report_path="report.txt"):
    with open(report_path, "w") as f:
        f.write(output)
    print(f"Text report saved to {report_path}")


def save_html_report(output, manifest, file_path, report_path="report.html"):
    timestamp = datetime.now().strftime("%B %d, %Y at %H:%M")

    # Count severities from output
    high = output.upper().count("HIGH")
    medium = output.upper().count("MEDIUM")
    low = output.upper().count("LOW")

    # Convert markdown-style content to basic HTML
    def convert_to_html(text):
        lines = text.split("\n")
        html_lines = []
        in_code_block = False
        in_table = False

        for line in lines:
            # Code blocks
            if line.strip().startswith("```"):
                if in_code_block:
                    html_lines.append("</code></pre>")
                    in_code_block = False
                else:
                    lang = line.strip().replace("```", "").strip()
                    html_lines.append(f'<pre><code class="language-{lang}">')
                    in_code_block = True
                continue

            if in_code_block:
                html_lines.append(
                    line.replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                )
                continue

            # Tables
            if line.strip().startswith("|"):
                if not in_table:
                    html_lines.append('<table>')
                    in_table = True
                if "---" in line:
                    continue
                cells = [c.strip() for c in line.split("|")[1:-1]]
                is_header = html_lines and "<table>" in html_lines[-2] if len(html_lines) >= 2 else False
                tag = "th" if is_header else "td"
                row = "".join(f"<{tag}>{c}</{tag}>" for c in cells)
                html_lines.append(f"<tr>{row}</tr>")
                continue
            else:
                if in_table:
                    html_lines.append("</table>")
                    in_table = False

            # Severity badges inline
            line = line.replace(
                "🔴 HIGH", '<span class="badge high">HIGH</span>'
            ).replace(
                "🟡 MEDIUM", '<span class="badge medium">MEDIUM</span>'
            ).replace(
                "🟢 LOW", '<span class="badge low">LOW</span>'
            )

            # Headings
            if line.startswith("## "):
                html_lines.append(f'<h2>{line[3:]}</h2>')
            elif line.startswith("### "):
                html_lines.append(f'<h3>{line[4:]}</h3>')
            elif line.startswith("# "):
                html_lines.append(f'<h1>{line[2:]}</h1>')
            # Bold
            elif line.strip().startswith("**") and line.strip().endswith("**"):
                html_lines.append(f'<p><strong>{line.strip()[2:-2]}</strong></p>')
            # Blockquote
            elif line.startswith("> "):
                html_lines.append(f'<blockquote>{line[2:]}</blockquote>')
            # List items
            elif line.strip().startswith("- "):
                html_lines.append(f'<li>{line.strip()[2:]}</li>')
            # Horizontal rule
            elif line.strip() == "---":
                html_lines.append('<hr>')
            # Empty line
            elif line.strip() == "":
                html_lines.append('<br>')
            # Regular paragraph
            else:
                html_lines.append(f'<p>{line}</p>')

        if in_table:
            html_lines.append("</table>")
        if in_code_block:
            html_lines.append("</code></pre>")

        return "\n".join(html_lines)

    body_content = convert_to_html(output)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>K8s Compliance Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0d1117;
            color: #e6edf3;
            line-height: 1.7;
            min-height: 100vh;
        }}

        /* Header */
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

        .meta-item {{
            display: flex;
            flex-direction: column;
            gap: 2px;
        }}

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

        /* Severity summary */
        .summary-bar {{
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 20px 60px;
            display: flex;
            gap: 16px;
            align-items: center;
            flex-wrap: wrap;
        }}

        .summary-label {{
            font-size: 13px;
            color: #8b949e;
            font-weight: 600;
            margin-right: 8px;
        }}

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

        .severity-pill.high {{
            background: rgba(248, 81, 73, 0.15);
            border: 1px solid rgba(248, 81, 73, 0.4);
            color: #f85149;
        }}

        .severity-pill.medium {{
            background: rgba(210, 153, 34, 0.15);
            border: 1px solid rgba(210, 153, 34, 0.4);
            color: #d29922;
        }}

        .severity-pill.low {{
            background: rgba(63, 185, 80, 0.15);
            border: 1px solid rgba(63, 185, 80, 0.4);
            color: #3fb950;
        }}

        .dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }}

        .high .dot {{ background: #f85149; }}
        .medium .dot {{ background: #d29922; }}
        .low .dot {{ background: #3fb950; }}

        /* Main layout */
        .container {{
            max-width: 1100px;
            margin: 0 auto;
            padding: 40px 60px;
            display: grid;
            grid-template-columns: 1fr 320px;
            gap: 40px;
        }}

        /* Report content */
        .report-content {{
            min-width: 0;
        }}

        h1 {{
            font-size: 22px;
            font-weight: 700;
            color: #f0f6fc;
            margin: 32px 0 12px;
            padding-bottom: 8px;
            border-bottom: 1px solid #30363d;
        }}

        h2 {{
            font-size: 18px;
            font-weight: 600;
            color: #58a6ff;
            margin: 28px 0 10px;
            padding: 16px 20px;
            background: #161b22;
            border-left: 3px solid #58a6ff;
            border-radius: 0 6px 6px 0;
        }}

        h3 {{
            font-size: 14px;
            font-weight: 600;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin: 20px 0 8px;
        }}

        p {{
            font-size: 14px;
            color: #c9d1d9;
            margin-bottom: 8px;
        }}

        li {{
            font-size: 14px;
            color: #c9d1d9;
            margin: 4px 0 4px 20px;
            list-style: disc;
        }}

        pre {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
            overflow-x: auto;
            margin: 12px 0;
        }}

        code {{
            font-family: 'Courier New', monospace;
            font-size: 13px;
            color: #e6edf3;
            line-height: 1.6;
        }}

        blockquote {{
            border-left: 3px solid #d29922;
            padding: 10px 16px;
            background: rgba(210, 153, 34, 0.08);
            border-radius: 0 6px 6px 0;
            font-size: 13px;
            color: #c9d1d9;
            margin: 12px 0;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 12px 0;
            font-size: 13px;
        }}

        th {{
            background: #161b22;
            color: #8b949e;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.8px;
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid #30363d;
        }}

        td {{
            padding: 10px 14px;
            border-bottom: 1px solid #21262d;
            color: #c9d1d9;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        hr {{
            border: none;
            border-top: 1px solid #30363d;
            margin: 32px 0;
        }}

        .badge {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.8px;
            text-transform: uppercase;
        }}

        .badge.high {{
            background: rgba(248, 81, 73, 0.15);
            color: #f85149;
            border: 1px solid rgba(248, 81, 73, 0.3);
        }}

        .badge.medium {{
            background: rgba(210, 153, 34, 0.15);
            color: #d29922;
            border: 1px solid rgba(210, 153, 34, 0.3);
        }}

        .badge.low {{
            background: rgba(63, 185, 80, 0.15);
            color: #3fb950;
            border: 1px solid rgba(63, 185, 80, 0.3);
        }}

        /* Sidebar */
        .sidebar {{
            position: sticky;
            top: 24px;
            align-self: start;
        }}

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

        .stat-row:last-child {{
            border-bottom: none;
        }}

        .stat-label {{
            color: #8b949e;
        }}

        .stat-value {{
            font-weight: 600;
            color: #e6edf3;
        }}

        .footer {{
            text-align: center;
            padding: 40px 60px;
            border-top: 1px solid #30363d;
            font-size: 12px;
            color: #484f58;
        }}

        @media (max-width: 768px) {{
            .container {{
                grid-template-columns: 1fr;
                padding: 24px;
            }}
            .header, .summary-bar {{
                padding: 24px;
            }}
            .sidebar {{
                position: static;
            }}
        }}
    </style>
</head>
<body>

    <div class="header">
        <div class="header-top">
            <div class="logo">🛡️</div>
            <div>
                <h1>K8s Compliance Scanner</h1>
                <div class="subtitle">AI-powered Kubernetes security analysis</div>
            </div>
        </div>
        <div class="meta-bar">
            <div class="meta-item">
                <span class="meta-label">File Scanned</span>
                <span class="meta-value">{file_path}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Generated</span>
                <span class="meta-value">{timestamp}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Model</span>
                <span class="meta-value">claude-sonnet-4-6</span>
            </div>
        </div>
    </div>

    <div class="summary-bar">
        <span class="summary-label">FINDINGS:</span>
        <div class="severity-pill high"><div class="dot"></div>{high} High</div>
        <div class="severity-pill medium"><div class="dot"></div>{medium} Medium</div>
        <div class="severity-pill low"><div class="dot"></div>{low} Low</div>
    </div>

    <div class="container">
        <div class="report-content">
            {body_content}
        </div>

        <div class="sidebar">
            <div class="sidebar-card">
                <h4>Scan Summary</h4>
                <div class="stat-row">
                    <span class="stat-label">Total Issues</span>
                    <span class="stat-value">{high + medium + low}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">High Severity</span>
                    <span class="stat-value" style="color: #f85149">{high}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Medium Severity</span>
                    <span class="stat-value" style="color: #d29922">{medium}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Low Severity</span>
                    <span class="stat-value" style="color: #3fb950">{low}</span>
                </div>
            </div>

            <div class="sidebar-card">
                <h4>Manifest Preview</h4>
                <div class="manifest-preview">{manifest[:800]}{"..." if len(manifest) > 800 else ""}</div>
            </div>
        </div>
    </div>

    <div class="footer">
        Generated by K8s Compliance Scanner &nbsp;·&nbsp; Powered by Claude AI &nbsp;·&nbsp; {timestamp}
    </div>

</body>
</html>"""

    with open(report_path, "w") as f:
        f.write(html)
    print(f"HTML report saved to {report_path}")


if __name__ == "__main__":
    manifest_path = "sample.yaml"

    print(f"Scanning {manifest_path}...\n")
    results, manifest = scan_manifest(manifest_path)

    print(results)
    save_text_report(results)
    save_html_report(results, manifest, manifest_path)