# K8s Compliance Scanner

A security tool that analyzes Kubernetes manifests for misconfigurations
using a deterministic rule engine, maps each finding to real compliance
framework controls, and uses Claude to generate a plain-English executive
summary on top of the findings.

## How it works

Compliance mapping is **not** left to the AI model to guess. `rules.py`
parses each manifest (Pods, and pod templates inside Deployments,
StatefulSets, DaemonSets, Jobs, and CronJobs) and runs it against a fixed
set of checks. Every check maps to a rule ID in `controls.py`, which
carries a hardcoded severity and citations to:

- CIS Kubernetes Benchmark
- NIST SP 800-53 Rev. 5
- PCI DSS v4.0
- SOC 2 Trust Services Criteria

Where a framework genuinely doesn't have a relevant control for a check
(e.g. missing resource limits isn't a PCI DSS data-security requirement),
the table says so explicitly (`N/A`) instead of forcing a mapping. See the
docstring in `controls.py` for the benchmark versions the citations are
based on — verify them against the exact version in scope before using
this in an actual audit artifact.

Claude is only used to write a short narrative summary contextualizing
the deterministic findings for a specific manifest — it's explicitly
instructed not to invent findings, severities, or control numbers. Run
with `--offline` to skip that call entirely and get rule-based findings
only, no API key required.

## What it does

- Scans Kubernetes YAML manifests (single or multi-document) for security
  misconfigurations: privileged containers, host namespace sharing, root
  users, missing `securityContext` hardening, hardcoded plaintext secrets,
  `latest`-tagged images, missing resource limits, and more
- Rates each finding by severity: HIGH, MEDIUM, or LOW, fixed per rule
- Maps every finding to CIS Kubernetes Benchmark, NIST 800-53, PCI DSS,
  and SOC 2 controls from a static, auditable table
- Generates a professional HTML report with remediation guidance

## Why I built this

I spent 8 years as an ISSO ensuring systems had their ATO 
before moving into DevOps work. I built this tool to bridge 
the gap between compliance requirements and real infrastructure 
— using AI to make security reviews faster and more accessible.

## Tech stack

- Python 3
- Anthropic Claude API
- YAML parsing

## Setup

1. Clone the repo
2. Create a virtual environment: `python3 -m venv venv`
3. Activate it: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Create a `.env` file with your API key: 
   `ANTHROPIC_API_KEY=your-key-here`
6. Run: `python3 scanner.py sample.yaml`
   (or `python3 scanner.py sample.yaml --offline` to skip the AI summary
   and get rule-based findings only, no API key needed)

## Output

The scanner generates two files:
- `report.txt` — plain text findings
- `report.html` — professional report with severity 
   badges and framework mappings

## Example

![Compliance Report Screenshot](ai-compliance-scanner-screenshot.png)