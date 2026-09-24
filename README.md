# AgentGuard

[![CI](https://github.com/asher0913/agent-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/asher0913/agent-guard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An explainable policy-enforcement gateway for AI agent tool calls. AgentGuard evaluates each
proposed action before execution and returns one of three decisions: `allow`,
`require_approval`, or `deny`.

The project focuses on the layer between an LLM and real tools—where prompt injection,
over-broad permissions, destructive commands, and accidental data exfiltration become concrete
security risks.

## What it protects

- Destructive shell commands and broad filesystem targets
- Credential or personal-data fields sent through external tools
- Prompt-injection content propagated into tool arguments
- Mutating actions attempted without the required scope
- Multi-step trajectories that become unsafe after benign initial actions

Every result includes a bounded risk score, human-readable reasons, and stable rule identifiers
for audit logs and downstream policy analytics.

## Request flow

```text
agent plan -> tool call -> AgentGuard policy engine -> allow -> tool executor
                                      |              -> approval queue
                                      +--------------> deny + audit record
```

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest

agent-guard-benchmark
uvicorn agent_guard.api:app --reload
```

Evaluate one tool call:

```bash
curl -X POST http://localhost:8000/v1/evaluate \
  -H 'content-type: application/json' \
  -d '{"tool":"execute_shell","arguments":{"command":"rm -rf /"}}'
```

Example response:

```json
{
  "action": "deny",
  "risk_score": 100,
  "reasons": ["destructive shell pattern detected"],
  "matched_rules": ["shell.destructive"]
}
```

## Evaluation

The included adversarial fixture benchmark measures precision, recall, and false-positive rate
across destructive commands, exfiltration attempts, prompt injection, and benign tool calls. It
is deliberately small and transparent: reported results describe these checked-in fixtures, not
general real-world security performance.

## Production extensions

- Organization-specific policy packs and signed rule releases
- Persistent, tamper-evident audit events
- Statistical and model-based detectors alongside deterministic rules
- Approval workflow adapters for Slack, Teams, and ticketing systems

## License

MIT
