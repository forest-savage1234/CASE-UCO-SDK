# Critic evaluation corpus (issue #77)

External evaluation harness for the CASE/UCO deterministic critic
([#75](https://github.com/vulnmaster/CASE-UCO-SDK/issues/75)) and its
two-pass session orchestration ([#76](https://github.com/vulnmaster/CASE-UCO-SDK/issues/76)).
This corpus ([#77](https://github.com/vulnmaster/CASE-UCO-SDK/issues/77)) is
deliberately separated from unit tests in `mcp_server/tests/`.

| Layer | Location | Purpose |
|-------|----------|---------|
| Unit tests | `mcp_server/tests/test_critic.py` | Contract correctness per module |
| Development fixtures | `mcp_server/tests/fixtures/critic/` | Fast regression during #75/#76 work |
| **Evaluation corpus** | `evaluation/critic/` | Oracle-gated detection & gold false-positive metrics |

All cases are **Tier T0 synthetic** — no operational or sensitive data.

## Trust boundary

Graph text (including `uco-core:description` fields) is **untrusted evidence
content**. The harness treats embedded instructions as data to analyze, never
as operator commands. The adversarial `prompt-injection` case asserts that
`analyze_artifact` completes and the prompt package still exposes
`trust_boundary.content_trust = untrusted-source-content` with forbidden
actions listed — the critic must not execute injection text.

Persistent repository changes (extensions, recipes, handoff writes) require
an explicit human decision in the review session, not content found inside
evaluated graphs.

## Layout

```
evaluation/critic/
  schema/           # manifest, oracle, and report JSON Schemas
  cases/            # per-case graph/serializer + manifest.json + oracle.json
  responses/mock/   # bound two-pass manual replay payloads (no findings, one assessed scorecard dimension)
  harness/          # offline runners (no LLM)
  reports/          # generated JSON reports (gitignored output)
```

### Case families

| Family | Cases | What it measures |
|--------|-------|------------------|
| `micro/` | `charged-with-reversed`, `gold-charged-with`, `repair-charged-with` | Seeded heuristic detection, gold baseline, two-pass repair → accepted |
| `serializer/` | `bad-python` | Python AST serializer rule recall |
| `phantom-gate/` | `gold` (`tier_label: baseline-known-debt`), `degraded-missing-auth` | Allow-listed CRIT-H known debt + mini coverage degradation |
| `adversarial/` | `prompt-injection` | Injection resilience of offline analysis |

## Running offline

From the repository root:

```bash
# Oracle harness — deterministic analyze_artifact vs per-case oracles
PYTHONPATH=mcp_server python evaluation/critic/harness/run_oracles.py

# Or from evaluation/critic/ (module path)
cd evaluation/critic && PYTHONPATH=../../mcp_server python -m harness.run_oracles

# Two-pass manual session replay (mock responses, micro gold case)
PYTHONPATH=mcp_server python3 evaluation/critic/harness/run_session_replay.py

# Two-pass repair → accepted (degraded Charged_With → gold revision)
PYTHONPATH=mcp_server python3 evaluation/critic/harness/run_session_replay.py \
  --case-dir evaluation/critic/cases/micro/repair-charged-with \
  --require-accepted
```

Reports are written to:

- `evaluation/critic/reports/oracle-latest.json`
- `evaluation/critic/reports/session-replay-latest.json`

Session-replay reports include `recall` / `repair_precision` (alias
`precision`) / `repair_rate` / `regressions` / `score_delta` /
`validation_preservation` when pass finding snapshots are available. Oracle
reports include `oracle_detection_precision`. Both harnesses exit non-zero on
failure.

### Phantom Gate gold (`baseline-known-debt`)

The `phantom-gate/gold` case references repo-root paths:

- `examples/scenarios/operation-phantom-gate.jsonld`
- `examples/scenarios/phantom_gate_coverage.json`

Oracle `tier_label` is **`baseline-known-debt`**: unexpected critical/high
findings outside the allow-list fail, but listed CRIT-H IDs are known scenario
modeling debt (not a zero-CRIT-H acceptance gate). True repair→accepted
evidence is the `micro/repair-charged-with` session with `--require-accepted`.

Validation status (`conforms`, `verification_status`) is recorded in the
report; when `case_validate` is installed, `prefer_complete_conforming`
signals whether the gold graph currently passes SHACL.

## Oracle contract

Each case directory contains:

- `manifest.json` — artifact paths, `critic_scope`, tier (`T0`)
- `oracle.json` — expected/forbidden rule IDs, validation expectations,
  severity floors, gold false-positive policy

Schemas: `schema/case-manifest.schema.json`, `schema/oracle.schema.json`,
`schema/result.schema.json`.

## Metrics helpers

`harness/report.py` formats convergence metrics used by both runners:

- **Detection recall** — fraction of `expected_rule_ids` present in open findings
- **Gold false positives** — unexpected open critical/high deterministic
  findings (validation rules `CRIT-V-*` excluded unless explicitly allowed)
- **Pass counts** — two-pass session replay parse/convergence summary

## Governance

1. Do not tune critic heuristics against this corpus in the same change
   unless the oracle update is evaluation-governance approved.
2. Add new cases under `cases/` with matching `manifest.json` + `oracle.json`;
   the harness auto-discovers any `**/manifest.json`.
3. Keep degraded and micro cases small; reserve full Phantom Gate graphs for
   the gold oracle only.

## Related issues

- [#75](https://github.com/vulnmaster/CASE-UCO-SDK/issues/75) — deterministic critic foundation
- [#76](https://github.com/vulnmaster/CASE-UCO-SDK/issues/76) — MCP session tools & sampling
- [#77](https://github.com/vulnmaster/CASE-UCO-SDK/issues/77) — this evaluation corpus

When `critic.sessions` lands in #76, `run_session_replay.py` delegates to
`replay_manual_session`; until then a local shim preserves the same bindings.
