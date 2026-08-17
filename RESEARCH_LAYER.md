# Research layer (contributor fork only)

This file is the preservation map for work that must **not** be forced
into official CASE/UCO SDK 1.x PRs. Official-track recuts live on
`vulnmaster/main`. The large trees stay here.

**Freeze tag (fork only):** `research-freeze/sdk-advanced-tree-5b1758c`  
**Frozen commit:** `5b1758c`  
**Branch:** `feature/v2-capability-defining-rearchitecture`

Do not push this tag to `vulnmaster/CASE-UCO-SDK`.

## Policy

- Stay on the 1.x line. No 2.0.0 / 2.0.1 version transition.
- One cohesive capability per official PR, ideally six or fewer
  substantive changes, based on current `vulnmaster/main`.
- Synthetic / public-safe fixtures only.
- No licensed catalog schemas, no product-internal hash algorithms, no
  automatic CSAM classification.

## Official-track recuts (opened 16–17 August 2026)

| Item | PR | Status |
|---|---|---|
| Composition Profiles catalog | [vulnmaster/CASE-UCO-SDK#110](https://github.com/vulnmaster/CASE-UCO-SDK/pull/110) | Open |
| Topology / semantic-spine docs | [#111](https://github.com/vulnmaster/CASE-UCO-SDK/pull/111) | Open |
| Generic fluent helpers | [#112](https://github.com/vulnmaster/CASE-UCO-SDK/pull/112) | Open |
| Method-aware hash index | [#113](https://github.com/vulnmaster/CASE-UCO-SDK/pull/113) | Open |
| Continuous critique wrapper (existing MCP critic) | [#114](https://github.com/vulnmaster/CASE-UCO-SDK/pull/114) | Open |
| Bounded offline adapter interface | [#115](https://github.com/vulnmaster/CASE-UCO-SDK/pull/115) | Open |
| Generic UCO perceptual-hash proposal | [#116](https://github.com/vulnmaster/CASE-UCO-SDK/pull/116) | Open (optional) |

Related official-track work outside this SDK:

| Item | PR | Status |
|---|---|---|
| CAC SHACL-SPARQL syntax | [CAC-Ontology#48](https://github.com/Project-VIC-International/CAC-Ontology/pull/48) | Ready for review |
| CAC DigitalService → OnlineService | [CAC-Ontology#50](https://github.com/Project-VIC-International/CAC-Ontology/pull/50) | Ready for review |
| CaseLinker Stage 1 / M01 | [CaseLinker#5](https://github.com/mrinaalr/CaseLinker/pull/5) | Draft open |

## Closed large PRs (disposition recorded)

- [#106](https://github.com/vulnmaster/CASE-UCO-SDK/pull/106) — Topology Articulation Framework. Closed; recut map in the closing comments.
- [#107](https://github.com/vulnmaster/CASE-UCO-SDK/pull/107) — v2 construction re-architecture. Closed; 2.x version transition is not carried forward.

## Kept only in this research layer

- 2.0.0 / 2.0.1 version metadata and package framing
- Workflow engine, named workflows, and parallel partition handlers
- `python/case_uco/critique/` duplicate critic
- `model_csam_evidence` and any auto-classifier
- PhotoDNA / VICS adapter implementations and catalog schemas
- Namespace-based `partition_by_profile` (v1.24.0 already has safer partitioning)
- Incremental-generator cache design
- Large timestamped topology inventories

## How to refresh this file

After each official recut is opened or merged, update the table above.
If the advanced tree moves, create a new fork-only tag
`research-freeze/sdk-advanced-tree-<shortsha>` and point this file at it.
Do not retag a published freeze.
