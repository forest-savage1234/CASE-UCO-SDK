# Review notes: SDK note: layered composition of trajectories

_Working notes for the contributor. Not part of the issue. Work through them before filing at https://github.com/ucoProject/UCO/issues/new._

## Lint findings

- **info** `no_contributor_statements` (proposal): Every statement is AI-drafted or cited. Mark the statements the contributor wrote or approved as provenance='contributor'.
- **warning** `vocabulary_definition_ai_drafted` (Term 1): Quote the UCO definition and cite it instead of an AI paraphrase.

## Confirm by hand

- [ ] Term 1: opened https://ontology.unifiedcyberontology.org/uco/core/Relationship; it resolves and supports the text: "An open-vocabulary link between UcoObjects. A composition edge may cite one, and the comp…"
- [ ] background[1]: opened https://github.com/ucoProject/UCO/issues/682; it resolves and supports the text: "CASE/UCO can record one investigation and one Relationship edge, and this SDK already has…"
- [ ] Read all 11 *[AI-drafted]* statement(s). Keep, rewrite (then mark as the contributor's), or delete each one
- [ ] Every CASE/UCO/CAC term named exists in the target release (lint found none missing)
- [ ] No single jurisdiction, legal system, or locale is treated as the default
- [ ] Things that should be objects (statutes, people, organizations, roles) are not stood in for by strings
- [ ] Roles are kept distinct from the people or organizations that hold them
- [ ] Sources are not circular: no AI-drafted statement is cited as support for itself
- [ ] Existing vocabularies were considered before new terms (for example SOSA/SSN, PROV-O, schema.org)
- [ ] check_existing_proposals was run, and related or duplicate issues are linked

## Companion files

None (no proposed classes or properties were given). The extension package is ported by hand under `extensions/layered/`. This note is not filed. `check_existing_proposals` returned HTTP 403 on CASE and CAC. The cited near-miss is UCO issue 682 (Capability) and `uco-core:Relationship`, which can name a link and does not compose trajectories.
