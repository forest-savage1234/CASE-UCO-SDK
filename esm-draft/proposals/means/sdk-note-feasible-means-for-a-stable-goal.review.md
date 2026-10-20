# Review notes: SDK note: feasible means for a stable goal

_Working notes for the contributor. Not part of the issue. Work through them before filing at https://github.com/ucoProject/UCO/issues/new._

## Lint findings

- **info** `no_contributor_statements` (proposal): Every statement is AI-drafted or cited. Mark the statements the contributor wrote or approved as provenance='contributor'.

## Confirm by hand

- [ ] Term 1: opened https://github.com/ucoProject/UCO/issues/682; it resolves and supports the text: "Add Capability class and capability namespace to support modular, graph-based capability …"
- [ ] Term 1 definition: opened https://github.com/ucoProject/UCO/issues/682; it resolves and supports the text: "Add Capability class and capability namespace to support modular, graph-based capability …"
- [ ] Term 1 definition: the *[from UCO issue 682]* tag links the exact comment or page quoted, and the quote is accurate
- [ ] Read all 10 *[AI-drafted]* statement(s). Keep, rewrite (then mark as the contributor's), or delete each one
- [ ] Every CASE/UCO/CAC term named exists in the target release (lint found none missing)
- [ ] No single jurisdiction, legal system, or locale is treated as the default
- [ ] Things that should be objects (statutes, people, organizations, roles) are not stood in for by strings
- [ ] Roles are kept distinct from the people or organizations that hold them
- [ ] Sources are not circular: no AI-drafted statement is cited as support for itself
- [ ] Existing vocabularies were considered before new terms (for example SOSA/SSN, PROV-O, schema.org)
- [ ] check_existing_proposals was run, and related or duplicate issues are linked

This note is not filed. `check_existing_proposals("capability")` on UCO returned issue 682 as the near-miss. The extension package is ported by hand under `extensions/means/`.

## Companion files

None (no proposed classes or properties were given).
