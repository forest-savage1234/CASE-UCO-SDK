<!-- Change proposal: SDK note: layered composition of trajectories -->
<!-- Target repository: UCO -->

**Suggested target release:** CASE/UCO 1.6.0  
**Contributor:** Mrinaal (@mrinaalr) with the assistance of the CASE/UCO SDK MCP/Agent (v1.31.1) powered by Grok 4.7

_This is a discussion draft, not a finished design. Every part of it is open to challenge; the open questions are where input is most wanted._

_Unmarked statements are the contributor's ideas. Statements marked *[from …]* come from the person or publication cited. Statements marked *[AI-drafted]* were written by an AI assistant, not supplied by the contributor._

# Background

CASE/UCO can record one investigation and one Relationship edge, and this SDK already has a thin trajectories extension for a single ordered occupancy. A case that runs several machines at once (a grooming path and a transit path, or a warrant path and a concurrent monitoring path) has no composition class that keeps each alphabet separate. uco-core:Relationship can name a link, but it does not say which trajectory is a layer, whether the case is sequential or concurrent, or whether a layer covers the whole alphabet. This local SDK extension records that composition. It is not a request to file the classes in CASE or UCO. Capability for a later selection rule remains open at https://github.com/ucoProject/UCO/issues/682. *[AI-drafted]*

# Competency questions

**Scenario:** A newspaper account describes one person whose conduct occupies a grooming path, a transit-and-harboring path, a labor path, and a trafficking path. Each path keeps its own states. The case also has a separate legal-process machine (warrant, custody, and overlapping monitoring) that must validate without an exploitation test. *[AI-drafted]*

## CQ 1

- **Question:** Can one case compose several trajectories without merging their states into one alphabet? *[AI-drafted]*
- **Expected answer:** Yes. An ExploitationStateMachine has one or more Layers, and each Layer occupies exactly one Trajectory. *[AI-drafted]*

## CQ 2

- **Question:** Can a legal-process machine use the same composition classes and omit any benefit-at-expense assessment? *[AI-drafted]*
- **Expected answer:** Yes. hasExpenseAssessment is optional and is omitted. The legal-process exemplar does not import an expense ontology. *[AI-drafted]*

## CQ 3

- **Question:** Where does a stable goal sit when a menu vocabulary is loaded later? *[AI-drafted]*
- **Expected answer:** On hasGoal, ranged only to UcoObject. The composition ontology does not import the menu ontology, so the range stays loose. *[AI-drafted]*

# Requirements

## Term 1: Relationship (UCO)

- **Definition:** An open-vocabulary link between UcoObjects. A composition edge may cite one, and the composition class remains the authority for how two layers meet. *[AI-drafted]*
- **Might connect to:** Coupling realizedBy *[AI-drafted]*

# Open questions

1. Should hasGoal narrow to a menu Goal class once the import cycle between composition and the menu vocabulary has a safe shape? *[AI-drafted]*

# Related issues and references

- https://github.com/ucoProject/UCO/issues/682
- https://github.com/vulnmaster/CASE-UCO-SDK/blob/main/docs/recipes/candidates/layered-esm-composition.md

---

<details>
<summary><b>Committee section</b> (to be filled out during review)</summary>

## Benefits and risks

To be filled out by the committee.

## Proposed ontology changes

To be filled out by the committee.

## Competency question queries and example data

To be filled out by the committee.

## Review checklist

- [ ] Each defined term has an agreed definition and connection point
- [ ] Benefits and risks recorded from discussion
- [ ] Proposed ontology changes drafted and linked
- [ ] Each competency question has a SPARQL query tested against example data
- [ ] Example instance data passes `case_validate`
- [ ] No "To be filled out by the committee." placeholders remain

</details>
