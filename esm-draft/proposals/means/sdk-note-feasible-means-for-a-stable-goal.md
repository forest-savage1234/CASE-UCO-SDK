<!-- Change proposal: SDK note: feasible means for a stable goal -->
<!-- Target repository: UCO -->

**Suggested target release:** CASE/UCO 1.6.0  
**Contributor:** Mrinaal (@mrinaalr) with the assistance of the CASE/UCO SDK MCP/Agent (v1.31.1) powered by Grok 4.7

_This is a discussion draft, not a finished design. Every part of it is open to challenge; the open questions are where input is most wanted._

_Unmarked statements are the contributor's ideas. Statements marked *[from …]* come from the person or publication cited. Statements marked *[AI-drafted]* were written by an AI assistant, not supplied by the contributor._

# Background

trajectories records the edge that was walked and the instrument on that edge. It does not record the other means a source names for the same stable goal, what put a means on the menu, or what took a means off. uco-action:Action is the walked act. UCO issue 682 proposes Capability for a person or tool and is still open; this local vocabulary does not file a second capability class. OffenderCapability is a local stand-in until that class exists. The menu stores no reward and no Bellman policy. *[AI-drafted]*

# Competency questions

**Scenario:** An affidavit names two ways the same cash-collection goal was carried out, months apart, by different runners: a rideshare handoff and a UPS shipment. Each is its own path. The source names both means. It does not say the runners compared them as one menu on one day. *[AI-drafted]*

## CQ 1

- **Question:** Does CASE/UCO already record the menu of means at a state, including a means the trajectory did not walk? *[AI-drafted]*
- **Expected answer:** No. Core has Action and instrument on the walked edge. It has no class for a means that was available and not walked. *[AI-drafted]*

## CQ 2

- **Question:** Where does an actor's ability to use one of those means go, given UCO issue 682? *[AI-drafted]*
- **Expected answer:** OffenderCapability is a local stand-in ranged beside the menu. It is not filed as a second Capability class. UCO issue 682 remains the upstream proposal. *[AI-drafted]*

## CQ 3

- **Question:** Can the menu store a reward or treat two independent realizations as one compared choice? *[AI-drafted]*
- **Expected answer:** No. The vocabulary defines no reward, utility float, or Bellman backup. selectionRule not_modeled is a legal value, and two independent realizations are two paths rather than one Selection. *[AI-drafted]*

# Requirements

## Term 1: Capability (UCO)

- **Definition:** Add Capability class and capability namespace to support modular, graph-based capability assertions (Tool/Module/Parser decomposition). *[from [UCO issue 682](https://github.com/ucoProject/UCO/issues/682)]*
- **Might connect to:** OffenderCapability is a local stand-in and is not a second filing of that class. *[AI-drafted]*

# Open questions

1. Once UCO 682 lands, should OffenderCapability be retired in favor of that class, or remain a role that points at it? *[AI-drafted]*

# Related issues and references

- https://github.com/ucoProject/UCO/issues/682
- https://github.com/vulnmaster/CASE-UCO-SDK/blob/main/docs/recipes/candidates/offense-means-set.md

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
