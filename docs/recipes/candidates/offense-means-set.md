# Means action-space

> Candidate recipe (see [candidates/README.md](README.md)); not in the [Recipe Index](../INDEX.md) until the extension is promoted. Extension: [`extensions/means/`](../../../extensions/means/).
> Related: [layered-esm-composition.md](layered-esm-composition.md), [expense-benefit-at-expense.md](expense-benefit-at-expense.md), [cross-ontology-composition.md](../cross-ontology-composition.md).

Record the action-space a walked `traj:Transition` was chosen from. Use this when one stable goal has more than one instrument, and the graph needs to say which one was walked without claiming the actor optimized. The extension name is `means`.

## When to use

| Need | Class |
|---|---|
| Stable end, shared by several means | `means:Goal` |
| A means at a state, walked or only available | `means:Option` |
| What this actor can actually use | `means:OffenderCapability` |
| A wall, guardian, or access denial | `means:Constraint` |
| Analyst friction and feasibility | `means:OptionAssessment` |
| Which option was treated as chosen | `means:Selection` |

Leave the walked technique on `traj:enactsAction` and the affordance on `uco-action:instrument`. Point `means:usesInstrument` at that same object. Put the stable goal on the case machine with `lay:hasGoal`. The options available at a state are the action-space. A constraint removes an option from it. Friction leaves the option in it.

`selectionRule` is `not_modeled`, `satisficing`, `discrete_choice`, or `opportunistic`. Use `not_modeled` unless a rule is actually being claimed. Do not store a reward here. Do not store ease on `traj:guard` or on `traj:transitionProbability`.

## Validate

```python
from case_uco.validation import validate_graph_file

validate_graph_file(
    "extensions/means/means-exemplar.ttl",
    extensions=["means"],
    profiles=["time", "prov-o"],
    strict_concepts=True,
    force_rdfs_inference=True,
)
```

Worked case: [`means-exemplar.ttl`](../../../extensions/means/means-exemplar.ttl).
