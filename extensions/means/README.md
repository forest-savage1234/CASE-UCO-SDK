# Means action-space (`means`)

Status: **candidate** · version **0.1.0**

The action-space behind a walked `traj:Transition`. `trajectories` records the edge that was walked. `layered` composes those edges into a case-level machine. This extension records the stable goal, the options in the action-space at a state, the actor's capability to use an option, a constraint that removes an option, and an inferred friction reading. The extension name stays `means`.

It does not define a reward. `selectionRule "not_modeled"` is the value to use when the graph must not claim that the actor optimized.

| Class | Role |
|---|---|
| `means:Goal` | Stable end. Not a reward, and not `R_G`. |
| `means:Option` | A means at a `traj:State`, walked or not. Cites `prov:wasDerivedFrom`. |
| `means:OffenderCapability` | What admits an option. Local stand-in for [UCO #682](https://github.com/ucoProject/UCO/issues/682). The class does not assert an offense by itself. |
| `means:Constraint` | A wall. Removes an option from the feasible set. |
| `means:OptionAssessment` | Friction. The option stays feasible and the cost rises. Cites `prov:wasGeneratedBy`. |
| `means:Selection` | Only when the record supports one compared menu. `selectionRule "not_modeled"` is a legal value. |

Friction levels are `low`, `moderate`, `high`, or `not_in_source`. Feasibility is `feasible` or `removed`. A high-friction option can remain feasible. A disrupted trajectory stays `traj:terminalPolarity "disrupted"` and is not restated here as a constraint.

`depends_on` is `trajectories` and `layered`. CAC `PlatformAffordance` remains the platform feature. Point `means:usesInstrument` at it when the case is a CAC case. Do not put perceived ease on that class.

## Exemplar

`means-exemplar.ttl` — United States v. Castanos Garcia (D. Mass.). One goal, move directed cash to the runners. Two options the affidavit names: rideshare (Agawam, February 2023, completed) and UPS (Attleboro, September–October 2022, disrupted). The ESM is `parallel` and `partial`: two independent realizations. They are not one `Selection`. The goal is on `lay:hasGoal`.

Friction levels in that file are an analyst reading. `selectionRule "not_modeled"` stays in the vocabulary for a menu a source actually compares.

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

`means-invalid-exemplar.ttl` must not conform.

- Recipe: [`docs/recipes/candidates/offense-means-set.md`](../../docs/recipes/candidates/offense-means-set.md)
