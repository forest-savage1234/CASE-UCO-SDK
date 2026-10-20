# Expense benefit-at-expense test

> Candidate recipe (see [candidates/README.md](README.md)); not in the [Recipe Index](../INDEX.md) until the extension is promoted. Extension: [`extensions/expense/`](../../../extensions/expense/).
> Related: [layered-esm-composition.md](layered-esm-composition.md), [offense-means-set.md](offense-means-set.md).

Optional test over a `traj:Trajectory`: whether harm to a person is the source of the gain. Keep this off warrant returns, legal-process machines, and the SI adoption path.

## When to use

| Need | Class |
|---|---|
| Facts about who supplied the gain | `expense:BenefitAnatomy` |
| Pass / fail of the SEP predicate | `expense:ExploitationAssessment` |

`benefitSource` is derived from the anatomy facts. Do not hand-set a string those facts would not derive. Status token is `realized_at_expense`. Naming a minor is not a pass.

Attach the assessment from a layered machine with `lay:hasExpenseAssessment` when `layered` is loaded. This ontology does not import `layered`.

## Validate

```bash
case_validate --built-version case-1.5.0 \
  --ontology-graph extensions/trajectories/trajectories.ttl \
  --ontology-graph extensions/trajectories/trajectories-shapes.ttl \
  --ontology-graph extensions/expense/expense.ttl \
  --ontology-graph extensions/expense/expense-shapes.ttl \
  --inference rdfs --allow-info \
  extensions/expense/expense-exemplar.ttl
```

`expense-invalid-exemplar.ttl` must fail.
