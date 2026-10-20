# Expense benefit-at-expense test (`expense`)

Status: **candidate** · version **0.5.0**

Optional exploitation predicate for a `traj:Trajectory`. `trajectories` stays at 0.3.1 and does not declare these classes. A warrant return, a legal-process machine, and the SI adoption path omit this extension.

| Class | Role |
|---|---|
| `expense:BenefitAnatomy` | Facts about one transition. `benefitSource` is derived. |
| `expense:ExploitationAssessment` | Whether the trajectory passes the benefit-at-expense test. Disjoint from `traj:PhaseAssertion`. |

The test passes (`extractionTestStatus "realized_at_expense"`) when an identified person supplies the gain, does not keep it, and the instrument alleges deception, coercion, or a vulnerability. A preexisting object can pass the narrower extraction half. Activity and use can pass the expense half and fail the object half. Naming a minor is not a pass. A completed offense whose gain is not a person's fails.

`depends_on` is `trajectories` only. Validate with `case-utils` 0.18.0 and `--built-version case-1.5.0`.

## Files

| File | Role |
|---|---|
| `expense.ttl` | T-Box |
| `expense-shapes.ttl` | SHACL, including derived `benefitSource` |
| `expense-exemplar.ttl` | Pass and fail fixtures that conform |
| `expense-invalid-exemplar.ttl` | Must fail (contradicting `benefitSource`, minor auto-pass, and related rejects) |

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

`expense-invalid-exemplar.ttl` must report `Conforms: False`.

- Recipe: [`docs/recipes/candidates/expense-benefit-at-expense.md`](../../docs/recipes/candidates/expense-benefit-at-expense.md)
