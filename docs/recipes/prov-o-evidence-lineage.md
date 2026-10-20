# PROV-O Evidence Lineage

> See [Recipe Index](INDEX.md) for all recipes.

Align CASE/UCO evidence and investigative actions with [W3C PROV-O](https://www.w3.org/TR/prov-o/) for interoperable provenance graphs. Domain objects stay primary; PROV-O types enrich the **same IRI** as `prov:Entity`, `prov:Activity`, or `prov:Agent`.

Issue: [#60](https://github.com/vulnmaster/CASE-UCO-SDK/issues/60)

## Scope

- Entity / Activity / Agent multi-typing rules
- `Tool` as instrument (`prov:Entity` + `prov:used`), not `prov:Agent` by default
- `ProvenanceRecord` vs acquisition `prov:Activity`
- Runnable exemplar: `examples/upper-ontology/prov-o-lineage/build_exemplar.py`

## PROV-O roles on CASE/UCO objects

| CASE/UCO class | PROV-O enrichment | Notes |
|---|---|---|
| `uco-observable:ObservableObject` | `prov:Entity` | Evidence, images, hashes |
| `case-investigation:InvestigativeAction` | `prov:Activity` | Imaging, parsing, verification |
| `uco-identity:Person` / examiner | `prov:Agent` | Human performer |
| `uco-tool:Tool` | `prov:Entity` | Used via `prov:used` — **not** an Agent unless autonomous |
| `case-investigation:ProvenanceRecord` | `prov:Entity` (optional) | Custody narrative container |

## Multi-typing rules

1. **Create domain object first** with `graph.create()`, then `graph.add_type(id, "prov:…")`.
2. **Lineage edges** use `graph.link(source_id, "prov:wasDerivedFrom", target_id)` and `prov:wasGeneratedBy` — never `create_relationship` for `prov:*` predicates.
3. **Association:** `prov:wasAssociatedWith` from Activity to Agent; `prov:used` from Activity to Entity (tool or input).
4. **One activity per forensic step.** Do not collapse imaging + hashing + verification into one Activity if the source distinguishes them.
5. **ProvenanceRecord ≠ Activity.** The record is a narrative index (`object` list); each custody/imaging step is its own `InvestigativeAction` / `prov:Activity`.

## ProvenanceRecord vs acquisition

| Concept | Model as | PROV-O analogue |
|---|---|---|
| Exhibit custody narrative | `ProvenanceRecord` + ordered `InvestigativeAction`s | Bundle of `prov:Entity` references |
| Single forensic operation | `InvestigativeAction` | `prov:Activity` |
| Derived image | `ObservableObject` | `prov:Entity` with `prov:wasDerivedFrom` + `prov:wasGeneratedBy` |
| Examiner | `Person` | `prov:Agent` |

See [chain-of-custody.md](chain-of-custody.md) for custody-specific action patterns.

## Python pattern

<details open><summary>Python</summary>

```python
from case_uco import CASEGraph
from case_uco.case.investigation import InvestigativeAction, ProvenanceRecord
from case_uco.uco.identity import Person
from case_uco.uco.observable import ObservableObject
from case_uco.uco.tool import Tool

graph = CASEGraph(extra_context={"prov": "http://www.w3.org/ns/prov#"})

examiner_id = "kb:examiner-1"
examiner = graph.create(Person, id=examiner_id, name="...")
graph.add_type(examiner_id, "prov:Agent")

tool_id = "kb:tool-1"
tool = graph.create(Tool, id=tool_id, name="...", version="...")
graph.add_type(tool_id, "prov:Entity")  # instrument, not Agent

source_id = "kb:source-1"
source = graph.create(ObservableObject, id=source_id, name="...")
graph.add_type(source_id, "prov:Entity")

image_id = "kb:image-1"
image = graph.create(ObservableObject, id=image_id, name="...")
graph.add_type(image_id, "prov:Entity")
graph.link(image_id, "prov:wasDerivedFrom", source_id)

action_id = "kb:action-image"
action = graph.create(InvestigativeAction, id=action_id, name="...",
    performer=examiner, object=[source], result=[image], instrument=[tool],
)
graph.add_type(action_id, "prov:Activity")
graph.link(image_id, "prov:wasGeneratedBy", action_id)
graph.link(action_id, "prov:used", tool_id)
graph.link(action_id, "prov:wasAssociatedWith", examiner_id)

provenance = graph.create(ProvenanceRecord, name="...", object=[source, image, action])
graph.write("prov-o-lineage.jsonld")
```

</details>

```bash
python examples/upper-ontology/prov-o-lineage/build_exemplar.py
```

## Validation

```bash
validate_graph("prov-o-lineage.jsonld", profiles=["prov-o"])

case_validate --built-version case-1.5.0 \
  --ontology-graph ontology/upper/shapes/sh-prov-o.ttl \
  --allow-info prov-o-lineage.jsonld
```

## Anti-patterns

| Anti-pattern | Fix |
|---|---|
| `Tool` as `prov:Agent` | Type as `prov:Entity`; link with `prov:used` |
| Separate PROV node duplicating evidence | Multi-type same IRI |
| `ProvenanceRecord` as only provenance | Also model each step as `InvestigativeAction` / `prov:Activity` |
| Missing `wasDerivedFrom` on derived image | Link image → source explicitly |
| Invented `prov:` terms | Use pinned registry terms only (`get_uco_profiles`) |

## Related

- [sosa-sensor-observations.md](sosa-sensor-observations.md) — tying sensor readings to the file they were extracted from
- [chain-of-custody.md](chain-of-custody.md) — custody actions and provenance records
- [starter-tool-run.md](starter-tool-run.md) — tool input/output linking
- [solveit-plan-execution-provenance.md](solveit-plan-execution-provenance.md) — `prov:Plan` and execution
- [cross-ontology-composition.md](cross-ontology-composition.md) — PROV-O with other profiles
