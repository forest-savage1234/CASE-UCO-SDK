# OWL-Time Temporal Evidence

> See [Recipe Index](INDEX.md) for all recipes.

Model forensic timelines with [W3C OWL-Time](https://www.w3.org/TR/owl-time/) alongside native CASE/UCO timestamps. Use **native** `start_time`/`end_time` on actions when a single interval suffices; add OWL-Time **resources** when you need instants, proper intervals, open intervals, or explicit clock correction.

Issue: [#61](https://github.com/vulnmaster/CASE-UCO-SDK/issues/61)

## Scope

- Native timestamps vs OWL-Time resources
- `time:Instant`, `time:Interval`, open intervals, timezone-aware instants
- Runnable exemplar: `examples/upper-ontology/owl-time/build_exemplar.py`

## When to use which

| Need | Approach |
|---|---|
| Action start/end from source | `InvestigativeAction.start_time` / `end_time` (native) |
| Evidence existed during a period | `time:Interval` linked via `time:hasTime` on same evidence IRI |
| Point event (login, seizure moment) | `time:Instant` with `time:inXSDDateTimeStamp` |
| Ongoing custody (no end yet) | Open `time:Interval` — `time:hasBeginning` only |
| Source gives local time + offset | `xsd:dateTimeStamp` with offset on `time:Instant` |

OWL-Time classes are not SDK dataclasses — use `graph.upsert_node()` for `time:Instant` / `time:Interval` nodes and `graph.add_property()` to link them.

## Patterns

### Proper interval on an action

Keep native timestamps **and** attach an OWL-Time interval when consumers need temporal algebra:

```python
graph.upsert_node("kb:interval-1", types="time:Interval", properties={
    "time:hasBeginning": {"@id": "kb:instant-start"},
    "time:hasEnd": {"@id": "kb:instant-end"},
})
graph.upsert_node("kb:instant-start", types="time:Instant", properties={
    "time:inXSDDateTimeStamp": {"@type": "xsd:dateTimeStamp", "@value": "..."},
})
graph.add_property(action_id, "time:hasTime", {"@id": "kb:interval-1"})
```

### Open interval (ongoing custody)

```python
graph.upsert_node("kb:interval-open", types="time:Interval", properties={
    "time:hasBeginning": {"@id": "kb:instant-custody-start"},
})
# No time:hasEnd — custody still open per source
graph.add_property(evidence_id, "time:hasTime", {"@id": "kb:interval-open"})
```

### Clock correction

When the source documents timezone or DST, encode it in the `time:inXSDDateTimeStamp` value (`2026-03-10T09:00:00-05:00`), not as a separate fudge factor.

## Python skeleton

<details open><summary>Python</summary>

```python
from case_uco import CASEGraph
from case_uco.case.investigation import InvestigativeAction
from datetime import datetime, timezone

graph = CASEGraph(extra_context={
    "time": "http://www.w3.org/2006/time#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
})

action_id = "kb:action-1"
action = graph.create(InvestigativeAction, id=action_id, name="...",
    start_time=datetime(2026, 3, 15, 14, 0, tzinfo=timezone.utc),
    end_time=datetime(2026, 3, 15, 14, 45, tzinfo=timezone.utc),
)

graph.upsert_node("kb:interval-1", types="time:Interval", properties={
    "time:hasBeginning": {"@id": "kb:instant-start"},
    "time:hasEnd": {"@id": "kb:instant-end"},
})
# ... upsert instants, then:
graph.add_property(action_id, "time:hasTime", {"@id": "kb:interval-1"})
graph.write("owl-time-temporal.jsonld")
```

</details>

```bash
python examples/upper-ontology/owl-time/build_exemplar.py
```

## Validation

```bash
validate_graph("owl-time-temporal.jsonld", profiles=["owl-time"])

case_validate --built-version case-1.5.0 \
  --ontology-graph ontology/upper/shapes/sh-time.ttl \
  --allow-info owl-time-temporal.jsonld
```

## Anti-patterns

| Anti-pattern | Fix |
|---|---|
| OWL-Time only, no native action times | Keep `start_time`/`end_time` when source provides them |
| Inline date string instead of `time:Instant` | Use `time:Instant` + `time:inXSDDateTimeStamp` |
| Closed interval when custody ongoing | Omit `time:hasEnd` |
| Duplicate interval nodes per object | One canonical interval IRI, referenced by `time:hasTime` |
| Fabricated `time:` properties | Consult pinned OWL-Time registry |

## Related

- [sosa-sensor-observations.md](sosa-sensor-observations.md) — `sosa:phenomenonTime` intervals for readings such as daily totals
- [existence-intervals.md](existence-intervals.md) — parallel temporal stacks (OWL-Time, gUFO, BFO)
- [event.md](event.md) — authentication and system events
- [forensic-lifecycle.md](forensic-lifecycle.md) — phase ordering
- [prov-o-evidence-lineage.md](prov-o-evidence-lineage.md) — provenance alongside time
