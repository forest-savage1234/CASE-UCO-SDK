# Cross-Ontology Composition

> See [Recipe Index](INDEX.md) for all recipes.

Compose **CASE/UCO core**, **domain extensions** (CAC, AEO, SOLVE-IT, `legalproc`, `cryptoinv`, …), and **upper-ontology profiles** (BFO, gUFO, PROV-O, OWL-Time, GeoSPARQL, FOAF, ORG, PROF) in a single investigation graph without breaking strict concept coverage or axiomatic consistency.

Replaces the former [cross-domain-extensions.md](cross-domain-extensions.md) guidance with a full composition policy.

## Principles

1. **Domain-first.** Every node starts as a CASE/UCO (or extension) type via `graph.create()`. Upper ontology enriches the **same IRI** via `graph.add_type()` / `graph.add_property()`.
2. **One foundational profile.** BFO **xor** gUFO — never both. CAC requires gUFO alignment; BFO is not recommended with CAC.
3. **Adopting profiles may be composed when dependencies and constraints are compatible.** PROV-O, OWL-Time, GeoSPARQL, FOAF, ORG, and PROF may coexist with each other and with either foundational choice when their import closures and SHACL constraints do not conflict.
4. **Extensions declare dependencies.** Use manifest `depends_on` (e.g. `rico` → `legalproc`) — validate with the top-level extension name.
5. **Public graph API only.** Use `create()`, `upsert_node()`, `add_type()`, `add_property()`, `link()` (for `prov:*` and other ontology edges), `create_relationship()` (UCO `Relationship` only), `get()` — not `graph.add_node` or direct `graph._objects` mutation.
6. **Compose only on evidence.** Each vocabulary describes a different kind of fact, and most pairs are unrelated: MITRE ATT&CK and ATLAS describe adversary tradecraft against computer and AI systems; `trafficking`, `elder-fraud`, `extortion` and `trajectories` describe offense conduct; SOLVE-IT describes forensic practice; CAC describes crimes against children. Bring a second vocabulary into a graph only when something in the evidence is a fact of that kind, and type only the nodes that fact supports. No extension pulls in a technique catalog through `depends_on`, and none should.

   *Example.* An offender extorts a victim and coerces them into planting malware on their employer's network, and the case holds the coercive messages plus host evidence of the implant. The extortion phases and actions use `extortion` on the trajectories state machine. The implant's execution, persistence and command-and-control use ATT&CK technique classes, typed only onto the `uco-action:Action` nodes the host evidence shows, and linked to the extortion actions by the shared performer and timeline. Without that host evidence the same case is extortion only, and ATT&CK stays out. A shared word ("credential theft", "spoofing") is not evidence; an artifact is.

## Composition policy matrix

| Layer | Examples | Combine with | Never combine |
|---|---|---|---|
| **CASE/UCO core** | Investigation, InvestigativeAction, ObservableObject | Everything below | — |
| **Domain extensions** | `cac`, `aeo`, `solveit`, `legalproc`, `cryptoinv`, `rico`, `weapons`, `drugs` | Core + adopting profiles + one foundational | Undeclared extension terms |
| **Foundational (pick one)** | `gUFO` **or** `BFO` | Core, extensions, adopting profiles | BFO + gUFO together |
| **Adopting profiles** | PROV-O, OWL-Time, GeoSPARQL, FOAF, ORG, PROF | Core, extensions, either foundational | Fabricated profile terms |
| **CAC-specific** | CAC detection, undercover, prosecution | **gUFO** (preferred), PROV-O, Time, FOAF | **BFO** |

### Extension + profile quick reference

| Extension | Recommended upper profiles | Avoid |
|---|---|---|
| `cac` | gUFO, PROV-O, OWL-Time, FOAF, ORG | BFO |
| `aeo` | PROV-O, OWL-Time, FOAF | — |
| `solveit` | PROV-O (Plan/Activity), gUFO | — |
| `legalproc` / `rico` | PROV-O, ORG, gUFO | BFO + gUFO |
| `cryptoinv` | PROV-O, OWL-Time, GeoSPARQL | — |
| Core-only forensic | PROV-O, OWL-Time, GeoSPARQL, FOAF | BFO + gUFO |

## Ordered modeling plan

Follow this order when building a composite graph:

```
1. Investigation container (name/description — populate object last)
2. Core evidence & actors (ObservableObject, Person, Location, Tool)
3. Extension-specific nodes (CAC detection, SOLVE-IT observables, charges, …)
4. InvestigativeActions / ProvenanceRecords (forensic narrative)
5. Upper-ontology enrichment (add_type on same IRI)
6. External resources (time:Interval, geo:Geometry, org:Membership, prov:Plan)
7. Cross-links (`link` for prov:*, `create_relationship` for UCO Relationship)
8. Investigation.object — wire top-level anchors
9. Optional PROF metadata (profile intent, not validation result)
```

## Python skeleton

<details open><summary>Python (composite)</summary>

```python
from case_uco import CASEGraph
from case_uco.case.investigation import Investigation, InvestigativeAction, ProvenanceRecord
from case_uco.uco.identity import Identity, Person
from case_uco.uco.observable import ObservableObject
from case_uco.uco.location import Location

graph = CASEGraph(extra_context={
    "gufo": "http://purl.org/nemo/gufo#",
    "prov": "http://www.w3.org/ns/prov#",
    "time": "http://www.w3.org/2006/time#",
    "geo": "http://www.opengis.net/ont/geosparql#",
    "sf": "http://www.opengis.net/ont/sf#",
    "foaf": "http://xmlns.com/foaf/0.1/",
    "org": "http://www.w3.org/ns/org#",
})

person_id = "kb:examiner-1"
person = graph.create(Person, id=person_id, name="...")
graph.add_type(person_id, "foaf:Person")
graph.add_type(person_id, "gufo:Object")
graph.add_type(person_id, "prov:Agent")

source_id = "kb:source-1"
source = graph.create(ObservableObject, id=source_id, name="...")
graph.add_type(source_id, "prov:Entity")
graph.add_type(source_id, "gufo:FunctionalComplex")

image_id = "kb:image-1"
image = graph.create(ObservableObject, id=image_id, name="...")
graph.add_type(image_id, "prov:Entity")
graph.add_type(image_id, "gufo:FunctionalComplex")

action_id = "kb:action-1"
action = graph.create(InvestigativeAction, id=action_id, name="...",
    performer=person, object=[source], result=[image],
)
graph.add_type(action_id, "prov:Activity")
graph.link(image_id, "prov:wasGeneratedBy", action_id)
graph.link(image_id, "prov:wasDerivedFrom", source_id)

graph.create(Investigation, name="...", object=[source, image, action])
graph.write("cross-ontology-composite.jsonld")
```

</details>

**Runnable composite exemplar:**

```bash
python examples/upper-ontology/composition/build_composite.py
```

## Validation

Pass extension names **and** profile names when validating composite graphs:

```bash
# MCP
validate_graph("cross-ontology-composite.jsonld",
    profiles=["gufo", "prov-o", "owl-time", "geosparql", "foaf", "org"])

# CLI
case_validate --built-version case-1.5.0 \
  --ontology-graph ontology/upper/shapes/sh-gufo.ttl \
  --ontology-graph ontology/upper/shapes/sh-prov-o.ttl \
  --ontology-graph ontology/upper/shapes/sh-time.ttl \
  --ontology-graph ontology/upper/shapes/sh-geo.ttl \
  --ontology-graph ontology/upper/shapes/sh-foaf.ttl \
  --ontology-graph ontology/upper/shapes/sh-org.ttl \
  --allow-info cross-ontology-composite.jsonld
```

With CAC content, add extension shapes:

```bash
validate_graph("cac-composite.jsonld", extensions=["cac"],
    profiles=["gufo", "prov-o"])
```

## Anti-patterns

| Anti-pattern | Fix |
|---|---|
| BFO + gUFO on one graph | Pick one foundational profile |
| CAC + BFO | Use gUFO enrichment |
| `graph.add_node` | `create()` + `upsert_node()` |
| Duplicate node per ontology | Multi-type same `@id` |
| Extension classes without manifest validation | `validate_graph(..., extensions=[...])` |
| Upper ontology replaces domain typing | Domain `@type` always present |
| Validation result on `prof:Profile` | Separate report resource — see [prof-validation-profile-metadata.md](prof-validation-profile-metadata.md) |
| Merging unrelated investigations for size | Partition by forensic boundary — [large-datasets.md](large-datasets.md) |
| Adding ATT&CK/ATLAS techniques to an offense-conduct or CAC graph because a step "sounds like" hacking | Add a technique catalog only when evidence shows that tradecraft (principle 6), and type only the actions that evidence supports |
| Enabling every extension a router lists without checking its `matched_keywords` against the evidence | Drop a family whose match is incidental wording rather than evidence |

## Recipe index (upper ontology)

| Topic | Recipe |
|---|---|
| BFO vs gUFO | [foundational-typing-bfo-gufo.md](foundational-typing-bfo-gufo.md) |
| PROV-O lineage | [prov-o-evidence-lineage.md](prov-o-evidence-lineage.md) |
| OWL-Time | [owl-time-temporal-evidence.md](owl-time-temporal-evidence.md) |
| GeoSPARQL | [geosparql-geospatial-evidence.md](geosparql-geospatial-evidence.md) |
| FOAF / ORG | [foaf-org-identity-roles.md](foaf-org-identity-roles.md) |
| PROF metadata | [prof-validation-profile-metadata.md](prof-validation-profile-metadata.md) |
| SOLVE-IT plan vs execution | [solveit-plan-execution-provenance.md](solveit-plan-execution-provenance.md) |
| Extensions | [extensions.md](extensions.md) |
| CAC workflows | [INDEX.md](INDEX.md) § Crimes Against Children |

## Related

- [qudt-quantities-and-units.md](qudt-quantities-and-units.md) — the QUDT profile: numbers with units and quantity kinds
- [sosa-sensor-observations.md](sosa-sensor-observations.md) — the SOSA/SSN profiles: sensor readings with QUDT results
- [extensions.md](extensions.md) — extension structure and strict concept coverage
- [cross-domain-extensions.md](cross-domain-extensions.md) — redirect stub (CAC/AEO quick start)
- [legal-process-modeling.md](legal-process-modeling.md) — `legalproc` composition
- [fraud-crypto-laundering.md](fraud-crypto-laundering.md) — `cryptoinv` + `legalproc`
- [ECOSYSTEM.md](../ECOSYSTEM.md) — companion tools and profile rationale
