# GeoSPARQL Geospatial Evidence

> See [Recipe Index](INDEX.md) for all recipes.

Model locations and derived geospatial analytics with [OGC GeoSPARQL 1.1](https://github.com/opengeospatial/ogc-geosparql). A `uco-location:Location` is multi-typed as `geo:Feature`; geometry lives on a **separate** `geo:Geometry` node linked by `geo:hasGeometry`.

Issue: [#62](https://github.com/vulnmaster/CASE-UCO-SDK/issues/62)

## Scope

- `Location` + `geo:Feature` on same IRI
- Separate `geo:Geometry` / `sf:Point` (or other SF type)
- Derived analytic geometry with PROV-O provenance
- Exemplar: `examples/upper-ontology/geosparql/build_exemplar.py`

## Modeling rules

1. **Domain first:** `graph.create(Location, id=..., has_facet=[...])` then `graph.add_type(id, "geo:Feature")`.
2. **Geometry is its own node** — never embed WKT only in `description`.
3. **CRS in WKT literal** — use `geo:asWKT` with `geo:wktLiteral` (or `geo:asGeoJSON` when source is GeoJSON).
4. **Derived geometries** (analyst-defined bounding polygons, warrant areas, cell-sector cones, routes) are separate `geo:Geometry` nodes with `prov:wasDerivedFrom` and `prov:wasGeneratedBy` pointing to the generating `InvestigativeAction`.
5. **Keep address facets** — `SimpleAddressFacet` / `LatLongCoordinatesFacet` complement GeoSPARQL; do not remove UCO facets when adding `geo:Feature`.

## Pattern

<details open><summary>Python</summary>

```python
from case_uco import CASEGraph
from case_uco.uco.location import Location, SimpleAddressFacet
from case_uco.case.investigation import InvestigativeAction

graph = CASEGraph(extra_context={
    "geo": "http://www.opengis.net/ont/geosparql#",
    "sf": "http://www.opengis.net/ont/sf#",
    "prov": "http://www.w3.org/ns/prov#",
})

site_id = "kb:site-1"
site = graph.create(Location, id=site_id, name="...",
    has_facet=[SimpleAddressFacet(street="...", locality="...", country="...")],
)
graph.add_type(site_id, "geo:Feature")

geom_id = "kb:point-1"
graph.upsert_node(geom_id, types=["geo:Geometry", "sf:Point"], properties={
    "geo:asWKT": {"@type": "geo:wktLiteral", "@value": "POINT(lon lat)"},
})
graph.add_property(site_id, "geo:hasGeometry", {"@id": geom_id})

# Analyst-defined bounding polygon (not a fixed-radius buffer)
bounding_id = "kb:bounding-polygon-1"
graph.upsert_node(bounding_id, types=["geo:Geometry", "sf:Polygon"], properties={
    "geo:asWKT": {"@type": "geo:wktLiteral", "@value": "POLYGON((...))"},
})
action_id = "kb:action-geofence"
action = graph.create(
    InvestigativeAction,
    id=action_id,
    name="Derive analyst bounding polygon",
)
graph.link(bounding_id, "prov:wasDerivedFrom", geom_id)
graph.link(bounding_id, "prov:wasGeneratedBy", action_id)
graph.write("geosparql-geospatial.jsonld")
```

</details>

```bash
python examples/upper-ontology/geosparql/build_exemplar.py
```

## Validation

```bash
validate_graph("geosparql-geospatial.jsonld", profiles=["geosparql"])

case_validate --built-version case-1.5.0 \
  --ontology-graph ontology/upper/shapes/sh-geo.ttl \
  --allow-info geosparql-geospatial.jsonld
```

## Anti-patterns

| Anti-pattern | Fix |
|---|---|
| WKT string in `uco-core:description` only | Separate `geo:Geometry` node |
| `geo:Feature` without `geo:hasGeometry` | Link geometry explicitly |
| Same IRI for Feature and Geometry | Separate nodes |
| Derived polygon without provenance | `prov:wasDerivedFrom` + `prov:wasGeneratedBy` |
| Invented `geo:`/`sf:` terms | Use pinned GeoSPARQL registry |

## Related

- [sosa-sensor-observations.md](sosa-sensor-observations.md) — GNSS readings whose locations carry geometries
- [location.md](location.md) — UCO location facets
- [cell-site.md](cell-site.md) — tower-derived positions
- [cargo-theft-route-staging.md](cargo-theft-route-staging.md) — route deviation
- [prov-o-evidence-lineage.md](prov-o-evidence-lineage.md) — derived geometry lineage
