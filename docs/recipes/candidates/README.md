# Candidate recipes (not yet operational)

Recipes drafted during live investigations start here. Files in this
directory are **not part of the operational catalog**: they are not
registered in `RECIPE_INDEX` and not listed in `docs/recipes/INDEX.md`.
Each one is registered in `CANDIDATE_RECIPE_INDEX`
(`mcp_server/domain_index.py`) so it is not lost. Routing returns a
candidate only when the query matches it strongly, and always labeled:
`candidate_recipe_hits` from `route_investigation_content`,
`candidate_recipes` from `get_recipes`, and `"status": "candidate"` from
`get_recipe` when no operational recipe matches better. Each label names the
extension to load by name.

| Candidate | Extension | Builds on |
|---|---|---|
| [uas-flight-log.md](uas-flight-log.md) | `uas` | [SOSA/SSN](../sosa-sensor-observations.md), [QUDT](../qudt-quantities-and-units.md), [location](../location.md) |
| [layered-esm-composition.md](layered-esm-composition.md) | `layered` | [cross-ontology composition](../cross-ontology-composition.md) |
| [offense-means-set.md](offense-means-set.md) | `means` | [layered ESM composition](layered-esm-composition.md) |
| [expense-benefit-at-expense.md](expense-benefit-at-expense.md) | `expense` | [layered ESM composition](layered-esm-composition.md) |

## Promotion workflow

1. Draft the recipe here following `docs/recipes/recipe-authoring.md`
   (structure, Tier T0 synthetic data, validated JSON-LD snippets).
2. Validate every embedded graph snippet with `validate_graph` /
   `case_validate` until it conforms with zero undeclared concepts.
3. Move the file into `docs/recipes/`, register it in `RECIPE_INDEX`
   (`mcp_server/domain_index.py`) and `docs/recipes/INDEX.md`, and remove
   its `CANDIDATE_RECIPE_INDEX` entry. `make promote-recipe` does all three.
4. Run `make test-mcp` — the catalog integrity tests fail if the recipe is
   unregistered, cross-links are broken, or routing keywords are missing.
5. Commit with provenance: source investigation (Tier-classified), authoring
   agent/tool, and reviewer.

Rollback: recipes are plain files under git; restore a previous approved
generation with `git checkout <ref> -- docs/recipes/<file>.md`.

See `mcp_server/knowledge_lifecycle.py` for the extension-ontology
equivalent (candidate/operational/deprecated manifest statuses).
