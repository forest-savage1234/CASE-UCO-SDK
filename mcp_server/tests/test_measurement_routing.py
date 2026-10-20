"""Routing to the QUDT and SOSA/SSN recipes, and to candidate recipes.

Measurement and sensor evidence must reach ``qudt-quantities-and-units.md``
and ``sosa-sensor-observations.md`` (#159), and candidate recipes under
``docs/recipes/candidates/`` must be findable but always labeled.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import recipe_ranking
import server
from domain_index import CANDIDATE_RECIPE_INDEX, RECIPE_INDEX
from investigation_router import route_investigation_content

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CANDIDATES_DIR = PROJECT_ROOT / "docs" / "recipes" / "candidates"
QUDT = "docs/recipes/qudt-quantities-and-units.md"
SOSA = "docs/recipes/sosa-sensor-observations.md"
UAS = "docs/recipes/candidates/uas-flight-log.md"
SENSOR_FAMILY = "sensor-telemetry-measurement"

VEHICLE = (
    "Infotainment extraction from a 2021 Ford F-150 (Berla iVe). GPS track log "
    "shows speed 72 mph, heading 184 degrees, and odometer readings at each "
    "ignition cycle."
)
WEARABLE = (
    "Fitbit export for the victim's wrist device: heart rate 142 bpm at 02:14, "
    "step count 0 between 02:20 and 03:05, accelerometer spikes recorded."
)
IOT = (
    "Smart thermostat logs from the residence show indoor temperature dropped "
    "from 21 C to 12 C after the door sensor reported open at 23:40."
)
DRONE = (
    "Seized DJI Mavic flight record: altitude 120 m AGL, battery voltage 15.2 V, "
    "ground speed 14 m/s, home point coordinates."
)
LAB_REPORT = (
    "Lab report: seized powder net weight 28.4 grams, purity 61 percent. Wire "
    "transfers totalled 12,500 USD."
)
INDICTMENT = (
    "COUNT ONE: On or about March 3, the defendant, a flight risk, was charged "
    "under 18 U.S.C. 2252A. The record shows two counts and a detention "
    "hearing; he was sentenced to 10 years."
)


def _route(text: str) -> dict:
    return route_investigation_content(PROJECT_ROOT, content_text=text)


@pytest.mark.parametrize("text", [VEHICLE, WEARABLE, IOT, DRONE])
def test_sensor_evidence_routes_to_sensor_family(text: str) -> None:
    payload = _route(text)
    top = payload["matched_families"][0]
    assert top["family_id"] == SENSOR_FAMILY
    assert {SOSA, QUDT} <= set(top["recipes"])
    profiles = payload["ordered_recommendations"]["recommended_profiles"]
    assert {"sosa", "ssn", "qudt"} <= set(profiles)


def test_drone_log_surfaces_uas_candidate_labeled() -> None:
    payload = _route(DRONE)
    hits = payload["candidate_recipe_hits"]
    assert hits[0]["file"] == UAS
    assert hits[0]["status"] == "candidate"
    assert hits[0]["extension"] == "uas"
    assert "extensions=['uas']" in hits[0]["note"]


def test_measured_quantities_attach_qudt_signal() -> None:
    payload = _route(LAB_REPORT)
    signals = payload["measurement_signals"]
    assert [q["text"] for q in signals["quantities"]] == ["28.4 grams", "61 percent", "12,500 USD"]
    assert signals["recipes"][0] == QUDT
    assert recipe_ranking.rank_recipes(LAB_REPORT)[0]["file"] == QUDT


def test_legal_text_gets_no_measurement_or_candidate_signals() -> None:
    payload = _route(INDICTMENT)
    assert "measurement_signals" not in payload
    assert "candidate_recipe_hits" not in payload


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("speed 72 mph, heading 184 degrees", [("72 mph", "unit:MI-PER-HR"), ("184 degrees", "unit:DEG")]),
        ("heart rate 142 bpm", [("142 bpm", "unit:BEAT-PER-MIN")]),
        ("battery voltage 15.2 V, ground speed 14 m/s", [("15.2 V", "unit:V"), ("14 m/s", "unit:M-PER-SEC")]),
        ("12,500 USD", [("12,500 USD", "unit:CCY_USD")]),
        ("13 TeV", [("13 TeV", None)]),
        ("18 U.S.C. 2252A, sentenced to 10 years at 3 pm", []),
        ("Apartment 4 B, Section 21 C", []),
    ],
)
def test_measured_quantities(text: str, expected: list[tuple[str, str | None]]) -> None:
    found = recipe_ranking.measured_quantities(text)
    assert [(q["text"], q["unit_id"]) for q in found] == expected


def test_currency_alone_is_a_weak_measurement_signal() -> None:
    quantities = recipe_ranking.measured_quantities("12,500 USD")
    assert recipe_ranking.measurement_signal_strength(quantities) == 0


def test_candidate_index_matches_candidate_directory() -> None:
    on_disk = {
        f"docs/recipes/candidates/{p.name}"
        for p in CANDIDATES_DIR.glob("*.md")
        if p.name != "README.md"
    }
    indexed = {entry["file"] for entry in CANDIDATE_RECIPE_INDEX}
    assert indexed == on_disk, "Register every candidate recipe in CANDIDATE_RECIPE_INDEX"
    assert not indexed & {entry["file"] for entry in RECIPE_INDEX}
    assert all(entry.get("extension") for entry in CANDIDATE_RECIPE_INDEX)


def test_candidates_link_to_operational_recipes_and_readme() -> None:
    readme = (CANDIDATES_DIR / "README.md").read_text(encoding="utf-8")
    operational = {Path(e["file"]).name for e in RECIPE_INDEX}
    for entry in CANDIDATE_RECIPE_INDEX:
        path = PROJECT_ROOT / entry["file"]
        assert f"({path.name})" in readme, f"{path.name} missing from candidates/README.md"
        links = set(re.findall(r"\.\./([a-z0-9-]+\.md)", path.read_text(encoding="utf-8")))
        assert links & operational, f"{path.name} links to no operational recipe"


def test_uas_candidate_cross_links_measurement_recipes() -> None:
    text = (PROJECT_ROOT / UAS).read_text(encoding="utf-8")
    assert "../sosa-sensor-observations.md" in text
    assert "../qudt-quantities-and-units.md" in text


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("drone flight log", UAS),
        ("layered esm composition", "docs/recipes/candidates/layered-esm-composition.md"),
        ("means action-space goal", "docs/recipes/candidates/offense-means-set.md"),
    ],
)
def test_get_recipe_falls_back_to_labeled_candidate(query: str, expected: str) -> None:
    result = server.get_recipe(query)
    assert result is not None
    assert result["file"] == expected
    assert result["status"] == "candidate"
    assert result["content"]


@pytest.mark.parametrize(("query", "expected"), [("qudt", QUDT), ("sosa", SOSA), ("units of measure", QUDT)])
def test_get_recipe_finds_measurement_recipes(query: str, expected: str) -> None:
    result = server.get_recipe(query)
    assert result is not None and result["file"] == expected
    assert "status" not in result


def test_get_recipes_lists_candidates_separately() -> None:
    result = server.get_recipes("drone flight log altitude", include_content=True)
    assert all("candidates/" not in m["file"] for m in result["recipes"])
    candidate = result["candidate_recipes"][0]
    assert candidate["file"] == UAS and candidate["status"] == "candidate"
    assert candidate["content"]
