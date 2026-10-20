"""Rank operational and candidate recipes against submitted text.

Recipes are matched on whole folded tokens (``semantic_retrieval.tokenize``),
weighted by how rare each token is across the catalog. Numbers with a QUDT
unit ("13 TeV", "72 mph", "142 bpm") are a second signal: they point at the
QUDT recipe even when no catalog keyword overlaps the text.
"""

from __future__ import annotations

import math
import re
from functools import lru_cache
from typing import Any

import semantic_retrieval
from domain_index import CANDIDATE_RECIPE_INDEX, RECIPE_INDEX

QUDT_RECIPE = "docs/recipes/qudt-quantities-and-units.md"
SOSA_RECIPE = "docs/recipes/sosa-sensor-observations.md"

_QUERY_STOP = frozenset(
    {
        "about", "after", "also", "before", "between", "could", "each",
        "into", "onto", "only", "other", "over", "present", "reported",
        "should", "such", "than", "then", "there", "these", "those", "under",
        "used", "using", "via", "what", "when", "where", "while", "would",
        "estimated", "involved", "abstract", "synthetic", "one", "two",
        "show", "shows", "showed", "report", "reports",
    }
)

# A candidate hit needs this much evidence; two shared common words are noise.
CANDIDATE_MIN_MATCHES = 3
CANDIDATE_MIN_SCORE = 10.0

_QUANTITY_RE = re.compile(
    r"(?<![\w.,§])(?P<num>\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?)(?P<space>\s?)"
    r"(?P<unit>%|°\s?[CF]\b|degrees?(?:\s+(?:Celsius|Fahrenheit|[CF]\b))?|"
    r"[A-Za-zµΩ][A-Za-z0-9/µΩ²³]*)(?![\w(])"
)
_UNIT_STOP = frozenset(
    {
        "a", "an", "and", "am", "as", "at", "by", "in", "is", "it", "no", "of",
        "on", "or", "pm", "st", "nd", "rd", "th", "the", "to", "x",
    }
)
_UNIT_ALIASES = {
    "lbs": "lb", "pound": "lb", "pounds": "lb", "kilo": "kg", "kilos": "kg",
    "mph": "mi/h", "kph": "km/h", "kmh": "km/h", "bpm": "BPM",
    "celsius": "°C", "fahrenheit": "°F",
}
_SI_PREFIXES = "TGMkmµun"
_PREFIXABLE_BASES = frozenset({"eV", "W", "Wh", "Hz", "Pa", "V", "A", "Ah", "J", "B", "b", "g", "m", "s"})
_NON_MEASUREMENT_KINDS = frozenset({"quantitykind:Time", "quantitykind:Count"})
_STATUTE_CONTEXT = re.compile(r"(?:§|u\.s\.c|usc|section|count)\s*$", re.IGNORECASE)
_MAX_QUANTITIES = 12
# One measured quantity outweighs any single shared catalog word.
QUANTITY_BOOST = 6.0


def _recipe_text(recipe: dict[str, str]) -> str:
    return f"{recipe['title']} {recipe['description']} {recipe['keywords']}"


@lru_cache(maxsize=1)
def _catalog() -> tuple[tuple[tuple[dict[str, str], frozenset[str], str], ...], dict[str, int]]:
    entries = []
    doc_freq: dict[str, int] = {}
    for status, catalog in (("operational", RECIPE_INDEX), ("candidate", CANDIDATE_RECIPE_INDEX)):
        for recipe in catalog:
            tokens = frozenset(semantic_retrieval.tokenize(_recipe_text(recipe)))
            entries.append((recipe, tokens, status))
            for token in tokens:
                doc_freq[token] = doc_freq.get(token, 0) + 1
    return tuple(entries), doc_freq


def _query_tokens(text: str) -> set[str]:
    return {t for t in semantic_retrieval.tokenize(text or "") if t not in _QUERY_STOP}


def _lookup_unit(token: str) -> dict[str, Any] | None:
    import qudt_units

    query = _UNIT_ALIASES.get(token.lower(), token)
    units = qudt_units.lookup_units(query, "", 1).get("units") or []
    if units and units[0]["match_score"] >= 85:
        return units[0]
    return None


def _resolve_unit(token: str) -> tuple[str | None, list[str]] | None:
    unit = _lookup_unit(token)
    if unit is not None:
        return unit["id"], list(unit.get("quantity_kinds") or [])
    if len(token) <= 4 and token[0] in _SI_PREFIXES and token[1:] in _PREFIXABLE_BASES:
        base = _lookup_unit(token[1:])
        if base is not None:
            return None, list(base.get("quantity_kinds") or [])
    return None


def measured_quantities(text: str) -> list[dict[str, Any]]:
    """Numbers followed by a pinned QUDT unit, excluding durations and counts."""

    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in _QUANTITY_RE.finditer(text or ""):
        raw_unit = match.group("unit")
        if raw_unit.lower() in _UNIT_STOP:
            continue
        if _STATUTE_CONTEXT.search(text[max(0, match.start() - 12) : match.start()]):
            continue
        if raw_unit.lower().startswith("degree"):
            tail = raw_unit.split()[-1].lower()
            unit_token = "°C" if tail in {"celsius", "c"} else "°F" if tail in {"fahrenheit", "f"} else "°"
        else:
            unit_token = raw_unit.replace(" ", "")
        # Single-letter units read as words when spaced from an integer ("Apartment 4 B").
        if len(unit_token) == 1 and unit_token.isalpha() and match.group("space") and "." not in match.group("num"):
            continue
        resolved = _resolve_unit(unit_token)
        if resolved is None:
            continue
        unit_id, kinds = resolved
        if kinds and set(kinds) & _NON_MEASUREMENT_KINDS:
            continue
        mention = match.group(0).strip()
        if mention in seen:
            continue
        seen.add(mention)
        found.append(
            {
                "text": mention,
                "unit_id": unit_id,
                "quantity_kinds": kinds[:3],
                "currency": "quantitykind:Currency" in kinds,
            }
        )
        if len(found) >= _MAX_QUANTITIES:
            break
    return found


def measurement_signal_strength(quantities: list[dict[str, Any]]) -> int:
    """Physical quantities count fully; currency amounts alone are weaker."""

    physical = sum(1 for q in quantities if not q["currency"])
    currency = len(quantities) - physical
    return physical + currency // 2


def _score(tokens: set[str], recipe_tokens: frozenset[str], doc_freq: dict[str, int], total: int) -> tuple[float, list[str]]:
    matched = sorted(tokens & recipe_tokens)
    score = sum(math.log(1 + total / doc_freq[t]) for t in matched)
    return score, matched


def _hit(recipe: dict[str, str], score: float, matched: list[str], status: str) -> dict[str, Any]:
    hit: dict[str, Any] = {
        "file": recipe["file"],
        "score": round(score, 4),
        "title": recipe["title"],
        "rationale": recipe["description"],
        "matched_terms": matched[:8],
    }
    if status == "candidate":
        hit["status"] = "candidate"
        hit["extension"] = recipe.get("extension")
        hit["note"] = (
            "Candidate recipe: its extension is not promoted. Load it by name "
            f"(validate_graph(..., extensions=['{recipe.get('extension')}'])) and "
            "review the pattern before relying on it."
        )
    return hit


def rank_recipes(text: str, *, limit: int = 6, quantities: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Top operational recipes for ``text``."""

    entries, doc_freq = _catalog()
    total = len(entries)
    tokens = _query_tokens(text)
    if quantities is None:
        quantities = measured_quantities(text)
    strength = measurement_signal_strength(quantities)
    scored: list[tuple[float, dict[str, str], list[str]]] = []
    for recipe, recipe_tokens, status in entries:
        if status != "operational":
            continue
        score, matched = _score(tokens, recipe_tokens, doc_freq, total)
        if recipe["file"] == QUDT_RECIPE and strength:
            score += QUANTITY_BOOST * min(strength, 3)
            matched = matched + [f"quantity:{q['text']}" for q in quantities[:3]]
        if score <= 0:
            continue
        scored.append((score, recipe, matched))
    scored.sort(key=lambda item: (-item[0], item[1]["title"]))
    return [_hit(recipe, score, matched, "operational") for score, recipe, matched in scored[:limit]]


def rank_candidate_recipes(text: str, *, limit: int = 3) -> list[dict[str, Any]]:
    """Candidate recipes with enough distinctive overlap to be worth reading."""

    entries, doc_freq = _catalog()
    total = len(entries)
    tokens = _query_tokens(text)
    scored = []
    for recipe, recipe_tokens, status in entries:
        if status != "candidate":
            continue
        score, matched = _score(tokens, recipe_tokens, doc_freq, total)
        if len(matched) >= CANDIDATE_MIN_MATCHES and score >= CANDIDATE_MIN_SCORE:
            scored.append((score, recipe, matched))
    scored.sort(key=lambda item: (-item[0], item[1]["title"]))
    return [_hit(recipe, score, matched, "candidate") for score, recipe, matched in scored[:limit]]
