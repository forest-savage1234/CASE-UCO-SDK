"""Resumable critic-session state machine (issue #76)."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import secrets
import shutil
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator, Literal

import workspace_policy
from critic.deterministic import CriticError, analyze_artifact
from critic.file_lock import FileLock, ensure_lock_file
from critic.graph_integrity import sha256_file
from critic.models import CriticArtifactRequest, CriticFinding, CriticReview, CriticScorecard
from critic.pass_merge import finalize_outcome_from_summary, merge_completed_pass_review
from critic.response_parser import (
    CriticResponseError,
    build_assessment_ledger,
    parse_critic_model_response,
)
from critic.schema_util import compute_review_config_sha256, validate_against_schema

REQUIRED_PASSES = 2
MAX_TOTAL_PASSES = 8
SESSION_DIR_NAME = "critic-sessions"
CRITIC_SESSION_SCHEMA = "1.2.0"
HANDOFF_CANDIDATES_DIR = "critic-handoffs/candidates"

ModelPolicy = Literal["disabled", "manual", "client_sampling"]
SessionState = Literal[
    "awaiting_critic_response",
    "awaiting_revision",
    "finalized",
    "cancelled",
    "failed",
]

POLICY_ENV = "CASE_UCO_CRITIC_MODEL_POLICY"
SESSION_ROOT_ENV = "CASE_UCO_CRITIC_SESSION_ROOT"
EXTEND_TOKEN_ENV = "CASE_UCO_CRITIC_EXTEND_TOKEN"
PERSIST_PROMPTS_ENV = "CASE_UCO_CRITIC_PERSIST_PROMPTS"
DEPLOYMENT_MODE_ENV = "CASE_UCO_MCP_CRITIC_MODE"

# Fields retained on disk for review-pass-N.json (prompt body never persisted by default).
_REVIEW_PASS_KEEP = (
    "artifact_hashes",
    "validation",
    "merged_findings",
    "scorecard",
    "analysis_status",
    "status",
    "rule_executions",
    "errors",
    "elapsed_ms",
)


class CriticSessionError(Exception):
    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code


@dataclass
class SessionConfig:
    graph_path: str
    serializer_path: str | None = None
    source_paths: list[str] = field(default_factory=list)
    coverage_contract_path: str | None = None
    provenance_manifest_path: str | None = None
    extensions: list[str] = field(default_factory=list)
    profiles: list[str] = field(default_factory=list)
    critic_scope: str = "both"
    additional_iterations: int = 0
    model_policy: ModelPolicy = "manual"
    report_output: str | None = None
    project_root: str | None = None
    serializer_mode: str = "auto"
    extra_ontology_graphs: list[str] = field(default_factory=list)
    force_rdfs_inference: bool = False


def normalize_model_policy(raw: str | None) -> ModelPolicy | None:
    """Normalize hyphen/underscore policy strings to ModelPolicy values."""

    if raw is None:
        return None
    cleaned = str(raw).strip().lower().replace("-", "_")
    if cleaned in {"disabled", "manual", "client_sampling"}:
        return cleaned  # type: ignore[return-value]
    return None


def default_model_policy() -> ModelPolicy:
    return normalize_model_policy(os.environ.get(POLICY_ENV)) or "manual"


def deployment_critic_mode() -> ModelPolicy:
    """Non-bypassable deployment gate for sampling.

    Explicit ``CASE_UCO_MCP_CRITIC_MODE`` always wins. When unset, profile
    defaults apply:

    - ``offline-investigation`` → ``manual``
    - production-like (``secure`` / ``production`` / ``prod`` /
      ``production-authoring`` / ``production-review``) → ``disabled``
    - otherwise (local/dev) → ``client_sampling``
    """

    explicit = normalize_model_policy(os.environ.get(DEPLOYMENT_MODE_ENV))
    if explicit is not None:
        return explicit
    profile = (os.environ.get("CASE_UCO_MCP_PROFILE") or "").strip().lower()
    if profile == "offline-investigation":
        return "manual"
    if profile in {
        "secure",
        "production",
        "prod",
        "production-authoring",
        "production-review",
    }:
        return "disabled"
    return "client_sampling"


def effective_model_policy(requested: str | ModelPolicy | None) -> ModelPolicy:
    """Clamp requested session policy by deployment mode ceiling."""

    requested_norm = normalize_model_policy(requested) or default_model_policy()
    deployment = deployment_critic_mode()
    rank = {"disabled": 0, "manual": 1, "client_sampling": 2}
    if rank[requested_norm] > rank[deployment]:
        return deployment
    return requested_norm


def _persist_prompts_enabled() -> bool:
    raw = (os.environ.get(PERSIST_PROMPTS_ENV) or "").strip().lower()
    return raw in {"1", "true", "yes"}


def session_root() -> Path:
    """Resolve session root under an approved write root (fail closed)."""

    override = os.environ.get(SESSION_ROOT_ENV)
    write_roots = workspace_policy.write_roots()
    if override:
        candidate = Path(override).expanduser().resolve()
        try:
            checked = workspace_policy.check_write_path(
                str(candidate), enforce_no_overwrite=False
            )
        except ValueError as exc:
            raise CriticSessionError(
                "critic_session_root_denied", "session root outside write roots"
            ) from exc
        checked.mkdir(parents=True, exist_ok=True)
        return checked
    if write_roots:
        path = (write_roots[0] / SESSION_DIR_NAME).resolve()
        try:
            checked = workspace_policy.check_write_path(
                str(path), enforce_no_overwrite=False
            )
        except ValueError as exc:
            raise CriticSessionError(
                "critic_session_root_denied", "session root outside write roots"
            ) from exc
        checked.mkdir(parents=True, exist_ok=True)
        return checked
    raise CriticSessionError(
        "critic_session_root_unavailable",
        "no write root configured for critic sessions",
    )


def _session_dir(session_id: str) -> Path:
    if not session_id.startswith("critsess-") or "/" in session_id or ".." in session_id:
        raise CriticSessionError("critic_session_invalid_id")
    return session_root() / session_id


@contextmanager
def _locked(session_id: str) -> Iterator[Path]:
    directory = _session_dir(session_id)
    if not directory.is_dir():
        raise CriticSessionError("critic_session_not_found")
    lock_path = directory / "lock"
    ensure_lock_file(lock_path)
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        with FileLock(lock_file):
            yield directory


def _atomic_write_json(path: Path, data: dict[str, Any]) -> str:
    """Atomically write JSON and return SHA-256 of the exact written bytes.

    Always writes UTF-8 bytes in binary mode so Windows does not translate
    ``\\n`` to ``\\r\\n`` (which would invalidate the digest).
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        raw = json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + "\n"
    except ValueError as exc:
        raise CriticSessionError(
            "critic_session_non_finite_number", str(path.name)
        ) from exc
    encoded = raw.encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    fd, tmp_name = tempfile.mkstemp(prefix=path.name, dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    return digest


def _session_projection_payload(session: dict[str, Any]) -> dict[str, Any]:
    """Full semantic session bound into each audit transition.

    Hashes the complete session object so newly added control fields are
    protected automatically. Excludes only ``latest_audit_event_sha256``, which
    is stamped after the audit event is hashed (back-reference).
    """

    projection = copy.deepcopy(session)
    projection.pop("latest_audit_event_sha256", None)
    return projection


def _compute_session_projection_sha256(session: dict[str, Any]) -> str:
    payload = _session_projection_payload(session)
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _append_audit(
    directory: Path,
    event: str,
    payload: dict[str, Any],
    *,
    prior_state: str | None = None,
    new_state: str | None = None,
    artifact_set_sha256: str | None = None,
) -> str:
    """Append a chained audit event; return ``event_sha256``.

    Optional ``session_projection_sha256``, ``files``, and ``outcome`` travel in
    ``payload``. Raises when the trailing audit line is corrupt instead of
    silently resetting the chain.
    """

    audit_path = directory / "audit.jsonl"
    previous_event_sha256 = "0" * 64
    sequence = 0
    if audit_path.is_file():
        raw = audit_path.read_bytes()
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        if lines:
            try:
                last = json.loads(lines[-1].decode("utf-8"))
                previous_event_sha256 = str(
                    last.get("event_sha256") or previous_event_sha256
                )
                sequence = int(last.get("sequence") or 0)
            except (json.JSONDecodeError, TypeError, ValueError, UnicodeDecodeError) as exc:
                raise CriticSessionError(
                    "critic_session_audit_corrupt",
                    "corrupt trailing audit line",
                ) from exc
    sequence += 1
    body = {
        "ts": time.time(),
        "event": event,
        "sequence": sequence,
        "previous_event_sha256": previous_event_sha256,
        "prior_state": prior_state,
        "new_state": new_state,
        "artifact_set_sha256": artifact_set_sha256,
        **payload,
    }
    # Hash without event_sha256 field.
    event_sha256 = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    body["event_sha256"] = event_sha256
    encoded = (json.dumps(body, sort_keys=True) + "\n").encode("utf-8")
    with audit_path.open("ab") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    return event_sha256


def _commit_session_transition(
    directory: Path,
    session: dict[str, Any],
    event: str,
    payload: dict[str, Any],
    *,
    prior_state: str | None,
    new_state: str | None,
    artifact_set_sha256: str | None = None,
) -> str:
    """Bind session projection → append audit → stamp event sha → save session."""

    projection = _compute_session_projection_sha256(session)
    event_sha = _append_audit(
        directory,
        event,
        {**payload, "session_projection_sha256": projection},
        prior_state=prior_state,
        new_state=new_state,
        artifact_set_sha256=artifact_set_sha256,
    )
    session["latest_audit_event_sha256"] = event_sha
    _save(directory, session)
    return event_sha


def _artifact_set_from_hashes(
    hashes: dict[str, Any],
    *,
    require_review_config: bool = True,
) -> dict[str, Any]:
    review_config_sha256 = hashes.get("review_config_sha256")
    if require_review_config and not review_config_sha256:
        raise CriticSessionError(
            "critic_session_hash_mismatch", "review_config_sha256 required"
        )
    result = {
        "graph_sha256": hashes.get("graph_sha256"),
        "serializer_sha256": hashes.get("serializer_sha256"),
        "source_sha256": dict(hashes.get("source_sha256") or {}),
        "coverage_contract_sha256": hashes.get("coverage_contract_sha256"),
        "provenance_manifest_sha256": hashes.get("provenance_manifest_sha256"),
        "extra_ontology_sha256": dict(hashes.get("extra_ontology_sha256") or {}),
    }
    if review_config_sha256:
        result["review_config_sha256"] = review_config_sha256
    return result


def _artifact_set_sha256(artifact_set: dict[str, Any]) -> str:
    payload = {
        "graph_sha256": artifact_set.get("graph_sha256"),
        "serializer_sha256": artifact_set.get("serializer_sha256"),
        "source_sha256": dict(sorted((artifact_set.get("source_sha256") or {}).items())),
        "coverage_contract_sha256": artifact_set.get("coverage_contract_sha256"),
        "provenance_manifest_sha256": artifact_set.get("provenance_manifest_sha256"),
        "extra_ontology_sha256": dict(
            sorted((artifact_set.get("extra_ontology_sha256") or {}).items())
        ),
        "review_config_sha256": artifact_set.get("review_config_sha256"),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _extra_ontology_hashes(paths: list[str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for idx, raw in enumerate(paths or [], start=1):
        path = _resolve_artifact_path(
            raw, allow_write_roots=True, label=f"extra_ontology:{idx}"
        )
        result[f"extra-{idx}:{path.name}"] = sha256_file(path)
    return result


def _project_root_for_config(cfg: dict[str, Any]) -> Path:
    import graph_validator

    if cfg.get("project_root"):
        return Path(str(cfg["project_root"])).expanduser().resolve()
    return graph_validator.PROJECT_ROOT


def _resolve_and_hash_bundle(cfg: dict[str, Any]) -> dict[str, Any]:
    """Re-resolve the validation bundle from disk and rehash all resources."""

    from validation_bundle import (
        ValidationBundleError,
        hash_validation_bundle_identity,
    )

    extras: list[str] = []
    for idx, raw in enumerate(cfg.get("extra_ontology_graphs") or [], start=1):
        path = _resolve_artifact_path(
            raw, allow_write_roots=True, label=f"extra_ontology:{idx}"
        )
        extras.append(str(path))
    try:
        return hash_validation_bundle_identity(
            extensions=list(cfg.get("extensions") or []),
            profiles=list(cfg.get("profiles") or []),
            extra_ontology_graphs=extras or None,
            project_root=_project_root_for_config(cfg),
            force_rdfs_inference=bool(cfg.get("force_rdfs_inference")),
            use_cache=False,
        )
    except ValidationBundleError as exc:
        raise CriticSessionError(
            "critic_session_bundle_drift", str(exc)
        ) from exc


def _artifact_set_for_config(
    hashes: dict[str, Any], cfg: dict[str, Any]
) -> dict[str, Any]:
    merged = dict(hashes)
    merged["extra_ontology_sha256"] = _extra_ontology_hashes(
        cfg.get("extra_ontology_graphs")
    )
    if not merged.get("review_config_sha256"):
        raise CriticSessionError(
            "critic_session_hash_mismatch", "review_config_sha256 required"
        )
    return _artifact_set_from_hashes(merged)


def _review_config_sha256_for(
    cfg: dict[str, Any],
    *,
    bundle_fingerprint: str | None = None,
    bundle_resource_hashes: dict[str, str] | None = None,
    extra_ontology_sha256: dict[str, str] | None = None,
    validator_version: str | None = None,
    built_version: str | None = None,
    resolver_schema_version: str | None = None,
) -> str:
    provenance_manifest_sha256: str | None = None
    if cfg.get("provenance_manifest_path"):
        try:
            manifest = _resolve_artifact_path(
                str(cfg["provenance_manifest_path"]),
                allow_write_roots=True,
                label="provenance_manifest",
            )
            provenance_manifest_sha256 = sha256_file(manifest)
        except CriticSessionError:
            provenance_manifest_sha256 = None
    return compute_review_config_sha256(
        critic_scope=str(cfg.get("critic_scope") or "both"),
        serializer_mode=str(cfg.get("serializer_mode") or "auto"),
        extensions=list(cfg.get("extensions") or []),
        profiles=list(cfg.get("profiles") or []),
        force_rdfs_inference=bool(cfg.get("force_rdfs_inference")),
        extra_ontology_sha256=(
            dict(extra_ontology_sha256)
            if extra_ontology_sha256 is not None
            else _extra_ontology_hashes(cfg.get("extra_ontology_graphs"))
        ),
        bundle_fingerprint=bundle_fingerprint,
        bundle_resource_hashes=bundle_resource_hashes,
        validator_version=validator_version,
        built_version=built_version,
        resolver_schema_version=resolver_schema_version,
        provenance_manifest_sha256=provenance_manifest_sha256,
    )


def _bundle_resource_hashes_from_validation(
    validation: dict[str, Any] | None,
) -> dict[str, str]:
    if not validation:
        return {}
    raw = validation.get("bundle_resource_hashes")
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    return {}


def _bundle_resources_signature(
    resources: list[dict[str, Any]] | None,
) -> list[tuple[str, str, str | None, str | None, str]]:
    """Stable comparable tuples: path, role, profile, extension, sha256."""

    signed: list[tuple[str, str, str | None, str | None, str]] = []
    for item in resources or []:
        signed.append(
            (
                str(item.get("path") or ""),
                str(item.get("role") or ""),
                item.get("profile_id"),
                item.get("extension"),
                str(item.get("sha256") or ""),
            )
        )
    return sorted(signed)


def _assert_bundle_matches_snapshot(
    live: dict[str, Any],
    snapshot: dict[str, Any],
    *,
    cfg: dict[str, Any],
    reviewed_config_sha256: str | None,
) -> str:
    """Fail closed when live disk bundle drifts from config-pass / reviewed sha.

    Returns the live ``review_config_sha256`` when checks pass.
    """

    snap_fp = snapshot.get("bundle_fingerprint")
    live_fp = live.get("bundle_fingerprint")
    if snap_fp is not None and snap_fp != live_fp:
        raise CriticSessionError(
            "critic_session_bundle_drift", "bundle_fingerprint"
        )

    snap_hashes = {
        str(k): str(v)
        for k, v in (snapshot.get("bundle_resource_hashes") or {}).items()
    }
    live_hashes = {
        str(k): str(v)
        for k, v in (live.get("bundle_resource_hashes") or {}).items()
    }
    if snap_hashes != live_hashes:
        raise CriticSessionError(
            "critic_session_bundle_drift", "bundle_resource_hashes"
        )

    snap_resources = snapshot.get("bundle_resources")
    if snap_resources is not None:
        if _bundle_resources_signature(snap_resources) != _bundle_resources_signature(
            live.get("bundle_resources")
        ):
            raise CriticSessionError(
                "critic_session_bundle_drift", "bundle_resources"
            )

    for field in ("profiles", "extensions"):
        snap_val = snapshot.get(field)
        if snap_val is not None and list(snap_val) != list(live.get(field) or []):
            raise CriticSessionError(
                "critic_session_bundle_drift", field
            )

    live_cfg = _review_config_sha256_for(
        cfg,
        bundle_fingerprint=live_fp,
        bundle_resource_hashes=live_hashes,
        validator_version=live.get("validator_version"),
        built_version=live.get("built_version"),
        resolver_schema_version=live.get("resolver_schema_version"),
    )
    expected_cfg = snapshot.get("review_config_sha256") or reviewed_config_sha256
    if not expected_cfg:
        raise CriticSessionError(
            "critic_session_hash_mismatch", "review_config_sha256 required"
        )
    if expected_cfg != live_cfg:
        raise CriticSessionError(
            "critic_session_bundle_drift", "review_config_sha256"
        )
    if reviewed_config_sha256 and reviewed_config_sha256 != live_cfg:
        raise CriticSessionError(
            "critic_session_bundle_drift", "review_config_sha256"
        )
    return live_cfg


_PASS_SCHEMA_BY_KIND = {
    "session": "critic-session.schema.json",
    "config": "critic-config-pass.schema.json",
    "review": "critic-review-pass.schema.json",
    "critic": "critic-critic-pass.schema.json",
    "completed": "critic-completed-pass.schema.json",
}


def _load_json_object(path: Path, *, code: str, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise CriticSessionError(code, f"missing {label}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CriticSessionError(code, f"corrupt {label}") from exc
    if not isinstance(data, dict):
        raise CriticSessionError(code, f"{label} must be object")
    return data


def _validate_persisted_object(
    data: dict[str, Any],
    *,
    kind: str,
    label: str,
) -> None:
    schema_name = _PASS_SCHEMA_BY_KIND[kind]
    try:
        validate_against_schema(
            data,
            schema_name,
            error_code="critic_session_schema_mismatch",
            label=label,
        )
    except ValueError as exc:
        message = str(exc)
        if message.startswith("critic_session_schema_mismatch"):
            raise CriticSessionError(
                "critic_session_schema_mismatch", message.split(":", 1)[-1].strip()
            ) from exc
        raise CriticSessionError("critic_session_schema_mismatch", message) from exc


def _load_review_pass(directory: Path, pass_number: int) -> dict[str, Any]:
    label = f"review-pass-{pass_number}.json"
    data = _load_json_object(
        directory / label,
        code="critic_session_corrupt",
        label=label,
    )
    _validate_persisted_object(data, kind="review", label=label)
    return data


def _load_completed_pass(directory: Path, pass_number: int) -> dict[str, Any]:
    label = f"completed-pass-{pass_number}.json"
    data = _load_json_object(
        directory / label,
        code="critic_session_corrupt",
        label=label,
    )
    _validate_persisted_object(data, kind="completed", label=label)
    return data


def _load_critic_pass(directory: Path, pass_number: int) -> dict[str, Any]:
    label = f"critic-pass-{pass_number}.json"
    data = _load_json_object(
        directory / label,
        code="critic_session_corrupt",
        label=label,
    )
    _validate_persisted_object(data, kind="critic", label=label)
    return data


def _load_config_pass(directory: Path, pass_number: int) -> dict[str, Any]:
    label = f"config-pass-{pass_number}.json"
    data = _load_json_object(
        directory / label,
        code="critic_session_corrupt",
        label=label,
    )
    _validate_persisted_object(data, kind="config", label=label)
    return data


def _record_pass_file_hash(
    session: dict[str, Any],
    pass_number: int,
    filename: str,
    digest: str,
) -> None:
    hashes = session.setdefault("pass_file_hashes", {})
    hashes[filename] = digest
    for item in session.get("passes") or []:
        if int(item.get("pass_number") or 0) == pass_number:
            files = item.setdefault("files", {})
            files[filename] = digest
            return
    # Pass row may not exist yet (start); caller attaches files on the new row.


def _expected_pass_file_hashes(session: dict[str, Any]) -> dict[str, str]:
    expected: dict[str, str] = {}
    top = session.get("pass_file_hashes")
    if isinstance(top, dict):
        expected.update({str(k): str(v) for k, v in top.items()})
    for item in session.get("passes") or []:
        files = item.get("files")
        if isinstance(files, dict):
            expected.update({str(k): str(v) for k, v in files.items()})
    return expected


def _verify_persisted_file_hashes(directory: Path, session: dict[str, Any]) -> None:
    """Fail closed when any recorded pass file digest does not match on-disk bytes."""

    expected = _expected_pass_file_hashes(session)
    if not expected:
        raise CriticSessionError(
            "critic_session_corrupt", "missing pass_file_hashes"
        )
    for filename, expected_hash in sorted(expected.items()):
        path = directory / filename
        if not path.is_file():
            raise CriticSessionError(
                "critic_session_corrupt", f"missing hashed file {filename}"
            )
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected_hash:
            raise CriticSessionError(
                "critic_session_file_hash_mismatch", filename
            )


def _verify_prompt_package_against_stored(
    package: dict[str, Any],
    *,
    stored_review: dict[str, Any],
    session: dict[str, Any],
) -> None:
    """Ensure rebuilt/loaded prompt package matches immutable review-pass metadata."""

    checks = (
        ("prompt_package_hash", "latest_prompt_package_hash"),
        ("prompt_content_sha256", "latest_prompt_content_sha256"),
        ("review_request_sha256", "latest_review_request_sha256"),
        ("response_schema_sha256", None),
        ("review_config_sha256", "latest_review_config_sha256"),
    )
    if not package.get("review_config_sha256"):
        raise CriticSessionError(
            "critic_session_prompt_rebuild_mismatch", "review_config_sha256 required"
        )
    if not stored_review.get("review_config_sha256"):
        raise CriticSessionError(
            "critic_session_prompt_rebuild_mismatch", "review_config_sha256 required"
        )
    for package_field, session_field in checks:
        got = package.get(package_field)
        expected = stored_review.get(package_field)
        if expected is not None and got != expected:
            raise CriticSessionError(
                "critic_session_prompt_rebuild_mismatch", package_field
            )
        if session_field:
            session_expected = session.get(session_field)
            if session_expected is not None and got != session_expected:
                raise CriticSessionError(
                    "critic_session_prompt_rebuild_mismatch", package_field
                )


def _resolve_artifact_path(
    path: str,
    *,
    allow_write_roots: bool,
    label: str,
) -> Path:
    """Resolve artifact paths: generated graph/serializer may live under write roots.

    Every caller must use the policy ``analyze_artifact`` applied at start, or a
    session that started cleanly cannot be finalized.
    """

    try:
        if allow_write_roots:
            return workspace_policy.check_read_path(
                path, include_write_roots=True
            )
        return workspace_policy.check_read_path(path)
    except ValueError as exc:
        raise CriticSessionError(
            "critic_session_artifact_path_denied", label
        ) from exc


def _rehash_config_artifacts(cfg: dict[str, Any]) -> dict[str, Any]:
    """Resolve current config paths through workspace policy and rehash.

    Graph/serializer/coverage (generated) may sit under approved write roots.
    Source evidence paths remain read-root-only.
    """

    graph_path = _resolve_artifact_path(
        cfg["graph_path"], allow_write_roots=True, label="graph"
    )
    serializer_sha = None
    # Graph-only reviews record serializer_path but leave serializer_sha256
    # empty, matching analyze_artifact. Hashing the file here makes finalize
    # disagree with the reviewed artifact set.
    scope = cfg.get("critic_scope") or "both"
    if cfg.get("serializer_path") and scope in {"serializer", "both"}:
        ser_path = _resolve_artifact_path(
            cfg["serializer_path"], allow_write_roots=True, label="serializer"
        )
        serializer_sha = sha256_file(ser_path)
    source_sha: dict[str, str] = {}
    for idx, raw in enumerate(cfg.get("source_paths") or [], start=1):
        path = _resolve_artifact_path(
            raw, allow_write_roots=True, label=f"source:{idx}"
        )
        source_sha[f"source-{idx}:{path.name}"] = sha256_file(path)
    coverage_sha = None
    if cfg.get("coverage_contract_path"):
        cov = _resolve_artifact_path(
            cfg["coverage_contract_path"],
            allow_write_roots=True,
            label="coverage",
        )
        coverage_sha = sha256_file(cov)
    provenance_sha = None
    if cfg.get("provenance_manifest_path"):
        man = _resolve_artifact_path(
            cfg["provenance_manifest_path"],
            allow_write_roots=True,
            label="provenance_manifest",
        )
        provenance_sha = sha256_file(man)
    return _artifact_set_from_hashes(
        {
            "graph_sha256": sha256_file(graph_path),
            "serializer_sha256": serializer_sha,
            "source_sha256": source_sha,
            "coverage_contract_sha256": coverage_sha,
            "provenance_manifest_sha256": provenance_sha,
            "extra_ontology_sha256": _extra_ontology_hashes(
                cfg.get("extra_ontology_graphs")
            ),
        },
        require_review_config=False,
    )


def _load(directory: Path) -> dict[str, Any]:
    path = directory / "session.json"
    if not path.is_file():
        raise CriticSessionError("critic_session_corrupt", "missing session.json")
    try:
        session = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CriticSessionError(
            "critic_session_corrupt", "corrupt session.json"
        ) from exc
    if not isinstance(session, dict) or not session.get("schema_version"):
        raise CriticSessionError(
            "critic_session_corrupt", "missing schema_version"
        )
    _validate_persisted_object(session, kind="session", label="session.json")
    if not isinstance(session.get("config"), dict):
        raise CriticSessionError("critic_session_corrupt", "config must be object")
    return session


def _save(directory: Path, session: dict[str, Any]) -> None:
    _atomic_write_json(directory / "session.json", session)


def _verify_audit_chain(directory: Path) -> list[dict[str, Any]]:
    """Walk audit.jsonl; return verified events. Raise on any chain failure."""

    audit_path = directory / "audit.jsonl"
    if not audit_path.is_file():
        raise CriticSessionError(
            "critic_session_audit_corrupt", "missing audit.jsonl"
        )
    previous_event_sha256 = "0" * 64
    expected_sequence = 0
    events: list[dict[str, Any]] = []
    for line_no, line in enumerate(
        audit_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CriticSessionError(
                "critic_session_audit_corrupt", f"invalid json at line {line_no}"
            ) from exc
        if not isinstance(event, dict):
            raise CriticSessionError(
                "critic_session_audit_corrupt",
                f"event must be object at line {line_no}",
            )
        expected_sequence += 1
        if int(event.get("sequence") or 0) != expected_sequence:
            raise CriticSessionError(
                "critic_session_audit_corrupt",
                f"sequence mismatch at line {line_no}",
            )
        if str(event.get("previous_event_sha256") or "") != previous_event_sha256:
            raise CriticSessionError(
                "critic_session_audit_corrupt",
                f"previous_event_sha256 mismatch at line {line_no}",
            )
        stored_hash = str(event.get("event_sha256") or "")
        body = {k: v for k, v in event.items() if k != "event_sha256"}
        computed = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if stored_hash != computed:
            raise CriticSessionError(
                "critic_session_audit_corrupt",
                f"event_sha256 mismatch at line {line_no}",
            )
        previous_event_sha256 = stored_hash
        events.append(event)
    return events


def _verify_session_integrity(directory: Path, session: dict[str, Any]) -> None:
    """Reconcile session.json projection with audit.jsonl and on-disk pass files."""

    events = _verify_audit_chain(directory)
    if not events:
        raise CriticSessionError("critic_session_audit_corrupt", "empty audit")

    audit_files: dict[str, str] = {}
    for ev in events:
        files = ev.get("files")
        if isinstance(files, dict):
            audit_files.update({str(k): str(v) for k, v in files.items()})

    session_files = {
        str(k): str(v) for k, v in (session.get("pass_file_hashes") or {}).items()
    }
    if session_files != audit_files:
        raise CriticSessionError(
            "critic_session_audit_reconcile_mismatch", "pass_file_hashes"
        )

    for item in session.get("passes") or []:
        files = item.get("files")
        if not isinstance(files, dict):
            continue
        for name, digest in files.items():
            if audit_files.get(str(name)) != str(digest):
                raise CriticSessionError(
                    "critic_session_audit_reconcile_mismatch",
                    f"pass.files:{name}",
                )

    for filename, expected_hash in sorted(audit_files.items()):
        path = directory / filename
        if not path.is_file():
            raise CriticSessionError(
                "critic_session_corrupt", f"missing hashed file {filename}"
            )
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected_hash:
            raise CriticSessionError(
                "critic_session_file_hash_mismatch", filename
            )

    latest = events[-1]
    if session.get("latest_audit_event_sha256") != latest.get("event_sha256"):
        raise CriticSessionError(
            "critic_session_incomplete_transaction", "latest_audit_event_sha256"
        )

    if session.get("state") != latest.get("new_state"):
        raise CriticSessionError(
            "critic_session_audit_reconcile_mismatch", "state"
        )

    expected_proj = _compute_session_projection_sha256(session)
    stored_proj = latest.get("session_projection_sha256")
    if not stored_proj or stored_proj != expected_proj:
        raise CriticSessionError(
            "critic_session_audit_reconcile_mismatch",
            "session_projection_sha256",
        )

    if latest.get("artifact_set_sha256") and (
        session.get("latest_artifact_set") or session.get("latest_reviewed_artifacts")
    ):
        reviewed = session.get("latest_reviewed_artifacts") or {}
        live = session.get("latest_artifact_set") or {}
        ok = (
            (live and _artifact_set_sha256(live) == latest["artifact_set_sha256"])
            or (
                reviewed
                and _artifact_set_sha256(reviewed) == latest["artifact_set_sha256"]
            )
        )
        if not ok:
            raise CriticSessionError(
                "critic_session_audit_reconcile_mismatch",
                "artifact_set_sha256",
            )

    if session.get("latest_review_config_sha256") and latest.get(
        "review_config_sha256"
    ):
        if session["latest_review_config_sha256"] != latest["review_config_sha256"]:
            raise CriticSessionError(
                "critic_session_audit_reconcile_mismatch",
                "review_config_sha256",
            )

    pass_numbers = [
        int(ev["pass"])
        for ev in events
        if ev.get("pass") is not None
    ]
    if pass_numbers and int(session.get("current_pass") or 0) != max(pass_numbers):
        raise CriticSessionError(
            "critic_session_audit_reconcile_mismatch", "current_pass"
        )

    if session.get("state") == "finalized":
        if latest.get("event") != "finalize":
            raise CriticSessionError(
                "critic_session_audit_reconcile_mismatch",
                "missing_finalize_event",
            )
        if latest.get("new_state") != "finalized":
            raise CriticSessionError(
                "critic_session_audit_reconcile_mismatch",
                "finalize_new_state",
            )
        if latest.get("outcome") != session.get("final_outcome"):
            raise CriticSessionError(
                "critic_session_audit_reconcile_mismatch",
                "final_outcome",
            )
        if bool(session.get("accepted")) != (
            session.get("final_outcome") == "accepted"
        ):
            raise CriticSessionError(
                "critic_session_audit_reconcile_mismatch", "accepted"
            )
        if latest.get("outcome") == "accepted" and not session.get("accepted"):
            raise CriticSessionError(
                "critic_session_audit_reconcile_mismatch", "accepted"
            )


def _write_config_pass(
    directory: Path,
    pass_number: int,
    *,
    config: dict[str, Any],
    package: dict[str, Any],
    validation: dict[str, Any] | None,
) -> tuple[str, str]:
    """Write config-pass-N.json; return (filename, sha256)."""

    review_config_sha256 = package.get("review_config_sha256")
    if not review_config_sha256:
        raise CriticSessionError(
            "critic_session_hash_mismatch", "review_config_sha256 required"
        )
    extra_ontology_sha256 = _extra_ontology_hashes(config.get("extra_ontology_graphs"))
    live = _resolve_and_hash_bundle(config)
    # Prefer live disk identity; fall back to validation only if resolve was empty
    # and validation carried a fingerprint (should not diverge in normal paths).
    bundle_fingerprint = live.get("bundle_fingerprint")
    if bundle_fingerprint is None and validation:
        bundle_fingerprint = validation.get("bundle_fingerprint")
    bundle_resource_hashes = dict(live.get("bundle_resource_hashes") or {})
    if not bundle_resource_hashes and validation:
        bundle_resource_hashes = _bundle_resource_hashes_from_validation(validation)
    expected_cfg = _review_config_sha256_for(
        config,
        bundle_fingerprint=bundle_fingerprint,
        bundle_resource_hashes=bundle_resource_hashes,
        extra_ontology_sha256=extra_ontology_sha256,
        validator_version=live.get("validator_version"),
        built_version=live.get("built_version"),
        resolver_schema_version=live.get("resolver_schema_version"),
    )
    if review_config_sha256 != expected_cfg:
        raise CriticSessionError(
            "critic_session_hash_mismatch", "review_config_sha256"
        )
    snapshot = {
        "config": dict(config),
        "review_config_sha256": review_config_sha256,
        "bundle_fingerprint": bundle_fingerprint,
        "bundle_resource_hashes": bundle_resource_hashes,
        "bundle_resources": list(live.get("bundle_resources") or []),
        "extra_ontology_sha256": extra_ontology_sha256,
        "inference": live.get("inference"),
        "resolver_schema_version": live.get("resolver_schema_version"),
        "built_version": live.get("built_version"),
        "validator_version": live.get("validator_version"),
        "extensions": list(live.get("extensions") or []),
        "profiles": list(live.get("profiles") or []),
    }
    filename = f"config-pass-{pass_number}.json"
    digest = _atomic_write_json(directory / filename, snapshot)
    return filename, digest


def _write_review_pass(
    directory: Path, pass_number: int, review: CriticReview
) -> tuple[dict[str, Any], dict[str, str]]:
    """Persist review metadata without raw prompt_package body by default.

    Returns ``(stored_review, file_hashes)``.
    """

    full = review.to_dict()
    package = full.get("prompt_package") or review.prompt_package or {}
    if not package.get("review_config_sha256"):
        raise CriticSessionError(
            "critic_session_hash_mismatch", "review_config_sha256 required"
        )
    stored: dict[str, Any] = {
        key: full[key] for key in _REVIEW_PASS_KEEP if key in full
    }
    if "schema_version" in full:
        stored["schema_version"] = full["schema_version"]
    stored["prompt_package_hash"] = package.get("prompt_package_hash")
    stored["prompt_content_sha256"] = package.get("prompt_content_sha256")
    stored["review_request_sha256"] = package.get("review_request_sha256")
    stored["review_config_sha256"] = package.get("review_config_sha256")
    stored["response_schema_sha256"] = package.get("response_schema_sha256")
    filename = f"review-pass-{pass_number}.json"
    digest = _atomic_write_json(directory / filename, stored)
    file_hashes = {filename: digest}
    if _persist_prompts_enabled():
        prompt_name = f"prompt-pass-{pass_number}.json"
        file_hashes[prompt_name] = _atomic_write_json(
            directory / prompt_name, package
        )
    return stored, file_hashes


def _target_passes(additional_passes_approved: int) -> int:
    return REQUIRED_PASSES + int(additional_passes_approved)


def _open_actionable_blockers(session: dict[str, Any]) -> bool:
    """True when critical/high remain open, or actionable medium findings remain."""

    summary = session.get("latest_review_summary") or {}
    counts = summary.get("finding_counts") or {}
    if int(counts.get("critical_high_open") or 0) > 0:
        return True
    for finding in session.get("prior_findings") or []:
        if finding.get("status") in {"resolved"}:
            continue
        severity = finding.get("severity")
        if severity in {"critical", "high"}:
            return True
        # Actionable medium: explicitly non-suppressible open medium findings.
        if severity == "medium" and finding.get("suppressible") is False:
            return True
    return False


def rebuild_prompt_package_for_pass(
    session: dict[str, Any],
    directory: Path,
    pass_number: int,
) -> dict[str, Any]:
    """Rebuild the prompt package for schema binding when prompt-pass file is absent."""

    cfg = session["config"]
    prior: list[CriticFinding] = []
    if pass_number > 1:
        completed_path = directory / f"completed-pass-{pass_number - 1}.json"
        if completed_path.is_file():
            completed = _load_completed_pass(directory, pass_number - 1)
            prior = _findings_from_review_dict(completed)
    request = CriticArtifactRequest(
        graph_path=cfg["graph_path"],
        serializer_path=cfg.get("serializer_path"),
        source_paths=list(cfg.get("source_paths") or []),
        coverage_contract_path=cfg.get("coverage_contract_path"),
        provenance_manifest_path=cfg.get("provenance_manifest_path"),
        extensions=list(cfg.get("extensions") or []),
        profiles=list(cfg.get("profiles") or []),
        critic_scope=cfg.get("critic_scope") or "both",
        project_root=cfg.get("project_root"),
        serializer_mode=cfg.get("serializer_mode") or "auto",  # type: ignore[arg-type]
        extra_ontology_graphs=list(cfg.get("extra_ontology_graphs") or []),
        force_rdfs_inference=bool(cfg.get("force_rdfs_inference")),
        prior_findings=prior,
        session_id=session["session_id"],
        pass_number=pass_number,
    )
    try:
        review = analyze_artifact(request)
    except CriticError as exc:
        raise CriticSessionError(exc.code, str(exc)) from exc
    if review.artifact_hashes.graph_sha256 != session.get("latest_artifact_hash"):
        raise CriticSessionError(
            "critic_session_hash_mismatch",
            "rebuilt prompt package artifact hash mismatch",
        )
    package = review.prompt_package
    review_config_sha = package.get("review_config_sha256")
    rebuilt_set = _artifact_set_for_config(
        {
            **review.artifact_hashes.to_dict(),
            "review_config_sha256": review_config_sha,
        },
        cfg,
    )
    latest_set = session.get("latest_artifact_set") or {}
    if latest_set and rebuilt_set != latest_set:
        raise CriticSessionError(
            "critic_session_hash_mismatch",
            "rebuilt prompt package artifact set mismatch",
        )
    stored_review = _load_review_pass(directory, pass_number)
    _verify_prompt_package_against_stored(
        package, stored_review=stored_review, session=session
    )
    # Config drift: recompute from live disk bundle (not stored validation hashes alone).
    live = _resolve_and_hash_bundle(cfg)
    recomputed = _review_config_sha256_for(
        cfg,
        bundle_fingerprint=live.get("bundle_fingerprint"),
        bundle_resource_hashes=live.get("bundle_resource_hashes"),
        validator_version=live.get("validator_version"),
        built_version=live.get("built_version"),
        resolver_schema_version=live.get("resolver_schema_version"),
    )
    if not review_config_sha or review_config_sha != recomputed:
        raise CriticSessionError(
            "critic_session_prompt_rebuild_mismatch", "review_config_sha256"
        )
    return package


def _new_session_id() -> str:
    return f"critsess-{uuid.uuid4().hex}"


def _review_summary(review: CriticReview) -> dict[str, Any]:
    open_findings = [
        f
        for f in review.merged_findings
        if f.status not in {"resolved"}
    ]
    return {
        "status": review.status,
        "analysis_status": review.analysis_status,
        "artifact_hashes": review.artifact_hashes.to_dict(),
        "validation": {
            "conforms": review.validation.conforms,
            "verification_status": review.validation.verification_status,
            "error_code": review.validation.error_code,
            "bundle_fingerprint": review.validation.bundle_fingerprint,
        },
        "finding_counts": {
            "merged": len(review.merged_findings),
            "open": len(open_findings),
            "critical_high_open": len(
                [f for f in open_findings if f.severity in {"critical", "high"}]
            ),
        },
        "open_finding_ids": [f.finding_id for f in open_findings],
        "rule_execution_count": len(review.rule_executions),
        "scorecard": review.scorecard.to_dict(),
        "errors": list(review.errors),
        "elapsed_ms": review.elapsed_ms,
    }


def _open_critical_high(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        f
        for f in findings
        if f.get("status") not in {"resolved"}
        and f.get("severity") in {"critical", "high"}
    ]


def _findings_from_review_dict(review_dict: dict[str, Any]) -> list[CriticFinding]:
    return [
        CriticFinding.from_dict(item)
        for item in review_dict.get("merged_findings") or []
    ]


def build_sampling_messages(prompt_package: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "role": "system",
            "content": str(prompt_package.get("system_role") or ""),
        },
        {
            "role": "user",
            "content": json.dumps(
                {
                    "instruction": (
                        "Return ONLY a JSON object matching response_schema. "
                        "No markdown fences."
                    ),
                    "prompt_package": prompt_package,
                },
                sort_keys=True,
            ),
        },
    ]


def start_critic_review(
    graph_path: str,
    serializer_path: str | None = None,
    source_paths: list[str] | None = None,
    coverage_contract_path: str | None = None,
    provenance_manifest_path: str | None = None,
    extensions: list[str] | None = None,
    profiles: list[str] | None = None,
    critic_scope: str = "both",
    additional_iterations: int = 0,
    model_policy: str | None = None,
    report_output: str | None = None,
    project_root: str | None = None,
    serializer_mode: str = "auto",
    extra_ontology_graphs: list[str] | None = None,
    force_rdfs_inference: bool = False,
) -> dict[str, Any]:
    if additional_iterations < 0:
        raise CriticSessionError("critic_session_invalid_additional_iterations")
    if additional_iterations > MAX_TOTAL_PASSES - REQUIRED_PASSES:
        raise CriticSessionError(
            "critic_session_pass_cap",
            f"additional_iterations exceeds cap of {MAX_TOTAL_PASSES - REQUIRED_PASSES}",
        )
    policy = effective_model_policy(
        model_policy
        if normalize_model_policy(model_policy) is not None
        else default_model_policy()
    )
    approved_additional = int(additional_iterations)
    target_passes = _target_passes(approved_additional)
    max_passes = target_passes

    resolved_report_output: str | None = None
    if report_output:
        try:
            resolved_report_output = str(
                workspace_policy.check_write_path(
                    report_output, enforce_no_overwrite=False
                )
            )
        except ValueError as exc:
            raise CriticSessionError(
                "critic_session_report_path_denied", "report path denied"
            ) from exc

    session_id = _new_session_id()
    directory = session_root() / session_id
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "lock").touch()

    request = CriticArtifactRequest(
        graph_path=graph_path,
        serializer_path=serializer_path,
        source_paths=list(source_paths or []),
        coverage_contract_path=coverage_contract_path,
        provenance_manifest_path=provenance_manifest_path,
        extensions=list(extensions or []),
        profiles=list(profiles or []),
        critic_scope=critic_scope,  # type: ignore[arg-type]
        project_root=project_root,
        serializer_mode=serializer_mode or "auto",  # type: ignore[arg-type]
        extra_ontology_graphs=list(extra_ontology_graphs or []),
        force_rdfs_inference=bool(force_rdfs_inference),
        session_id=session_id,
        pass_number=1,
    )
    try:
        review = analyze_artifact(request)
    except CriticError as exc:
        shutil.rmtree(directory, ignore_errors=True)
        raise CriticSessionError(exc.code, str(exc)) from exc
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise

    config = asdict(
        SessionConfig(
            graph_path=graph_path,
            serializer_path=serializer_path,
            source_paths=list(source_paths or []),
            coverage_contract_path=coverage_contract_path,
            provenance_manifest_path=provenance_manifest_path,
            extensions=list(extensions or []),
            profiles=list(profiles or []),
            critic_scope=critic_scope,
            additional_iterations=approved_additional,
            model_policy=policy,
            report_output=resolved_report_output,
            project_root=project_root,
            serializer_mode=serializer_mode or "auto",
            extra_ontology_graphs=list(extra_ontology_graphs or []),
            force_rdfs_inference=bool(force_rdfs_inference),
        )
    )
    _stored_review, review_hashes = _write_review_pass(directory, 1, review)
    config_name, config_digest = _write_config_pass(
        directory,
        1,
        config=config,
        package=review.prompt_package,
        validation=review.validation.to_dict(),
    )
    pass_files = {**review_hashes, config_name: config_digest}

    extend_token = secrets.token_urlsafe(24)
    extend_challenge = secrets.token_urlsafe(18)
    review_config_sha = review.prompt_package.get("review_config_sha256")
    artifact_set = _artifact_set_for_config(
        {
            **review.artifact_hashes.to_dict(),
            "review_config_sha256": review_config_sha,
        },
        config,
    )
    session = {
        "schema_version": CRITIC_SESSION_SCHEMA,
        "session_id": session_id,
        "state": "awaiting_critic_response" if policy != "disabled" else "awaiting_revision",
        "model_policy": policy,
        "required_passes": REQUIRED_PASSES,
        "additional_passes_approved": approved_additional,
        "target_passes": target_passes,
        "max_total_passes": max_passes,
        "current_pass": 1,
        "completed_critic_responses": 0,
        "completed_deterministic_passes": 1,
        "config": config,
        "artifact_hash_history": [review.artifact_hashes.graph_sha256],
        "latest_artifact_hash": review.artifact_hashes.graph_sha256,
        "latest_reviewed_hash": None,
        "latest_artifact_set": artifact_set,
        "latest_reviewed_artifacts": None,
        "latest_prompt_package_hash": review.prompt_package.get("prompt_package_hash"),
        "latest_prompt_content_sha256": review.prompt_package.get("prompt_content_sha256"),
        "latest_review_request_sha256": review.prompt_package.get("review_request_sha256"),
        "latest_review_config_sha256": review_config_sha,
        "latest_serializer_sha256": review.artifact_hashes.serializer_sha256,
        "latest_bundle_fingerprint": (review.validation.bundle_fingerprint
                                      if hasattr(review.validation, "bundle_fingerprint")
                                      else None),
        "latest_review_summary": _review_summary(review),
        "prior_finding_ids": [f.finding_id for f in review.merged_findings],
        "prior_findings": [f.to_dict() for f in review.merged_findings],
        "extend_approval_token": extend_token,
        "extend_approval_challenge": extend_challenge,
        "pass_file_hashes": dict(pass_files),
        "passes": [
            {
                "pass_number": 1,
                "deterministic": _review_summary(review),
                "critic": None,
                "completed_pass": None,
                "files": dict(pass_files),
            }
        ],
    }
    if policy == "disabled":
        session["state"] = "awaiting_revision"
        session["latest_reviewed_hash"] = review.artifact_hashes.graph_sha256
        session["latest_reviewed_artifacts"] = artifact_set

    _commit_session_transition(
        directory,
        session,
        "start",
        {
            "pass": 1,
            "model_policy": policy,
            "files": dict(pass_files),
            "review_config_sha256": review_config_sha,
        },
        prior_state=None,
        new_state=session["state"],
        artifact_set_sha256=_artifact_set_sha256(artifact_set),
    )

    result = {
        "session_id": session_id,
        "state": session["state"],
        "pass_number": 1,
        "model_policy": policy,
        "required_passes": REQUIRED_PASSES,
        "target_passes": target_passes,
        "max_total_passes": max_passes,
        "additional_passes_approved": approved_additional,
        "review": _review_summary(review),
        "prompt_package": review.prompt_package if policy != "disabled" else None,
        "assessment_ledger": build_assessment_ledger(review.merged_findings),
        "next_action": (
            "submit_manual_critic_response"
            if policy == "manual"
            else (
                "start_critic_review_with_sampling"
                if policy == "client_sampling"
                else "submit_critic_revision_or_finalize"
            )
        ),
        "extend_approval_challenge": extend_challenge,
    }
    return result


def get_critic_review_status(session_id: str) -> dict[str, Any]:
    with _locked(session_id) as directory:
        session = _load(directory)
        _verify_session_integrity(directory, session)
    return {
        "session_id": session_id,
        "state": session["state"],
        "model_policy": session["model_policy"],
        "current_pass": session["current_pass"],
        "completed_critic_responses": session["completed_critic_responses"],
        "completed_deterministic_passes": session["completed_deterministic_passes"],
        "required_passes": session["required_passes"],
        "target_passes": session.get("target_passes")
        or _target_passes(session.get("additional_passes_approved") or 0),
        "additional_passes_approved": session["additional_passes_approved"],
        "max_total_passes": session["max_total_passes"],
        "latest_artifact_hash": session["latest_artifact_hash"],
        "latest_reviewed_hash": session["latest_reviewed_hash"],
        "latest_reviewed_artifacts": session.get("latest_reviewed_artifacts"),
        "latest_review_summary": session.get("latest_review_summary"),
        "final_outcome": session.get("final_outcome"),
        "extend_approval_challenge": session.get("extend_approval_challenge"),
        "passes": [
            {
                "pass_number": p["pass_number"],
                "has_critic": p.get("critic") is not None,
                "deterministic_status": (p.get("deterministic") or {}).get("status"),
                "completed_status": (p.get("completed_pass") or {}).get("status"),
            }
            for p in session.get("passes") or []
        ],
    }


def _model_review_attested(
    *,
    finding_count: int,
    assessment_count: int,
    notes: str,
    scorecard: CriticScorecard,
) -> bool:
    """Whether a manual pass shows that someone reviewed the graph.

    An empty findings list with an empty scorecard is a schema shell. It is
    not evidence that entity types were compared to their source text.
    """

    if finding_count or assessment_count or notes.strip():
        return True
    dimensions = (
        scorecard.schema_concept_conformance,
        scorecard.source_fidelity,
        scorecard.semantic_precision,
        scorecard.provenance_custody,
        scorecard.markings_authorization,
        scorecard.coverage_completeness,
        scorecard.serializer_quality,
        scorecard.maintainability_reproducibility,
    )
    return any(dimension.assessed for dimension in dimensions)


def submit_manual_critic_response(
    session_id: str,
    response: dict[str, Any] | str,
    *,
    sampling: dict[str, Any] | None = None,
) -> dict[str, Any]:
    with _locked(session_id) as directory:
        session = _load(directory)
        _verify_session_integrity(directory, session)
        if session["model_policy"] == "disabled":
            raise CriticSessionError("critic_session_manual_disabled")
        if session["state"] != "awaiting_critic_response":
            raise CriticSessionError(
                "critic_session_invalid_state", session["state"]
            )
        prior_state = session["state"]
        pass_number = int(session["current_pass"])
        prompt_path = directory / f"prompt-pass-{pass_number}.json"
        if prompt_path.is_file():
            prompt = _load_json_object(
                prompt_path,
                code="critic_session_corrupt",
                label=f"prompt-pass-{pass_number}.json",
            )
        else:
            prompt = rebuild_prompt_package_for_pass(session, directory, pass_number)
        review_dict = _load_review_pass(directory, pass_number)
        _verify_prompt_package_against_stored(
            prompt, stored_review=review_dict, session=session
        )
        hashes = review_dict["artifact_hashes"]
        det_findings = _findings_from_review_dict(review_dict)
        ledger = build_assessment_ledger(det_findings)
        try:
            parsed = parse_critic_model_response(
                response,
                expected_graph_sha256=hashes["graph_sha256"],
                expected_prompt_package_hash=prompt["prompt_package_hash"],
                expected_serializer_sha256=hashes.get("serializer_sha256"),
                session_id=session_id,
                pass_number=pass_number,
                expected_review_request_sha256=prompt.get("review_request_sha256"),
                expected_review_config_sha256=prompt.get("review_config_sha256"),
                bound_schema=prompt.get("response_schema"),
                allowed_assessments=ledger,
            )
        except CriticResponseError as exc:
            raise CriticSessionError(exc.code, str(exc)) from exc

        model_scorecard = parsed["scorecard"]
        if not isinstance(model_scorecard, CriticScorecard):
            model_scorecard = CriticScorecard.from_dict(model_scorecard or {})
        det_scorecard = CriticScorecard.from_dict(
            (review_dict.get("scorecard") or {})
        )
        assessments = list(parsed.get("finding_assessments") or [])
        critic_findings = list(parsed["findings"])
        completed = merge_completed_pass_review(
            deterministic_findings=det_findings,
            assessments=assessments,
            new_critic_findings=critic_findings,
            det_scorecard=det_scorecard,
            model_scorecard=model_scorecard,
            validation=dict(review_dict.get("validation") or {}),
            analysis_status=str(review_dict.get("analysis_status") or "complete"),
            artifact_hashes=hashes,
            status=None,
        )
        completed_name = f"completed-pass-{pass_number}.json"
        critic_name = f"critic-pass-{pass_number}.json"
        completed_digest = _atomic_write_json(
            directory / completed_name, completed
        )
        critic_payload = {
            "findings": [f.to_dict() for f in critic_findings],
            "finding_assessments": assessments,
            "scorecard": completed["scorecard"],
        }
        critic_digest = _atomic_write_json(
            directory / critic_name, critic_payload
        )
        written_files = {
            completed_name: completed_digest,
            critic_name: critic_digest,
        }
        for filename, digest in written_files.items():
            _record_pass_file_hash(session, pass_number, filename, digest)

        critic_record: dict[str, Any] = {
            "finding_ids": [f.finding_id for f in critic_findings],
            "finding_count": len(critic_findings),
            "assessment_count": len(assessments),
            "notes": parsed.get("notes") or "",
            "scorecard": completed["scorecard"],
            "completed_status": completed["status"],
            "finding_counts": completed["finding_counts"],
            "model_review_attested": _model_review_attested(
                finding_count=len(critic_findings),
                assessment_count=len(assessments),
                notes=str(parsed.get("notes") or ""),
                scorecard=model_scorecard,
            ),
        }
        if sampling:
            # Persist sampling metadata (model, tokens, status, fallback reason).
            critic_record["sampling"] = {
                "status": sampling.get("status"),
                "model": sampling.get("model"),
                "input_tokens": sampling.get("input_tokens"),
                "output_tokens": sampling.get("output_tokens"),
                "fallback": sampling.get("fallback"),
                "error": sampling.get("error"),
                "metadata": sampling.get("metadata") or {},
            }
        for item in session["passes"]:
            if item["pass_number"] == pass_number:
                item["critic"] = critic_record
                item["completed_pass"] = {
                    "status": completed["status"],
                    "finding_counts": completed["finding_counts"],
                    "open_finding_ids": completed["open_finding_ids"],
                }
                break

        artifact_set = _artifact_set_for_config(
            {
                **hashes,
                "review_config_sha256": prompt.get("review_config_sha256")
                or review_dict.get("review_config_sha256"),
            },
            session["config"],
        )
        session["completed_critic_responses"] = int(session["completed_critic_responses"]) + 1
        session["latest_reviewed_hash"] = hashes["graph_sha256"]
        session["latest_reviewed_artifacts"] = artifact_set
        session["latest_artifact_set"] = artifact_set
        session["latest_review_summary"] = {
            "status": completed["status"],
            "analysis_status": completed["analysis_status"],
            "artifact_hashes": hashes,
            "validation": completed["validation"],
            "finding_counts": completed["finding_counts"],
            "open_finding_ids": completed["open_finding_ids"],
            "scorecard": completed["scorecard"],
            "errors": list(review_dict.get("errors") or []),
            "elapsed_ms": review_dict.get("elapsed_ms"),
        }
        session["state"] = "awaiting_revision"
        session["prior_findings"] = completed["merged_findings"]
        session["prior_finding_ids"] = [
            f["finding_id"] for f in completed["merged_findings"]
        ]
        _commit_session_transition(
            directory,
            session,
            "manual_critic_response",
            {
                "pass": pass_number,
                "finding_count": len(critic_findings),
                "assessment_count": len(assessments),
                "completed_status": completed["status"],
                "sampling_status": (sampling or {}).get("status"),
                "files": written_files,
                "review_config_sha256": (
                    prompt.get("review_config_sha256")
                    or review_dict.get("review_config_sha256")
                ),
            },
            prior_state=prior_state,
            new_state=session["state"],
            artifact_set_sha256=_artifact_set_sha256(artifact_set),
        )
        return {
            "session_id": session_id,
            "state": session["state"],
            "pass_number": pass_number,
            "completed_critic_responses": session["completed_critic_responses"],
            "critic": critic_record,
            "completed_pass": session["latest_review_summary"],
            "next_action": "submit_critic_revision",
        }


def apply_sampled_critic_response(
    session_id: str,
    raw_text_or_dict: dict[str, Any] | str,
    *,
    sampling: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return submit_manual_critic_response(
        session_id, raw_text_or_dict, sampling=sampling
    )


def submit_critic_revision(
    session_id: str,
    graph_path: str,
    serializer_path: str | None = None,
    source_paths: list[str] | None = None,
    coverage_contract_path: str | None = None,
    change_summary: str | None = None,
    addressed_finding_ids: list[str] | None = None,
    extensions: list[str] | None = None,
    profiles: list[str] | None = None,
    serializer_mode: str | None = None,
    extra_ontology_graphs: list[str] | None = None,
    force_rdfs_inference: bool | None = None,
) -> dict[str, Any]:
    with _locked(session_id) as directory:
        session = _load(directory)
        _verify_session_integrity(directory, session)
        if session["state"] != "awaiting_revision":
            raise CriticSessionError(
                "critic_session_invalid_state", session["state"]
            )
        target_passes = int(
            session.get("target_passes")
            or _target_passes(session.get("additional_passes_approved") or 0)
        )
        if session["current_pass"] >= session["max_total_passes"] and (
            session["completed_critic_responses"] >= target_passes
            or session["model_policy"] == "disabled"
        ):
            # Allow final confirmation analysis only if under cap for next pass.
            pass

        next_pass = int(session["current_pass"]) + 1
        if next_pass > session["max_total_passes"]:
            raise CriticSessionError("critic_session_pass_cap")

        cfg = session["config"]
        prior_raw = session.get("prior_findings") or []
        prior = [CriticFinding.from_dict(item) for item in prior_raw]

        if serializer_mode is not None:
            cfg["serializer_mode"] = serializer_mode
        if extra_ontology_graphs is not None:
            cfg["extra_ontology_graphs"] = list(extra_ontology_graphs)
        if force_rdfs_inference is not None:
            cfg["force_rdfs_inference"] = bool(force_rdfs_inference)

        request = CriticArtifactRequest(
            graph_path=graph_path,
            serializer_path=serializer_path
            if serializer_path is not None
            else cfg.get("serializer_path"),
            source_paths=list(
                source_paths
                if source_paths is not None
                else cfg.get("source_paths") or []
            ),
            coverage_contract_path=(
                coverage_contract_path
                if coverage_contract_path is not None
                else cfg.get("coverage_contract_path")
            ),
            extensions=list(
                extensions if extensions is not None else cfg.get("extensions") or []
            ),
            profiles=list(
                profiles if profiles is not None else cfg.get("profiles") or []
            ),
            critic_scope=cfg.get("critic_scope") or "both",
            project_root=cfg.get("project_root"),
            serializer_mode=cfg.get("serializer_mode") or "auto",  # type: ignore[arg-type]
            extra_ontology_graphs=list(cfg.get("extra_ontology_graphs") or []),
            force_rdfs_inference=bool(cfg.get("force_rdfs_inference")),
            prior_findings=prior,
            session_id=session_id,
            pass_number=next_pass,
        )
        try:
            review = analyze_artifact(request)
        except CriticError as exc:
            raise CriticSessionError(exc.code, str(exc)) from exc

        # Update config paths before building artifact set so extras/paths match.
        session["config"]["graph_path"] = graph_path
        if serializer_path is not None:
            session["config"]["serializer_path"] = serializer_path
        if source_paths is not None:
            session["config"]["source_paths"] = list(source_paths)
        if coverage_contract_path is not None:
            session["config"]["coverage_contract_path"] = coverage_contract_path
        if extensions is not None:
            session["config"]["extensions"] = list(extensions)
        if profiles is not None:
            session["config"]["profiles"] = list(profiles)

        new_hash = review.artifact_hashes.graph_sha256
        review_config_sha = review.prompt_package.get("review_config_sha256")
        new_set = _artifact_set_for_config(
            {
                **review.artifact_hashes.to_dict(),
                "review_config_sha256": review_config_sha,
            },
            session["config"],
        )
        old_set = session.get("latest_artifact_set") or {}
        if new_set == old_set and _open_actionable_blockers(session):
            raise CriticSessionError(
                "critic_session_revision_unchanged",
                "artifact set unchanged while blockers remain",
            )

        # Drift check: package review_config must match recomputed config+bundle.
        # Drift check: package review_config must match live disk bundle identity.
        live = _resolve_and_hash_bundle(session["config"])
        expected_cfg = _review_config_sha256_for(
            session["config"],
            bundle_fingerprint=live.get("bundle_fingerprint"),
            bundle_resource_hashes=live.get("bundle_resource_hashes"),
            validator_version=live.get("validator_version"),
            built_version=live.get("built_version"),
            resolver_schema_version=live.get("resolver_schema_version"),
        )
        if not review_config_sha or review_config_sha != expected_cfg:
            raise CriticSessionError(
                "critic_session_hash_mismatch", "review_config_sha256"
            )

        _stored_review, review_hashes = _write_review_pass(directory, next_pass, review)
        config_name, config_digest = _write_config_pass(
            directory,
            next_pass,
            config=session["config"],
            package=review.prompt_package,
            validation=review.validation.to_dict(),
        )
        pass_files = {**review_hashes, config_name: config_digest}
        for filename, digest in pass_files.items():
            _record_pass_file_hash(session, next_pass, filename, digest)

        session["current_pass"] = next_pass
        session["completed_deterministic_passes"] = (
            int(session["completed_deterministic_passes"]) + 1
        )
        session["artifact_hash_history"].append(new_hash)
        session["latest_artifact_hash"] = new_hash
        session["latest_prompt_package_hash"] = review.prompt_package.get(
            "prompt_package_hash"
        )
        session["latest_prompt_content_sha256"] = review.prompt_package.get(
            "prompt_content_sha256"
        )
        session["latest_review_request_sha256"] = review.prompt_package.get(
            "review_request_sha256"
        )
        session["latest_review_config_sha256"] = review_config_sha
        session["latest_serializer_sha256"] = review.artifact_hashes.serializer_sha256
        session["latest_review_summary"] = _review_summary(review)
        session["latest_artifact_set"] = new_set
        session["latest_bundle_fingerprint"] = review.validation.bundle_fingerprint
        if change_summary:
            session["last_change_summary"] = change_summary[:2000]
        if addressed_finding_ids:
            session["last_addressed_finding_ids"] = list(addressed_finding_ids)[:200]

        session["passes"].append(
            {
                "pass_number": next_pass,
                "deterministic": _review_summary(review),
                "critic": None,
                "completed_pass": None,
                "files": dict(pass_files),
            }
        )

        if session["model_policy"] == "disabled":
            session["latest_reviewed_hash"] = new_hash
            session["latest_reviewed_artifacts"] = session["latest_artifact_set"]
            session["state"] = "awaiting_revision"
            next_action = (
                "finalize_critic_review"
                if session["completed_deterministic_passes"] >= target_passes
                else "submit_critic_revision"
            )
        else:
            session["state"] = "awaiting_critic_response"
            next_action = "submit_manual_critic_response"

        session["prior_findings"] = [f.to_dict() for f in review.merged_findings]
        session["prior_finding_ids"] = [f.finding_id for f in review.merged_findings]
        _commit_session_transition(
            directory,
            session,
            "revision",
            {
                "pass": next_pass,
                "graph_sha256": new_hash,
                "addressed": list(addressed_finding_ids or [])[:50],
                "files": dict(pass_files),
                "review_config_sha256": review_config_sha,
            },
            prior_state="awaiting_revision",
            new_state=session["state"],
            artifact_set_sha256=_artifact_set_sha256(session["latest_artifact_set"]),
        )
        return {
            "session_id": session_id,
            "state": session["state"],
            "pass_number": next_pass,
            "review": _review_summary(review),
            "assessment_ledger": build_assessment_ledger(review.merged_findings),
            "prompt_package": (
                None
                if session["model_policy"] == "disabled"
                else review.prompt_package
            ),
            "next_action": next_action,
        }


def extend_critic_review(
    session_id: str,
    additional_iterations: int,
    *,
    approval_token: str,
) -> dict[str, Any]:
    if not isinstance(additional_iterations, int) or additional_iterations <= 0:
        raise CriticSessionError("critic_session_invalid_additional_iterations")
    with _locked(session_id) as directory:
        session = _load(directory)
        _verify_session_integrity(directory, session)
        if session["state"] in {"finalized", "cancelled"}:
            raise CriticSessionError("critic_session_invalid_state", session["state"])
        env_token = os.environ.get(EXTEND_TOKEN_ENV)
        expected_tokens = {
            t
            for t in (
                env_token,
                session.get("extend_approval_token"),
                session.get("extend_approval_challenge"),
            )
            if t
        }
        if not approval_token or approval_token not in expected_tokens:
            raise CriticSessionError("critic_session_extend_denied")
        prior_state = session["state"]
        new_additional = int(session["additional_passes_approved"]) + additional_iterations
        new_target = _target_passes(new_additional)
        if new_target > MAX_TOTAL_PASSES:
            raise CriticSessionError("critic_session_pass_cap")
        # One-time challenge: rotate after successful use when challenge matched.
        if approval_token == session.get("extend_approval_challenge"):
            session["extend_approval_challenge"] = secrets.token_urlsafe(18)
        session["additional_passes_approved"] = new_additional
        session["target_passes"] = new_target
        session["max_total_passes"] = new_target
        _commit_session_transition(
            directory,
            session,
            "extend",
            {
                "additional_iterations": additional_iterations,
                "max": new_target,
                "target_passes": new_target,
            },
            prior_state=prior_state,
            new_state=session["state"],
        )
        return {
            "session_id": session_id,
            "additional_passes_approved": new_additional,
            "target_passes": new_target,
            "max_total_passes": new_target,
            "state": session["state"],
            "extend_approval_challenge": session.get("extend_approval_challenge"),
        }


def finalize_critic_review(session_id: str) -> dict[str, Any]:
    with _locked(session_id) as directory:
        session = _load(directory)
        if session["state"] in {"cancelled", "finalized"}:
            raise CriticSessionError("critic_session_invalid_state", session["state"])

        _verify_session_integrity(directory, session)

        target_passes = int(
            session.get("target_passes")
            or _target_passes(session.get("additional_passes_approved") or 0)
        )
        policy = session["model_policy"]
        if policy == "disabled":
            if int(session["completed_deterministic_passes"]) < target_passes:
                raise CriticSessionError("critic_session_passes_incomplete")
        else:
            if int(session["completed_critic_responses"]) < target_passes:
                raise CriticSessionError("critic_session_passes_incomplete")
            if session["state"] != "awaiting_revision":
                raise CriticSessionError(
                    "critic_session_invalid_state", session["state"]
                )

        cfg = session["config"]
        # Rehash complete artifact set from disk and compare to last reviewed set.
        current_set = _rehash_config_artifacts(cfg)
        reviewed_set = session.get("latest_reviewed_artifacts") or {}
        if not reviewed_set:
            raise CriticSessionError("critic_session_hash_mismatch", "no reviewed artifacts")

        # Re-resolve validation bundle from disk and compare to config-pass snapshot.
        pass_number = int(session["current_pass"])
        config_snapshot = _load_config_pass(directory, pass_number)
        live_bundle = _resolve_and_hash_bundle(cfg)
        reviewed_cfg = (
            session.get("latest_review_config_sha256")
            or reviewed_set.get("review_config_sha256")
        )
        live_cfg = _assert_bundle_matches_snapshot(
            live_bundle,
            config_snapshot,
            cfg=cfg,
            reviewed_config_sha256=reviewed_cfg,
        )
        current_set["review_config_sha256"] = live_cfg

        if current_set != reviewed_set:
            raise CriticSessionError(
                "critic_session_hash_mismatch",
                "artifact set changed after last review",
            )
        if session["latest_artifact_hash"] != session["latest_reviewed_hash"]:
            raise CriticSessionError("critic_session_hash_mismatch")

        # Prefer optional final validation re-run when the validator is available.
        try:
            import graph_validator

            if graph_validator.validator_available():
                report = graph_validator.validate_graph_file(
                    cfg["graph_path"],
                    extensions=list(cfg.get("extensions") or []) or None,
                    profiles=list(cfg.get("profiles") or []) or None,
                    project_root=_project_root_for_config(cfg),
                    extra_ontology_graphs=list(cfg.get("extra_ontology_graphs") or [])
                    or None,
                    force_rdfs_inference=bool(cfg.get("force_rdfs_inference")),
                )
                if (
                    report.verification_status != "complete"
                    or report.conforms is not True
                ):
                    raise CriticSessionError(
                        "critic_session_validation_incomplete",
                        "final validation did not conform",
                    )
                if (
                    report.bundle_fingerprint
                    and report.bundle_fingerprint
                    != live_bundle.get("bundle_fingerprint")
                ):
                    raise CriticSessionError(
                        "critic_session_bundle_drift", "bundle_fingerprint"
                    )
        except CriticSessionError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise CriticSessionError(
                "critic_session_validation_incomplete",
                type(exc).__name__,
            ) from exc

        summary = session.get("latest_review_summary") or {}
        # Prefer completed-pass file for the latest critic pass when present.
        completed_path = directory / f"completed-pass-{pass_number}.json"
        if completed_path.is_file():
            completed = _load_completed_pass(directory, pass_number)
            summary = {
                "status": completed.get("status"),
                "analysis_status": completed.get("analysis_status"),
                "artifact_hashes": completed.get("artifact_hashes"),
                "validation": completed.get("validation"),
                "finding_counts": completed.get("finding_counts"),
                "open_finding_ids": completed.get("open_finding_ids"),
                "scorecard": completed.get("scorecard"),
            }

        outcome = finalize_outcome_from_summary(summary)
        if outcome == "validation_incomplete":
            raise CriticSessionError("critic_session_validation_incomplete")
        if outcome == "needs_revision":
            raise CriticSessionError("critic_session_nonconforming")
        if outcome == "analysis_incomplete":
            raise CriticSessionError("critic_session_analysis_incomplete")
        if outcome == "blocked_with_findings":
            raise CriticSessionError("critic_session_blockers_remain")

        review_substance = "not_applicable"
        if policy != "disabled":
            critic_passes = [
                item.get("critic") or {}
                for item in session.get("passes") or []
                if item.get("critic")
            ]
            if critic_passes and all(
                item.get("model_review_attested") is False for item in critic_passes
            ):
                review_substance = "empty_shell"
            elif critic_passes:
                review_substance = "reviewed"
            if outcome == "accepted" and review_substance == "empty_shell":
                outcome = "review_unattested"

        report_payload = {
            "session_id": session_id,
            "finalized": True,
            "outcome": outcome,
            "accepted": outcome == "accepted",
            "review_substance": review_substance,
            "latest_artifact_hash": session["latest_artifact_hash"],
            "latest_reviewed_artifacts": reviewed_set,
            "summary": summary,
            "bundle_fingerprint": live_bundle.get("bundle_fingerprint"),
        }
        # Write report before committing finalized state (P0-5).
        if cfg.get("report_output"):
            try:
                out = workspace_policy.check_write_path(
                    cfg["report_output"], enforce_no_overwrite=False
                )
                _atomic_write_json(out, report_payload)
            except CriticSessionError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise CriticSessionError(
                    "critic_session_report_write_failed",
                    type(exc).__name__,
                ) from exc

        # accepted and completed_with_findings are successful finalizations
        prior_state = session["state"]
        session["state"] = "finalized"
        session["finalized_at"] = time.time()
        session["final_outcome"] = outcome
        session["accepted"] = outcome == "accepted"
        _commit_session_transition(
            directory,
            session,
            "finalize",
            {
                "hash": session["latest_artifact_hash"],
                "outcome": outcome,
                "accepted": session["accepted"],
                "files": dict(session.get("pass_file_hashes") or {}),
                "artifact_set": current_set,
                "review_config_sha256": current_set.get("review_config_sha256"),
                "bundle_fingerprint": live_bundle.get("bundle_fingerprint"),
            },
            prior_state=prior_state,
            new_state="finalized",
            artifact_set_sha256=_artifact_set_sha256(current_set),
        )

        return {
            "session_id": session_id,
            "state": "finalized",
            "outcome": outcome,
            "accepted": session["accepted"],
            "review_substance": review_substance,
            "latest_artifact_hash": session["latest_artifact_hash"],
            "latest_reviewed_hash": session["latest_reviewed_hash"],
            "latest_reviewed_artifacts": reviewed_set,
            "summary": summary,
        }


def cancel_critic_review(session_id: str) -> dict[str, Any]:
    with _locked(session_id) as directory:
        session = _load(directory)
        _verify_session_integrity(directory, session)
        if session["state"] == "finalized":
            raise CriticSessionError("critic_session_invalid_state", "finalized")
        prior_state = session["state"]
        session["state"] = "cancelled"
        _commit_session_transition(
            directory,
            session,
            "cancel",
            {},
            prior_state=prior_state,
            new_state="cancelled",
        )
        return {"session_id": session_id, "state": "cancelled"}


def load_session_for_handoff(session_id: str) -> dict[str, Any]:
    with _locked(session_id) as directory:
        session = _load(directory)
        if session["state"] != "finalized":
            raise CriticSessionError("critic_session_not_finalized")
        _verify_session_integrity(directory, session)
        pass_number = int(session["current_pass"])
        review = _load_review_pass(directory, pass_number)
        _load_config_pass(directory, pass_number)
        completed_path = directory / f"completed-pass-{pass_number}.json"
        if completed_path.is_file():
            completed = _load_completed_pass(directory, pass_number)
            review = {
                **review,
                "merged_findings": completed.get("merged_findings")
                or review.get("merged_findings"),
                "artifact_hashes": completed.get("artifact_hashes")
                or review.get("artifact_hashes"),
            }
        critic_path = directory / f"critic-pass-{pass_number}.json"
        critic = (
            _load_critic_pass(directory, pass_number)
            if critic_path.is_file()
            else {"findings": []}
        )
        return {
            "session": session,
            "review": review,
            "critic": critic,
            "directory": str(directory),
        }


def replay_manual_session(
    *,
    case_dir: Path | str,
    pass1_response_path: Path | str,
    pass2_response_path: Path | str,
    session_id: str | None = None,
    project_root: Path | str | None = None,
    pass1_graph_path: Path | str | None = None,
    pass2_graph_path: Path | str | None = None,
) -> dict[str, Any]:
    """Real two-pass session state-machine replay for evaluation harnesses."""

    case_dir = Path(case_dir)
    manifest = json.loads((case_dir / "manifest.json").read_text(encoding="utf-8"))
    if pass1_graph_path:
        graph_path = Path(pass1_graph_path).resolve()
    else:
        graph_path = (case_dir / manifest["graph_path"]).resolve()
    if pass2_graph_path:
        pass2_graph = Path(pass2_graph_path).resolve()
    elif manifest.get("pass2_graph_path"):
        pass2_graph = (case_dir / manifest["pass2_graph_path"]).resolve()
    else:
        pass2_graph = graph_path
    started = start_critic_review(
        graph_path=str(graph_path),
        critic_scope=manifest.get("critic_scope", "graph"),
        model_policy="manual",
        extensions=list(manifest.get("extensions") or []),
        profiles=list(manifest.get("profiles") or []),
        coverage_contract_path=(
            str((case_dir / manifest["coverage_contract_path"]).resolve())
            if manifest.get("coverage_contract_path")
            else None
        ),
        source_paths=[
            str((case_dir / p).resolve()) for p in (manifest.get("source_paths") or [])
        ],
        project_root=str(project_root) if project_root else None,
        serializer_mode=manifest.get("serializer_mode", "auto"),
        extra_ontology_graphs=[
            str((case_dir / p).resolve())
            if not Path(p).is_absolute()
            else str(Path(p).resolve())
            for p in (manifest.get("extra_ontology_graphs") or [])
        ],
        force_rdfs_inference=bool(manifest.get("force_rdfs_inference")),
    )
    sid = started["session_id"]
    if session_id:
        # Keep generated id; external ids are not injectable into store path.
        pass

    def _bind(template: dict[str, Any], package: dict[str, Any], pass_number: int) -> dict[str, Any]:
        bound = dict(template)
        bound["schema_version"] = template.get("schema_version", "1.2.0")
        bound["graph_sha256"] = package["artifact_hashes"]["graph_sha256"]
        bound["serializer_sha256"] = package["artifact_hashes"].get("serializer_sha256")
        bound["prompt_package_hash"] = package["prompt_package_hash"]
        bound["session_id"] = sid
        bound["pass_number"] = pass_number
        bound["review_request_sha256"] = package.get("review_request_sha256")
        bound["review_config_sha256"] = package.get("review_config_sha256")
        bound.setdefault("findings", [])
        bound.setdefault("finding_assessments", [])
        bound.setdefault("scorecard", {})
        return bound

    def _finding_snapshot(pass_number: int) -> dict[str, Any]:
        review_path = session_root() / sid / f"review-pass-{pass_number}.json"
        if not review_path.is_file():
            return {
                "open": 0,
                "resolved": 0,
                "regressions": 0,
                "open_rule_ids": [],
                "resolved_rule_ids": [],
                "validation_conforms": None,
                "scorecard": None,
            }
        review = json.loads(review_path.read_text(encoding="utf-8"))
        open_ids: list[str] = []
        resolved_ids: list[str] = []
        regressions = 0
        for finding in review.get("merged_findings") or []:
            rule_id = finding.get("rule_id")
            status = finding.get("status")
            if status == "resolved" and rule_id:
                resolved_ids.append(str(rule_id))
            elif status == "regression":
                regressions += 1
                if rule_id:
                    open_ids.append(str(rule_id))
            elif status != "resolved" and rule_id:
                open_ids.append(str(rule_id))
        validation = review.get("validation") or {}
        return {
            "open": len(open_ids),
            "resolved": len(resolved_ids),
            "regressions": regressions,
            "open_rule_ids": sorted(set(open_ids)),
            "resolved_rule_ids": sorted(set(resolved_ids)),
            "validation_conforms": validation.get("conforms"),
            "scorecard": review.get("scorecard"),
        }

    pass1_template = json.loads(Path(pass1_response_path).read_text(encoding="utf-8"))
    pass1 = submit_manual_critic_response(
        sid, _bind(pass1_template, started["prompt_package"], 1)
    )
    snap1 = _finding_snapshot(1)
    revised = submit_critic_revision(
        sid,
        graph_path=str(pass2_graph),
        change_summary="evaluation replay pass-2 artifact",
    )
    pass2_template = json.loads(Path(pass2_response_path).read_text(encoding="utf-8"))
    package2 = revised.get("prompt_package") or {}
    pass2 = submit_manual_critic_response(
        sid, _bind(pass2_template, package2, 2)
    )
    snap2 = _finding_snapshot(2)
    final_error = None
    final: dict[str, Any] | None = None
    try:
        final = finalize_critic_review(sid)
    except CriticSessionError as exc:
        final_error = {"code": exc.code, "message": str(exc)}

    return {
        "case_id": manifest.get("case_id"),
        "session_id": sid,
        "pass1_graph": str(graph_path),
        "pass2_graph": str(pass2_graph),
        "passes": [
            {
                "pass_number": 1,
                "parsed_ok": True,
                "model_finding_count": pass1.get("critic", {}).get("finding_count"),
                "completed_status": (pass1.get("completed_pass") or {}).get("status"),
                "findings": snap1,
            },
            {
                "pass_number": 2,
                "parsed_ok": True,
                "model_finding_count": pass2.get("critic", {}).get("finding_count"),
                "completed_status": (pass2.get("completed_pass") or {}).get("status"),
                "findings": snap2,
            },
        ],
        "converged": bool(
            final
            and final.get("outcome") in {"accepted", "completed_with_findings"}
        ),
        "finalized": final is not None,
        "final": final,
        "final_error": final_error,
        "final_status": (pass2.get("completed_pass") or {}).get("status"),
        "final_outcome": (final or {}).get("outcome"),
        "accepted": bool((final or {}).get("accepted")),
    }
