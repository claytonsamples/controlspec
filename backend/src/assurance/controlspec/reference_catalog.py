"""Immutable, non-authoritative catalog for the ControlSpec reference API."""

from __future__ import annotations

from collections.abc import Iterable
from importlib import resources
from importlib.resources.abc import Traversable
from typing import Literal

from pydantic import Field, TypeAdapter

from assurance.contracts.canonical import canonical_json, sha256_digest
from assurance.controlspec.api_models import (
    REFERENCE_AUTHORITY,
    CatalogBinding,
    CatalogEntryMetadata,
    CatalogId,
    ControlDetailResponse,
    ControlListResponse,
    ControlSelection,
    ControlSummary,
    PackDetailResponse,
    PackListResponse,
    PackSelection,
    PackSummary,
    ReferenceSelection,
)
from assurance.controlspec.canonical import verify_object_digest
from assurance.controlspec.contracts import (
    ActionIntent,
    CanonicalSet,
    Control,
    ControlPack,
    ControlRef,
    ControlSpecModel,
    ControlStatus,
    Decision,
    HashDigest,
    Identifier,
    SemVer,
    UtcTimestamp,
)
from assurance.controlspec.facts import (
    ApprovalFact,
    EvaluationFacts,
    PublishedControlSnapshot,
    SnapshotAuthorityMode,
    facts_digest,
    finalize_snapshot,
    verify_fact,
)

_CATALOG_ID = TypeAdapter(CatalogId)
_DEFAULT_RELEASE_ID = "v0.1.1"
_DEFAULT_DATA_ROOT = "assurance.controlspec.reference_catalog_data.v0_1_1"
_DEFAULT_MANIFEST_SHA256 = (
    "sha256:4f24ef9ceefab3f1b9e3174901991116070da94e97a79b92b3492ee4d501fb1b"
)
_DEFAULT_ARTIFACT_COUNT = 8
_V0_DATA_ROOT = "assurance.controlspec.reference_catalog_data.v0"


class ReferenceCatalogError(ValueError):
    """The immutable reference catalog or one exact selector is invalid."""


class CatalogItemNotFoundError(ReferenceCatalogError):
    """An exact catalog ID is absent."""


class CatalogBindingMismatchError(ReferenceCatalogError):
    """A known catalog identity was supplied with the wrong digest."""


class ReferencePackArtifact(ControlSpecModel):
    pack: ControlPack
    metadata: CatalogEntryMetadata


class ReferenceFactFixture(ControlSpecModel):
    """One exact server-owned portable fact input for a reference profile."""

    intent: ActionIntent
    retained_decision: Decision
    control_refs: CanonicalSet[ControlRef]


def clone_reference_pack_artifact(
    value: ReferencePackArtifact,
) -> ReferencePackArtifact:
    """Detach one complete pack/Control/metadata graph from caller ownership."""

    raw = canonical_json(value)
    clone = ReferencePackArtifact.model_validate_json(raw, strict=True)
    if canonical_json(clone) != raw:
        raise ReferenceCatalogError("reference pack artifact cannot be cloned exactly")
    return clone


def _clone_control(value: Control) -> Control:
    raw = canonical_json(value)
    clone = Control.model_validate_json(raw, strict=True)
    if canonical_json(clone) != raw or not verify_object_digest(clone):
        raise ReferenceCatalogError("reference Control cannot be cloned exactly")
    return clone


def _clone_pack(value: ControlPack) -> ControlPack:
    raw = canonical_json(value)
    clone = ControlPack.model_validate_json(raw, strict=True)
    if canonical_json(clone) != raw or not verify_object_digest(clone):
        raise ReferenceCatalogError("reference ControlPack cannot be cloned exactly")
    return clone


class ReferenceScenarioFixture(ControlSpecModel):
    """Closed, package-owned inputs for one exact public reference scenario."""

    schema_name: Literal["controlspec/reference/v0/scenario-fixture"] = Field(
        "controlspec/reference/v0/scenario-fixture", alias="schema"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    release_id: Literal["v0.1.1"] = "v0.1.1"
    fixture_id: Identifier
    version: SemVer
    profile_kind: Literal["portable_core", "riskspec_enterprise"]
    selection: PackSelection
    reference_time: UtcTimestamp
    intent: ActionIntent
    control_refs: CanonicalSet[ControlRef]
    approval_basis_decision: Decision | None = None
    approvals: CanonicalSet[ApprovalFact] = ()
    retained_decision: Decision | None = None
    semantic_digest: HashDigest | None = None


def _scenario_digest(value: ReferenceScenarioFixture) -> str:
    payload = value.model_dump(mode="json", by_alias=True, exclude_none=False)
    payload.pop("semantic_digest", None)
    return sha256_digest(canonical_json(payload))


def finalize_reference_scenario(
    value: ReferenceScenarioFixture,
) -> ReferenceScenarioFixture:
    return value.model_copy(update={"semantic_digest": _scenario_digest(value)})


def verify_reference_scenario(value: ReferenceScenarioFixture) -> bool:
    return value.semantic_digest == _scenario_digest(value)


def clone_reference_scenario(
    value: ReferenceScenarioFixture,
) -> ReferenceScenarioFixture:
    """Deterministically detach every nested scenario value from caller ownership."""

    raw = canonical_json(value)
    clone = ReferenceScenarioFixture.model_validate_json(raw, strict=True)
    if canonical_json(clone) != raw or not verify_reference_scenario(clone):
        raise ReferenceCatalogError("scenario cannot be cloned with exact integrity")
    return clone


def _validate_scenario_approval(
    *,
    scenario: ReferenceScenarioFixture,
    approval: ApprovalFact,
) -> None:
    if not verify_fact(approval):
        raise ReferenceCatalogError("scenario ApprovalFact digest is invalid")
    basis = scenario.approval_basis_decision
    assert basis is not None
    if (
        approval.intent_ref != basis.intent_ref
        or approval.basis_decision_ref.namespace != basis.namespace
        or approval.basis_decision_ref.decision_id != basis.decision_id
        or approval.basis_decision_ref.semantic_digest != basis.semantic_digest
        or not (approval.valid_from <= scenario.reference_time < approval.valid_until)
    ):
        raise ReferenceCatalogError("scenario approval is not exactly bound and valid")
    requirements = tuple(
        item
        for item in basis.approval_requirements
        if item.requirement_id == approval.requirement_id
    )
    if len(requirements) != 1:
        raise ReferenceCatalogError(
            "scenario approval does not bind one exact basis requirement"
        )
    requirement = requirements[0]
    if approval.roles != (requirement.role,):
        raise ReferenceCatalogError("scenario approval role differs from requirement")
    if approval.scope_digest != sha256_digest(canonical_json(requirement.scope)):
        raise ReferenceCatalogError("scenario approval scope differs from requirement")
    if set(approval.separated_role_actor_ids) != set(
        requirement.separate_from_roles
    ):
        raise ReferenceCatalogError(
            "scenario approval separation roles differ from requirement"
        )
    if not approval.approved or not approval.lineage_complete:
        raise ReferenceCatalogError(
            "attempted self-approval fixture must be approved and lineage-complete"
        )
    if approval.approver != scenario.intent.actor:
        raise ReferenceCatalogError(
            "attempted self-approval approver must equal the requesting actor"
        )
    actor_id = scenario.intent.actor.actor_id
    actor_bound_to_separated_role = any(
        actor_id in actor_ids
        for actor_ids in approval.separated_role_actor_ids.values()
    )
    if not requirement.separate_from_actor and not actor_bound_to_separated_role:
        raise ReferenceCatalogError(
            "attempted self-approval lacks the source-required actor relationship"
        )
    if scenario.profile_kind == "riskspec_enterprise":
        proposer = "riskspec.enterprise.subject_role.proposer"
        if actor_id not in approval.separated_role_actor_ids.get(proposer, ()):
            raise ReferenceCatalogError(
                "enterprise attempted self-approval must bind proposer to actor"
            )


def scenario_fixture_digest(
    fixtures: Iterable[ReferenceScenarioFixture],
) -> str:
    payload = {
        "schema": "controlspec/reference/v0/scenario-fixture-set",
        "schema_version": "0.1.0",
        "release_id": _DEFAULT_RELEASE_ID,
        "fixtures": tuple(fixtures),
    }
    return sha256_digest(canonical_json(payload))


def fact_fixture_digest(
    fixtures: Iterable[ReferenceFactFixture],
) -> str:
    """Bind the exact canonical fixture set without interpreting profile semantics."""

    payload = {
        "schema": "controlspec/reference/v0/fact-fixture-set",
        "schema_version": "0.1.0",
        "fixtures": tuple(fixtures),
    }
    return sha256_digest(canonical_json(payload))


_EMPTY_FACTS = EvaluationFacts(
    approval_basis_ref=None,
    approvals=(),
    evidence=(),
    profile_assessments=(),
)


def control_catalog_id(control: Control) -> CatalogId:
    return _CATALOG_ID.validate_python(
        f"{control.namespace}:{control.control_id}@{control.version}",
        strict=True,
    )


def pack_catalog_id(pack: ControlPack) -> CatalogId:
    return _CATALOG_ID.validate_python(
        f"{pack.namespace}:{pack.pack_id}@{pack.version}",
        strict=True,
    )


def _require_digest(value: Control | ControlPack) -> str:
    if value.semantic_digest is None or not verify_object_digest(value):
        raise ReferenceCatalogError("catalog object semantic digest is invalid")
    return value.semantic_digest


def _control_summary(
    control: Control,
    *,
    metadata: CatalogEntryMetadata,
) -> ControlSummary:
    return ControlSummary(
        catalog_id=control_catalog_id(control),
        namespace=control.namespace,
        control_id=control.control_id,
        version=control.version,
        semantic_digest=_require_digest(control),
        status=control.status.value,
        title=control.title,
        metadata=metadata,
    )


def _pack_summary(
    pack: ControlPack,
    *,
    metadata: CatalogEntryMetadata,
) -> PackSummary:
    return PackSummary(
        catalog_id=pack_catalog_id(pack),
        namespace=pack.namespace,
        pack_id=pack.pack_id,
        version=pack.version,
        semantic_digest=_require_digest(pack),
        status=pack.status.value,
        title=pack.title,
        metadata=metadata,
    )


class ImmutableReferenceCatalog:
    """Validated startup value; exposes no mutation or lifecycle operation."""

    def __init__(
        self,
        artifacts: Iterable[ReferencePackArtifact],
        *,
        fact_fixtures: Iterable[ReferenceFactFixture] = (),
        scenarios: Iterable[ReferenceScenarioFixture] = (),
        release_id: str = "v0.1.0",
    ) -> None:
        ordered = tuple(
            sorted(
                (clone_reference_pack_artifact(item) for item in artifacts),
                key=lambda item: str(pack_catalog_id(item.pack)),
            )
        )
        if not ordered:
            raise ReferenceCatalogError("reference catalog requires at least one pack")

        packs: dict[str, ReferencePackArtifact] = {}
        controls: dict[str, Control] = {}
        control_metadata: dict[str, CatalogEntryMetadata] = {}
        containing_packs: dict[str, set[str]] = {}
        control_digests: dict[tuple[str, str, str], str] = {}
        for artifact in ordered:
            pack = artifact.pack
            _require_digest(pack)
            pack_id = str(pack_catalog_id(pack))
            if pack_id in packs:
                raise ReferenceCatalogError("duplicate pack catalog ID")
            if artifact.metadata.reference_evaluation_enabled and (
                pack.status is not ControlStatus.PUBLISHED
            ):
                raise ReferenceCatalogError(
                    "reference-enabled packs must be semantically published"
                )
            packs[pack_id] = artifact
            for control in pack.controls:
                digest = _require_digest(control)
                identity = (control.namespace, control.control_id, control.version)
                previous = control_digests.setdefault(identity, digest)
                if previous != digest:
                    raise ReferenceCatalogError(
                        "same Control identity/version has unequal catalog semantics"
                    )
                control_id = str(control_catalog_id(control))
                controls.setdefault(control_id, control)
                prior_metadata = control_metadata.setdefault(control_id, artifact.metadata)
                if prior_metadata != artifact.metadata:
                    raise ReferenceCatalogError(
                        "one Control cannot carry conflicting catalog metadata"
                    )
                containing_packs.setdefault(control_id, set()).add(pack_id)

        ordered_fixtures = tuple(
            sorted(
                fact_fixtures,
                key=lambda item: (
                    item.intent.namespace,
                    item.intent.intent_id,
                    item.intent.intent_digest or "",
                ),
            )
        )
        for fixture in ordered_fixtures:
            if fixture.intent.intent_digest is None or not verify_object_digest(
                fixture.intent
            ):
                raise ReferenceCatalogError("fact fixture intent digest is invalid")
            if fixture.retained_decision.semantic_digest is None or not verify_object_digest(
                fixture.retained_decision
            ):
                raise ReferenceCatalogError("fact fixture Decision digest is invalid")
            intent_ref = fixture.retained_decision.intent_ref
            if (
                intent_ref.namespace != fixture.intent.namespace
                or intent_ref.intent_id != fixture.intent.intent_id
                or intent_ref.intent_digest != fixture.intent.intent_digest
            ):
                raise ReferenceCatalogError("fact fixture Decision binds another intent")
            for reference in fixture.control_refs:
                key = str(
                    _CATALOG_ID.validate_python(
                        f"{reference.namespace}:{reference.control_id}@{reference.version}",
                        strict=True,
                    )
                )
                try:
                    control = controls[key]
                except KeyError as exc:
                    raise ReferenceCatalogError(
                        "fact fixture references a Control outside the catalog"
                    ) from exc
                if control.semantic_digest != reference.semantic_digest:
                    raise ReferenceCatalogError(
                        "fact fixture Control digest differs from the catalog"
                    )

        ordered_scenarios = tuple(
            sorted(
                (clone_reference_scenario(item) for item in scenarios),
                key=lambda item: (item.fixture_id, item.version),
            )
        )
        scenario_ids: set[tuple[str, str]] = set()
        scenario_keys: set[tuple[str, str, str, str]] = set()
        for scenario in ordered_scenarios:
            if release_id != _DEFAULT_RELEASE_ID or scenario.release_id != release_id:
                raise ReferenceCatalogError("scenario release identity differs from catalog")
            if not verify_reference_scenario(scenario):
                raise ReferenceCatalogError("scenario semantic digest is invalid")
            fixture_identity = (scenario.fixture_id, scenario.version)
            if fixture_identity in scenario_ids:
                raise ReferenceCatalogError("duplicate scenario fixture identity")
            scenario_ids.add(fixture_identity)
            selection_digest = sha256_digest(canonical_json(scenario.selection))
            scenario_key = (
                selection_digest,
                scenario.reference_time,
                scenario.intent.intent_digest or "",
                scenario.profile_kind,
            )
            if scenario_key in scenario_keys:
                raise ReferenceCatalogError("ambiguous exact scenario match key")
            scenario_keys.add(scenario_key)
            if scenario.intent.intent_digest is None or not verify_object_digest(
                scenario.intent
            ):
                raise ReferenceCatalogError("scenario ActionIntent digest is invalid")
            try:
                artifact = packs[str(scenario.selection.catalog_id)]
            except KeyError as exc:
                raise ReferenceCatalogError(
                    "scenario selects a pack outside the catalog"
                ) from exc
            if artifact.pack.semantic_digest != scenario.selection.semantic_digest:
                raise ReferenceCatalogError("scenario pack digest differs from catalog")
            actual_refs = tuple(
                ControlRef(
                    namespace=control.namespace,
                    control_id=control.control_id,
                    version=control.version,
                    semantic_digest=_require_digest(control),
                )
                for control in artifact.pack.controls
            )
            if scenario.control_refs != actual_refs:
                raise ReferenceCatalogError(
                    "scenario Control set must equal the complete selected pack"
                )
            if scenario.profile_kind == "portable_core":
                if scenario.retained_decision is not None:
                    raise ReferenceCatalogError(
                        "portable scenarios cannot contain retained profile Decisions"
                    )
                if scenario.intent.namespace.startswith("riskspec.enterprise"):
                    raise ReferenceCatalogError(
                        "portable scenarios cannot use the enterprise namespace"
                    )
            else:
                if not scenario.intent.namespace.startswith("riskspec.enterprise."):
                    raise ReferenceCatalogError(
                        "enterprise scenarios must remain profile namespaced"
                    )
                if scenario.retained_decision is None:
                    raise ReferenceCatalogError(
                        "enterprise scenarios require one retained Decision"
                    )
            decisions = tuple(
                item
                for item in (
                    scenario.approval_basis_decision,
                    scenario.retained_decision,
                )
                if item is not None
            )
            for decision in decisions:
                if decision.semantic_digest is None or not verify_object_digest(decision):
                    raise ReferenceCatalogError("scenario Decision digest is invalid")
                if (
                    decision.intent_ref.namespace != scenario.intent.namespace
                    or decision.intent_ref.intent_id != scenario.intent.intent_id
                    or decision.intent_ref.intent_digest != scenario.intent.intent_digest
                ):
                    raise ReferenceCatalogError("scenario Decision binds another intent")
                if not set(decision.applied_controls) <= set(scenario.control_refs):
                    raise ReferenceCatalogError(
                        "scenario Decision binds Controls outside the exact selected set"
                    )
            if bool(scenario.approvals) != bool(scenario.approval_basis_decision):
                raise ReferenceCatalogError(
                    "scenario approvals require exactly one stored basis Decision"
                )
            for approval in scenario.approvals:
                _validate_scenario_approval(scenario=scenario, approval=approval)

        fixture_digest = (
            scenario_fixture_digest(ordered_scenarios)
            if ordered_scenarios
            else fact_fixture_digest(ordered_fixtures)
        )
        payload = {
            "schema": "controlspec/reference/v0/catalog",
            "schema_version": "0.1.0",
            "artifacts": tuple(
                artifact.model_dump(mode="json", by_alias=True, exclude_none=False)
                for artifact in ordered
            ),
            "fact_fixture_digest": fixture_digest,
        }
        if release_id != "v0.1.0":
            payload["release_id"] = release_id
        self._artifacts = ordered
        self._fact_fixtures = ordered_fixtures
        self._scenarios = ordered_scenarios
        self._release_id = release_id
        self._fact_fixture_digest = fixture_digest
        self._packs = packs
        self._controls = controls
        self._control_metadata = control_metadata
        self._containing_packs = {
            key: tuple(sorted(value)) for key, value in containing_packs.items()
        }
        self._catalog_digest = sha256_digest(canonical_json(payload))

    @property
    def catalog_digest(self) -> str:
        return self._catalog_digest

    @property
    def fact_fixtures(self) -> tuple[ReferenceFactFixture, ...]:
        return self._fact_fixtures

    @property
    def fact_fixture_digest(self) -> str:
        return self._fact_fixture_digest

    @property
    def release_id(self) -> str:
        return self._release_id

    @property
    def scenarios(self) -> tuple[ReferenceScenarioFixture, ...]:
        return tuple(clone_reference_scenario(item) for item in self._scenarios)

    def list_controls(self) -> ControlListResponse:
        summaries = tuple(
            _control_summary(
                self._controls[catalog_id],
                metadata=self._control_metadata[catalog_id],
            )
            for catalog_id in sorted(self._controls)
        )
        response = ControlListResponse(
            items=summaries,
            catalog_digest=self._catalog_digest,
            authority=REFERENCE_AUTHORITY,
        )
        return response.model_copy(deep=True)

    def list_packs(self) -> PackListResponse:
        summaries = tuple(
            _pack_summary(
                self._packs[catalog_id].pack,
                metadata=self._packs[catalog_id].metadata,
            )
            for catalog_id in sorted(self._packs)
        )
        response = PackListResponse(
            items=summaries,
            catalog_digest=self._catalog_digest,
            authority=REFERENCE_AUTHORITY,
        )
        return response.model_copy(deep=True)

    def get_control(self, catalog_id: str) -> ControlDetailResponse:
        try:
            control = self._controls[catalog_id]
        except KeyError as exc:
            raise CatalogItemNotFoundError("Control catalog ID is absent") from exc
        response = ControlDetailResponse(
            control=_clone_control(control),
            summary=_control_summary(
                control,
                metadata=self._control_metadata[catalog_id],
            ),
            containing_pack_catalog_ids=self._containing_packs[catalog_id],
            catalog_digest=self._catalog_digest,
            authority=REFERENCE_AUTHORITY,
        )
        return response.model_copy(deep=True)

    def get_pack(self, catalog_id: str) -> PackDetailResponse:
        try:
            artifact = self._packs[catalog_id]
        except KeyError as exc:
            raise CatalogItemNotFoundError("ControlPack catalog ID is absent") from exc
        response = PackDetailResponse(
            pack=_clone_pack(artifact.pack),
            summary=_pack_summary(artifact.pack, metadata=artifact.metadata),
            control_catalog_ids=tuple(
                control_catalog_id(control) for control in artifact.pack.controls
            ),
            catalog_digest=self._catalog_digest,
            authority=REFERENCE_AUTHORITY,
        )
        return response.model_copy(deep=True)

    @staticmethod
    def _verify_retained_artifact(artifact: ReferencePackArtifact) -> None:
        pack = artifact.pack
        _require_digest(pack)
        for control in pack.controls:
            _require_digest(control)

    def resolve(
        self,
        selection: ReferenceSelection,
        *,
        observed_at: str,
    ) -> tuple[PublishedControlSnapshot, CatalogBinding]:
        catalog_ids: tuple[CatalogId, ...]
        controls: tuple[Control, ...]
        source_artifacts: tuple[ReferencePackArtifact, ...]
        if isinstance(selection, PackSelection):
            catalog_ids = (selection.catalog_id,)
            try:
                artifact = self._packs[str(selection.catalog_id)]
            except KeyError as exc:
                raise CatalogItemNotFoundError("ControlPack catalog ID is absent") from exc
            if not artifact.metadata.reference_evaluation_enabled:
                raise ReferenceCatalogError("ControlPack is not enabled for reference evaluation")
            if artifact.pack.semantic_digest != selection.semantic_digest:
                raise CatalogBindingMismatchError("ControlPack digest does not match catalog")
            self._verify_retained_artifact(artifact)
            controls = tuple(_clone_control(control) for control in artifact.pack.controls)
            source_artifacts = (artifact,)
        elif isinstance(selection, ControlSelection):
            catalog_ids = tuple(item.catalog_id for item in selection.controls)
            selected_controls: list[Control] = []
            source_pack_ids: set[str] = set()
            for item in selection.controls:
                key = str(item.catalog_id)
                try:
                    control = self._controls[key]
                except KeyError as exc:
                    raise CatalogItemNotFoundError("Control catalog ID is absent") from exc
                if not self._control_metadata[key].reference_evaluation_enabled:
                    raise ReferenceCatalogError(
                        "Control is not enabled for reference evaluation"
                    )
                if control.semantic_digest != item.semantic_digest:
                    raise CatalogBindingMismatchError("Control digest does not match catalog")
                _require_digest(control)
                selected_controls.append(_clone_control(control))
                source_pack_ids.update(self._containing_packs[key])
            controls = tuple(selected_controls)
            source_artifacts = tuple(
                self._packs[pack_id] for pack_id in sorted(source_pack_ids)
            )
        else:  # pragma: no cover - closed discriminated union
            raise ReferenceCatalogError("unsupported reference selection")

        for artifact in source_artifacts:
            self._verify_retained_artifact(artifact)
        extensions = {
            declaration.key
            for artifact in source_artifacts
            for declaration in artifact.pack.extension_requirements
        }
        display_extensions = {
            declaration.key
            for artifact in source_artifacts
            for declaration in artifact.pack.extension_requirements
            if declaration.classification == "display"
        }
        verifiers = {
            declaration.name
            for artifact in source_artifacts
            for declaration in artifact.pack.vocabularies.verifiers
        }
        snapshot = finalize_snapshot(
            PublishedControlSnapshot(
                controls=controls,
                observed_at=observed_at,
                authority_mode=SnapshotAuthorityMode.NON_AUTHORITATIVE_CONFORMANCE,
                host_authority_refs=(),
                supported_extensions=tuple(sorted(extensions)),
                display_extensions=tuple(sorted(display_extensions)),
                supported_verifiers=tuple(sorted(verifiers)),
            )
        )
        binding = CatalogBinding(
            catalog_digest=self._catalog_digest,
            selection_digest=sha256_digest(canonical_json(selection)),
            fact_fixture_digest=fact_fixture_digest(()),
            facts_digest=facts_digest(_EMPTY_FACTS),
            semantic_input_digest=sha256_digest(
                canonical_json(
                    {
                        "catalog_digest": self._catalog_digest,
                        "selection_digest": sha256_digest(canonical_json(selection)),
                        "fact_fixture_digest": fact_fixture_digest(()),
                        "facts_digest": facts_digest(_EMPTY_FACTS),
                    }
                )
            ),
            selected_catalog_ids=catalog_ids,
        )
        return snapshot, binding


def _json_inventory(root: Traversable, *, prefix: str = "") -> set[str]:
    result: set[str] = set()
    for item in root.iterdir():
        relative = f"{prefix}/{item.name}" if prefix else item.name
        if item.is_dir():
            result.update(_json_inventory(item, prefix=relative))
        elif item.is_file() and item.name.endswith(".json"):
            result.add(relative)
    return result


def _validate_default_release_manifest(root: Traversable) -> dict[str, bytes]:
    """Authenticate the closed v0.1.1 JSON inventory before parsing any object."""

    try:
        manifest = root.joinpath("manifest.sha256").read_bytes()
    except (FileNotFoundError, OSError) as exc:
        raise ReferenceCatalogError("v0.1.1 reference manifest is unavailable") from exc
    if sha256_digest(manifest) != _DEFAULT_MANIFEST_SHA256:
        raise ReferenceCatalogError("v0.1.1 reference manifest byte hash is invalid")
    try:
        text = manifest.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ReferenceCatalogError("v0.1.1 reference manifest is not ASCII") from exc
    if not text.endswith("\n") or "\r" in text:
        raise ReferenceCatalogError("v0.1.1 reference manifest bytes are noncanonical")
    entries: dict[str, str] = {}
    for line in text.splitlines():
        digest, separator, relative = line.partition("  ")
        if (
            separator != "  "
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not relative
            or relative in entries
        ):
            raise ReferenceCatalogError("v0.1.1 reference manifest entry is invalid")
        entries[relative] = f"sha256:{digest}"
    if (
        len(entries) != _DEFAULT_ARTIFACT_COUNT
        or sum(relative.startswith("packs/") for relative in entries) != 4
        or sum(relative.startswith("scenarios/") for relative in entries) != 4
        or any(not relative.endswith(".json") for relative in entries)
    ):
        raise ReferenceCatalogError("v0.1.1 reference manifest inventory is invalid")
    if _json_inventory(root) != set(entries):
        raise ReferenceCatalogError("v0.1.1 package JSON inventory is invalid")
    validated: dict[str, bytes] = {}
    for relative in sorted(entries):
        try:
            raw = root.joinpath(*relative.split("/")).read_bytes()
        except (FileNotFoundError, OSError) as exc:
            raise ReferenceCatalogError(
                "v0.1.1 manifested reference artifact is unavailable"
            ) from exc
        if sha256_digest(raw) != entries[relative]:
            raise ReferenceCatalogError(
                "v0.1.1 manifested reference artifact byte hash is invalid"
            )
        validated[relative] = raw
    return validated


def _load_reference_catalog(*, data_root: str, release_id: str) -> ImmutableReferenceCatalog:
    """Load one complete package-local release; never mix release roots."""

    root = resources.files(data_root)
    validated = (
        _validate_default_release_manifest(root)
        if release_id == _DEFAULT_RELEASE_ID
        else None
    )
    package = root.joinpath("packs")
    artifacts: list[ReferencePackArtifact] = []
    for item in sorted(package.iterdir(), key=lambda value: value.name):
        if item.name.startswith("_") or not item.name.endswith(".json"):
            continue
        raw = (
            validated[f"packs/{item.name}"]
            if validated is not None
            else item.read_bytes()
        )
        artifact = ReferencePackArtifact.model_validate_json(raw, strict=True)
        if canonical_json(artifact) != raw:
            raise ReferenceCatalogError("reference catalog artifact is not canonical JSON")
        artifacts.append(artifact)
    if release_id == "v0.1.0":
        fixture_package = root.joinpath("profile_cases")
        fixtures: list[ReferenceFactFixture] = []
        for item in sorted(fixture_package.iterdir(), key=lambda value: value.name):
            if item.name.startswith("_") or not item.name.endswith(".json"):
                continue
            raw = item.read_bytes()
            fixture = ReferenceFactFixture.model_validate_json(raw, strict=True)
            if canonical_json(fixture) != raw:
                raise ReferenceCatalogError("reference fact fixture is not canonical JSON")
            fixtures.append(fixture)
        return ImmutableReferenceCatalog(
            artifacts,
            fact_fixtures=fixtures,
            release_id=release_id,
        )

    assert validated is not None
    scenario_package = root.joinpath("scenarios")
    scenarios: list[ReferenceScenarioFixture] = []
    for item in sorted(scenario_package.iterdir(), key=lambda value: value.name):
        if item.name.startswith("_") or not item.name.endswith(".json"):
            continue
        raw = validated[f"scenarios/{item.name}"]
        scenario = ReferenceScenarioFixture.model_validate_json(raw, strict=True)
        if canonical_json(scenario) != raw:
            raise ReferenceCatalogError("reference scenario fixture is not canonical JSON")
        scenarios.append(scenario)
    return ImmutableReferenceCatalog(
        artifacts,
        scenarios=scenarios,
        release_id=release_id,
    )


def load_v0_reference_catalog() -> ImmutableReferenceCatalog:
    """Load the byte-preserved ControlSpec v0.1 reference data."""

    return _load_reference_catalog(data_root=_V0_DATA_ROOT, release_id="v0.1.0")


def load_default_reference_catalog() -> ImmutableReferenceCatalog:
    """Load the immutable v0.1.1 example-surface release."""

    return _load_reference_catalog(
        data_root=_DEFAULT_DATA_ROOT,
        release_id=_DEFAULT_RELEASE_ID,
    )
