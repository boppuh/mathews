"""Deterministic simulator-flow assertion selection contracts.

Repository configuration owns the single compiled flow and typed assertion
catalog. A task may only select entries from that immutable catalog and bind
them to bounded acceptance-criterion identifiers. There is intentionally no
field for an agent-authored claim, script, predicate, or pass result.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import InitVar, dataclass
from enum import StrEnum
from typing import Self, cast
from uuid import UUID

from mathews_configuration.repository import (
    AssertionKind,
    AssertionRole,
    E2EFlow,
    OperationKind,
    RepositoryConfiguration,
    RepositoryConfigurationError,
)

TASK_ASSERTION_CONTRACT_SCHEMA_VERSION = 1
_MAX_ACCEPTANCE_CRITERIA = 64
_MAX_ASSERTION_BINDINGS = 256
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,254}")
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_ACCEPTED_BRIEF_FACTORY_TOKEN = object()
_TASK_CONTRACT_FACTORY_TOKEN = object()


@dataclass(frozen=True, slots=True)
class CriterionAssertionRequirement:
    """The exact task-selectable catalog assertions approved for one criterion."""

    acceptance_criterion_id: str
    required_assertion_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.acceptance_criterion_id, "acceptance criterion id")
        if not isinstance(self.required_assertion_ids, tuple):
            raise RepositoryConfigurationError(
                "required criterion assertion ids must be an immutable tuple"
            )
        if (
            not self.required_assertion_ids
            or len(self.required_assertion_ids) > _MAX_ASSERTION_BINDINGS
        ):
            raise RepositoryConfigurationError(
                "criterion assertion requirement must contain bounded assertion ids"
            )
        _unique_identifiers(
            self.required_assertion_ids,
            "required criterion assertion ids",
        )


class BriefApprovalDisposition(StrEnum):
    """The only persisted brief-decision states consumed by this contract."""

    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


@dataclass(frozen=True, slots=True)
class PersistedBriefApprovalRecord:
    """Typed row projection supplied by the task 4.1 persistence adapter."""

    task_id: UUID
    brief_id: UUID
    decision_id: UUID
    disposition: BriefApprovalDisposition
    brief_version: int
    brief_digest: str
    assertion_requirements: tuple[CriterionAssertionRequirement, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.task_id, UUID)
            or not isinstance(self.brief_id, UUID)
            or not isinstance(self.decision_id, UUID)
        ):
            raise RepositoryConfigurationError(
                "brief-approval record ids must be UUIDs"
            )
        if not isinstance(self.disposition, BriefApprovalDisposition):
            raise RepositoryConfigurationError(
                "brief-approval disposition is unsupported"
            )
        if not isinstance(self.assertion_requirements, tuple) or any(
            not isinstance(requirement, CriterionAssertionRequirement)
            for requirement in self.assertion_requirements
        ):
            raise RepositoryConfigurationError(
                "brief-approval requirements must be typed immutable tuples"
            )
        _positive_integer(self.brief_version, "brief version")
        if _DIGEST_PATTERN.fullmatch(self.brief_digest) is None:
            raise RepositoryConfigurationError(
                "brief digest must be a canonical SHA-256 address"
            )


@dataclass(frozen=True, slots=True)
class AcceptedBriefAssertionSource:
    """Validated accepted projection; persistence remains a control-plane boundary."""

    task_id: UUID
    brief_id: UUID
    approval_decision_id: UUID
    brief_version: int
    brief_digest: str
    assertion_requirements: tuple[CriterionAssertionRequirement, ...]
    _factory_token: InitVar[object | None] = None

    def __post_init__(self, _factory_token: object | None) -> None:
        if _factory_token is not _ACCEPTED_BRIEF_FACTORY_TOKEN:
            raise RepositoryConfigurationError(
                "accepted brief assertion source must come from the persisted "
                "brief-approval boundary"
            )
        if (
            not isinstance(self.task_id, UUID)
            or not isinstance(self.brief_id, UUID)
            or not isinstance(self.approval_decision_id, UUID)
        ):
            raise RepositoryConfigurationError(
                "accepted brief task, brief, and approval-decision ids must be UUIDs"
            )
        if not isinstance(self.assertion_requirements, tuple) or any(
            not isinstance(requirement, CriterionAssertionRequirement)
            for requirement in self.assertion_requirements
        ):
            raise RepositoryConfigurationError(
                "accepted brief assertion requirements must be typed immutable tuples"
            )
        _positive_integer(self.brief_version, "brief version")
        if _DIGEST_PATTERN.fullmatch(self.brief_digest) is None:
            raise RepositoryConfigurationError(
                "brief digest must be a canonical SHA-256 address"
            )
        if (
            not self.assertion_requirements
            or len(self.assertion_requirements) > _MAX_ACCEPTANCE_CRITERIA
        ):
            raise RepositoryConfigurationError(
                "accepted brief must contain 1 to "
                f"{_MAX_ACCEPTANCE_CRITERIA} acceptance criteria"
            )
        criterion_ids = self.acceptance_criterion_ids
        if len(criterion_ids) != len(set(criterion_ids)):
            raise RepositoryConfigurationError(
                "accepted brief criterion requirements must be unique"
            )

    @property
    def acceptance_criterion_ids(self) -> tuple[str, ...]:
        return tuple(
            requirement.acceptance_criterion_id
            for requirement in self.assertion_requirements
        )

    @classmethod
    def from_approval_record(
        cls,
        record: PersistedBriefApprovalRecord,
    ) -> Self:
        if not isinstance(record, PersistedBriefApprovalRecord):
            raise RepositoryConfigurationError(
                "accepted brief source requires a typed approval-record projection"
            )
        if record.disposition is not BriefApprovalDisposition.ACCEPTED:
            raise RepositoryConfigurationError(
                "task assertions require an accepted persisted brief decision"
            )
        return cls(
            task_id=record.task_id,
            brief_id=record.brief_id,
            approval_decision_id=record.decision_id,
            brief_version=record.brief_version,
            brief_digest=record.brief_digest,
            assertion_requirements=record.assertion_requirements,
            _factory_token=_ACCEPTED_BRIEF_FACTORY_TOKEN,
        )


@dataclass(frozen=True, slots=True)
class CriterionAssertionBinding:
    """One catalog assertion selected for one acceptance criterion."""

    acceptance_criterion_id: str
    assertion_id: str
    kind: AssertionKind
    verifier_catalog_key: str

    def __post_init__(self) -> None:
        _identifier(self.acceptance_criterion_id, "acceptance criterion id")
        _identifier(self.assertion_id, "assertion id")
        if not isinstance(self.kind, AssertionKind):
            raise RepositoryConfigurationError("assertion kind is unsupported")
        _identifier(
            self.verifier_catalog_key,
            "verifier catalog key",
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "acceptance_criterion_id": self.acceptance_criterion_id,
            "assertion_id": self.assertion_id,
            "kind": self.kind.value,
            "verifier_catalog_key": self.verifier_catalog_key,
        }

    @classmethod
    def from_dict(cls, value: object) -> Self:
        fields = _exact_mapping(
            value,
            {
                "acceptance_criterion_id",
                "assertion_id",
                "kind",
                "verifier_catalog_key",
            },
            "criterion assertion binding",
        )
        return cls(
            acceptance_criterion_id=_string(
                fields["acceptance_criterion_id"],
                "acceptance criterion id",
            ),
            assertion_id=_string(fields["assertion_id"], "assertion id"),
            kind=_assertion_kind(fields["kind"]),
            verifier_catalog_key=_string(
                fields["verifier_catalog_key"],
                "verifier catalog key",
            ),
        )


@dataclass(frozen=True, slots=True)
class TaskAssertionContract:
    """Exact task-to-flow assertion binding with no executable free-form input."""

    schema_version: int
    configuration_id: UUID
    configuration_version: int
    configuration_digest: str
    task_id: UUID
    brief_id: UUID
    approval_decision_id: UUID
    brief_version: int
    brief_digest: str
    flow_id: str
    flow_version: int
    fixture_id: str
    fixture_version: int
    fixture_digest: str
    required_assertion_ids: tuple[str, ...]
    acceptance_criterion_ids: tuple[str, ...]
    bindings: tuple[CriterionAssertionBinding, ...]
    _factory_token: InitVar[object | None] = None

    def __post_init__(self, _factory_token: object | None) -> None:
        if _factory_token is not _TASK_CONTRACT_FACTORY_TOKEN:
            raise RepositoryConfigurationError(
                "task assertion contract must be compiled against an accepted "
                "brief and repository configuration"
            )
        if (
            not isinstance(self.configuration_id, UUID)
            or not isinstance(self.task_id, UUID)
            or not isinstance(self.brief_id, UUID)
            or not isinstance(self.approval_decision_id, UUID)
        ):
            raise RepositoryConfigurationError(
                "configuration, task, brief, and approval-decision ids must be UUIDs"
            )
        if (
            not isinstance(self.required_assertion_ids, tuple)
            or not isinstance(self.acceptance_criterion_ids, tuple)
            or not isinstance(self.bindings, tuple)
        ):
            raise RepositoryConfigurationError(
                "task assertion collections must be immutable tuples"
            )
        if any(
            not isinstance(binding, CriterionAssertionBinding)
            for binding in self.bindings
        ):
            raise RepositoryConfigurationError(
                "task assertion bindings must use typed binding contracts"
            )
        if self.schema_version != TASK_ASSERTION_CONTRACT_SCHEMA_VERSION:
            raise RepositoryConfigurationError(
                "task assertion contract schema version is unsupported"
            )
        _positive_integer(self.configuration_version, "configuration version")
        _positive_integer(self.brief_version, "brief version")
        _positive_integer(self.flow_version, "E2E flow version")
        _positive_integer(self.fixture_version, "fixture version")
        if _DIGEST_PATTERN.fullmatch(self.configuration_digest) is None:
            raise RepositoryConfigurationError(
                "configuration digest must be a canonical SHA-256 address"
            )
        if _DIGEST_PATTERN.fullmatch(self.fixture_digest) is None:
            raise RepositoryConfigurationError(
                "fixture digest must be a canonical SHA-256 address"
            )
        if _DIGEST_PATTERN.fullmatch(self.brief_digest) is None:
            raise RepositoryConfigurationError(
                "brief digest must be a canonical SHA-256 address"
            )
        _identifier(self.flow_id, "E2E flow id")
        _identifier(self.fixture_id, "fixture id")
        if (
            not self.required_assertion_ids
            or len(self.required_assertion_ids) > _MAX_ASSERTION_BINDINGS
        ):
            raise RepositoryConfigurationError(
                "task assertion contract must contain bounded baseline assertions"
            )
        _unique_identifiers(
            self.required_assertion_ids,
            "required E2E assertion ids",
        )
        if (
            not self.acceptance_criterion_ids
            or len(self.acceptance_criterion_ids) > _MAX_ACCEPTANCE_CRITERIA
        ):
            raise RepositoryConfigurationError(
                "task assertion contract must contain 1 to "
                f"{_MAX_ACCEPTANCE_CRITERIA} acceptance criteria"
            )
        _unique_identifiers(
            self.acceptance_criterion_ids,
            "acceptance criterion ids",
        )
        if not self.bindings or len(self.bindings) > _MAX_ASSERTION_BINDINGS:
            raise RepositoryConfigurationError(
                "task assertion contract must contain 1 to "
                f"{_MAX_ASSERTION_BINDINGS} assertion bindings"
            )
        pairs = [
            (binding.acceptance_criterion_id, binding.assertion_id)
            for binding in self.bindings
        ]
        if len(pairs) != len(set(pairs)):
            raise RepositoryConfigurationError(
                "criterion/assertion bindings must be unique"
            )
        bound_criteria = {
            binding.acceptance_criterion_id for binding in self.bindings
        }
        if bound_criteria != set(self.acceptance_criterion_ids):
            raise RepositoryConfigurationError(
                "every acceptance criterion must have a typed assertion binding"
            )

    @classmethod
    def for_configuration(
        cls,
        configuration: RepositoryConfiguration,
        *,
        accepted_brief: AcceptedBriefAssertionSource,
        assertion_selections: Sequence[tuple[str, str]],
    ) -> Self:
        """Compile IDs into immutable typed bindings from the active catalog."""

        criteria = accepted_brief.acceptance_criterion_ids
        selections = tuple(assertion_selections)
        if any(
            not isinstance(selection, tuple)
            or len(selection) != 2
            or not all(isinstance(value, str) for value in selection)
            for selection in selections
        ):
            raise RepositoryConfigurationError(
                "assertion selections must be criterion/assertion id pairs"
            )
        assertions_by_id = {
            assertion.assertion_id: assertion
            for assertion in configuration.assertion_catalog
        }
        requirements_by_criterion = {
            requirement.acceptance_criterion_id: set(
                requirement.required_assertion_ids
            )
            for requirement in accepted_brief.assertion_requirements
        }
        selected_by_criterion: dict[str, set[str]] = {}
        bindings: list[CriterionAssertionBinding] = []
        for criterion_id, assertion_id in selections:
            try:
                assertion = assertions_by_id[assertion_id]
            except KeyError:
                raise RepositoryConfigurationError(
                    "task selected an assertion outside the configured catalog"
                ) from None
            if assertion.role is not AssertionRole.TASK_SELECTABLE:
                raise RepositoryConfigurationError(
                    "task criteria may select only task-selectable assertions"
                )
            selected_by_criterion.setdefault(criterion_id, set()).add(assertion_id)
            bindings.append(
                CriterionAssertionBinding(
                    acceptance_criterion_id=criterion_id,
                    assertion_id=assertion.assertion_id,
                    kind=assertion.kind,
                    verifier_catalog_key=assertion.catalog_key,
                )
            )
        if selected_by_criterion != requirements_by_criterion:
            raise RepositoryConfigurationError(
                "task assertion selections must exactly match the accepted brief's "
                "criterion requirements"
            )
        flow = _configured_flow(configuration)
        contract = cls(
            schema_version=TASK_ASSERTION_CONTRACT_SCHEMA_VERSION,
            configuration_id=configuration.configuration_id,
            configuration_version=configuration.version,
            configuration_digest=configuration.digest,
            task_id=accepted_brief.task_id,
            brief_id=accepted_brief.brief_id,
            approval_decision_id=accepted_brief.approval_decision_id,
            brief_version=accepted_brief.brief_version,
            brief_digest=accepted_brief.brief_digest,
            flow_id=flow.flow_id,
            flow_version=flow.version,
            fixture_id=flow.fixture_id,
            fixture_version=flow.fixture_version,
            fixture_digest=flow.fixture_digest,
            required_assertion_ids=flow.required_assertion_ids,
            acceptance_criterion_ids=criteria,
            bindings=tuple(bindings),
            _factory_token=_TASK_CONTRACT_FACTORY_TOKEN,
        )
        contract.validate_against(configuration, accepted_brief)
        return contract

    def validate_against(
        self,
        configuration: RepositoryConfiguration,
        accepted_brief: AcceptedBriefAssertionSource,
    ) -> None:
        """Fail closed unless every copied value matches one exact configuration."""

        flow = _configured_flow(configuration)
        if (
            self.configuration_id != configuration.configuration_id
            or self.configuration_version != configuration.version
            or self.configuration_digest != configuration.digest
            or self.task_id != accepted_brief.task_id
            or self.brief_id != accepted_brief.brief_id
            or self.approval_decision_id != accepted_brief.approval_decision_id
            or self.brief_version != accepted_brief.brief_version
            or self.brief_digest != accepted_brief.brief_digest
            or self.acceptance_criterion_ids
            != accepted_brief.acceptance_criterion_ids
            or self.flow_id != flow.flow_id
            or self.flow_version != flow.version
            or self.fixture_id != flow.fixture_id
            or self.fixture_version != flow.fixture_version
            or self.fixture_digest != flow.fixture_digest
            or self.required_assertion_ids != flow.required_assertion_ids
        ):
            raise RepositoryConfigurationError(
                "task assertion contract is not bound to the exact repository "
                "configuration, flow, and fixture"
            )
        assertions_by_id = {
            assertion.assertion_id: assertion
            for assertion in configuration.assertion_catalog
        }
        selected_ids: set[str] = set()
        selected_by_criterion: dict[str, set[str]] = {}
        for binding in self.bindings:
            try:
                assertion = assertions_by_id[binding.assertion_id]
            except KeyError:
                raise RepositoryConfigurationError(
                    "task assertion binding references an unknown catalog assertion"
                ) from None
            if (
                binding.kind is not assertion.kind
                or binding.verifier_catalog_key != assertion.catalog_key
                or assertion.role is not AssertionRole.TASK_SELECTABLE
            ):
                raise RepositoryConfigurationError(
                    "task assertion binding does not match its typed catalog entry"
                )
            selected_ids.add(binding.assertion_id)
            selected_by_criterion.setdefault(
                binding.acceptance_criterion_id,
                set(),
            ).add(binding.assertion_id)
        if not selected_ids:
            raise RepositoryConfigurationError(
                "task assertion contract must select typed criterion assertions"
            )
        required_by_criterion = {
            requirement.acceptance_criterion_id: set(
                requirement.required_assertion_ids
            )
            for requirement in accepted_brief.assertion_requirements
        }
        if selected_by_criterion != required_by_criterion:
            raise RepositoryConfigurationError(
                "task assertion bindings do not match the accepted brief's "
                "criterion requirements"
            )

    @property
    def digest(self) -> str:
        return f"sha256:{hashlib.sha256(self.to_json().encode()).hexdigest()}"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "configuration_id": str(self.configuration_id),
            "configuration_version": self.configuration_version,
            "configuration_digest": self.configuration_digest,
            "task_id": str(self.task_id),
            "brief_id": str(self.brief_id),
            "approval_decision_id": str(self.approval_decision_id),
            "brief_version": self.brief_version,
            "brief_digest": self.brief_digest,
            "flow_id": self.flow_id,
            "flow_version": self.flow_version,
            "fixture_id": self.fixture_id,
            "fixture_version": self.fixture_version,
            "fixture_digest": self.fixture_digest,
            "required_assertion_ids": list(self.required_assertion_ids),
            "acceptance_criterion_ids": list(self.acceptance_criterion_ids),
            "bindings": [binding.to_dict() for binding in self.bindings],
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )

    @classmethod
    def from_dict(
        cls,
        configuration: RepositoryConfiguration,
        accepted_brief: AcceptedBriefAssertionSource,
        value: object,
    ) -> Self:
        fields = _exact_mapping(
            value,
            {
                "schema_version",
                "configuration_id",
                "configuration_version",
                "configuration_digest",
                "task_id",
                "brief_id",
                "approval_decision_id",
                "brief_version",
                "brief_digest",
                "flow_id",
                "flow_version",
                "fixture_id",
                "fixture_version",
                "fixture_digest",
                "required_assertion_ids",
                "acceptance_criterion_ids",
                "bindings",
            },
            "task assertion contract",
        )
        raw_configuration_id = _string(
            fields["configuration_id"],
            "configuration id",
        )
        try:
            configuration_id = UUID(raw_configuration_id)
            task_id = UUID(_string(fields["task_id"], "task id"))
            brief_id = UUID(_string(fields["brief_id"], "brief id"))
            approval_decision_id = UUID(
                _string(fields["approval_decision_id"], "approval decision id")
            )
        except ValueError:
            raise RepositoryConfigurationError(
                "configuration, task, and brief ids must be UUIDs"
            ) from None
        contract = cls(
            schema_version=_integer(fields["schema_version"], "schema version"),
            configuration_id=configuration_id,
            configuration_version=_integer(
                fields["configuration_version"],
                "configuration version",
            ),
            configuration_digest=_string(
                fields["configuration_digest"],
                "configuration digest",
            ),
            task_id=task_id,
            brief_id=brief_id,
            approval_decision_id=approval_decision_id,
            brief_version=_integer(fields["brief_version"], "brief version"),
            brief_digest=_string(fields["brief_digest"], "brief digest"),
            flow_id=_string(fields["flow_id"], "E2E flow id"),
            flow_version=_integer(fields["flow_version"], "E2E flow version"),
            fixture_id=_string(fields["fixture_id"], "fixture id"),
            fixture_version=_integer(
                fields["fixture_version"],
                "fixture version",
            ),
            fixture_digest=_string(fields["fixture_digest"], "fixture digest"),
            required_assertion_ids=_string_tuple(
                fields["required_assertion_ids"],
                "required E2E assertion ids",
            ),
            acceptance_criterion_ids=_string_tuple(
                fields["acceptance_criterion_ids"],
                "acceptance criterion ids",
            ),
            bindings=tuple(
                CriterionAssertionBinding.from_dict(binding)
                for binding in _sequence(fields["bindings"], "assertion bindings")
            ),
            _factory_token=_TASK_CONTRACT_FACTORY_TOKEN,
        )
        contract.validate_against(configuration, accepted_brief)
        return contract


def _configured_flow(configuration: RepositoryConfiguration) -> E2EFlow:
    flows = tuple(
        operation.e2e_flow
        for operation in configuration.operations
        if operation.kind is OperationKind.SIMULATOR_E2E
        and operation.e2e_flow is not None
    )
    if len(flows) != 1:
        raise RepositoryConfigurationError(
            "repository configuration must contain exactly one E2E flow"
        )
    return flows[0]


def _exact_mapping(
    value: object,
    keys: set[str],
    field: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise RepositoryConfigurationError(f"{field} must be an object")
    normalized = cast(Mapping[str, object], value)
    if set(normalized) != keys:
        raise RepositoryConfigurationError(f"{field} has missing or unknown fields")
    return normalized


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(
        value,
        (str, bytes, bytearray),
    ):
        raise RepositoryConfigurationError(f"{field} must be an array")
    return value


def _string(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise RepositoryConfigurationError(f"{field} must be text")
    return value


def _string_tuple(value: object, field: str) -> tuple[str, ...]:
    return tuple(_string(item, field) for item in _sequence(value, field))


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RepositoryConfigurationError(f"{field} must be an integer")
    return value


def _positive_integer(value: int, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RepositoryConfigurationError(f"{field} must be a positive integer")


def _identifier(value: str, field: str) -> None:
    if _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise RepositoryConfigurationError(
            f"{field} must be a bounded catalog identifier"
        )


def _unique_identifiers(values: tuple[str, ...], field: str) -> None:
    for value in values:
        _identifier(value, field)
    if len(values) != len(set(values)):
        raise RepositoryConfigurationError(f"{field} must be unique")


def _assertion_kind(value: object) -> AssertionKind:
    if not isinstance(value, str):
        raise RepositoryConfigurationError("assertion kind must be text")
    try:
        return AssertionKind(value)
    except ValueError:
        raise RepositoryConfigurationError("assertion kind is unsupported") from None
