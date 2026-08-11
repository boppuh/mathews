"""Executable structural contract shared by learned and active review rules."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import cast

AVAILABLE_REVIEW_EVIDENCE_TYPES = frozenset(
    {
        "github-webhook",
        "review-resolution-assessment",
        "hermes-tool-proposal",
        "hermes-tool-authorization",
        "hermes-tool-result",
        "workspace-diff",
        "review-repair-candidate",
        "validation-decision",
        "draft-pull-request-proof",
    }
)


@dataclass(frozen=True, slots=True)
class ExecutableReviewRule:
    categories: tuple[str, ...]
    required_labels: tuple[str, ...]
    path_prefixes: tuple[str, ...]
    max_files: int
    evidence_requirements: tuple[str, ...]


def executable_review_rule(
    *,
    scope: object,
    matcher: object,
    risk_class: object,
    evidence_requirements: object,
) -> ExecutableReviewRule:
    """Validate the exact data shape consumed by review-rule matching."""

    if (
        risk_class != "LOW"
        or not isinstance(scope, dict)
        or set(scope) != {"path_prefixes", "max_files"}
        or not isinstance(matcher, dict)
        or set(matcher) != {"categories", "required_labels"}
    ):
        raise ValueError("review rule is not executable")
    categories = _unique_strings(matcher.get("categories"), required=True)
    labels = _unique_strings(matcher.get("required_labels"), required=False)
    prefixes = tuple(
        _path(value)
        for value in _unique_strings(scope.get("path_prefixes"), required=True)
    )
    maximum = scope.get("max_files")
    requirements = _unique_strings(evidence_requirements, required=True)
    if (
        isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or not 1 <= maximum <= 32
        or not set(requirements).issubset(AVAILABLE_REVIEW_EVIDENCE_TYPES)
    ):
        raise ValueError("review rule is not executable")
    return ExecutableReviewRule(categories, labels, prefixes, maximum, requirements)


def _unique_strings(value: object, *, required: bool) -> tuple[str, ...]:
    if (
        not isinstance(value, list | tuple)
        or (required and not value)
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise ValueError("review rule is not executable")
    values = tuple(cast(str, item) for item in value)
    if len(values) != len(set(values)):
        raise ValueError("review rule is not executable")
    return values


def _path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if (
        not normalized
        or normalized.startswith("/")
        or normalized.endswith("/")
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or len(normalized) > 500
    ):
        raise ValueError("review rule is not executable")
    return candidate.as_posix()
