from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from mathews_host_agent.processes import (
    ObservedProcess,
    OwnedProcessError,
    OwnedProcessGroupManager,
    OwnedProcessState,
    ProcessIdentity,
)


@dataclass(slots=True)
class FakeController:
    observations: dict[int, ObservedProcess | None]
    terminated_groups: list[tuple[int, float]] = field(default_factory=list)

    def observe(self, pid: int) -> ObservedProcess | None:
        return self.observations.get(pid)

    def terminate_group(
        self,
        expected: ObservedProcess,
        *,
        grace_seconds: float,
    ) -> bool:
        if self.observations.get(expected.pid) != expected:
            return False
        self.terminated_groups.append(
            (expected.process_group_id, grace_seconds)
        )
        self.observations[expected.pid] = None
        return True


def _identity(*, pid: int = 501, nonce: UUID | None = None) -> ProcessIdentity:
    return ProcessIdentity(
        job_id=uuid4(),
        lease_id=uuid4(),
        fencing_token=7,
        pid=pid,
        process_group_id=pid,
        birth_token=f"birth:{pid}",
        ownership_nonce=nonce or uuid4(),
    )


def _manager(
    tmp_path: Path,
    identity: ProcessIdentity,
) -> tuple[OwnedProcessGroupManager, FakeController]:
    controller = FakeController(
        {
            identity.pid: ObservedProcess(
                pid=identity.pid,
                process_group_id=identity.process_group_id,
                birth_token=identity.birth_token,
            )
        }
    )
    manager = OwnedProcessGroupManager(
        (tmp_path / "private" / "host.sqlite3").resolve(),
        controller=controller,
    )
    return manager, controller


def test_exact_owned_group_is_terminated_once_and_replayed(
    tmp_path: Path,
) -> None:
    identity = _identity()
    manager, controller = _manager(tmp_path, identity)
    manager.register(identity)
    manager.register(identity)

    first = manager.terminate_owned(
        identity,
        idempotency_key="cancel:process:501",
    )
    replay = manager.terminate_owned(
        identity,
        idempotency_key="cancel:process:501",
    )

    assert first.state is OwnedProcessState.TERMINATED
    assert first.replayed is False
    assert replay.state is OwnedProcessState.TERMINATED
    assert replay.replayed is True
    assert controller.terminated_groups == [(501, 2.0)]


def test_reused_pid_is_marked_gone_without_signalling(
    tmp_path: Path,
) -> None:
    identity = _identity()
    manager, controller = _manager(tmp_path, identity)
    manager.register(identity)
    controller.observations[identity.pid] = ObservedProcess(
        pid=identity.pid,
        process_group_id=identity.process_group_id,
        birth_token="different-birth",
    )

    result = manager.terminate_owned(
        identity,
        idempotency_key="cancel:reused-pid",
    )

    assert result.state is OwnedProcessState.GONE
    assert controller.terminated_groups == []


def test_unowned_or_conflicting_process_is_never_signalled(
    tmp_path: Path,
) -> None:
    identity = _identity()
    manager, controller = _manager(tmp_path, identity)
    manager.register(identity)
    unowned = ProcessIdentity(
        job_id=identity.job_id,
        lease_id=identity.lease_id,
        fencing_token=identity.fencing_token,
        pid=identity.pid,
        process_group_id=identity.process_group_id,
        birth_token=identity.birth_token,
        ownership_nonce=uuid4(),
    )

    with pytest.raises(OwnedProcessError, match="PROCESS_NOT_OWNED"):
        manager.terminate_owned(
            unowned,
            idempotency_key="cancel:unowned",
        )
    with pytest.raises(
        OwnedProcessError,
        match="TERMINATION_IDEMPOTENCY_CONFLICT",
    ):
        manager.terminate_owned(
            identity,
            idempotency_key="cancel:first",
        )
        manager.terminate_owned(
            identity,
            idempotency_key="cancel:second",
        )
    assert controller.terminated_groups == [(identity.process_group_id, 2.0)]


def test_process_identity_requires_a_dedicated_group() -> None:
    with pytest.raises(
        OwnedProcessError,
        match="INVALID_PROCESS_IDENTITY",
    ):
        ProcessIdentity(
            job_id=uuid4(),
            lease_id=uuid4(),
            fencing_token=1,
            pid=501,
            process_group_id=500,
            birth_token="birth:501",
            ownership_nonce=uuid4(),
        )
