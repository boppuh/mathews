import hashlib
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from mathews_control_plane.artifacts import (
    ArtifactCorruptionError,
    ArtifactNotFoundError,
    ArtifactPathError,
    ArtifactStore,
    InvalidArtifactAddressError,
)


def _artifact_path(root: Path, address: str) -> Path:
    hex_digest = address.removeprefix("sha256:")
    return root / "sha256" / hex_digest[:2] / hex_digest[2:]


def test_put_and_get_content_addressed_artifact(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    payload = b"deterministic artifact bytes"
    expected_digest = hashlib.sha256(payload).hexdigest()

    artifact = store.put_bytes(payload)

    assert artifact.address == f"sha256:{expected_digest}"
    assert artifact.size == len(payload)
    assert store.get_bytes(artifact.address) == payload
    assert _artifact_path(store.root, artifact.address).read_bytes() == payload
    assert _artifact_path(store.root, artifact.address).stat().st_mode & 0o777 == 0o600
    assert store.root.stat().st_mode & 0o777 == 0o700
    assert not list(store.root.rglob(".artifact-*"))


@pytest.mark.parametrize("payload", (b"", b"\x00\xff\x80binary\npayload"))
def test_empty_and_binary_payloads_round_trip(tmp_path: Path, payload: bytes) -> None:
    store = ArtifactStore(tmp_path / "artifacts")

    artifact = store.put_bytes(payload)

    assert artifact.size == len(payload)
    assert store.get_bytes(artifact.address) == payload


def test_duplicate_write_is_idempotent(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    payload = b"one immutable value"
    first = store.put_bytes(payload)
    stored_path = _artifact_path(store.root, first.address)
    initial_inode = stored_path.stat().st_ino
    initial_mtime = stored_path.stat().st_mtime_ns

    second = store.put_bytes(payload)

    assert second == first
    assert stored_path.stat().st_ino == initial_inode
    assert stored_path.stat().st_mtime_ns == initial_mtime
    assert not list(store.root.rglob(".artifact-*"))


def test_retrieval_detects_corruption_without_exposing_content(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    secret_payload = b"credential-that-must-not-leak"
    artifact = store.put_bytes(secret_payload)
    _artifact_path(store.root, artifact.address).write_bytes(b"corrupted-secret-value")

    with pytest.raises(ArtifactCorruptionError) as error:
        store.get_bytes(artifact.address)

    message = str(error.value)
    assert artifact.address in message
    assert secret_payload.decode() not in message
    assert "corrupted-secret-value" not in message


def test_duplicate_write_refuses_to_replace_corrupted_content(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    payload = b"expected content"
    artifact = store.put_bytes(payload)
    stored_path = _artifact_path(store.root, artifact.address)
    stored_path.write_bytes(b"unexpected content")

    with pytest.raises(ArtifactCorruptionError):
        store.put_bytes(payload)

    assert stored_path.read_bytes() == b"unexpected content"


@pytest.mark.parametrize(
    "address",
    (
        "",
        "md5:" + ("0" * 32),
        "sha256:",
        "sha256:" + ("0" * 63),
        "sha256:" + ("0" * 65),
        "sha256:" + ("A" * 64),
        "sha256:../../outside",
        "sha256:" + ("0" * 62) + "/.",
    ),
)
def test_retrieval_rejects_noncanonical_and_traversal_addresses(
    tmp_path: Path, address: str
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")

    with pytest.raises(InvalidArtifactAddressError):
        store.get_bytes(address)

    assert not store.root.exists()


def test_missing_artifact_raises_safe_error(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    address = "sha256:" + ("0" * 64)

    with pytest.raises(ArtifactNotFoundError, match=address):
        store.get_bytes(address)


def test_symlinked_storage_directory_cannot_escape_root(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "sha256").symlink_to(outside, target_is_directory=True)
    store = ArtifactStore(root)

    with pytest.raises(ArtifactPathError, match="not a real directory"):
        store.put_bytes(b"must remain confined")

    assert not list(outside.iterdir())


def test_directory_swap_during_publish_cannot_escape_open_shard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "artifacts"
    outside = tmp_path / "outside"
    displaced = tmp_path / "displaced-shard"
    outside.mkdir()
    store = ArtifactStore(root)
    payload = b"remain anchored to the verified directory"
    digest = hashlib.sha256(payload).hexdigest()
    shard = root / "sha256" / digest[:2]
    original_link = os.link
    swapped = False

    def swap_then_link(source: str, target: str, **kwargs: Any) -> None:
        nonlocal swapped
        if not swapped:
            shard.rename(displaced)
            shard.symlink_to(outside, target_is_directory=True)
            swapped = True
        original_link(source, target, **kwargs)

    monkeypatch.setattr(os, "link", swap_then_link)

    with pytest.raises(ArtifactPathError, match="detached during operation"):
        store.put_bytes(payload)

    assert not list(outside.iterdir())
    assert not (displaced / digest[2:]).exists()
    assert not list(displaced.glob(".artifact-*"))


@pytest.mark.parametrize("operation", ("put", "get"))
def test_directory_swap_during_existing_read_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    root = tmp_path / "artifacts"
    outside = tmp_path / "outside"
    displaced = tmp_path / "displaced-shard"
    outside.mkdir()
    store = ArtifactStore(root)
    payload = b"detached reads must not report success"
    artifact = store.put_bytes(payload)
    digest = artifact.address.removeprefix("sha256:")
    shard = root / "sha256" / digest[:2]
    original_read = store._read_verified
    swapped = False

    def read_then_swap(
        directory_descriptor: int,
        artifact_name: str,
        address: str,
    ) -> bytes:
        nonlocal swapped
        result = original_read(directory_descriptor, artifact_name, address)
        if not swapped:
            shard.rename(displaced)
            shard.symlink_to(outside, target_is_directory=True)
            swapped = True
        return result

    monkeypatch.setattr(store, "_read_verified", read_then_swap)

    with pytest.raises(ArtifactPathError, match="detached during operation"):
        if operation == "put":
            store.put_bytes(payload)
        else:
            store.get_bytes(artifact.address)

    assert not list(outside.iterdir())


def test_new_directory_entries_are_fsynced_before_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "artifacts"
    payload = b"durable directory chain"
    digest = hashlib.sha256(payload).hexdigest()
    original_fsync = os.fsync
    fsynced_directory_inodes: set[int] = set()

    def record_fsync(descriptor: int) -> None:
        descriptor_stat = os.fstat(descriptor)
        if stat.S_ISDIR(descriptor_stat.st_mode):
            fsynced_directory_inodes.add(descriptor_stat.st_ino)
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", record_fsync)

    ArtifactStore(root).put_bytes(payload)

    durable_directories = (
        tmp_path,
        root,
        root / "sha256",
        root / "sha256" / digest[:2],
    )
    assert {directory.stat().st_ino for directory in durable_directories}.issubset(
        fsynced_directory_inodes
    )


def test_symlinked_artifact_is_never_followed(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    outside = tmp_path / "outside-secret"
    outside.write_bytes(b"external secret")
    address = "sha256:" + hashlib.sha256(outside.read_bytes()).hexdigest()
    stored_path = _artifact_path(store.root, address)
    stored_path.parent.mkdir(parents=True)
    stored_path.symlink_to(outside)

    with pytest.raises(ArtifactPathError) as error:
        store.get_bytes(address)

    assert "external secret" not in str(error.value)


def test_store_uses_artifact_root_settings_contract(tmp_path: Path) -> None:
    from mathews_control_plane.settings import Settings

    configured_root = tmp_path / "configured-artifacts"
    settings = Settings(artifact_root=configured_root)

    store = ArtifactStore.from_settings(settings)
    artifact = store.put_bytes(b"configured")

    assert store.root == settings.artifact_root
    assert store.get_bytes(artifact.address) == b"configured"
