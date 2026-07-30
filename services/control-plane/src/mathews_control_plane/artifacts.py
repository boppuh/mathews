"""Content-addressed local artifact storage.

Artifact payloads are deliberately absent from return values, exception messages,
and logging. Callers receive only an immutable address and byte count.
"""

from __future__ import annotations

import errno
import hashlib
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Self

_ALGORITHM = "sha256"
_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_HEX_DIGEST_LENGTH = 64


class ArtifactStoreError(RuntimeError):
    """Base class for artifact-store failures."""


class InvalidArtifactAddressError(ValueError):
    """Raised when an artifact address is not canonical and safe."""


class ArtifactNotFoundError(ArtifactStoreError):
    """Raised when an addressed artifact does not exist."""


class ArtifactCorruptionError(ArtifactStoreError):
    """Raised when stored bytes do not match their content address."""


class ArtifactPathError(ArtifactStoreError):
    """Raised when a storage path escapes or redirects outside the artifact root."""


class ArtifactStoreSettings(Protocol):
    """The settings boundary needed by the artifact store."""

    artifact_root: Path


@dataclass(frozen=True, slots=True)
class StoredArtifact:
    """Non-sensitive metadata for a stored artifact."""

    address: str
    size: int


class ArtifactStore:
    """Store immutable byte payloads under their SHA-256 content address."""

    def __init__(self, root: Path) -> None:
        self.root = Path(os.path.abspath(root.expanduser()))

    @classmethod
    def from_settings(cls, settings: ArtifactStoreSettings) -> Self:
        """Create a store using the control-plane ``artifact_root`` contract."""

        return cls(settings.artifact_root)

    def put_bytes(self, payload: bytes) -> StoredArtifact:
        """Durably store bytes and return their canonical content address."""

        hex_digest = hashlib.sha256(payload).hexdigest()
        address = f"{_ALGORITHM}:{hex_digest}"
        artifact_name = hex_digest[2:]
        directory_descriptor = self._open_digest_directory(hex_digest, create=True)
        try:
            try:
                existing = self._read_verified(
                    directory_descriptor,
                    artifact_name,
                    address,
                )
            except ArtifactNotFoundError:
                pass
            else:
                self._verify_digest_directory(directory_descriptor, hex_digest)
                return StoredArtifact(address=address, size=len(existing))

            temporary_name = f".artifact-{secrets.token_hex(16)}"
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(
                temporary_name,
                flags,
                _FILE_MODE,
                dir_fd=directory_descriptor,
            )
            descriptor_open = True
            try:
                with os.fdopen(descriptor, "wb") as temporary_file:
                    descriptor_open = False
                    temporary_file.write(payload)
                    temporary_file.flush()
                    os.fsync(temporary_file.fileno())

                while True:
                    try:
                        # Both names are resolved relative to the already verified
                        # and open shard directory. The hard-link install is atomic
                        # and never replaces an existing immutable address.
                        os.link(
                            temporary_name,
                            artifact_name,
                            src_dir_fd=directory_descriptor,
                            dst_dir_fd=directory_descriptor,
                            follow_symlinks=False,
                        )
                    except FileExistsError:
                        try:
                            existing = self._read_verified(
                                directory_descriptor,
                                artifact_name,
                                address,
                            )
                        except ArtifactNotFoundError:
                            # A concurrent remover won the race after link(2).
                            continue
                        self._verify_digest_directory(
                            directory_descriptor,
                            hex_digest,
                        )
                        return StoredArtifact(address=address, size=len(existing))
                    else:
                        break

                try:
                    self._verify_digest_directory(
                        directory_descriptor,
                        hex_digest,
                    )
                except ArtifactPathError:
                    self._unlink_if_same_artifact(
                        directory_descriptor,
                        temporary_name,
                        artifact_name,
                    )
                    raise
            finally:
                if descriptor_open:
                    os.close(descriptor)
                try:
                    os.unlink(temporary_name, dir_fd=directory_descriptor)
                except FileNotFoundError:
                    pass
                self._fsync_directory(directory_descriptor)
        finally:
            os.close(directory_descriptor)

        return StoredArtifact(address=address, size=len(payload))

    def get_bytes(self, address: str) -> bytes:
        """Retrieve bytes after validating both the address and stored content."""

        hex_digest = _validate_address(address)
        try:
            directory_descriptor = self._open_digest_directory(hex_digest, create=False)
        except FileNotFoundError:
            raise ArtifactNotFoundError(f"artifact not found: {address}") from None

        try:
            payload = self._read_verified(
                directory_descriptor,
                hex_digest[2:],
                address,
            )
            self._verify_digest_directory(directory_descriptor, hex_digest)
            return payload
        finally:
            os.close(directory_descriptor)

    def delete_bytes(self, address: str) -> bool:
        """Idempotently destroy one safely resolved artifact through descriptors.

        The caller owns reference coordination. This primitive refuses redirected,
        non-regular, or swapped targets and fsyncs the shard after unlinking. A
        digest mismatch does not prevent deletion of corrupted sensitive bytes.
        """

        hex_digest = _validate_address(address)
        try:
            directory_descriptor = self._open_digest_directory(hex_digest, create=False)
        except FileNotFoundError:
            return False

        artifact_name = hex_digest[2:]
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            try:
                descriptor = os.open(
                    artifact_name,
                    flags,
                    dir_fd=directory_descriptor,
                )
            except FileNotFoundError:
                return False
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ArtifactPathError(
                        f"artifact path is redirected: {address}"
                    ) from None
                raise

            with os.fdopen(descriptor, "rb") as artifact_file:
                opened_stat = os.fstat(artifact_file.fileno())
                if not stat.S_ISREG(opened_stat.st_mode):
                    raise ArtifactCorruptionError(
                        f"artifact is not a regular file: {address}"
                    )

            try:
                current_stat = os.stat(
                    artifact_name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return False
            if not stat.S_ISREG(current_stat.st_mode) or (
                current_stat.st_dev,
                current_stat.st_ino,
            ) != (opened_stat.st_dev, opened_stat.st_ino):
                raise ArtifactPathError(
                    "artifact changed during deletion"
                )

            self._verify_digest_directory(directory_descriptor, hex_digest)
            os.unlink(artifact_name, dir_fd=directory_descriptor)
            self._fsync_directory(directory_descriptor)
            return True
        finally:
            os.close(directory_descriptor)

    def _open_digest_directory(self, hex_digest: str, *, create: bool) -> int:
        root_descriptor = self._open_root(create=create)
        try:
            algorithm_descriptor = self._open_child_directory(
                root_descriptor,
                _ALGORITHM,
                create=create,
            )
        finally:
            os.close(root_descriptor)

        try:
            return self._open_child_directory(
                algorithm_descriptor,
                hex_digest[:2],
                create=create,
            )
        finally:
            os.close(algorithm_descriptor)

    def _verify_digest_directory(
        self,
        expected_descriptor: int,
        hex_digest: str,
    ) -> None:
        try:
            current_descriptor = self._open_digest_directory(hex_digest, create=False)
        except (FileNotFoundError, ArtifactPathError):
            raise ArtifactPathError(
                "artifact storage directory detached during operation"
            ) from None

        try:
            expected_stat = os.fstat(expected_descriptor)
            current_stat = os.fstat(current_descriptor)
            if (expected_stat.st_dev, expected_stat.st_ino) != (
                current_stat.st_dev,
                current_stat.st_ino,
            ):
                raise ArtifactPathError("artifact storage directory detached during operation")
        finally:
            os.close(current_descriptor)

    def _open_root(self, *, create: bool) -> int:
        components = self.root.parts
        if not self.root.is_absolute() or not components:
            raise ArtifactPathError("artifact root must be an absolute path")

        descriptor = os.open(
            components[0],
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            for component in components[1:]:
                child_descriptor = self._open_child_directory(
                    descriptor,
                    component,
                    create=create,
                    restrict=False,
                )
                os.close(descriptor)
                descriptor = child_descriptor
            os.fchmod(descriptor, _DIRECTORY_MODE)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @staticmethod
    def _open_child_directory(
        parent_descriptor: int,
        name: str,
        *,
        create: bool,
        restrict: bool = True,
    ) -> int:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        except FileNotFoundError:
            if not create:
                raise
            try:
                os.mkdir(name, _DIRECTORY_MODE, dir_fd=parent_descriptor)
            except FileExistsError:
                pass
            else:
                # Persist the new directory entry before it can become part of a
                # successfully returned artifact path.
                ArtifactStore._fsync_directory(parent_descriptor)

            try:
                descriptor = os.open(name, flags, dir_fd=parent_descriptor)
            except OSError as error:
                raise ArtifactPathError(
                    "artifact storage directory was redirected during creation"
                ) from error
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ArtifactPathError(
                    "artifact storage directory is not a real directory"
                ) from None
            raise

        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise ArtifactPathError("artifact storage directory is not a real directory")
        if restrict:
            os.fchmod(descriptor, _DIRECTORY_MODE)
        return descriptor

    @staticmethod
    def _read_verified(
        directory_descriptor: int,
        artifact_name: str,
        address: str,
    ) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(
                artifact_name,
                flags,
                dir_fd=directory_descriptor,
            )
        except FileNotFoundError:
            raise ArtifactNotFoundError(f"artifact not found: {address}") from None
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ArtifactPathError(f"artifact path is redirected: {address}") from None
            raise

        with os.fdopen(descriptor, "rb") as artifact_file:
            if not stat.S_ISREG(os.fstat(artifact_file.fileno()).st_mode):
                raise ArtifactCorruptionError(f"artifact is not a regular file: {address}")
            payload = artifact_file.read()

        actual_digest = hashlib.sha256(payload).hexdigest()
        expected_digest = address.removeprefix(f"{_ALGORITHM}:")
        if actual_digest != expected_digest:
            raise ArtifactCorruptionError(f"artifact content hash mismatch: {address}")
        return payload

    @staticmethod
    def _unlink_if_same_artifact(
        directory_descriptor: int,
        temporary_name: str,
        artifact_name: str,
    ) -> None:
        try:
            temporary_stat = os.stat(
                temporary_name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            artifact_stat = os.stat(
                artifact_name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return

        if (temporary_stat.st_dev, temporary_stat.st_ino) != (
            artifact_stat.st_dev,
            artifact_stat.st_ino,
        ):
            return
        os.unlink(artifact_name, dir_fd=directory_descriptor)

    @staticmethod
    def _fsync_directory(descriptor: int) -> None:
        os.fsync(descriptor)


def _validate_address(address: str) -> str:
    prefix = f"{_ALGORITHM}:"
    if not address.startswith(prefix):
        raise InvalidArtifactAddressError("artifact address must use sha256")

    hex_digest = address.removeprefix(prefix)
    if len(hex_digest) != _HEX_DIGEST_LENGTH or any(
        character not in "0123456789abcdef" for character in hex_digest
    ):
        raise InvalidArtifactAddressError("artifact address must contain 64 lowercase hex digits")
    return hex_digest
