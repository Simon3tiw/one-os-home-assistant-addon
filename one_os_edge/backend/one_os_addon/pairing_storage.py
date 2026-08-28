from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


class UnsafeIdentityStorage(RuntimeError):
    pass


class IdentityStore:
    """Durable secret storage rooted at a private, non-symlink directory."""

    def __init__(self, root: Path | str):
        self.root = Path(root)

    def has_pairing_material(self) -> bool:
        """Inspect the initial-pairing guard without reading, repairing, or deleting secrets."""
        paths = (
            "identity-key.pem",
            "certificate.pem",
            "ca-chain.pem",
            "candidate-key.pem",
            "candidate-certificate.pem",
            "candidate-chain.pem",
            "candidate-promotion.json",
            "renewal-key.pem",
            "renewal-certificate.pem",
            "renewal-chain.pem",
            "renewal-promotion.json",
            "old-identity-key.pem",
            "old-certificate.pem",
            "old-ca-chain.pem",
            "transient/pairing.json",
            "transient/renewal.json",
        )
        return any(
            (self.root / relative).exists() or (self.root / relative).is_symlink()
            for relative in paths
        )

    def _ensure_directory(self, path: Path) -> None:
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            raise UnsafeIdentityStorage("identity directory unavailable") from error
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise UnsafeIdentityStorage("identity path is not a safe directory")
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise UnsafeIdentityStorage("unsafe identity directory owner or mode")

    def _open_directory(self, path: Path) -> int:
        self._ensure_directory(path)
        flags = os.O_RDONLY | os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise UnsafeIdentityStorage("unsafe identity directory") from error
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            os.close(descriptor)
            raise UnsafeIdentityStorage("identity directory changed during access")
        return descriptor

    def _atomic_write(self, directory: Path, name: str, data: bytes) -> None:
        descriptor = self._open_directory(directory)
        temporary = f".{name}.{os.getpid()}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        file_descriptor = None
        try:
            file_descriptor = os.open(temporary, flags, 0o600, dir_fd=descriptor)
            os.fchmod(file_descriptor, 0o600)
            view = memoryview(data)
            while view:
                written = os.write(file_descriptor, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(file_descriptor)
            os.close(file_descriptor)
            file_descriptor = None
            os.replace(temporary, name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
            os.fsync(descriptor)
        except OSError as error:
            try:
                os.unlink(temporary, dir_fd=descriptor)
            except OSError:
                pass
            raise UnsafeIdentityStorage("atomic identity write failed") from error
        finally:
            if file_descriptor is not None:
                os.close(file_descriptor)
            os.close(descriptor)

    def _read_private(self, directory: Path, name: str) -> bytes:
        descriptor = self._open_directory(directory)
        file_descriptor = None
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            file_descriptor = os.open(name, flags, dir_fd=descriptor)
            info = os.fstat(file_descriptor)
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)
            ):
                raise UnsafeIdentityStorage("unsafe identity file owner, mode, or inode")
            chunks = []
            total = 0
            while True:
                chunk = os.read(file_descriptor, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > 131072:
                    raise UnsafeIdentityStorage("identity file is oversized")
                chunks.append(chunk)
            return b"".join(chunks)
        except UnsafeIdentityStorage:
            raise
        except OSError as error:
            raise UnsafeIdentityStorage("unsafe identity file") from error
        finally:
            if file_descriptor is not None:
                os.close(file_descriptor)
            os.close(descriptor)

    def _delete(self, directory: Path, name: str) -> None:
        descriptor = self._open_directory(directory)
        try:
            try:
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return
            if not stat.S_ISREG(info.st_mode):
                raise UnsafeIdentityStorage("refusing to delete non-regular secret")
            os.unlink(name, dir_fd=descriptor)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def load_or_create_identity(self) -> ec.EllipticCurvePrivateKey:
        self._ensure_directory(self.root)
        path = self.root / "identity-key.pem"
        if path.exists() or path.is_symlink():
            return self.load_identity()
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self._atomic_write(self.root, "identity-key.pem", pem)
        return self.load_identity()

    def load_identity(self) -> ec.EllipticCurvePrivateKey:
        pem = self._read_private(self.root, "identity-key.pem")
        try:
            key = serialization.load_pem_private_key(pem, password=None)
        except (TypeError, ValueError) as error:
            raise UnsafeIdentityStorage("corrupt identity key") from error
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise UnsafeIdentityStorage("identity key is not P-256")
        return key

    def create_candidate(self) -> ec.EllipticCurvePrivateKey:
        self._ensure_directory(self.root)
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self._atomic_write(self.root, "candidate-key.pem", pem)
        return key

    def load_candidate(self) -> ec.EllipticCurvePrivateKey:
        pem = self._read_private(self.root, "candidate-key.pem")
        try:
            key = serialization.load_pem_private_key(pem, password=None)
        except (TypeError, ValueError) as error:
            raise UnsafeIdentityStorage("corrupt candidate key") from error
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise UnsafeIdentityStorage("candidate key is not P-256")
        return key

    def write_candidate_credential(self, certificate_pem: str, chain_pem: str) -> None:
        self._atomic_write(self.root, "candidate-certificate.pem", certificate_pem.encode("ascii"))
        self._atomic_write(self.root, "candidate-chain.pem", chain_pem.encode("ascii"))

    def read_candidate_credential(self) -> tuple[str, str]:
        return (
            self._read_private(self.root, "candidate-certificate.pem").decode("ascii"),
            self._read_private(self.root, "candidate-chain.pem").decode("ascii"),
        )

    def read_identity_credential(self) -> tuple[str, str]:
        return (
            self._read_private(self.root, "certificate.pem").decode("ascii"),
            self._read_private(self.root, "ca-chain.pem").decode("ascii"),
        )

    def write_identity_credential(self, certificate_pem: str, chain_pem: str) -> None:
        self._atomic_write(self.root, "certificate.pem", certificate_pem.encode("ascii"))
        self._atomic_write(self.root, "ca-chain.pem", chain_pem.encode("ascii"))

    def create_renewal_candidate(self) -> ec.EllipticCurvePrivateKey:
        key = ec.generate_private_key(ec.SECP256R1())
        self.write_renewal_candidate(key, overwrite=True)
        return self.load_renewal_candidate()

    def write_renewal_candidate(
        self, key: ec.EllipticCurvePrivateKey, *, overwrite: bool = False
    ) -> None:
        self._ensure_directory(self.root)
        path = self.root / "renewal-key.pem"
        if not overwrite and (path.exists() or path.is_symlink()):
            raise UnsafeIdentityStorage("renewal key already exists")
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self._atomic_write(self.root, "renewal-key.pem", pem)

    def load_renewal_candidate(self) -> ec.EllipticCurvePrivateKey:
        try:
            key = serialization.load_pem_private_key(
                self._read_private(self.root, "renewal-key.pem"), password=None
            )
        except (TypeError, ValueError) as error:
            raise UnsafeIdentityStorage("corrupt renewal key") from error
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise UnsafeIdentityStorage("renewal key is not P-256")
        return key

    def renewal_private_pem(self) -> str:
        return self._read_private(self.root, "renewal-key.pem").decode("ascii")

    def write_renewal_credential(self, certificate_pem: str, chain_pem: str) -> None:
        self._atomic_write(self.root, "renewal-certificate.pem", certificate_pem.encode("ascii"))
        self._atomic_write(self.root, "renewal-chain.pem", chain_pem.encode("ascii"))

    def read_renewal_credential(self) -> tuple[str, str]:
        return (
            self._read_private(self.root, "renewal-certificate.pem").decode("ascii"),
            self._read_private(self.root, "renewal-chain.pem").decode("ascii"),
        )

    def write_renewal(self, record: dict[str, Any]) -> None:
        transient = self.root / "transient"
        self._ensure_directory(self.root)
        self._ensure_directory(transient)
        self._atomic_write(
            transient,
            "renewal.json",
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )

    def read_renewal(self) -> dict[str, Any] | None:
        transient = self.root / "transient"
        path = transient / "renewal.json"
        if not path.exists() and not path.is_symlink():
            return None
        try:
            value = json.loads(self._read_private(transient, "renewal.json"))
            if not isinstance(value, dict):
                raise ValueError("record is not an object")
            return value
        except (ValueError, UnicodeError, UnsafeIdentityStorage):
            self.delete_renewal()
            return None

    def promote_renewal(self) -> None:
        active = ("identity-key.pem", "certificate.pem", "ca-chain.pem")
        renewal = ("renewal-key.pem", "renewal-certificate.pem", "renewal-chain.pem")
        old = ("old-identity-key.pem", "old-certificate.pem", "old-ca-chain.pem")
        marker = "renewal-promotion.json"
        candidate_data = [self._read_private(self.root, name) for name in renewal]
        if not (self.root / marker).exists():
            for name, source in zip(old, active, strict=True):
                self._atomic_write(self.root, name, self._read_private(self.root, source))
            self._atomic_write(
                self.root,
                marker,
                json.dumps(
                    [hashlib.sha256(data).hexdigest() for data in candidate_data],
                    separators=(",", ":"),
                ).encode("ascii"),
            )
        try:
            expected = json.loads(self._read_private(self.root, marker))
            if expected != [hashlib.sha256(data).hexdigest() for data in candidate_data]:
                raise UnsafeIdentityStorage("renewal promotion binding mismatch")
            for name, data in zip(active, candidate_data, strict=True):
                self._atomic_write(self.root, name, data)
            for name, data in zip(active, candidate_data, strict=True):
                if self._read_private(self.root, name) != data:
                    raise UnsafeIdentityStorage("renewal promotion verification failed")
            self._delete(self.root, marker)
            for name in (*old, *renewal):
                self._delete(self.root, name)
        except (OSError, ValueError, UnsafeIdentityStorage) as error:
            for name, backup in zip(active, old, strict=True):
                try:
                    self._atomic_write(self.root, name, self._read_private(self.root, backup))
                except UnsafeIdentityStorage:
                    pass
            if isinstance(error, UnsafeIdentityStorage):
                raise
            raise UnsafeIdentityStorage("renewal promotion failed") from error

    def renewal_promotion_in_progress(self) -> bool:
        return (self.root / "renewal-promotion.json").exists()

    def delete_renewal(self) -> None:
        if not self.root.exists() or self.root.is_symlink():
            return
        transient = self.root / "transient"
        if transient.exists() and not transient.is_symlink():
            self._delete(transient, "renewal.json")
        for name in (
            "renewal-key.pem",
            "renewal-certificate.pem",
            "renewal-chain.pem",
            "renewal-promotion.json",
            "old-identity-key.pem",
            "old-certificate.pem",
            "old-ca-chain.pem",
        ):
            self._delete(self.root, name)

    def identity_private_pem(self) -> str:
        return self._read_private(self.root, "identity-key.pem").decode("ascii")

    def revoke_identity(self) -> None:
        self.delete_renewal()
        if not self.root.exists() or self.root.is_symlink():
            return
        for name in ("identity-key.pem", "certificate.pem", "ca-chain.pem"):
            self._delete(self.root, name)

    def candidate_private_pem(self) -> str:
        return self._read_private(self.root, "candidate-key.pem").decode("ascii")

    def promote_candidate(self) -> None:
        names = (
            ("candidate-key.pem", "identity-key.pem"),
            ("candidate-certificate.pem", "certificate.pem"),
            ("candidate-chain.pem", "ca-chain.pem"),
        )
        marker_name = "candidate-promotion.json"
        marker_path = self.root / marker_name
        if marker_path.exists() or marker_path.is_symlink():
            try:
                marker = json.loads(self._read_private(self.root, marker_name))
            except (ValueError, UnicodeError) as error:
                raise UnsafeIdentityStorage("invalid candidate promotion marker") from error
            if not isinstance(marker, dict) or set(marker) != {active for _, active in names}:
                raise UnsafeIdentityStorage("invalid candidate promotion marker")
        else:
            marker = {
                active: hashlib.sha256(self._read_private(self.root, candidate)).hexdigest()
                for candidate, active in names
            }
            self._atomic_write(
                self.root,
                marker_name,
                json.dumps(marker, sort_keys=True, separators=(",", ":")).encode("ascii"),
            )
        descriptor = self._open_directory(self.root)
        try:
            for candidate, active in names:
                candidate_path = self.root / candidate
                try:
                    data = self._read_private(self.root, candidate)
                    source = candidate
                except UnsafeIdentityStorage:
                    if candidate_path.exists() or candidate_path.is_symlink():
                        raise
                    data = self._read_private(self.root, active)
                    source = None
                if hashlib.sha256(data).hexdigest() != marker[active]:
                    raise UnsafeIdentityStorage("candidate promotion binding mismatch")
                if source is not None:
                    os.replace(source, active, src_dir_fd=descriptor, dst_dir_fd=descriptor)
                os.fsync(descriptor)
            os.unlink(marker_name, dir_fd=descriptor)
            os.fsync(descriptor)
        except OSError as error:
            raise UnsafeIdentityStorage("candidate promotion failed") from error
        finally:
            os.close(descriptor)

    def promotion_in_progress(self) -> bool:
        path = self.root / "candidate-promotion.json"
        return path.exists() or path.is_symlink()

    def delete_candidate(self) -> None:
        if not self.root.exists() or self.root.is_symlink():
            return
        for name in (
            "candidate-key.pem",
            "candidate-certificate.pem",
            "candidate-chain.pem",
            "candidate-promotion.json",
        ):
            self._delete(self.root, name)

    def write_transient(self, record: dict[str, Any]) -> None:
        transient = self.root / "transient"
        self._ensure_directory(self.root)
        self._ensure_directory(transient)
        data = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self._atomic_write(transient, "pairing.json", data)

    def read_transient(self, expected: dict[str, Any] | None = None) -> dict[str, Any] | None:
        transient = self.root / "transient"
        path = transient / "pairing.json"
        if not path.exists() and not path.is_symlink():
            return None
        try:
            value = json.loads(self._read_private(transient, "pairing.json"))
            if not isinstance(value, dict):
                raise ValueError("record is not an object")
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError, UnsafeIdentityStorage):
            self.delete_transient()
            return None
        if expected and any(value.get(key) != item for key, item in expected.items()):
            self.delete_transient()
            return None
        return value

    def delete_transient(self) -> None:
        transient = self.root / "transient"
        if transient.exists() and not transient.is_symlink():
            self._delete(transient, "pairing.json")
