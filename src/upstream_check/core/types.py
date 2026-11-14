"""Type inference, duration/timestamp parsing, canonical source resolution, descriptor-safe I/O, and redaction."""

from __future__ import annotations

from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import errno
import math
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, List, Optional, Sequence, Tuple, Union
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from upstream_check.core.models import InferredType

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

NULL_STRINGS = {"", "null", "none", "na", "n/a", "nan", "nil", "<na>"}
BOOL_STRINGS = {"true", "false"}

SECRET_QUERY_KEYS = {
    "key",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "auth",
    "auth_token",
    "authorization",
    "bearer",
    "password",
    "passwd",
    "pwd",
    "secret",
    "client_secret",
    "sig",
    "signature",
    "credential",
    "credentials",
    "jwt",
    "session",
    "session_id",
    "private_key",
}

SECRET_SUBSTRINGS = (
    "token",
    "key",
    "secret",
    "password",
    "passwd",
    "credential",
    "bearer",
    "auth",
    "sig",
    "jwt",
)

DURATION_PATTERN = re.compile(
    r"^\s*(?:(\d+(?:\.\d+)?)\s*d)?\s*(?:(\d+(?:\.\d+)?)\s*h)?"
    r"\s*(?:(\d+(?:\.\d+)?)\s*m)?\s*(?:(\d+(?:\.\d+)?)\s*s)?\s*$",
    re.IGNORECASE,
)

ISO_DATE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(?:[T\s]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$"
)

INLINE_URL_RE = re.compile(r"https?://[^\s'\"<>]+")
ENV_VAR_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ENV_INTERP_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
ANY_DOLLAR_BRACE_RE = re.compile(r"\$\{([^}]*)\}|\$\{")
SAFE_SOURCE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

WIN_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
WIN_DRIVE_RELATIVE_RE = re.compile(r"^[A-Za-z]:(?![\\/])")
WIN_DRIVE_URI_PATH_RE = re.compile(r"^/[A-Za-z]:(?:[\\/]|$)")
URI_SCHEME_PREFIX_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
ENCODED_SEP_OR_NULL_RE = re.compile(r"%(?:00|2[fF]|5[cC])")


@dataclass(frozen=True)
class ResolvedSourceTarget:
    """Canonical classification and resolved path representation for an upstream source URL."""

    raw_url: str
    expanded_url: str
    is_remote: bool
    scheme: str
    local_path: Optional[Path] = None
    canonical_path: Optional[Path] = None

    def protected_paths(self) -> List[Path]:
        """Return all filesystem path representations that must be protected for this source."""
        if self.is_remote or self.local_path is None:
            return []
        out: List[Path] = [self.local_path]
        if self.canonical_path is not None and self.canonical_path not in out:
            out.append(self.canonical_path)
        try:
            resolved = self.local_path.resolve()
            if resolved not in out:
                out.append(resolved)
        except OSError:
            pass
        return out


def _normalize_local_filesystem_path(
    raw_local_path: str, base_dir: Optional[Union[str, Path]] = None
) -> Tuple[Path, Path]:
    """Normalize a local filesystem path relative to base_dir without losing symlink identity."""
    if "\x00" in raw_local_path:
        raise ValueError("Invalid local filesystem path: contains null byte.")
    cand = Path(raw_local_path)
    if cand.is_absolute():
        anchored = Path(os.path.abspath(str(cand)))
    else:
        root = (
            Path(base_dir).resolve()
            if base_dir is not None
            else Path.cwd().resolve()
        )
        anchored = Path(os.path.abspath(str(root / cand)))
    try:
        resolved = anchored.resolve()
    except OSError:
        resolved = anchored
    return anchored, resolved


def resolve_source_target(
    raw_url: str, base_dir: Optional[Union[str, Path]] = None
) -> ResolvedSourceTarget:
    """Canonically expand environment variables, classify scheme, and resolve local or remote source targets."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("source.url cannot be empty.")

    cleaned_raw = raw_url.strip()
    expanded = expand_env_vars(cleaned_raw).strip()
    if not expanded:
        raise ValueError("Expanded source.url cannot be empty.")
    if "\x00" in expanded:
        raise ValueError("Invalid source.url: contains null byte.")

    if WIN_DRIVE_PATH_RE.match(expanded) or expanded.startswith("\\\\"):
        local_path = Path(expanded)
        canonical_path = (
            Path(os.path.abspath(str(local_path)))
            if os.name == "nt"
            else local_path
        )
        return ResolvedSourceTarget(
            raw_url=raw_url,
            expanded_url=expanded,
            is_remote=False,
            scheme="file",
            local_path=local_path,
            canonical_path=canonical_path,
        )

    if WIN_DRIVE_RELATIVE_RE.match(expanded):
        raise ValueError(
            f"Ambiguous drive-relative path '{redact_url(expanded)}' is not supported. "
            "Use an explicit relative path or an absolute path."
        )

    scheme_match = URI_SCHEME_PREFIX_RE.match(expanded)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        if scheme in ("http", "https"):
            if not expanded.lower().startswith(f"{scheme}://"):
                raise ValueError(
                    f"Invalid {scheme.upper()} URL '{redact_url(expanded)}': expected '{scheme}://'."
                )
            parsed = urlsplit(expanded)
            if not parsed.netloc:
                raise ValueError(
                    f"Invalid {scheme.upper()} URL '{redact_url(expanded)}': missing host."
                )
            return ResolvedSourceTarget(
                raw_url=raw_url,
                expanded_url=expanded,
                is_remote=True,
                scheme=scheme,
                local_path=None,
                canonical_path=None,
            )

        if scheme == "file":
            if not expanded.lower().startswith("file://"):
                raise ValueError(
                    "Invalid file URI: must start with 'file://' (e.g., 'file:///path/to/file')."
                )
            parsed = urlsplit(expanded)
            if parsed.query or parsed.fragment:
                raise ValueError(
                    "Invalid file URI: query ('?') and fragment ('#') components are not supported "
                    "in file:// URIs (percent-encode literal '#' as '%23' and '?' as '%3F')."
                )
            if parsed.netloc and parsed.netloc.lower() != "localhost":
                if os.name == "nt":
                    if ENCODED_SEP_OR_NULL_RE.search(parsed.path):
                        raise ValueError(
                            "Invalid file URI: encoded path separators (%2F, %5C) or null bytes (%00) "
                            "are not permitted."
                        )
                    unc_subpath = unquote(parsed.path).replace("/", "\\")
                    unc_full = f"\\\\{parsed.netloc}{unc_subpath}"
                    local_path = Path(unc_full)
                    return ResolvedSourceTarget(
                        raw_url=raw_url,
                        expanded_url=expanded,
                        is_remote=False,
                        scheme="file",
                        local_path=local_path,
                        canonical_path=Path(os.path.abspath(str(local_path))),
                    )
                raise ValueError(
                    f"Invalid file URI host '{parsed.netloc}': local file URIs must use "
                    "'file:///path/to/file' or 'file://localhost/path/to/file'."
                )
            if not parsed.path:
                raise ValueError("Invalid file URI: path component cannot be empty.")
            if ENCODED_SEP_OR_NULL_RE.search(parsed.path):
                raise ValueError(
                    "Invalid file URI: encoded path separators (%2F, %5C) or null bytes (%00) "
                    "are not permitted."
                )
            decoded_path = unquote(parsed.path)
            if "\x00" in decoded_path:
                raise ValueError("Invalid file URI: decoded path contains null byte.")
            if WIN_DRIVE_URI_PATH_RE.match(decoded_path):
                win_str = decoded_path[1:]
                local_path = Path(win_str)
                canonical_path = (
                    Path(os.path.abspath(str(local_path)))
                    if os.name == "nt"
                    else local_path
                )
                return ResolvedSourceTarget(
                    raw_url=raw_url,
                    expanded_url=expanded,
                    is_remote=False,
                    scheme="file",
                    local_path=local_path,
                    canonical_path=canonical_path,
                )
            local_path, canonical_path = _normalize_local_filesystem_path(
                decoded_path, base_dir=base_dir
            )
            return ResolvedSourceTarget(
                raw_url=raw_url,
                expanded_url=expanded,
                is_remote=False,
                scheme="file",
                local_path=local_path,
                canonical_path=canonical_path,
            )

        raise ValueError(
            f"Unsupported URL scheme '{scheme}://'. Supported schemes are 'http://', 'https://', "
            "'file://', or local filesystem paths."
        )

    local_path, canonical_path = _normalize_local_filesystem_path(
        expanded, base_dir=base_dir
    )
    return ResolvedSourceTarget(
        raw_url=raw_url,
        expanded_url=expanded,
        is_remote=False,
        scheme="file",
        local_path=local_path,
        canonical_path=canonical_path,
    )


def validate_source_name(name: str) -> str:
    """Validate that a source name is a safe identifier and cannot traverse directories."""
    cleaned = name.strip() if isinstance(name, str) else ""
    if not cleaned:
        raise ValueError("source.name cannot be empty.")
    if (
        "/" in cleaned
        or "\\" in cleaned
        or ".." in cleaned
        or not SAFE_SOURCE_NAME_RE.match(cleaned)
    ):
        raise ValueError(
            f"Invalid source name '{name}'. Source names must match "
            "'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' and must not contain path separators or '..'."
        )
    return cleaned


def resolve_safe_baseline_path(raw_rel_path: str, base_dir: Path) -> Path:
    """Resolve a baseline file path and verify it stays strictly within base_dir."""
    root = base_dir.resolve()
    expanded_rel = expand_env_vars(raw_rel_path.strip())
    candidate = Path(expanded_rel)
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"Baseline path '{raw_rel_path}' escapes project directory '{root}'."
        ) from exc
    return resolved


def paths_refer_to_same_file(path_a: Path, path_b: Path) -> bool:
    """Return True if path_a and path_b refer to the same file via path normalization, symlink, or hard link."""
    try:
        abs_a = os.path.normcase(os.path.abspath(str(path_a)))
        abs_b = os.path.normcase(os.path.abspath(str(path_b)))
        if abs_a == abs_b:
            return True
    except OSError:
        pass

    try:
        norm_a = os.path.normcase(str(path_a.resolve()))
        norm_b = os.path.normcase(str(path_b.resolve()))
        if norm_a == norm_b:
            return True
    except OSError:
        pass

    for follow_a in (True, False):
        for follow_b in (True, False):
            try:
                stat_a = os.stat(path_a, follow_symlinks=follow_a)
                stat_b = os.stat(path_b, follow_symlinks=follow_b)
                if os.path.samestat(stat_a, stat_b):
                    return True
            except OSError:
                continue

    try:
        if os.path.samefile(str(path_a), str(path_b)):
            return True
    except OSError:
        pass
    return False


def _snapshot_protected_stats(
    protected_paths: Iterable[Path],
) -> List[Tuple[Path, os.stat_result]]:
    """Capture (path, stat_result) snapshots for all existing protected files before opening a destination."""
    snapshots: List[Tuple[Path, os.stat_result]] = []
    for prot in protected_paths:
        for follow in (True, False):
            try:
                st = os.stat(prot, follow_symlinks=follow)
                snapshots.append((prot, st))
            except OSError:
                continue
    return snapshots


def _is_reparse_or_symlink_stat(st: os.stat_result, target_path: Path) -> bool:
    """Return True if a stat result or path represents a symbolic link or Windows reparse point."""
    if stat.S_ISLNK(st.st_mode) or os.path.islink(target_path):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if getattr(st, "st_file_attributes", 0) & reparse_flag:
        return True
    return False


def _clear_nonblock_flag(fd: int) -> None:
    """Clear O_NONBLOCK on an already-verified regular file descriptor when supported."""
    nonblock_flag = getattr(os, "O_NONBLOCK", 0)
    if fcntl is not None and nonblock_flag != 0:
        try:
            cur_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            if cur_flags & nonblock_flag:
                fcntl.fcntl(fd, fcntl.F_SETFL, cur_flags & ~nonblock_flag)
        except OSError:
            pass


def safe_read_regular_file_bytes(
    path: Path,
    max_bytes: Optional[int] = None,
    label: str = "file",
) -> Tuple[bytes, os.stat_result]:
    """Open path with O_RDONLY | O_NONBLOCK, verify S_ISREG via fstat(), and read up to max_bytes.

    Prevents blocking on FIFOs/named pipes or special device files when reading configurations,
    baselines, or local data sources.
    """
    nonblock_flag = getattr(os, "O_NONBLOCK", 0)
    try:
        lstat_pre = os.lstat(path)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"File not found: {path}") from exc
    except OSError as exc:
        raise ValueError(f"Could not inspect {label} '{path}': {exc}") from exc

    if stat.S_ISFIFO(lstat_pre.st_mode) or stat.S_ISSOCK(lstat_pre.st_mode):
        raise ValueError(f"Path is not a regular file: {path}")

    try:
        fd = os.open(str(path), os.O_RDONLY | nonblock_flag)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"File not found: {path}") from exc
    except OSError as exc:
        raise ValueError(f"Could not open {label} '{path}': {exc}") from exc

    try:
        fd_stat = os.fstat(fd)
        if not stat.S_ISREG(fd_stat.st_mode):
            raise ValueError(f"Path is not a regular file: {path}")
        if max_bytes is not None and fd_stat.st_size > max_bytes:
            raise ValueError(
                f"File size ({fd_stat.st_size} bytes) exceeds max_response_bytes ({max_bytes} bytes)"
            )
        _clear_nonblock_flag(fd)
        chunks: List[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise ValueError(
                    f"File size ({total} bytes) exceeds max_response_bytes ({max_bytes} bytes)"
                )
            chunks.append(chunk)
        return b"".join(chunks), fd_stat
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def verify_target_not_aliased_or_linked(
    target_path: Path,
    protected_paths: Iterable[Path],
    label: str = "output file",
    forbid_symlinks: bool = True,
    forbid_multiple_hardlinks: bool = True,
) -> None:
    """Verify target_path does not alias any protected path via path, symlink, hard link, or special file."""
    if forbid_symlinks and os.path.islink(target_path):
        raise ValueError(
            f"Refusing to write {label} '{target_path}': destination is a symbolic link."
        )

    for prot in protected_paths:
        if paths_refer_to_same_file(target_path, prot):
            raise ValueError(
                f"Refusing to write {label} '{target_path}' because it aliases "
                f"protected file '{prot}'."
            )

    if os.path.lexists(target_path):
        try:
            st = os.lstat(target_path)
        except OSError as exc:
            raise ValueError(
                f"Refusing to write {label} '{target_path}': could not inspect destination: {exc}"
            ) from exc
        if forbid_symlinks and _is_reparse_or_symlink_stat(st, target_path):
            raise ValueError(
                f"Refusing to write {label} '{target_path}': destination is a symbolic link."
            )
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(
                f"Refusing to write {label} '{target_path}': destination is not a regular file."
            )
        if forbid_multiple_hardlinks and st.st_nlink > 1:
            raise ValueError(
                f"Refusing to write {label} '{target_path}': destination has "
                f"{st.st_nlink} hard links and modifying it would alter another file."
            )


def verify_open_fd_safe(
    fd: int,
    target_path: Path,
    protected_paths: Iterable[Path],
    label: str = "output file",
    pre_protected_stats: Optional[Sequence[Tuple[Path, os.stat_result]]] = None,
    verify_path_binding: bool = True,
) -> os.stat_result:
    """Verify an already-open file descriptor via fstat() before writing a single byte."""
    fd_stat = os.fstat(fd)
    if not stat.S_ISREG(fd_stat.st_mode):
        raise ValueError(
            f"Refusing to write {label} '{target_path}': opened file descriptor is not a regular file."
        )
    if fd_stat.st_ino == 0 or fd_stat.st_dev == 0:
        raise ValueError(
            f"Refusing to write {label} '{target_path}': platform/filesystem did not provide "
            "verifiable device/inode identity on opened descriptor (fail-closed protection)."
        )
    if fd_stat.st_nlink > 1:
        raise ValueError(
            f"Refusing to write {label} '{target_path}': opened file descriptor has "
            f"{fd_stat.st_nlink} hard links and modifying it would alter another file."
        )
    if fd_stat.st_nlink < 1:
        raise ValueError(
            f"Refusing to write {label} '{target_path}': opened file descriptor was unlinked."
        )

    if pre_protected_stats:
        for prot_path, prot_st in pre_protected_stats:
            if os.path.samestat(fd_stat, prot_st):
                raise ValueError(
                    f"Refusing to write {label} '{target_path}' because opened descriptor "
                    f"aliases protected file '{prot_path}'."
                )

    for prot in protected_paths:
        for follow in (True, False):
            try:
                prot_st = os.stat(prot, follow_symlinks=follow)
            except OSError:
                continue
            if os.path.samestat(fd_stat, prot_st):
                raise ValueError(
                    f"Refusing to write {label} '{target_path}' because opened descriptor "
                    f"aliases protected file '{prot}'."
                )

    if verify_path_binding:
        try:
            path_lstat = os.lstat(target_path)
        except OSError as exc:
            raise ValueError(
                f"Refusing to write {label} '{target_path}': destination disappeared during verification: {exc}"
            ) from exc
        if _is_reparse_or_symlink_stat(path_lstat, target_path):
            raise ValueError(
                f"Refusing to write {label} '{target_path}': destination is a symbolic link."
            )
        if not stat.S_ISREG(path_lstat.st_mode):
            raise ValueError(
                f"Refusing to write {label} '{target_path}': destination is not a regular file."
            )
        if not os.path.samestat(fd_stat, path_lstat):
            raise ValueError(
                f"Refusing to write {label} '{target_path}': destination inode changed during open "
                "(concurrent filesystem modification detected)."
            )

    return fd_stat


def _write_all_to_fd(fd: int, content: str) -> None:
    """Write UTF-8 text bytes directly to an already-verified file descriptor and fsync."""
    data = content.encode("utf-8")
    total_written = 0
    while total_written < len(data):
        written = os.write(fd, data[total_written:])
        if written <= 0:
            raise OSError("Short write to verified file descriptor.")
        total_written += written
    os.fsync(fd)


def safe_append_text_verified(
    target_path: Path,
    content: str,
    protected_paths: Iterable[Path] = (),
    allow_existing: bool = True,
    label: str = "step summary ($GITHUB_STEP_SUMMARY)",
) -> None:
    """Open target_path for appending without check-then-open or FIFO-blocking races, verify fstat(), and write.

    - Uses `O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_NOFOLLOW` when creating a new file or when
      `allow_existing=False`.
    - When `allow_existing=True` and the destination already exists, opens with
      `O_WRONLY | O_APPEND | O_NOFOLLOW | O_NONBLOCK` so named pipes (FIFOs) without a reader fail
      immediately with `ENXIO` rather than blocking, and FIFOs with a reader or special device files
      are rejected immediately by `verify_open_fd_safe()` (`stat.S_ISREG(fd_stat.st_mode)`).
    """
    protected_list = list(protected_paths)
    pre_stats = _snapshot_protected_stats(protected_list)

    parent_dir = target_path.parent
    if os.path.islink(parent_dir):
        raise ValueError(
            f"Refusing to write {label} '{target_path}': parent directory '{parent_dir}' is a symbolic link."
        )
    parent_dir.mkdir(parents=True, exist_ok=True)
    for prot in protected_list:
        if paths_refer_to_same_file(target_path, prot):
            raise ValueError(
                f"Refusing to write {label} '{target_path}' because it aliases "
                f"protected file '{prot}'."
            )

    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    nonblock_flag = getattr(os, "O_NONBLOCK", 0)
    excl_flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | nofollow_flag | nonblock_flag
    )
    fd: Optional[int] = None
    created_new = False
    fd_stat: Optional[os.stat_result] = None

    try:
        try:
            fd = os.open(str(target_path), excl_flags, 0o644)
            created_new = True
        except FileExistsError as exc:
            if not allow_existing:
                raise ValueError(
                    f"Refusing to modify existing file '{target_path}' for {label} "
                    "because configuration or protected-path verification failed (fail-closed protection)."
                ) from exc
            if os.name == "nt" and nofollow_flag == 0:
                lstat_pre = os.lstat(target_path)
                if _is_reparse_or_symlink_stat(lstat_pre, target_path):
                    raise ValueError(
                        f"Refusing to write {label} '{target_path}': destination is a symbolic link."
                    )
                if not stat.S_ISREG(lstat_pre.st_mode):
                    raise ValueError(
                        f"Refusing to write {label} '{target_path}': destination is not a regular file."
                    )
            open_existing_flags = (
                os.O_WRONLY | os.O_APPEND | nofollow_flag | nonblock_flag
            )
            try:
                fd = os.open(str(target_path), open_existing_flags)
            except OSError as open_exc:
                if open_exc.errno in (
                    getattr(errno, "ELOOP", 40),
                    getattr(errno, "EMLINK", 31),
                ) or os.path.islink(target_path):
                    raise ValueError(
                        f"Refusing to write {label} '{target_path}': destination is a symbolic link."
                    ) from open_exc
                if open_exc.errno in (
                    getattr(errno, "ENXIO", 6),
                    getattr(errno, "ENODEV", 19),
                    getattr(errno, "EOPNOTSUPP", 95),
                ):
                    raise ValueError(
                        f"Refusing to write {label} '{target_path}': destination is not a regular file."
                    ) from open_exc
                raise ValueError(
                    f"Refusing to write {label} '{target_path}': {open_exc}"
                ) from open_exc
        except OSError as exc:
            if exc.errno in (
                getattr(errno, "ELOOP", 40),
                getattr(errno, "EMLINK", 31),
            ) or os.path.islink(target_path):
                raise ValueError(
                    f"Refusing to write {label} '{target_path}': destination is a symbolic link."
                ) from exc
            raise ValueError(
                f"Refusing to write {label} '{target_path}': {exc}"
            ) from exc

        fd_stat = verify_open_fd_safe(
            fd=fd,
            target_path=target_path,
            protected_paths=protected_list,
            label=label,
            pre_protected_stats=pre_stats,
            verify_path_binding=True,
        )
        _clear_nonblock_flag(fd)
        _write_all_to_fd(fd, content)
    except Exception:
        if created_new and fd_stat is not None:
            try:
                cur_lstat = os.lstat(target_path)
                if os.path.samestat(cur_lstat, fd_stat):
                    target_path.unlink()
            except OSError:
                pass
        raise
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def atomic_write_text_safe(
    target_path: Path,
    content: str,
    protected_paths: Iterable[Path] = (),
    allow_overwrite_existing: bool = True,
    label: str = "output file",
) -> None:
    """Safely write text to target_path using descriptor-verified exclusive creation or temp-file + atomic replace."""
    protected_list = list(protected_paths)
    pre_stats = _snapshot_protected_stats(protected_list)
    verify_target_not_aliased_or_linked(
        target_path, protected_list, label=label
    )

    parent_dir = target_path.parent
    if os.path.islink(parent_dir):
        raise ValueError(
            f"Refusing to write {label} '{target_path}': parent directory '{parent_dir}' is a symbolic link."
        )
    parent_dir.mkdir(parents=True, exist_ok=True)

    if not allow_overwrite_existing:
        safe_append_text_verified(
            target_path=target_path,
            content=content,
            protected_paths=protected_list,
            allow_existing=False,
            label=label,
        )
        return

    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=".upstream-check-",
        suffix=".tmp",
        dir=str(parent_dir),
        text=True,
    )
    tmp_path = Path(tmp_name)
    closed_tmp = False
    try:
        verify_open_fd_safe(
            fd=tmp_fd,
            target_path=tmp_path,
            protected_paths=protected_list,
            label=label,
            pre_protected_stats=pre_stats,
            verify_path_binding=True,
        )
        _write_all_to_fd(tmp_fd, content)
        os.close(tmp_fd)
        closed_tmp = True

        verify_target_not_aliased_or_linked(
            target_path, protected_list, label=label
        )
        for prot_path, prot_st in pre_stats:
            try:
                if os.path.samestat(os.lstat(target_path), prot_st):
                    raise ValueError(
                        f"Refusing to write {label} '{target_path}' because it aliases "
                        f"protected file '{prot_path}'."
                    )
            except FileNotFoundError:
                pass
        os.replace(str(tmp_path), str(target_path))
    except Exception:
        if not closed_tmp:
            try:
                os.close(tmp_fd)
            except OSError:
                pass
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise


def validate_env_placeholder_syntax(value: str) -> None:
    """Ensure every '${...}' placeholder in value is closed and contains a valid identifier."""
    if not isinstance(value, str) or "${" not in value:
        return
    for match in ANY_DOLLAR_BRACE_RE.finditer(value):
        inner = match.group(1)
        if inner is None:
            raise ValueError(
                "Unclosed environment variable placeholder '${' in configuration value."
            )
        if not inner:
            raise ValueError(
                "Empty environment variable placeholder '${}' in configuration value."
            )
        if not ENV_VAR_NAME_RE.match(inner):
            raise ValueError(
                f"Malformed environment variable placeholder '${{{inner}}}' "
                "(variable names must match ^[A-Za-z_][A-Za-z0-9_]*$)."
            )


def expand_env_vars(value: str) -> str:
    """Validate and expand ${ENV_VAR} placeholders in URLs or header values, raising ValueError if invalid or unset."""
    if not isinstance(value, str) or "${" not in value:
        return value

    validate_env_placeholder_syntax(value)
    missing_vars: List[str] = []

    def _replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        env_val = os.environ.get(var_name)
        if env_val is None or env_val == "":
            missing_vars.append(var_name)
            return ""
        return env_val

    expanded = ENV_INTERP_RE.sub(_replace, value)
    if missing_vars:
        vars_str = ", ".join(sorted(set(missing_vars)))
        raise ValueError(
            f"Unresolved or empty environment variable(s): {vars_str}"
        )
    return expanded


def _is_secret_param_name(key: str) -> bool:
    low = key.lower().strip()
    return low in SECRET_QUERY_KEYS or any(sub in low for sub in SECRET_SUBSTRINGS)


def _is_safe_placeholder(val: str) -> bool:
    if val == "REDACTED":
        return True
    if "${" not in val:
        return False
    try:
        validate_env_placeholder_syntax(val)
    except ValueError:
        return False
    stripped = ENV_INTERP_RE.sub("", val).strip()
    if stripped.lower() in ("", "bearer", "basic", "token", ":"):
        return True
    return False


def _inspect_and_redact_kv_pairs(
    raw_segment: str,
) -> Tuple[bool, str]:
    """Inspect a query or fragment string for secret key=value pairs and return (has_secret, redacted_str)."""
    if not raw_segment:
        return False, raw_segment
    pairs = parse_qsl(raw_segment, keep_blank_values=True)
    if not pairs:
        return False, raw_segment
    found_secret = False
    redacted_pairs: List[Tuple[str, str]] = []
    for k, v in pairs:
        if _is_secret_param_name(k) and v:
            if not _is_safe_placeholder(v):
                found_secret = True
            redacted_pairs.append((k, "REDACTED"))
        else:
            redacted_pairs.append((k, v))
    return found_secret, urlencode(redacted_pairs)


def has_plaintext_credentials(url: str) -> bool:
    """Return True if a URL contains hardcoded userinfo, secret query params, or secret fragment params."""
    if not url or "://" not in url:
        return False
    try:
        parts = urlsplit(url)
        if "@" in parts.netloc:
            userinfo, _ = parts.netloc.rsplit("@", 1)
            if not _is_safe_placeholder(userinfo):
                return True
        query_secret, _ = _inspect_and_redact_kv_pairs(parts.query)
        if query_secret:
            return True
        if parts.fragment:
            frag = parts.fragment
            frag_query = frag.split("?", 1)[1] if "?" in frag else frag
            frag_secret, _ = _inspect_and_redact_kv_pairs(frag_query)
            if frag_secret:
                return True
        return False
    except Exception:
        return False


def redact_url(url: str) -> str:
    """Redact credentials and sensitive tokens from URL netloc, query, and fragment."""
    if not url or "://" not in url:
        return url
    try:
        parts = urlsplit(url)
        netloc = parts.netloc
        if "@" in netloc:
            _, hostpart = netloc.rsplit("@", 1)
            netloc = f"***@{hostpart}"
        _, safe_query = _inspect_and_redact_kv_pairs(parts.query)

        safe_fragment = parts.fragment
        if parts.fragment:
            if "?" in parts.fragment:
                prefix, frag_q = parts.fragment.split("?", 1)
                _, red_frag_q = _inspect_and_redact_kv_pairs(frag_q)
                safe_fragment = f"{prefix}?{red_frag_q}"
            elif "=" in parts.fragment:
                _, safe_fragment = _inspect_and_redact_kv_pairs(parts.fragment)

        return urlunsplit(
            (parts.scheme, netloc, parts.path, safe_query, safe_fragment)
        )
    except Exception:
        return url


def redact_text(text: str) -> str:
    """Redact any URLs embedded inside exception messages or error strings."""
    if not text or "http" not in text:
        return text
    return INLINE_URL_RE.sub(lambda m: redact_url(m.group(0)), text)


def is_missing(value: Any) -> bool:
    """Check whether a cell value represents a null/missing entry without mutating the source value."""
    if value is None:
        return True
    if isinstance(value, float) and math.isnan(value):
        return True
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.lower() in NULL_STRINGS:
            return True
    return False


def to_float(value: Any) -> Optional[float]:
    """Attempt to parse a value as a finite float (returns None if not a finite number or on overflow)."""
    if is_missing(value) or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            fval = float(value)
        except (OverflowError, ValueError):
            return None
        return fval if math.isfinite(fval) else None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            fval = float(s)
            return fval if math.isfinite(fval) else None
        except (OverflowError, ValueError):
            return None
    return None


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse ISO-8601, RFC-2822 (HTTP Last-Modified), or Unix epoch into a UTC datetime."""
    if is_missing(value) or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            val = float(value)
        except (OverflowError, ValueError):
            return None
        if not math.isfinite(val):
            return None
        if 946684800 <= val <= 4102444800:
            return datetime.fromtimestamp(val, tz=timezone.utc)
        if 946684800000 <= val <= 4102444800000:
            return datetime.fromtimestamp(val / 1000.0, tz=timezone.utc)
        return None
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    norm = s[:-1] + "+00:00" if s.endswith(("Z", "z")) else s
    try:
        dt = datetime.fromisoformat(norm)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        dt_http = parsedate_to_datetime(s)
        if dt_http is not None:
            if dt_http.tzinfo is None:
                return dt_http.replace(tzinfo=timezone.utc)
            return dt_http.astimezone(timezone.utc)
    except Exception:
        pass
    return None


def infer_value_type(value: Any, from_csv: bool = False) -> InferredType:
    """Infer the semantic data type of a single value."""
    if is_missing(value):
        return InferredType.NULL
    if isinstance(value, bool):
        return InferredType.BOOLEAN
    if isinstance(value, int):
        try:
            fval = float(value)
            if not math.isfinite(fval):
                return InferredType.STRING
        except OverflowError:
            return InferredType.STRING
        return InferredType.INTEGER
    if isinstance(value, float):
        return InferredType.NUMBER if math.isfinite(value) else InferredType.STRING
    if isinstance(value, dict):
        return InferredType.OBJECT
    if isinstance(value, list):
        return InferredType.ARRAY
    if isinstance(value, str):
        s = value.strip()
        if not from_csv:
            if ISO_DATE_RE.match(s) and parse_timestamp(s) is not None:
                return InferredType.DATETIME
            return InferredType.STRING
        if s.lower() in BOOL_STRINGS:
            return InferredType.BOOLEAN
        if re.match(r"^[+-]?\d+$", s):
            if len(s.lstrip("+-")) > 1 and s.lstrip("+-").startswith("0"):
                return InferredType.STRING
            if to_float(s) is None:
                return InferredType.STRING
            return InferredType.INTEGER
        if re.match(r"^[+-]?(?:\d+\.\d*|\.\d+|\d+(?:\.\d+)?[eE][+-]?\d+)$", s):
            fval = to_float(s)
            return InferredType.NUMBER if fval is not None else InferredType.STRING
        if ISO_DATE_RE.match(s) and parse_timestamp(s) is not None:
            return InferredType.DATETIME
        return InferredType.STRING
    return InferredType.STRING


def infer_column_type(
    values: Sequence[Any], from_csv: bool = False
) -> InferredType:
    """Infer the dominant semantic type of a column across non-null values."""
    non_null_types = [
        infer_value_type(v, from_csv=from_csv)
        for v in values
        if not is_missing(v)
    ]
    if not non_null_types:
        return InferredType.NULL

    unique_types = set(non_null_types)
    if unique_types == {InferredType.INTEGER}:
        return InferredType.INTEGER
    if unique_types <= {InferredType.INTEGER, InferredType.NUMBER}:
        return InferredType.NUMBER
    if len(unique_types) == 1:
        return next(iter(unique_types))
    return InferredType.STRING


def types_compatible(
    expected: str, actual: str, from_csv: bool = False
) -> bool:
    """Determine whether an actual inferred column type satisfies an expected type."""
    exp = expected.lower().strip()
    act = actual.lower().strip()
    if act == InferredType.NULL.value:
        return exp == InferredType.NULL.value
    if exp == act:
        return True
    if exp in ("number", "float", "numeric") and act in ("number", "integer"):
        return True
    if exp in ("int", "integer") and act == "integer":
        return True
    if exp in ("str", "string", "text"):
        if act in ("string", "datetime"):
            return True
        if from_csv and act in ("integer", "number", "boolean"):
            return True
    if exp in ("bool", "boolean") and act == "boolean":
        return True
    if exp in ("datetime", "timestamp", "date") and act == "datetime":
        return True
    return False


def normalize_display_type(inferred: str) -> str:
    """Normalize integer/number display for clear user reporting."""
    if inferred in ("integer", "number"):
        return "number"
    return inferred


def parse_duration_seconds(spec: Any) -> float:
    """Parse a human-readable duration string like '36h', '2d', '90m', '1d12h' into finite seconds."""
    if isinstance(spec, bool):
        raise ValueError("Duration specification cannot be a boolean.")
    if isinstance(spec, (int, float)):
        try:
            fval = float(spec)
        except OverflowError as exc:
            raise ValueError(f"Duration specification overflowed float range: {spec}") from exc
        if not math.isfinite(fval):
            raise ValueError(f"Duration specification must be finite (got {spec}).")
        return fval
    s = str(spec).strip()
    if not s:
        raise ValueError("Empty duration specification")
    if re.match(r"^\d+(?:\.\d+)?$", s):
        try:
            fval = float(s) * 3600.0
        except OverflowError as exc:
            raise ValueError(f"Duration specification overflowed: {spec}") from exc
        if not math.isfinite(fval):
            raise ValueError(f"Duration specification must be finite (got {spec}).")
        return fval
    m = DURATION_PATTERN.match(s)
    if not m or not any(m.groups()):
        raise ValueError(
            f"Invalid duration '{spec}'. Expected format like '36h', '2d', '30m', or '1d12h'."
        )
    days = float(m.group(1) or 0)
    hours = float(m.group(2) or 0)
    minutes = float(m.group(3) or 0)
    seconds = float(m.group(4) or 0)
    total = days * 86400.0 + hours * 3600.0 + minutes * 60.0 + seconds
    if not math.isfinite(total):
        raise ValueError(f"Duration specification overflowed to non-finite value: {spec}")
    return total
