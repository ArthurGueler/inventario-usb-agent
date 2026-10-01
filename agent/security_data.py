"""Security gates for the agent data directory and runtime context.

The service stores an authentication token and command results under the data
directory.  A writable directory owned by an interactive user would make the
token and command channel mutable by that user, so the Windows service refuses
to start networking until the directory and every existing child have a
protected DACL.

Production Windows validation intentionally requires pywin32.  Tests can
inject a small backend, but there is no environment-variable or permissive
fallback that can weaken the service policy.
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
import stat
from typing import Any
from urllib.parse import urlsplit

EXPECTED_SERVER_URL = "https://inventario.in9automacao.com.br"
SECURITY_DATA_CAPABILITY = "secure_data_acl_v1"
SECURITY_MARKER_KEY = "security_enrolled_marker"
SECURITY_ROTATION_OLD_KEY = "security_rotation_old_token"
SECURITY_ROTATION_NEW_KEY = "security_rotation_new_token"
SECURITY_ROTATION_PENDING_KEY = "security_rotation_pending"

FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
SE_DACL_PROTECTED = 0x1000
ERROR_INVALID_REPARSE_DATA = 4392
ERROR_NOT_ALL_ASSIGNED = 1300


class SecurityDataError(RuntimeError):
    """Raised when the local security precondition cannot be proven."""


def enable_security_privileges(
    *,
    security_module: Any | None = None,
    api_module: Any | None = None,
    con_module: Any | None = None,
) -> None:
    """Enable the token privileges needed to assign SYSTEM ownership.

    The installer/configuration command runs elevated as an administrator,
    rather than as LocalSystem.  Windows normally keeps these privileges
    present-but-disabled in an administrator token, so merely checking
    elevation is not enough for ``SetNamedSecurityInfo`` to change the owner.

    Module arguments are intentionally injectable for unit tests.  Production
    Windows calls import pywin32 and fail closed when it is unavailable or a
    privilege cannot be enabled; there is no permissive fallback.
    """

    injected = any(module is not None for module in (security_module, api_module, con_module))
    if not injected and os.name != "nt":
        # The real ACL backend is Windows-only.  This no-op keeps the test ACL
        # backend usable on development hosts without pretending to secure a
        # Windows token there.
        return
    if security_module is None or api_module is None or con_module is None:
        try:
            import win32api as api_module  # type: ignore[import,redefined-outer-name]
            import win32con as con_module  # type: ignore[import,redefined-outer-name]
            import win32security as security_module  # type: ignore[import,redefined-outer-name]
        except ImportError as exc:
            raise SecurityDataError("pywin32 is required to enable ACL privileges") from exc

    token_access = (
        getattr(con_module, "TOKEN_ADJUST_PRIVILEGES", 0x0020)
        | getattr(con_module, "TOKEN_QUERY", 0x0008)
    )
    enabled = getattr(con_module, "SE_PRIVILEGE_ENABLED", 0x0002)
    get_last_error = getattr(api_module, "GetLastError", None)
    set_last_error = getattr(api_module, "SetLastError", None)
    try:
        token = security_module.OpenProcessToken(
            api_module.GetCurrentProcess(),
            token_access,
        )
    except Exception as exc:
        raise SecurityDataError("cannot open process token for ACL privileges") from exc

    try:
        for privilege_name in ("SeRestorePrivilege", "SeTakeOwnershipPrivilege"):
            try:
                luid = security_module.LookupPrivilegeValue(None, privilege_name)
                if callable(set_last_error):
                    set_last_error(0)
                result = security_module.AdjustTokenPrivileges(
                    token,
                    False,
                    [(luid, enabled)],
                )
                if result is False:
                    raise SecurityDataError(
                        f"cannot enable {privilege_name} for secure data ACL"
                    )
                if callable(get_last_error) and get_last_error() == ERROR_NOT_ALL_ASSIGNED:
                    raise SecurityDataError(
                        f"cannot enable {privilege_name} for secure data ACL"
                    )
            except Exception as exc:
                # pywin32 reports ERROR_NOT_ALL_ASSIGNED (1300) through this
                # call when an elevated token does not actually hold a
                # requested privilege.  Treat every error as a hard failure.
                raise SecurityDataError(
                    f"cannot enable {privilege_name} for secure data ACL"
                ) from exc
    finally:
        try:
            api_module.CloseHandle(token)
        except Exception:
            # Closing the temporary token handle is best effort; privilege
            # enablement itself has already been checked above.
            pass


def canonical_server_url(value: str | None) -> str:
    """Validate the one production origin accepted by the agent.

    A trailing slash is the only tolerated spelling difference.  User info,
    non-default ports, paths, query strings and fragments are rejected.
    """

    if not isinstance(value, str) or not value:
        raise SecurityDataError("server URL is missing")
    candidate = value.strip()
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise SecurityDataError("server URL is malformed") from exc
    if parsed.scheme.lower() != "https":
        raise SecurityDataError("server URL must use HTTPS")
    if hostname is None or hostname.lower() != "inventario.in9automacao.com.br":
        raise SecurityDataError("server URL origin is not allowed")
    if parsed.username or parsed.password:
        raise SecurityDataError("server URL cannot contain credentials")
    if port not in (None, 443):
        raise SecurityDataError("server URL port is not allowed")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise SecurityDataError("server URL must not contain a path or query")
    if candidate.rstrip('/') != EXPECTED_SERVER_URL:
        raise SecurityDataError("server URL is not the canonical production origin")
    return EXPECTED_SERVER_URL


def is_elevated() -> bool:
    """Return whether the current process may configure/protect agent data."""

    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def is_local_system() -> bool:
    """Return true only for the Windows LocalSystem token (SID S-1-5-18)."""

    if os.name != "nt":
        return False
    try:
        import win32api  # type: ignore[import]
        import win32con  # type: ignore[import]
        import win32security  # type: ignore[import]

        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32con.TOKEN_QUERY,
        )
        try:
            sid, _attributes = win32security.GetTokenInformation(
                token, win32security.TokenUser
            )
            sid_text = win32security.ConvertSidToStringSid(sid)
            return sid_text.upper() == "S-1-5-18"
        finally:
            try:
                win32api.CloseHandle(token)
            except Exception:
                pass
    except Exception:
        # Missing pywin32 must fail closed for command consumption.
        return False


def _path_has_reparse_attribute(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        info = path.lstat()
        attributes = getattr(info, "st_file_attributes", 0)
        return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise SecurityDataError(f"cannot inspect data path: {type(exc).__name__}") from exc


def _assert_parent_components_safe(path: Path) -> None:
    """Reject a symlink/junction in any existing component of the path."""

    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor or os.sep)
    for part in absolute.parts[1:] if absolute.anchor else absolute.parts:
        current = current / part
        if current.exists() and _path_has_reparse_attribute(current):
            raise SecurityDataError("data path contains a reparse point")


def iter_data_tree(root: Path) -> list[Path]:
    """Return root and all descendants without following reparse points."""

    root = Path(root)
    if _path_has_reparse_attribute(root):
        raise SecurityDataError("data directory is a reparse point")
    result: list[Path] = [root]
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SecurityDataError(
                f"cannot enumerate data directory: {type(exc).__name__}"
            ) from exc
        for entry in entries:
            child = Path(entry.path)
            if _path_has_reparse_attribute(child):
                raise SecurityDataError("data directory contains a reparse point")
            result.append(child)
            try:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(child)
            except OSError as exc:
                raise SecurityDataError(
                    f"cannot inspect data entry: {type(exc).__name__}"
                ) from exc
    return result


class WindowsAclBackend:
    """pywin32 implementation of the protected SYSTEM/Admin DACL policy."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise SecurityDataError("Windows ACL backend is only available on Windows")
        try:
            import ntsecuritycon  # type: ignore[import]
            import win32api  # type: ignore[import]
            import win32con  # type: ignore[import]
            import win32security  # type: ignore[import]
        except ImportError as exc:
            raise SecurityDataError("pywin32 is required for secure agent data") from exc
        enable_security_privileges(
            security_module=win32security,
            api_module=win32api,
            con_module=win32con,
        )
        self._security = win32security
        self._full_access = getattr(ntsecuritycon, "FILE_ALL_ACCESS", 0x1F01FF)
        self._se_file_object = getattr(win32security, "SE_FILE_OBJECT", 1)
        self._owner_info = getattr(win32security, "OWNER_SECURITY_INFORMATION", 0x1)
        self._dacl_info = getattr(win32security, "DACL_SECURITY_INFORMATION", 0x4)
        self._protected_info = 0x80000000  # PROTECTED_DACL_SECURITY_INFORMATION
        self._access_allowed = getattr(win32security, "ACCESS_ALLOWED_ACE_TYPE", 0)
        self._acl_revision = getattr(win32security, "ACL_REVISION", 2)
        self._object_inherit = getattr(win32security, "OBJECT_INHERIT_ACE", 0x1)
        self._container_inherit = getattr(win32security, "CONTAINER_INHERIT_ACE", 0x2)
        self._system_sid = win32security.ConvertStringSidToSid("S-1-5-18")
        self._admins_sid = win32security.ConvertStringSidToSid("S-1-5-32-544")

    def _acl(self, path: Path) -> Any:
        acl = self._security.ACL()
        flags = 0
        if path.is_dir():
            flags = self._object_inherit | self._container_inherit
        acl.AddAccessAllowedAceEx(self._acl_revision, flags, self._full_access, self._system_sid)
        acl.AddAccessAllowedAceEx(self._acl_revision, flags, self._full_access, self._admins_sid)
        return acl

    def apply(self, path: Path) -> None:
        self._security.SetNamedSecurityInfo(
            str(path),
            self._se_file_object,
            self._owner_info | self._dacl_info | self._protected_info,
            self._system_sid,
            None,
            self._acl(path),
            None,
        )

    @staticmethod
    def _sid_text(security: Any, sid: Any) -> str:
        return security.ConvertSidToStringSid(sid).upper()

    def validate(self, path: Path) -> None:
        descriptor = self._security.GetNamedSecurityInfo(
            str(path),
            self._se_file_object,
            self._owner_info | self._dacl_info,
        )
        owner = descriptor.GetSecurityDescriptorOwner()
        if self._sid_text(self._security, owner) != "S-1-5-18":
            raise SecurityDataError("data entry owner is not LocalSystem")
        control, _revision = descriptor.GetSecurityDescriptorControl()
        if not (control & SE_DACL_PROTECTED):
            raise SecurityDataError("data entry DACL is not protected")
        dacl = descriptor.GetSecurityDescriptorDacl()
        if dacl is None or dacl.GetAceCount() != 2:
            raise SecurityDataError("data entry DACL contains unexpected entries")
        actual: set[str] = set()
        for index in range(dacl.GetAceCount()):
            ace = dacl.GetAce(index)
            if len(ace) == 3:
                header, mask, sid = ace
                ace_type = header[0]
            else:
                ace_type, _flags, mask, sid = ace
            if ace_type != self._access_allowed or mask != self._full_access:
                raise SecurityDataError("data entry DACL contains unexpected permissions")
            actual.add(self._sid_text(self._security, sid))
        if actual != {"S-1-5-18", "S-1-5-32-544"}:
            raise SecurityDataError("data entry DACL principals are not restricted")


class PosixTestAclBackend:
    """Conservative test backend for non-Windows unit tests only."""

    def apply(self, path: Path) -> None:
        try:
            if path.is_dir():
                path.chmod(stat.S_IRWXU)
            else:
                path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError as exc:
            raise SecurityDataError("cannot protect test data path") from exc

    def validate(self, path: Path) -> None:
        mode = stat.S_IMODE(path.stat().st_mode)
        expected = 0o700 if path.is_dir() else 0o600
        if mode != expected:
            raise SecurityDataError("test data path permissions are not private")


def ensure_secure_data_dir(
    data_dir: Path | str,
    *,
    backend: Any | None = None,
    create: bool = True,
) -> Path:
    """Create/protect/verify the data directory and every existing child."""

    root = Path(data_dir)
    _assert_parent_components_safe(root.parent)
    if create:
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise SecurityDataError("cannot create secure data directory") from exc
    if not root.exists() or not root.is_dir():
        raise SecurityDataError("secure data directory is unavailable")
    _assert_parent_components_safe(root)
    entries = iter_data_tree(root)
    acl = backend
    if acl is None:
        acl = WindowsAclBackend() if os.name == "nt" else PosixTestAclBackend()
    # Root first ensures inherited ACEs are correct before child repair.
    for path in entries:
        if _path_has_reparse_attribute(path):
            raise SecurityDataError("data directory changed to a reparse point")
        try:
            acl.apply(path)
        except SecurityDataError:
            raise
        except Exception as exc:
            raise SecurityDataError(
                f"cannot apply data ACL: {type(exc).__name__}"
            ) from exc
    _assert_parent_components_safe(root)
    # Re-enumerate after repair: a junction inserted during repair is a hard
    # failure rather than something we follow.
    for path in iter_data_tree(root):
        if _path_has_reparse_attribute(path):
            raise SecurityDataError("data directory changed to a reparse point")
        try:
            acl.validate(path)
        except SecurityDataError:
            raise
        except Exception as exc:
            raise SecurityDataError(
                f"cannot validate data ACL: {type(exc).__name__}"
            ) from exc
    return root


def validate_secure_data_dir(data_dir: Path | str, *, backend: Any | None = None) -> Path:
    """Validate without modifying ACLs; used immediately before networking."""

    root = Path(data_dir)
    if not root.exists() or not root.is_dir():
        raise SecurityDataError("secure data directory is unavailable")
    _assert_parent_components_safe(root)
    acl = backend
    if acl is None:
        acl = WindowsAclBackend() if os.name == "nt" else PosixTestAclBackend()
    for path in iter_data_tree(root):
        try:
            acl.validate(path)
        except SecurityDataError:
            raise
        except Exception as exc:
            raise SecurityDataError(
                f"cannot validate data ACL: {type(exc).__name__}"
            ) from exc
    return root


def can_consume_remote_commands(*, service_context: bool) -> bool:
    """Only a LocalSystem-hosted service may claim remote commands."""

    return bool(service_context and os.name == "nt" and is_local_system())
