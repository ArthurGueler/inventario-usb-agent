"""Remote command execution for the Windows service agent.

The command channel is deliberately implemented as an at-most-once worker:
the command is written to a local journal before a child process is started,
and a result is written to that journal before it is sent to the server.  A
restart can therefore retry a result, but can never silently run a command a
second time.

The worker does not provide an interactive shell.  Every process is started
with an explicit argument vector and with stdin disconnected.  On Windows a
Job Object owns the process tree so timeout/stop does not leave descendants
running after the service exits.
"""

from __future__ import annotations

import base64
import datetime as _datetime
import ctypes
import locale
import logging
import os
from pathlib import Path
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Literal

logger = logging.getLogger(__name__)

MIN_TIMEOUT_SECONDS = 10
MAX_TIMEOUT_SECONDS = 300
MAX_OUTPUT_BYTES = 64 * 1024
MAX_COMMAND_UTF8_BYTES = 16 * 1024
MAX_CMD_COMMAND_CHARS = 8191
MAX_CREATEPROCESS_COMMAND_CHARS = 32760
COMMAND_POLL_INTERVAL = 15
VALID_SHELLS = frozenset({"powershell", "cmd"})
VALID_STATUSES = frozenset({"succeeded", "failed", "timed_out", "unknown"})

CommandStatus = Literal["succeeded", "failed", "timed_out", "unknown"]


class CommandValidationError(ValueError):
    """Raised when the server sends a command outside the agent contract."""


@dataclass(frozen=True)
class CommandJob:
    """A validated command claim returned by the server."""

    command_id: str
    shell: Literal["powershell", "cmd"]
    command: str
    timeout_seconds: int
    receipt_token: str

    @classmethod
    def from_payload(cls, payload: Any) -> "CommandJob":
        if not isinstance(payload, dict):
            raise CommandValidationError("job must be an object")

        command_id = payload.get("id", payload.get("command_id"))
        receipt_token = payload.get("receipt_token")
        shell = payload.get("shell")
        command = payload.get("command")
        timeout = payload.get("timeout_seconds")

        if not isinstance(command_id, str) or not command_id.strip():
            raise CommandValidationError("job id is required")
        if len(command_id) > 128 or not re.fullmatch(r"[A-Za-z0-9._:-]+", command_id):
            raise CommandValidationError("job id has invalid format")
        if not isinstance(receipt_token, str) or not receipt_token:
            raise CommandValidationError("receipt token is required")
        if len(receipt_token) > 512:
            raise CommandValidationError("receipt token is too long")
        if shell not in VALID_SHELLS:
            raise CommandValidationError("shell must be powershell or cmd")
        if not isinstance(command, str) or not command.strip():
            raise CommandValidationError("command is required")
        # Keep the JSON field bounded before it reaches the process builder.
        # CMD has a stricter native command-line limit; PowerShell is checked
        # again after UTF-16LE/Base64 encoding in build_command_argv().
        if len(command.encode("utf-8")) > MAX_COMMAND_UTF8_BYTES:
            raise CommandValidationError(
                f"command exceeds {MAX_COMMAND_UTF8_BYTES} UTF-8 bytes"
            )
        if shell == "cmd" and len(command) > MAX_CMD_COMMAND_CHARS:
            raise CommandValidationError(
                f"cmd command exceeds {MAX_CMD_COMMAND_CHARS} characters"
            )
        if isinstance(timeout, bool) or not isinstance(timeout, int):
            raise CommandValidationError("timeout_seconds must be an integer")
        if not MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS:
            raise CommandValidationError(
                f"timeout_seconds must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}"
            )

        return cls(
            command_id=command_id,
            shell=shell,
            command=command,
            timeout_seconds=timeout,
            receipt_token=receipt_token,
        )


@dataclass(frozen=True)
class CommandResult:
    status: CommandStatus
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    output_truncated: bool = False

    def __post_init__(self) -> None:
        if self.status not in VALID_STATUSES:
            raise ValueError(f"invalid command status: {self.status}")


@dataclass(frozen=True)
class JournalRecord:
    command_id: str
    receipt_token: str
    shell: str
    command: str
    timeout_seconds: int
    state: str
    status: CommandStatus | None
    stdout: str
    stderr: str
    exit_code: int | None
    output_truncated: bool
    attempts: int
    last_error: str | None


def _utc_now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).isoformat()


def _journal_path(db_or_path: Any) -> Path:
    """Derive a separate journal file beside LocalDB's private SQLite file."""

    raw_path = getattr(db_or_path, "_path", db_or_path)
    if raw_path is None:
        return Path.cwd() / "agent_commands.db"
    path = Path(raw_path)
    if path.suffix:
        return path.with_name(f"{path.stem}.commands.sqlite3")
    return path / "agent_commands.db"


class CommandJournal:
    """Durable command state, separate from the USB event queue database."""

    def __init__(self, db_or_path: Any = None, journal_path: Path | str | None = None):
        self.path = Path(journal_path) if journal_path is not None else _journal_path(db_or_path)
        self._secure_required = bool(getattr(db_or_path, "secure_required", False))
        self._security_backend = getattr(db_or_path, "_security_backend", None)
        if self._secure_required:
            from .security_data import ensure_secure_data_dir

            ensure_secure_data_dir(self.path.parent, backend=self._security_backend)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()
        if self._secure_required:
            from .security_data import ensure_secure_data_dir

            ensure_secure_data_dir(self.path.parent, backend=self._security_backend)
        self._recover_started_commands()

    def _connect(self) -> sqlite3.Connection:
        if self._secure_required:
            # Protect journal WAL/SHM files that may have appeared after the
            # previous connection before opening another handle or sending
            # any result over the network.
            from .security_data import ensure_secure_data_dir

            ensure_secure_data_dir(self.path.parent, backend=self._security_backend)
        conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS remote_commands (
                    command_id       TEXT PRIMARY KEY,
                    receipt_token    TEXT NOT NULL,
                    shell            TEXT NOT NULL,
                    command          TEXT NOT NULL,
                    timeout_seconds  INTEGER NOT NULL,
                    state            TEXT NOT NULL,
                    status           TEXT,
                    stdout           TEXT NOT NULL DEFAULT '',
                    stderr           TEXT NOT NULL DEFAULT '',
                    exit_code        INTEGER,
                    output_truncated INTEGER NOT NULL DEFAULT 0,
                    created_at       TEXT NOT NULL,
                    started_at       TEXT,
                    completed_at     TEXT,
                    posted_at        TEXT,
                    attempts         INTEGER NOT NULL DEFAULT 0,
                    last_error      TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_remote_commands_pending
                    ON remote_commands(state, created_at);
                """
            )

    def _recover_started_commands(self) -> None:
        """Never rerun a command whose process may have existed before a crash."""

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE remote_commands
                   SET state = 'result_pending',
                       status = 'unknown',
                       stdout = '',
                       stderr = 'agent restarted before the command result was available',
                       exit_code = NULL,
                       output_truncated = 0,
                       completed_at = COALESCE(completed_at, ?)
                 WHERE state IN ('started', 'running')
                   AND status IS NULL
                """,
                (_utc_now(),),
            )

    @staticmethod
    def _row_to_record(row: sqlite3.Row | None) -> JournalRecord | None:
        if row is None:
            return None
        return JournalRecord(
            command_id=row["command_id"],
            receipt_token=row["receipt_token"],
            shell=row["shell"],
            command=row["command"],
            timeout_seconds=int(row["timeout_seconds"]),
            state=row["state"],
            status=row["status"],
            stdout=row["stdout"] or "",
            stderr=row["stderr"] or "",
            exit_code=row["exit_code"],
            output_truncated=bool(row["output_truncated"]),
            attempts=int(row["attempts"]),
            last_error=row["last_error"],
        )

    def get(self, command_id: str) -> JournalRecord | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM remote_commands WHERE command_id = ?", (command_id,)
            ).fetchone()
            return self._row_to_record(row)

    def begin(self, job: CommandJob) -> JournalRecord:
        """Write command identity/state before spawning any process.

        A duplicate claim returns its existing record.  The worker must never
        execute a record that is not in the newly-created ``started`` state.
        """

        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM remote_commands WHERE command_id = ?", (job.command_id,)
            ).fetchone()
            if row is not None:
                return self._row_to_record(row)  # type: ignore[return-value]
            conn.execute(
                """
                INSERT INTO remote_commands
                    (command_id, receipt_token, shell, command, timeout_seconds,
                     state, created_at, started_at)
                VALUES (?, ?, ?, ?, ?, 'started', ?, ?)
                """,
                (
                    job.command_id,
                    job.receipt_token,
                    job.shell,
                    job.command,
                    job.timeout_seconds,
                    _utc_now(),
                    _utc_now(),
                ),
            )
            row = conn.execute(
                "SELECT * FROM remote_commands WHERE command_id = ?", (job.command_id,)
            ).fetchone()
            return self._row_to_record(row)  # type: ignore[return-value]

    def mark_running(self, command_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE remote_commands SET state = 'running' WHERE command_id = ? AND state = 'started'",
                (command_id,),
            )

    def record_result(self, command_id: str, result: CommandResult) -> None:
        """Persist the complete result before any network request is made."""

        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT state, status FROM remote_commands WHERE command_id = ?", (command_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown command: {command_id}")
            # A result is immutable.  In particular, do not overwrite an
            # already-persisted result after a process restart or retry.
            if row["status"] is not None or row["state"] in ("result_pending", "acked"):
                return
            conn.execute(
                """
                UPDATE remote_commands
                   SET state = 'result_pending', status = ?, stdout = ?, stderr = ?,
                       exit_code = ?, output_truncated = ?, completed_at = ?
                 WHERE command_id = ?
                """,
                (
                    result.status,
                    result.stdout,
                    result.stderr,
                    result.exit_code,
                    int(result.output_truncated),
                    _utc_now(),
                    command_id,
                ),
            )

    def pending_results(self) -> list[JournalRecord]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM remote_commands WHERE state = 'result_pending' ORDER BY created_at, command_id"
            ).fetchall()
            return [self._row_to_record(row) for row in rows]  # type: ignore[misc]

    def has_pending_results(self) -> bool:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM remote_commands WHERE state = 'result_pending' LIMIT 1"
            ).fetchone()
            return row is not None

    def mark_attempt_failed(self, command_id: str, error: str) -> None:
        # Do not include response bodies or command text in this field.
        safe_error = str(error).replace("\r", " ").replace("\n", " ")[:500]
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE remote_commands SET attempts = attempts + 1, last_error = ? WHERE command_id = ?",
                (safe_error, command_id),
            )

    def mark_acked(self, command_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE remote_commands
                   SET state = 'acked', posted_at = ?, last_error = NULL
                 WHERE command_id = ? AND state = 'result_pending'
                """,
                (_utc_now(), command_id),
            )


def _windows_system_root(environ: dict[str, str] | None = None) -> Path:
    env = environ or os.environ
    root = env.get("SystemRoot") or env.get("WINDIR") or r"C:\Windows"
    return Path(root)


def _powershell_path(environ: dict[str, str] | None = None) -> str:
    return str(_windows_system_root(environ) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")


def _cmd_path(environ: dict[str, str] | None = None) -> str:
    env = environ or os.environ
    value = env.get("ComSpec") or env.get("COMSPEC")
    if value:
        candidate = Path(value)
        if candidate.is_absolute():
            return str(candidate)
    return str(_windows_system_root(env) / "System32" / "cmd.exe")


def build_command_argv(shell: str, command: str, environ: dict[str, str] | None = None) -> list[str]:
    """Build a non-shell=True argv for a remote command."""

    if shell == "powershell":
        encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
        argv = [
            _powershell_path(environ),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded,
        ]
        if sum(len(part) + 1 for part in argv) > MAX_CREATEPROCESS_COMMAND_CHARS:
            raise CommandValidationError(
                f"powershell command exceeds the {MAX_CREATEPROCESS_COMMAND_CHARS}-character process limit"
            )
        return argv
    if shell == "cmd":
        if len(command) > MAX_CMD_COMMAND_CHARS:
            raise CommandValidationError(
                f"cmd command exceeds {MAX_CMD_COMMAND_CHARS} characters"
            )
        return [_cmd_path(environ), "/d", "/s", "/c", command]
    raise CommandValidationError("shell must be powershell or cmd")


class _OutputCollector:
    def __init__(self, maximum: int = MAX_OUTPUT_BYTES):
        self.maximum = maximum
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.total = 0
        self.truncated = False
        self._lock = threading.Lock()

    def append(self, stream_name: str, chunk: bytes) -> None:
        if not chunk:
            return
        with self._lock:
            remaining = self.maximum - self.total
            if remaining <= 0:
                self.truncated = True
                return
            kept = chunk[:remaining]
            if stream_name == "stdout":
                self.stdout.extend(kept)
            else:
                self.stderr.extend(kept)
            self.total += len(kept)
            if len(kept) != len(chunk):
                self.truncated = True

    def result(self) -> tuple[str, str, bool]:
        with self._lock:
            stdout = _decode_output(bytes(self.stdout))
            stderr = _decode_output(bytes(self.stderr))
            stdout_bytes = stdout.encode("utf-8")
            stderr_bytes = stderr.encode("utf-8")
            total = len(stdout_bytes) + len(stderr_bytes)
            truncated = self.truncated or total > self.maximum
            if total > self.maximum:
                stdout_bytes = stdout_bytes[:self.maximum]
                remaining = self.maximum - len(stdout_bytes)
                stderr_bytes = stderr_bytes[:max(0, remaining)]
                stdout = stdout_bytes.decode("utf-8", errors="ignore")
                stderr = stderr_bytes.decode("utf-8", errors="ignore")
            return stdout, stderr, truncated


def _decode_output(data: bytes) -> str:
    """Decode common PowerShell/CMD encodings without logging raw output."""
    encodings = ["utf-8", locale.getpreferredencoding(False), "cp850", "cp1252"]
    for encoding in dict.fromkeys(encodings):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


class _WindowsJob:
    """Small pywin32 Job Object wrapper; imported only on Windows."""

    def __init__(self, process: subprocess.Popen[Any]):
        self.handle: Any = None
        self._backend: str | None = None
        self.attached = os.name != "nt"
        if os.name != "nt":
            return
        try:
            import win32job  # type: ignore[import]

            handle = win32job.CreateJobObject(None, None)
            self.handle = handle
            info = win32job.QueryInformationJobObject(
                handle, win32job.JobObjectExtendedLimitInformation
            )
            info["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            win32job.SetInformationJobObject(
                handle, win32job.JobObjectExtendedLimitInformation, info
            )
            win32job.AssignProcessToJobObject(handle, process._handle)  # type: ignore[attr-defined]
            self.handle = handle
            self._backend = "pywin32"
            self.attached = True
        except Exception:
            self.close()
            # pywin32 is listed in the installer requirements, but frozen or
            # minimal deployments can omit it.  Use the same native Windows
            # API through ctypes rather than ever resuming an unprotected
            # process.
            self.handle = None
            self._backend = None
            self.attached = self._attach_ctypes(process)

    def _attach_ctypes(self, process: subprocess.Popen[Any]) -> bool:
        try:
            from ctypes import wintypes

            kernel32 = ctypes.windll.kernel32
            kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.SetInformationJobObject.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
            ]
            kernel32.SetInformationJobObject.restype = wintypes.BOOL
            kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("ReadOperationCount", ctypes.c_ulonglong),
                    ("WriteOperationCount", ctypes.c_ulonglong),
                    ("OtherOperationCount", ctypes.c_ulonglong),
                    ("ReadTransferCount", ctypes.c_ulonglong),
                    ("WriteTransferCount", ctypes.c_ulonglong),
                    ("OtherTransferCount", ctypes.c_ulonglong),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                return False
            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
            ok = kernel32.SetInformationJobObject(
                handle,
                9,  # JobObjectExtendedLimitInformation
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if not ok or not kernel32.AssignProcessToJobObject(handle, process._handle):
                kernel32.CloseHandle(handle)
                return False
            self.handle = handle
            self._backend = "ctypes"
            return True
        except Exception:
            return False

    def terminate(self, process: subprocess.Popen[Any]) -> None:
        if self.handle is not None:
            try:
                if self._backend == "pywin32":
                    import win32job  # type: ignore[import]

                    win32job.TerminateJobObject(self.handle, 1)
                else:
                    from ctypes import wintypes

                    kernel32 = ctypes.windll.kernel32
                    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
                    kernel32.TerminateJobObject.restype = wintypes.BOOL
                    if not kernel32.TerminateJobObject(self.handle, 1):
                        raise OSError("TerminateJobObject failed")
                return
            except Exception:
                pass
        if os.name == "nt":
            taskkill = str(_windows_system_root() / "System32" / "taskkill.exe")
            try:
                taskkill_result = subprocess.run(
                    [taskkill, "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if taskkill_result.returncode == 0:
                    return
            except Exception:
                pass
        try:
            process.kill()
        except Exception:
            pass

    @staticmethod
    def resume(process: subprocess.Popen[Any]) -> bool:
        """Resume a CREATE_SUSPENDED child after it has joined the Job Object."""
        if os.name != "nt":
            return True
        thread_handle = getattr(process, "_thread_handle", None)
        if thread_handle is not None:
            try:
                import win32process  # type: ignore[import]

                value = win32process.ResumeThread(thread_handle)
                return value not in (-1, 0xFFFFFFFF)
            except Exception:
                try:
                    value = ctypes.windll.kernel32.ResumeThread(thread_handle)
                    return value not in (-1, 0xFFFFFFFF)
                except Exception:
                    return False

        # CPython closes the primary thread handle before Popen returns.  It
        # still leaves the thread suspended, so find that one thread by PID
        # and resume it through the Toolhelp API.
        try:
            kernel32 = ctypes.windll.kernel32
            from ctypes import wintypes

            class THREADENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ThreadID", wintypes.DWORD),
                    ("th32OwnerProcessID", wintypes.DWORD),
                    ("tpBasePri", wintypes.LONG),
                    ("tpDeltaPri", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD),
                ]

            # Explicit signatures are required on 64-bit Windows; ctypes'
            # default c_int return type truncates HANDLE values.
            kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
            kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
            kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
            kernel32.Thread32First.restype = wintypes.BOOL
            kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
            kernel32.Thread32Next.restype = wintypes.BOOL
            kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel32.OpenThread.restype = wintypes.HANDLE
            kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
            kernel32.ResumeThread.restype = wintypes.DWORD
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL

            snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)
            invalid = ctypes.c_void_p(-1).value
            snapshot_value = getattr(snapshot, "value", snapshot)
            if snapshot_value in (-1, invalid):
                return False

            entry = THREADENTRY32()
            entry.dwSize = ctypes.sizeof(THREADENTRY32)
            found = False
            if kernel32.Thread32First(snapshot, ctypes.byref(entry)):
                while True:
                    if entry.th32OwnerProcessID == process.pid:
                        thread = kernel32.OpenThread(0x0002, False, entry.th32ThreadID)
                        if thread:
                            try:
                                found = kernel32.ResumeThread(thread) != 0xFFFFFFFF
                            finally:
                                kernel32.CloseHandle(thread)
                            if found:
                                break
                    if not kernel32.Thread32Next(snapshot, ctypes.byref(entry)):
                        break
            kernel32.CloseHandle(snapshot)
            return found
        except Exception:
            return False

    def close(self) -> None:
        if self.handle is None:
            return
        try:
            if self._backend == "pywin32":
                import win32api  # type: ignore[import]

                win32api.CloseHandle(self.handle)
            else:
                from ctypes import wintypes

                kernel32 = ctypes.windll.kernel32
                kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
                kernel32.CloseHandle.restype = wintypes.BOOL
                kernel32.CloseHandle(self.handle)
        except Exception:
            try:
                self.handle.Close()
            except Exception:
                pass
        self.handle = None
        self._backend = None


class CommandExecutor:
    """Runs one validated job, draining output and enforcing timeout/stop."""

    def __init__(
        self,
        cwd: Path | str | None = None,
        environ: dict[str, str] | None = None,
        popen_factory: Callable[..., subprocess.Popen[Any]] | None = None,
        maximum_output: int = MAX_OUTPUT_BYTES,
    ):
        if cwd is not None:
            self.cwd = Path(cwd)
        elif getattr(sys, "frozen", False):
            # PyInstaller extracts module files to a temporary directory;
            # remote commands must run from the installed agent directory.
            self.cwd = Path(sys.executable).resolve().parent
        else:
            self.cwd = Path(__file__).resolve().parent.parent
        self.environ = dict(environ or os.environ)
        self._popen = popen_factory or subprocess.Popen
        self._maximum_output = maximum_output
        self._active_lock = threading.RLock()
        self._active_process: subprocess.Popen[Any] | None = None
        self._active_job: _WindowsJob | None = None
        self._stop_requested = threading.Event()

    def execute(self, job: CommandJob) -> CommandResult:
        if self._stop_requested.is_set():
            return CommandResult(status="unknown")

        try:
            argv = build_command_argv(job.shell, job.command, self.environ)
        except Exception as exc:
            return CommandResult(status="failed", stderr=f"invalid command: {exc}")
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        if os.name == "nt":
            # Keep the primary thread suspended while it is assigned to the
            # Job Object.  This closes the small process-tree escape race
            # between CreateProcess and AssignProcessToJobObject.
            creationflags |= getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
        popen_kwargs: dict[str, Any] = {
            "cwd": str(self.cwd),
            "env": self.environ,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "shell": False,
            "creationflags": creationflags,
        }
        if os.name != "nt":
            # This also makes timeout/stop safe for test commands that spawn a
            # child on POSIX; Windows uses the Job Object below.
            popen_kwargs["start_new_session"] = True

        try:
            process = self._popen(argv, **popen_kwargs)
        except Exception as exc:
            return CommandResult(status="failed", stderr=f"failed to start command: {exc}")

        job_handle = _WindowsJob(process)
        with self._active_lock:
            self._active_process = process
            self._active_job = job_handle
        if not job_handle.attached or not job_handle.resume(process):
            job_handle.terminate(process)
            try:
                process.wait(timeout=5)
            except Exception:
                pass
            job_handle.close()
            with self._active_lock:
                self._active_process = None
                self._active_job = None
            return CommandResult(status="failed", stderr="failed to secure command process")

        collector = _OutputCollector(self._maximum_output)
        readers = [
            threading.Thread(
                target=self._drain_stream,
                args=(process.stdout, "stdout", collector),
                daemon=True,
                name="CommandStdoutReader",
            ),
            threading.Thread(
                target=self._drain_stream,
                args=(process.stderr, "stderr", collector),
                daemon=True,
                name="CommandStderrReader",
            ),
        ]
        for reader in readers:
            reader.start()

        status: CommandStatus = "failed"
        try:
            deadline = time.monotonic() + job.timeout_seconds
            stopped = False
            timed_out = False
            while True:
                return_code = process.poll()
                if self._stop_requested.is_set():
                    stopped = True
                    if return_code is None:
                        self._terminate(process, job_handle)
                elif return_code is not None:
                    status = "succeeded" if return_code == 0 else "failed"
                    break
                elif time.monotonic() >= deadline:
                    timed_out = True
                    self._terminate(process, job_handle)
                if stopped or timed_out:
                    try:
                        return_code = process.wait(timeout=5)
                    except Exception:
                        return_code = process.poll()
                    status = "unknown" if stopped else "timed_out"
                    break
                try:
                    process.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            # Ensure the process is not left behind if an unusual wait error
            # occurs, then let reader threads drain the closed pipes.
            if process.poll() is None and self._stop_requested.is_set():
                self._terminate(process, job_handle)
            try:
                process.wait(timeout=5)
            except Exception:
                pass
            job_handle.close()
            for reader in readers:
                reader.join(timeout=5)
            with self._active_lock:
                self._active_process = None
                self._active_job = None

        stdout, stderr, truncated = collector.result()
        return_code = process.returncode
        return CommandResult(
            status=status,
            stdout=stdout,
            stderr=stderr,
            exit_code=return_code,
            output_truncated=truncated,
        )

    @staticmethod
    def _drain_stream(stream: Any, stream_name: str, collector: _OutputCollector) -> None:
        if stream is None:
            return
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                collector.append(stream_name, chunk)
        except Exception:
            # A killed process may close a pipe while a reader is inside read.
            pass

    @staticmethod
    def _terminate(process: subprocess.Popen[Any], job_handle: _WindowsJob) -> None:
        if os.name == "nt":
            job_handle.terminate(process)
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=1)
            except Exception:
                os.killpg(process.pid, signal.SIGKILL)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass

    def stop(self) -> None:
        self._stop_requested.set()
        with self._active_lock:
            process = self._active_process
            job_handle = self._active_job
        if process is not None and job_handle is not None:
            self._terminate(process, job_handle)
        elif process is not None:
            try:
                process.kill()
            except Exception:
                pass


class CommandWorker:
    """Claims, executes and acknowledges commands in a dedicated thread."""

    def __init__(
        self,
        db: Any,
        reporter: Any,
        agent_version: str,
        interval: int = COMMAND_POLL_INTERVAL,
        journal: CommandJournal | None = None,
        executor: CommandExecutor | None = None,
        enabled: bool = False,
        service_context: bool | None = None,
    ):
        self._db = db
        # Reporter.for_commands() returns a private requests.Session.  Fakes
        # used by tests generally do not implement it and are used directly.
        isolated = getattr(reporter, "for_commands", None)
        self._reporter = isolated() if callable(isolated) and reporter.__class__.__module__ == "agent.reporter" else reporter
        self._agent_version = agent_version
        self._interval = interval
        self._journal = journal or CommandJournal(db)
        self._executor = executor or CommandExecutor()
        self._enabled = bool(enabled)
        if self._enabled and service_context is not None:
            from .security_data import can_consume_remote_commands

            # The production service supplies its hosting context explicitly;
            # standalone/admin callers therefore cannot consume commands even
            # if they accidentally request ``enabled=True``.
            self._enabled = can_consume_remote_commands(
                service_context=service_context,
            )
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._run_lock = threading.Lock()

    @property
    def journal(self) -> CommandJournal:
        return self._journal

    def start(self) -> None:
        if not self._enabled:
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            daemon=True,
            name="CommandPollThread",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._executor.stop()
        thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=10)

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.run_once()
            except Exception as exc:
                # Never include command text or command output in service logs.
                logger.warning("remote command cycle failed: %s", exc)
            self._stop_event.wait(self._interval)

    @staticmethod
    def _unwrap_job(response: Any) -> Any:
        if not isinstance(response, dict):
            return None
        if response.get("success") is False:
            return None
        data = response.get("data")
        if isinstance(data, dict):
            # Production contract is data=<job|null>; accept data.job too so
            # an envelope introduced by an older server remains harmless.
            if "job" in data:
                return data.get("job")
            if "id" in data or "command_id" in data:
                return data
        return response.get("job")

    def flush_results(self) -> bool:
        sent_any = False
        for record in self._journal.pending_results():
            payload = {
                "receipt_token": record.receipt_token,
                "status": record.status,
                "stdout": record.stdout,
                "stderr": record.stderr,
                "exit_code": record.exit_code,
                "output_truncated": record.output_truncated,
            }
            try:
                response = self._reporter.send_command_result(record.command_id, payload)
                if not isinstance(response, dict) or response.get("success") is not True:
                    raise RuntimeError("command result rejected")
            except Exception as exc:
                self._journal.mark_attempt_failed(record.command_id, type(exc).__name__)
                continue
            self._journal.mark_acked(record.command_id)
            sent_any = True
        return sent_any

    def run_once(self) -> bool:
        """Run one flush/claim/execute cycle. Returns whether a job was claimed."""

        if not self._enabled:
            return False
        with self._run_lock:
            # Result acknowledgement is mandatory before the next claim.  If
            # it cannot be sent, leave the journal pending and do not execute.
            self.flush_results()
            if self._journal.has_pending_results() or self._stop_event.is_set():
                return False

            response = self._reporter.claim_command(self._agent_version)
            payload = self._unwrap_job(response)
            if payload is None:
                return False
            try:
                job = CommandJob.from_payload(payload)
            except CommandValidationError as exc:
                logger.warning("remote command claim rejected by agent validation: %s", exc)
                return False

            record = self._journal.begin(job)
            # Duplicate claims, including commands recovered as unknown after
            # restart, must never spawn a second process.
            if record.state != "started" or record.status is not None:
                return False
            if self._stop_event.is_set():
                self._journal.record_result(job.command_id, CommandResult(status="unknown"))
                return False

            self._journal.mark_running(job.command_id)
            try:
                result = self._executor.execute(job)
            except Exception as exc:
                # A durable failed result is safer than leaving a running
                # journal row that would block future claims indefinitely.
                result = CommandResult(status="failed", stderr=f"agent execution error: {type(exc).__name__}")
            self._journal.record_result(job.command_id, result)
            # Send immediately, but leave a durable pending result if network
            # delivery fails.  The next cycle retries only this result.
            self.flush_results()
            return True
