import base64
import io
import subprocess
import threading

import pytest

from agent.commands import (
    MAX_OUTPUT_BYTES,
    CommandExecutor,
    CommandJob,
    CommandJournal,
    CommandResult,
    CommandValidationError,
    CommandWorker,
    _OutputCollector,
    build_command_argv,
)


def job(**changes):
    values = {
        "id": "job-1",
        "receipt_token": "receipt-1",
        "shell": "powershell",
        "command": "Write-Output ok",
        "timeout_seconds": 10,
    }
    values.update(changes)
    return CommandJob.from_payload(values)


def test_builds_explicit_cmd_and_encoded_powershell_argv():
    powershell = build_command_argv("powershell", "Write-Output 'olá'", {"SystemRoot": r"C:\Windows"})
    assert powershell[0].endswith(r"System32\WindowsPowerShell\v1.0\powershell.exe") or powershell[0].endswith(
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    assert powershell[1:5] == ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand"]
    decoded = base64.b64decode(powershell[5]).decode("utf-16le")
    assert decoded == "Write-Output 'olá'"

    cmd = build_command_argv("cmd", "whoami", {"ComSpec": r"C:\Windows\System32\cmd.exe"})
    assert cmd == [r"C:\Windows\System32\cmd.exe", "/d", "/s", "/c", "whoami"]


@pytest.mark.parametrize(
    "changes",
    [
        {"shell": "bash"},
        {"timeout_seconds": 9},
        {"timeout_seconds": 301},
        {"timeout_seconds": True},
        {"command": ""},
        {"command": "x" * (16 * 1024 + 1)},
        {"shell": "cmd", "command": "x" * 8192},
    ],
)
def test_rejects_invalid_job_contract(changes):
    with pytest.raises(CommandValidationError):
        job(**changes)


class FakeProcess:
    def __init__(self, stdout=b"", stderr=b"", running=False):
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.pid = 999999
        self.returncode = None if running else 0
        self.running = running

    def poll(self):
        return None if self.running else self.returncode

    def wait(self, timeout=None):
        if self.running:
            raise subprocess.TimeoutExpired("fake", timeout)
        return self.returncode

    def kill(self):
        self.running = False
        self.returncode = -9


class FakeJob:
    attached = True

    def __init__(self, process):
        self.process = process

    @staticmethod
    def resume(process):
        return True

    @staticmethod
    def terminate(process):
        process.kill()

    @staticmethod
    def close():
        pass


def test_executor_bounds_combined_output(monkeypatch):
    process = FakeProcess(stdout=b"o" * MAX_OUTPUT_BYTES, stderr=b"e" * 1024)
    executor = CommandExecutor(
        environ={"ComSpec": r"C:\Windows\System32\cmd.exe"},
        popen_factory=lambda argv, **kwargs: process,
        maximum_output=MAX_OUTPUT_BYTES,
    )
    monkeypatch.setattr("agent.commands._WindowsJob", FakeJob)
    result = executor.execute(job(shell="cmd", command="echo output"))
    assert result.status == "succeeded"
    assert result.output_truncated is True
    assert len((result.stdout + result.stderr).encode("utf-8")) <= MAX_OUTPUT_BYTES


def test_executor_marks_timeout_and_stop(monkeypatch):
    process = FakeProcess(running=True)
    executor = CommandExecutor(environ={"ComSpec": r"C:\Windows\System32\cmd.exe"}, popen_factory=lambda argv, **kwargs: process)
    process2 = FakeProcess(running=True)
    executor2 = CommandExecutor(environ={"ComSpec": r"C:\Windows\System32\cmd.exe"}, popen_factory=lambda argv, **kwargs: process2)
    monkeypatch.setattr("agent.commands._WindowsJob", FakeJob)
    clock = iter([0.0, 11.0])
    monkeypatch.setattr("agent.commands.time.monotonic", lambda: next(clock))
    result = executor.execute(job(shell="cmd", command="timeout"))
    assert result.status == "timed_out"
    assert process.returncode == -9

    monkeypatch.setattr("agent.commands.time.monotonic", lambda: 0.0)
    result_holder = []
    thread = threading.Thread(target=lambda: result_holder.append(executor2.execute(job(shell="cmd", command="stop"))))
    thread.start()
    for _ in range(100):
        if executor2._active_process is not None:
            break
    executor2.stop()
    thread.join(timeout=2)
    assert result_holder and result_holder[0].status == "unknown"


class FakeReporter:
    def __init__(self, job_payload):
        self.job_payload = job_payload
        self.claims = 0
        self.results = 0
        self.fail_result_once = True

    def claim_command(self, agent_version):
        self.claims += 1
        return {"success": True, "data": self.job_payload}

    def send_command_result(self, command_id, result):
        self.results += 1
        if self.fail_result_once:
            self.fail_result_once = False
            raise OSError("offline")
        return {"success": True}


class FakeExecutor:
    def __init__(self):
        self.calls = 0

    def execute(self, job):
        self.calls += 1
        return CommandResult(status="succeeded", stdout="ok", exit_code=0)

    def stop(self):
        pass


def test_result_retry_never_reruns_command(tmp_path):
    payload = {
        "id": "job-retry",
        "receipt_token": "receipt-retry",
        "shell": "cmd",
        "command": "whoami",
        "timeout_seconds": 10,
    }
    reporter = FakeReporter(payload)
    executor = FakeExecutor()
    journal = CommandJournal(journal_path=tmp_path / "commands.sqlite3")
    worker = CommandWorker(
        db=tmp_path / "agent.db",
        reporter=reporter,
        agent_version="1.3.25",
        journal=journal,
        executor=executor,
        enabled=True,
    )

    assert worker.run_once() is True
    assert executor.calls == 1
    assert journal.has_pending_results() is True
    assert worker.run_once() is False
    assert executor.calls == 1
    assert reporter.results == 2


def test_started_command_recovers_as_unknown_without_rerun(tmp_path):
    payload = {
        "id": "job-crash",
        "receipt_token": "receipt-crash",
        "shell": "cmd",
        "command": "whoami",
        "timeout_seconds": 10,
    }
    path = tmp_path / "commands.sqlite3"
    first = CommandJournal(journal_path=path)
    first.begin(CommandJob.from_payload(payload))

    reporter = FakeReporter(payload)
    reporter.fail_result_once = False
    executor = FakeExecutor()
    recovered = CommandJournal(journal_path=path)
    record = recovered.get("job-crash")
    assert record.status == "unknown"
    assert record.state == "result_pending"

    worker = CommandWorker(
        db=tmp_path / "agent.db",
        reporter=reporter,
        agent_version="1.3.25",
        journal=recovered,
        executor=executor,
        enabled=True,
    )
    worker.run_once()
    assert executor.calls == 0
    assert recovered.get("job-crash").state == "acked"
