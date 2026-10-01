"""Benign Windows integration checks; never contact the inventory server."""
import sys
import ctypes
import time
import uuid

import pytest

from agent.commands import CommandExecutor, CommandJob

pytestmark = pytest.mark.skipif(sys.platform != 'win32', reason='Windows process integration')


def job(shell, command):
    return CommandJob.from_payload({
        'id': str(uuid.uuid4()), 'receipt_token': 'a' * 64,
        'shell': shell, 'command': command, 'timeout_seconds': 10,
    })


@pytest.mark.parametrize('shell,command', [
    ('powershell', "Write-Output 'inventory-command-smoke'"),
    ('cmd', 'echo inventory-command-smoke'),
])
def test_windows_shell_execution(shell, command, tmp_path):
    result = CommandExecutor(cwd=tmp_path).execute(job(shell, command))
    assert result.status == 'succeeded', result.stderr
    assert result.exit_code == 0
    assert 'inventory-command-smoke' in result.stdout


def test_windows_timeout_terminates_child(tmp_path):
    # Explicit non-ShellExecute creation makes the child part of the job tree.
    command = r"""
$s = New-Object System.Diagnostics.ProcessStartInfo
$s.FileName = "$env:SystemRoot\System32\cmd.exe"
$s.Arguments = '/d /c ping -n 60 127.0.0.1 > nul'
$s.UseShellExecute = $false
$s.CreateNoWindow = $true
$p = [System.Diagnostics.Process]::Start($s)
Write-Output $p.Id
Start-Sleep -Seconds 60
"""
    result = CommandExecutor(cwd=tmp_path).execute(job('powershell', command))
    assert result.status == 'timed_out', result.stderr
    child_pid = int(result.stdout.strip().splitlines()[0])
    for _ in range(30):
        if not pid_is_running(child_pid):
            break
        time.sleep(0.1)
    assert not pid_is_running(child_pid), 'Owned child survived the timeout'


def pid_is_running(pid):
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:
            return False
        raise ctypes.WinError(error)
    try:
        code = wintypes.DWORD()
        if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        return code.value == 259
    finally:
        kernel.CloseHandle(handle)
