from pathlib import Path
import sys
from unittest.mock import MagicMock

import pytest
import requests

from agent import security_data
from agent.commands import CommandJournal, CommandWorker
from agent.local_db import LocalDB
from agent.reporter import Reporter


class RecordingAcl:
    def __init__(self):
        self.applied = []
        self.validated = []

    def apply(self, path):
        self.applied.append(Path(path))

    def validate(self, path):
        self.validated.append(Path(path))


class FailingAcl:
    def apply(self, path):
        raise PermissionError('denied')

    def validate(self, path):
        raise AssertionError('must not validate after apply failure')


def test_canonical_server_url_accepts_only_production_origin():
    assert security_data.canonical_server_url(
        'https://inventario.in9automacao.com.br/'
    ) == security_data.EXPECTED_SERVER_URL
    for value in (
        'http://inventario.in9automacao.com.br',
        'https://inventario.in9automacao.com.br.evil.test',
        'https://inventario.in9automacao.com.br:8443',
        'https://inventario.in9automacao.com.br/path',
        'https://user:pass@inventario.in9automacao.com.br',
    ):
        with pytest.raises(security_data.SecurityDataError):
            security_data.canonical_server_url(value)


def test_secure_data_rejects_reparse_entry_before_acl_changes(tmp_path, monkeypatch):
    root = tmp_path / 'data'
    bad = root / 'junction-like-entry'
    bad.mkdir(parents=True)
    backend = RecordingAcl()
    original = security_data._path_has_reparse_attribute
    monkeypatch.setattr(
        security_data,
        '_path_has_reparse_attribute',
        lambda path: Path(path) == bad or original(path),
    )

    with pytest.raises(security_data.SecurityDataError):
        security_data.ensure_secure_data_dir(root, backend=backend)
    assert backend.applied == []


def test_secure_data_fails_closed_when_acl_repair_fails(tmp_path):
    with pytest.raises(security_data.SecurityDataError):
        security_data.ensure_secure_data_dir(
            tmp_path / 'data', backend=FailingAcl()
        )


def test_secure_data_repairs_and_verifies_database_sidecars(tmp_path):
    root = tmp_path / 'data'
    root.mkdir()
    for name in ('agent.db', 'agent.db.commands.sqlite3', 'agent.db.commands.sqlite3-wal', 'agent.db.commands.sqlite3-shm'):
        (root / name).write_bytes(b'')
    backend = RecordingAcl()

    security_data.ensure_secure_data_dir(root, backend=backend)

    assert set(backend.applied) == set(backend.validated)
    assert root / 'agent.db.commands.sqlite3-wal' in backend.validated
    assert root / 'agent.db.commands.sqlite3-shm' in backend.validated


def test_local_db_secure_mode_protects_before_and_after_schema(tmp_path):
    backend = RecordingAcl()
    db = LocalDB(
        db_path=tmp_path / 'data' / 'agent.db',
        require_secure=True,
        security_backend=backend,
    )
    assert db.path.exists()
    assert backend.applied
    db.validate_security()


def test_local_db_security_repairs_sidecars_created_after_initialization(tmp_path):
    backend = RecordingAcl()
    db = LocalDB(
        db_path=tmp_path / 'data' / 'agent.db',
        require_secure=True,
        security_backend=backend,
    )
    sidecar = db.path.with_name(f'{db.path.name}-wal')
    sidecar.write_bytes(b'wal')

    db.validate_security()

    assert sidecar in backend.applied
    assert sidecar in backend.validated


def test_secure_command_journal_repairs_sidecars_before_reconnect(tmp_path):
    backend = RecordingAcl()
    db = LocalDB(
        db_path=tmp_path / 'data' / 'agent.db',
        require_secure=True,
        security_backend=backend,
    )
    journal = CommandJournal(db_or_path=db)
    sidecar = journal.path.with_name(f'{journal.path.name}-shm')
    sidecar.write_bytes(b'shm')

    with journal._connect() as conn:
        conn.execute('SELECT 1')

    assert sidecar in backend.applied
    assert sidecar in backend.validated


def test_default_db_path_uses_dedicated_data_directory(monkeypatch):
    from agent import local_db

    monkeypatch.setattr(sys, 'platform', 'linux')
    path = local_db._default_db_path()

    assert path.name == 'agent.db'
    assert path.parent.name == 'data'


def test_enable_security_privileges_enables_owner_privileges():
    calls = []

    class FakeApi:
        @staticmethod
        def GetCurrentProcess():
            return 'process'

        @staticmethod
        def CloseHandle(token):
            calls.append(('close', token))

    class FakeCon:
        TOKEN_ADJUST_PRIVILEGES = 0x20
        TOKEN_QUERY = 0x08
        SE_PRIVILEGE_ENABLED = 0x02

    class FakeSecurity:
        @staticmethod
        def OpenProcessToken(process, access):
            calls.append(('open', process, access))
            return 'token'

        @staticmethod
        def LookupPrivilegeValue(system, name):
            calls.append(('lookup', system, name))
            return f'luid:{name}'

        @staticmethod
        def AdjustTokenPrivileges(token, disable_all, privileges):
            calls.append(('adjust', token, disable_all, privileges))

    security_data.enable_security_privileges(
        security_module=FakeSecurity,
        api_module=FakeApi,
        con_module=FakeCon,
    )

    assert ('open', 'process', 0x28) in calls
    assert [call[2] for call in calls if call[0] == 'lookup'] == [
        'SeRestorePrivilege',
        'SeTakeOwnershipPrivilege',
    ]
    assert len([call for call in calls if call[0] == 'adjust']) == 2
    assert ('close', 'token') in calls


def test_enable_security_privileges_fails_closed_on_adjust_error():
    class FakeApi:
        GetCurrentProcess = staticmethod(lambda: 'process')
        CloseHandle = staticmethod(lambda token: None)

    class FakeCon:
        TOKEN_ADJUST_PRIVILEGES = 0x20
        TOKEN_QUERY = 0x08
        SE_PRIVILEGE_ENABLED = 0x02

    class FakeSecurity:
        OpenProcessToken = staticmethod(lambda process, access: 'token')
        LookupPrivilegeValue = staticmethod(lambda system, name: name)

        @staticmethod
        def AdjustTokenPrivileges(token, disable_all, privileges):
            raise PermissionError('not assigned')

    with pytest.raises(security_data.SecurityDataError):
        security_data.enable_security_privileges(
            security_module=FakeSecurity,
            api_module=FakeApi,
            con_module=FakeCon,
        )


def test_enable_security_privileges_rejects_not_all_assigned():
    class FakeApi:
        _last_error = 0

        @staticmethod
        def GetCurrentProcess():
            return 'process'

        @classmethod
        def SetLastError(cls, value):
            cls._last_error = value

        @classmethod
        def GetLastError(cls):
            return cls._last_error

        @staticmethod
        def CloseHandle(token):
            pass

    class FakeCon:
        TOKEN_ADJUST_PRIVILEGES = 0x20
        TOKEN_QUERY = 0x08
        SE_PRIVILEGE_ENABLED = 0x02

    class FakeSecurity:
        @staticmethod
        def OpenProcessToken(process, access):
            return 'token'

        @staticmethod
        def LookupPrivilegeValue(system, name):
            return name

        @staticmethod
        def AdjustTokenPrivileges(token, disable_all, privileges):
            FakeApi._last_error = security_data.ERROR_NOT_ALL_ASSIGNED

    with pytest.raises(security_data.SecurityDataError):
        security_data.enable_security_privileges(
            security_module=FakeSecurity,
            api_module=FakeApi,
            con_module=FakeCon,
        )


def test_late_security_enrollment_starts_remote_features_once(monkeypatch, tmp_path):
    import agent.service as service_module

    starts = {'updater': 0, 'packages': 0, 'commands': 0}

    class FakeWorker:
        def __init__(self, kind, **kwargs):
            self.kind = kind

        def start(self):
            starts[self.kind] += 1

        def stop(self):
            pass

    class FakeUpdater(FakeWorker):
        def __init__(self, **kwargs):
            super().__init__('updater', **kwargs)

    class FakePackages(FakeWorker):
        def __init__(self, **kwargs):
            super().__init__('packages', **kwargs)

    class FakeCommands(FakeWorker):
        def __init__(self, **kwargs):
            super().__init__('commands', **kwargs)

    monkeypatch.setattr(service_module, 'Updater', FakeUpdater)
    monkeypatch.setattr(service_module, 'PackageManager', FakePackages)
    monkeypatch.setattr(service_module, 'CommandWorker', FakeCommands)
    monkeypatch.setattr(service_module, 'can_consume_remote_commands', lambda **kwargs: True)

    core = service_module.AgentCore(LocalDB(db_path=tmp_path / 'agent.db'), service_context=True)
    core._reporter = MagicMock()
    core._try_install_anydesk = MagicMock()

    # Startup had no enrollment; the first gate is intentionally a no-op.
    assert core._start_remote_features(core._reporter) is False

    # A late enrollment ACK enables the workers, and repeated heartbeats do
    # not construct or start another instance.
    core._security_ready = True
    assert core._start_remote_features(core._reporter) is True
    assert core._start_remote_features(core._reporter) is True
    assert starts == {'updater': 1, 'packages': 1, 'commands': 1}


def test_reporter_rejects_noncanonical_origin_before_http():
    with pytest.raises(security_data.SecurityDataError):
        Reporter(
            'http://inventario.in9automacao.com.br',
            'token',
            enforce_origin=True,
        )


def test_reporter_disables_redirects_and_posts_security_enroll():
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        'success': True,
        'data': {'security_enrolled': True},
    }
    response.raise_for_status.return_value = None
    session = MagicMock()
    session.post.return_value = response
    session.headers = {}
    reporter = Reporter(
        security_data.EXPECTED_SERVER_URL,
        'old-token',
        session=session,
        enforce_origin=True,
    )

    reporter.security_enroll('1.3.26', 'new-token')

    kwargs = session.post.call_args.kwargs
    assert kwargs['allow_redirects'] is False
    assert session.post.call_args.args[0].endswith('/api/agent/security-enroll')
    assert kwargs['json']['capabilities'] == ['secure_data_acl_v1']


def test_command_worker_disabled_does_not_claim(tmp_path):
    reporter = MagicMock()
    journal = CommandJournal(journal_path=tmp_path / 'commands.sqlite3')
    worker = CommandWorker(
        db=tmp_path / 'agent.db',
        reporter=reporter,
        agent_version='1.3.26',
        journal=journal,
    )

    assert worker.run_once() is False
    reporter.claim_command.assert_not_called()


def test_command_worker_nonservice_context_does_not_claim(tmp_path):
    reporter = MagicMock()
    journal = CommandJournal(journal_path=tmp_path / 'commands.sqlite3')
    worker = CommandWorker(
        db=tmp_path / 'agent.db',
        reporter=reporter,
        agent_version='1.3.26',
        journal=journal,
        enabled=True,
        service_context=False,
    )

    assert worker.run_once() is False
    reporter.claim_command.assert_not_called()


def test_tray_pending_events_never_opens_local_db(monkeypatch):
    from agent import tray

    class DeniedLocalDB:
        def __init__(self):
            raise AssertionError('tray must not open LocalDB')

    monkeypatch.setattr('agent.local_db.LocalDB', DeniedLocalDB)
    assert tray._pending_events() == 0


def test_remote_commands_require_local_system_context(monkeypatch):
    assert security_data.can_consume_remote_commands(service_context=False) is False
    monkeypatch.setattr(security_data, 'is_local_system', lambda: False)
    assert security_data.can_consume_remote_commands(service_context=True) is False
