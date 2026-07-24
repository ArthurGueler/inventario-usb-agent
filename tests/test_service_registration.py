from unittest.mock import MagicMock, patch

from agent.service import AGENT_VERSION, AgentCore, DEFAULT_SERVER_URL


def test_ensure_base_config_recovers_missing_installer_config():
    db = MagicMock()
    db.server_url = None
    db.token = None
    core = AgentCore(db)

    core._ensure_base_config()

    assert db.server_url == DEFAULT_SERVER_URL
    assert isinstance(db.token, str)
    assert len(db.token) == 64


def test_recovery_sends_complete_registration_payload():
    db = MagicMock()
    db.collaborator_name = 'Pessoa Teste'
    reporter = MagicMock()
    reporter.register_new.return_value = {
        'data': {'machine_id': 'machine-123', 'status': 'pending'},
    }
    core = AgentCore(db)
    core._reporter = reporter
    specs = {
        'hostname': 'DESK-NEW',
        'mac_address': 'AA:BB:CC:DD:EE:FF',
        'bios_serial': 'SERIAL-123',
        'ram_gb': 16,
    }

    assert core._recover_registration(specs, 'DESK-NEW') is True

    reporter.register_new.assert_called_once_with(
        hostname='DESK-NEW',
        mac_address='AA:BB:CC:DD:EE:FF',
        bios_serial='SERIAL-123',
        collaborator_name='Pessoa Teste',
        anydesk_id=None,
        agent_version=AGENT_VERSION,
        specs=specs,
        registration_reason='recovery',
    )
    assert db.machine_id == 'machine-123'


def test_initial_register_recovers_when_machine_id_is_missing():
    db = MagicMock()
    db.machine_id = None
    core = AgentCore(db)
    core._reporter = MagicMock()
    specs = {'hostname': 'DESK-NEW'}

    with patch('agent.service.capture_machine_specs', return_value=specs), \
         patch.object(core, '_recover_registration', return_value=True) as recover:
        core._do_register()

    recover.assert_called_once_with(specs, 'DESK-NEW')
    core._reporter.register.assert_not_called()


def test_recovery_rejects_response_without_machine_id():
    db = MagicMock()
    db.machine_id = None
    reporter = MagicMock()
    reporter.register_new.return_value = {'data': {'status': 'pending'}}
    core = AgentCore(db)
    core._reporter = reporter

    assert core._recover_registration({'hostname': 'DESK-NEW'}, 'DESK-NEW') is False
    assert db.machine_id is None
