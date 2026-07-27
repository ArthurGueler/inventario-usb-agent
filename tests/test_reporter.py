# tests/test_reporter.py
"""
Testes do Reporter com mock HTTP (sem rede real).
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from agent.reporter import Reporter


FAKE_URL = 'http://localhost:3000'
FAKE_TOKEN = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678ab'


@pytest.fixture
def reporter():
    return Reporter(server_url=FAKE_URL, token=FAKE_TOKEN)


class TestReporterTokenHint:
    def test_hint_shows_last_8_chars(self, reporter):
        hint = reporter._token_hint()
        assert hint == f'...{FAKE_TOKEN[-8:]}'

    def test_short_token_masked(self):
        r = Reporter(server_url=FAKE_URL, token='short')
        assert r._token_hint() == '***'


class TestRegister:
    def test_register_posts_correct_payload(self, reporter):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {'success': True, 'machine_id': 'uuid-123', 'status': 'pending'}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(reporter._session, 'post', return_value=mock_resp) as mock_post:
            result = reporter.register(
                hostname='DESKTOP-TEST',
                agent_version='1.0.0',
                specs={'cpu': 'Intel i5', 'ram_gb': 8},
            )

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert '/api/agent/register' in call_kwargs[0][0]
        payload = call_kwargs[1]['json']
        assert payload['hostname'] == 'DESKTOP-TEST'
        assert payload['agent_version'] == '1.0.0'
        assert payload['specs']['cpu'] == 'Intel i5'
        assert result['machine_id'] == 'uuid-123'


class TestHeartbeat:
    def test_heartbeat_posts_to_correct_path(self, reporter):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {'success': True}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(reporter._session, 'post', return_value=mock_resp) as mock_post:
            reporter.heartbeat()

        url_called = mock_post.call_args[0][0]
        assert url_called == f'{FAKE_URL}/api/agent/heartbeat'


class TestSendUsbEvent:
    def test_send_event_posts_payload(self, reporter):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {'success': True, 'hash_id': 'abc123', 'alert': None}
        mock_resp.raise_for_status = MagicMock()

        event = {
            'event_type': 'connected',
            'event_time': '2026-04-01T14:00:00.000Z',
            'vid': '046D',
            'pid': 'C52B',
            'serial': '3&11583659&0',
            'friendly_name': 'Logitech USB Receiver',
            'pnp_device_id': 'USB\\VID_046D&PID_C52B\\3&11583659&0',
        }

        with patch.object(reporter._session, 'post', return_value=mock_resp) as mock_post:
            result = reporter.send_usb_event(event)

        url_called = mock_post.call_args[0][0]
        assert url_called == f'{FAKE_URL}/api/agent/usb-event'
        assert result['success'] is True
        assert result['alert'] is None

    def test_send_event_with_alert_response(self, reporter):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            'success': True,
            'hash_id': 'def456',
            'alert': {
                'id': 'alert-uuid',
                'type': 'relocated',
                'severity': 'info',
                'message': 'Dispositivo movido de DESK-A para DESK-B',
            }
        }
        mock_resp.raise_for_status = MagicMock()

        with patch.object(reporter._session, 'post', return_value=mock_resp):
            result = reporter.send_usb_event({'event_type': 'connected'})

        assert result['alert']['type'] == 'relocated'


class TestIsOnline:
    def test_online_when_tcp_connects(self, reporter):
        with patch('socket.create_connection') as mock_conn:
            mock_conn.return_value.__enter__ = MagicMock()
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            assert reporter.is_online() is True

    def test_offline_when_tcp_fails(self, reporter):
        with patch('socket.create_connection', side_effect=OSError('refused')):
            assert reporter.is_online() is False


class TestUsbSnapshot:
    def test_sync_usb_snapshot_posts_devices(self, reporter):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {'success': True, 'connected': 1, 'disconnected': 4}
        mock_resp.raise_for_status = MagicMock()
        devices = [{'vid': '1532', 'pid': '008A'}]

        with patch.object(reporter._session, 'post', return_value=mock_resp) as mock_post:
            result = reporter.sync_usb_snapshot(devices)

        assert mock_post.call_args[0][0] == f'{FAKE_URL}/api/agent/usb-snapshot'
        assert mock_post.call_args[1]['json'] == {'devices': devices}
        assert result['disconnected'] == 4


class TestRegisterNew:
    def test_register_new_without_token_header(self, reporter):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            'success': True,
            'machine_id': 'new-uuid',
            'token': 'newtoken123456789012345678901234',
            'status': 'pending',
        }
        mock_resp.raise_for_status = MagicMock()

        with patch('requests.post', return_value=mock_resp) as mock_post:
            result = reporter.register_new(
                hostname='DESK-NEW',
                mac_address='AA:BB:CC:DD:EE:FF',
                bios_serial='PF2BXX12',
                agent_version='1.3.20',
                specs={'hostname': 'DESK-NEW', 'ram_gb': 16},
                registration_reason='installation',
            )

        call_kwargs = mock_post.call_args[1]
        # Não deve ter X-Agent-Token (rota pública)
        assert 'X-Agent-Token' not in call_kwargs.get('headers', {})
        assert call_kwargs['json']['agent_version'] == '1.3.20'
        assert call_kwargs['json']['specs']['ram_gb'] == 16
        assert call_kwargs['json']['registration_reason'] == 'installation'
        assert result['machine_id'] == 'new-uuid'
