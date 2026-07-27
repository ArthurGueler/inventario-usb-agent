from agent.updater import Updater


class FakeReporter:
    def __init__(self, response):
        self.response = response

    def check_version(self):
        return self.response


def test_check_once_unwraps_standard_api_response(monkeypatch):
    reporter = FakeReporter({
        'success': True,
        'data': {
            'needs_update': True,
            'current_version': '1.3.18',
            'download_url': 'https://example.test/usb_agent.exe',
            'sha256': 'abc123',
        },
    })
    updater = Updater(reporter)
    called = []
    monkeypatch.setattr(updater, '_apply_update', lambda url, sha: called.append((url, sha)))

    updater._check_once()

    assert called == [('https://example.test/usb_agent.exe', 'abc123')]


def test_check_once_still_accepts_legacy_flat_response(monkeypatch):
    reporter = FakeReporter({
        'needs_update': True,
        'current_version': '1.3.18',
        'download_url': '/api/agent/download',
    })
    updater = Updater(reporter)
    called = []
    monkeypatch.setattr(updater, '_apply_update', lambda url, sha: called.append((url, sha)))

    updater._check_once()

    assert called == [('/api/agent/download', None)]


def test_windows_replace_script_stops_all_agent_processes_and_retries(monkeypatch, tmp_path):
    updater = Updater(FakeReporter({}))
    current = tmp_path / 'usb_agent.exe'
    incoming = tmp_path / 'usb_agent_update.exe'
    current.write_bytes(b'old')
    incoming.write_bytes(b'new')
    monkeypatch.setattr('subprocess.Popen', lambda *args, **kwargs: None)

    updater._schedule_replace_windows(current, incoming)

    script = (tmp_path / '_update_replace.bat').read_text(encoding='utf-8')
    assert 'sc stop IN9USBAgent' in script
    assert 'taskkill /F /IM usb_agent.exe' in script
    assert ':retry' in script
    assert 'apos 30 tentativas' in script
    assert 'sc start IN9USBAgent' in script
    assert str(current.with_suffix('.bak')) in script
