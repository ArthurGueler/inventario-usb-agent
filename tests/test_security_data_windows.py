"""Real ACL repair on disposable data only; no service or network changes."""
import os

import pytest

from agent.security_data import ensure_secure_data_dir, is_elevated, validate_secure_data_dir


@pytest.mark.skipif(os.name != 'nt', reason='Windows ACL integration')
def test_windows_repairs_legacy_acl_before_using_sqlite(tmp_path):
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        import win32security as security
    else:
        security = pytest.importorskip('win32security')
    if not is_elevated():
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            pytest.fail('Release validation requires an elevated Windows runner')
        pytest.skip('ACL ownership repair requires an elevated Windows test runner')
    from agent.local_db import LocalDB

    root = tmp_path / 'disposable-agent-data'
    root.mkdir()
    legacy = security.ACL()
    legacy.AddAccessAllowedAceEx(
        security.ACL_REVISION, 3, 0x1F01FF,
        security.ConvertStringSidToSid('S-1-1-0'),
    )
    security.SetNamedSecurityInfo(
        str(root), security.SE_FILE_OBJECT,
        security.DACL_SECURITY_INFORMATION | 0x80000000,
        None, None, legacy, None,
    )
    (root / 'existing.txt').write_text('not-a-credential', encoding='utf-8')
    ensure_secure_data_dir(root)
    validate_secure_data_dir(root)
    db = LocalDB(root / 'agent.db', require_secure=True)
    db.set_config('test-only', 'safe')
    assert db.get_config('test-only') == 'safe'
    ensure_secure_data_dir(root)
    validate_secure_data_dir(root)
    for entry in (root, root / 'existing.txt', root / 'agent.db'):
        descriptor = security.GetNamedSecurityInfo(
            str(entry), security.SE_FILE_OBJECT,
            security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION,
        )
        assert security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) == 'S-1-5-18'
        dacl = descriptor.GetSecurityDescriptorDacl()
        assert dacl.GetAceCount() == 2
        assert {
            security.ConvertSidToStringSid(dacl.GetAce(i)[2])
            for i in range(dacl.GetAceCount())
        } == {'S-1-5-18', 'S-1-5-32-544'}
