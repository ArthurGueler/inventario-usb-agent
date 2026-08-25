import zipfile

import pytest

from agent.packages import PackageManager, Target, rewrite_config


# Amostra real do web_connection.l4j.ini de uma máquina configurada
L4J_INI = """-Xms256m
-Xmx256m
-Dempresa=sankhya
-Dporta=9096
-DskwHost=https://antigo.exemplo.com.br/mge
-DintegrBalanca="Digitron"
-DbalancaPort=COM9
-XX:+UseTLAB
"""


class FakeReporter:
    def __init__(self, response=None):
        self.response = response or {}
        self.health = []

    def list_packages(self):
        return self.response

    def report_health(self, code, level='info', message=None, context=None):
        self.health.append((code, level, message, context))


# =============================================================================
# rewrite_config
# =============================================================================

def test_rewrite_config_preserva_config_de_hardware_local():
    out = rewrite_config(L4J_INI, {
        'skwHost': 'https://fioforte.sankhyacloud.com.br/mge',
        'porta': 9096,
    })

    assert '-DskwHost=https://fioforte.sankhyacloud.com.br/mge' in out
    assert '-Dporta=9096' in out
    # a balança da máquina não pode ser sobrescrita
    assert '-DbalancaPort=COM9' in out
    assert '-DintegrBalanca="Digitron"' in out
    assert '-Xms256m' in out
    assert '-XX:+UseTLAB' in out
    assert 'antigo.exemplo.com.br' not in out


def test_rewrite_config_acrescenta_chave_ausente():
    out = rewrite_config(L4J_INI, {'portaWebSocket': 9098})
    assert '-DportaWebSocket=9098' in out
    assert out.count('-DportaWebSocket=') == 1


def test_rewrite_config_nao_confunde_chaves_com_prefixo_comum():
    # -Dporta= e -DportaWebSocket= compartilham prefixo; cada um tem que ir
    # para a sua própria linha
    out = rewrite_config(L4J_INI, {'porta': 9096, 'portaWebSocket': 9098})
    assert '-Dporta=9096' in out
    assert '-DportaWebSocket=9098' in out


def test_rewrite_config_formato_properties():
    original = 'versao=1.0\nporta=9096\nminHeap=-Xms512m\n'
    out = rewrite_config(original, {'porta': 9099}, fmt='properties')
    assert 'porta=9099' in out
    assert 'minHeap=-Xms512m' in out
    assert 'versao=1.0' in out


def test_rewrite_config_preserva_crlf():
    out = rewrite_config('-Dporta=1\r\n-Dx=2\r\n', {'porta': 9096})
    assert '\r\n' in out
    assert '-Dporta=9096\r\n' in out


def test_rewrite_config_idempotente():
    values = {'skwHost': 'https://fioforte.sankhyacloud.com.br/mge'}
    once = rewrite_config(L4J_INI, values)
    twice = rewrite_config(once, values)
    assert once == twice


# =============================================================================
# Manifesto
# =============================================================================

@pytest.mark.parametrize('resp', [
    [{'name': 'a'}],
    {'packages': [{'name': 'a'}]},
    {'data': {'packages': [{'name': 'a'}]}},
    {'success': True, 'data': [{'name': 'a'}]},
])
def test_unwrap_aceita_todos_os_formatos_de_resposta(resp):
    assert PackageManager._unwrap(resp) == [{'name': 'a'}]


def test_unwrap_lida_com_resposta_vazia():
    assert PackageManager._unwrap({}) == []
    assert PackageManager._unwrap({'data': {}}) == []


def test_check_once_nao_explode_quando_servidor_nao_tem_a_rota():
    class Broken:
        def list_packages(self):
            raise RuntimeError('404 Not Found')

    PackageManager(Broken()).check_once()  # não deve levantar


def test_check_once_reporta_falha_de_pacote():
    reporter = FakeReporter({'packages': [{'name': 'quebrado'}]})  # sem extract_to
    PackageManager(reporter).check_once()

    assert reporter.health
    code, level, _message, context = reporter.health[0]
    assert code == 'package_failed'
    assert level == 'error'
    assert context == {'package': 'quebrado'}


# =============================================================================
# Download
# =============================================================================

def test_download_recusa_pacote_sem_sha256():
    manager = PackageManager(FakeReporter())
    with pytest.raises(ValueError, match='sha256'):
        manager._download({'payload_url': 'https://exemplo.test/p.zip'})


# =============================================================================
# Extração
# =============================================================================

def _zip_with(tmp_path, members):
    path = tmp_path / 'payload.zip'
    with zipfile.ZipFile(path, 'w') as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return path


def test_extract_bloqueia_zip_slip(tmp_path):
    payload = _zip_with(tmp_path, {'../fora.txt': 'malicioso'})
    dest = tmp_path / 'destino'
    manager = PackageManager(FakeReporter())

    with pytest.raises(ValueError, match='fora do destino'):
        manager._extract(payload, Target(dest, None))

    assert not (tmp_path / 'fora.txt').exists()


def test_extract_grava_conteudo_legitimo(tmp_path):
    payload = _zip_with(tmp_path, {'Sankhya web/executar/web_connection.exe': 'MZ'})
    dest = tmp_path / 'destino'

    PackageManager(FakeReporter())._extract(payload, Target(dest, None))

    assert (dest / 'Sankhya web' / 'executar' / 'web_connection.exe').read_text() == 'MZ'


# =============================================================================
# Alvos e detecção
# =============================================================================

def test_targets_machine_wide(tmp_path):
    manager = PackageManager(FakeReporter())
    targets = manager.targets({'extract_to': str(tmp_path)})
    assert targets == [Target(tmp_path, None)]


def test_targets_exige_extract_to():
    with pytest.raises(ValueError, match='extract_to'):
        PackageManager(FakeReporter()).targets({'name': 'x'})


def test_is_installed_usa_detect_path(tmp_path):
    exe = tmp_path / 'app.exe'
    manager = PackageManager(FakeReporter())
    pkg = {'extract_to': str(tmp_path), 'detect_path': str(exe)}

    assert manager.is_installed(pkg, Target(tmp_path, None)) is False
    exe.write_text('MZ')
    assert manager.is_installed(pkg, Target(tmp_path, None)) is True


# =============================================================================
# Config aplicada num alvo
# =============================================================================

def test_apply_config_grava_backup_uma_unica_vez(tmp_path):
    ini = tmp_path / 'web_connection.l4j.ini'
    ini.write_text(L4J_INI, encoding='latin-1')
    pkg = {'config_files': [{
        'path': str(ini),
        'format': 'jvm_args',
        'values': {'skwHost': 'https://fioforte.sankhyacloud.com.br/mge'},
    }]}
    manager = PackageManager(FakeReporter())

    manager._apply_config(pkg, Target(tmp_path, None))
    backup = ini.with_suffix(ini.suffix + '.in9bak')
    assert backup.exists()
    assert 'antigo.exemplo.com.br' in backup.read_text(encoding='latin-1')
    assert 'fioforte.sankhyacloud.com.br' in ini.read_text(encoding='latin-1')

    # segunda passada não muda nada e não sobrescreve o backup original
    manager._apply_config(pkg, Target(tmp_path, None))
    assert 'antigo.exemplo.com.br' in backup.read_text(encoding='latin-1')


# =============================================================================
# Firewall
#
# O bug que motivou estes testes: uma regra só de porta NÃO suprime o diálogo
# "Permitir acesso" do Windows. O diálogo é por PROGRAMA, e confirmá-lo exige
# senha de admin — o que trava o usuário comum no logon.
# =============================================================================

def _capture_firewall(monkeypatch, pkg, targets):
    monkeypatch.setattr('agent.packages.sys.platform', 'win32')
    manager = PackageManager(FakeReporter())
    scripts = []
    monkeypatch.setattr(manager, '_powershell', lambda script: scripts.append(script))
    manager._apply_firewall(pkg, targets)
    return scripts


def test_firewall_cria_regra_por_programa_em_cada_perfil(monkeypatch, tmp_path):
    perfis = []
    for nome in ('ana', 'bruno'):
        exe = tmp_path / nome / 'app' / 'javaw.exe'
        exe.parent.mkdir(parents=True)
        exe.write_text('MZ')
        perfis.append(Target(tmp_path / nome, tmp_path / nome))

    pkg = {'firewall': [{
        'name': 'Sankhya WC',
        'ports': [9096, 9098],
        'program': '%USERPROFILE%\\app\\javaw.exe',
    }]}

    scripts = _capture_firewall(monkeypatch, pkg, perfis)

    assert len(scripts) == 2
    juntos = ' '.join(scripts)
    assert 'Sankhya WC - ana' in juntos
    assert 'Sankhya WC - bruno' in juntos
    assert juntos.count('-Program') == 2
    assert '-LocalPort 9096,9098' in juntos


def test_firewall_pula_perfil_sem_o_binario(monkeypatch, tmp_path):
    presente = tmp_path / 'ana'
    (presente / 'app').mkdir(parents=True)
    (presente / 'app' / 'javaw.exe').write_text('MZ')
    ausente = tmp_path / 'bruno'
    ausente.mkdir()

    pkg = {'firewall': [{
        'name': 'Sankhya WC',
        'ports': [9096],
        'program': '%USERPROFILE%\\app\\javaw.exe',
    }]}
    targets = [Target(presente, presente), Target(ausente, ausente)]

    scripts = _capture_firewall(monkeypatch, pkg, targets)

    assert len(scripts) == 1
    assert 'ana' in scripts[0]


def test_firewall_sem_program_cria_regra_unica_de_porta(monkeypatch, tmp_path):
    pkg = {'firewall': [{'name': 'Porta solta', 'ports': [9096]}]}
    scripts = _capture_firewall(monkeypatch, pkg, [Target(tmp_path, tmp_path)])

    assert len(scripts) == 1
    assert '-Program' not in scripts[0]
    assert '-LocalPort 9096' in scripts[0]


def test_firewall_remove_bloqueios_pelo_caminho_do_programa(monkeypatch, tmp_path):
    pkg = {'firewall': [{
        'name': 'Sankhya WC',
        'ports': [9096],
        'purge_blocking_program_matching': 'Sankhya web',
    }]}
    scripts = _capture_firewall(monkeypatch, pkg, [Target(tmp_path, tmp_path)])

    purga = scripts[0]
    assert '-Action Block' in purga
    assert 'Get-NetFirewallApplicationFilter' in purga
    assert 'Sankhya web' in purga
    assert 'Remove-NetFirewallRule' in purga


def test_firewall_escapa_aspas_simples_no_nome(monkeypatch, tmp_path):
    pkg = {'firewall': [{'name': "Regra d'Agua", 'ports': [9096]}]}
    scripts = _capture_firewall(monkeypatch, pkg, [Target(tmp_path, tmp_path)])
    assert "d''Agua" in scripts[0]


# =============================================================================
# Supervisão (ensure_running)
#
# O agente roda como SYSTEM na sessão 0; manter o app de pé significa lançá-lo
# dentro da sessão de quem está logado, e não insistir para sempre se ele morre.
# =============================================================================

class FakeToken:
    def __init__(self):
        self.closed = False

    def Close(self):
        self.closed = True


class FakeWinSession:
    """Substitui agent.packages.win_session nos testes."""

    Session = _RealSession = None  # preenchido abaixo

    def __init__(self, profile, sessions, running=False):
        self._profile = profile
        self._sessions = sessions
        self.running = running
        self.launches = []
        self.launch_ok = True
        self.tokens = []

    def active_sessions(self):
        return self._sessions

    def user_token(self, session_id):
        token = FakeToken()
        self.tokens.append(token)
        return token

    def profile_dir(self, token):
        return self._profile

    def is_running(self, exe_path, username=None):
        return self.running

    def launch_as_user(self, token, command, cwd=None):
        self.launches.append((command, str(cwd) if cwd else None))
        return 4242 if self.launch_ok else None


def _supervised_manager(monkeypatch, tmp_path, running=False, sessions=None):
    from agent.win_session import Session

    exe = tmp_path / 'app' / 'jre' / 'bin' / 'javaw.exe'
    exe.parent.mkdir(parents=True)
    exe.write_text('MZ')

    sessions = sessions if sessions is not None else [Session(2, 'DOM\\ana')]
    fake = FakeWinSession(tmp_path, sessions, running=running)
    monkeypatch.setattr('agent.packages.win_session', fake)
    monkeypatch.setattr('agent.packages.sys.platform', 'win32')

    manager = PackageManager(FakeReporter())
    manager._supervised = [('sankhya', {
        'process_path': '%USERPROFILE%\\app\\jre\\bin\\javaw.exe',
        'command': '"%USERPROFILE%\\app\\executar\\web_connection.exe"',
    })]
    return manager, fake


def test_supervisao_inicia_o_app_quando_nao_esta_rodando(monkeypatch, tmp_path):
    manager, fake = _supervised_manager(monkeypatch, tmp_path, running=False)

    manager.supervise_once()

    assert len(fake.launches) == 1
    comando, cwd = fake.launches[0]
    # as aspas do comando têm que sobreviver à expansão
    assert comando.startswith('"') and comando.endswith('web_connection.exe"')
    assert str(tmp_path) in comando
    assert '%USERPROFILE%' not in comando
    assert cwd.endswith('bin')


def test_supervisao_nao_faz_nada_se_ja_esta_rodando(monkeypatch, tmp_path):
    manager, fake = _supervised_manager(monkeypatch, tmp_path, running=True)
    manager.supervise_once()
    assert fake.launches == []


def test_supervisao_fecha_o_token_sempre(monkeypatch, tmp_path):
    manager, fake = _supervised_manager(monkeypatch, tmp_path, running=True)
    manager.supervise_once()
    assert fake.tokens and all(t.closed for t in fake.tokens)


def test_supervisao_respeita_carencia_apos_disparar(monkeypatch, tmp_path):
    manager, fake = _supervised_manager(monkeypatch, tmp_path, running=False)

    manager.supervise_once()
    manager.supervise_once()  # o app ainda estaria subindo

    assert len(fake.launches) == 1


def test_supervisao_desiste_depois_de_falhas_seguidas(monkeypatch, tmp_path):
    from agent import packages as mod

    manager, fake = _supervised_manager(monkeypatch, tmp_path, running=False)
    fake.launch_ok = False
    monkeypatch.setattr(mod, 'LAUNCH_GRACE_SECONDS', 0)

    for _ in range(mod.MAX_LAUNCH_FAILURES + 3):
        manager.supervise_once()

    assert len(fake.launches) == mod.MAX_LAUNCH_FAILURES
    codes = [h[0] for h in manager._reporter.health]
    assert 'package_launch_failed' in codes


def test_supervisao_ignora_perfil_sem_o_app_instalado(monkeypatch, tmp_path):
    from agent.win_session import Session

    vazio = tmp_path / 'sem_app'
    vazio.mkdir()
    fake = FakeWinSession(vazio, [Session(2, 'DOM\\ana')], running=False)
    monkeypatch.setattr('agent.packages.win_session', fake)
    monkeypatch.setattr('agent.packages.sys.platform', 'win32')

    manager = PackageManager(FakeReporter())
    manager._supervised = [('sankhya', {
        'process_path': '%USERPROFILE%\\app\\jre\\bin\\javaw.exe',
        'command': '"%USERPROFILE%\\app\\executar\\web_connection.exe"',
    })]
    manager.supervise_once()

    assert fake.launches == []


def test_supervisao_sem_ninguem_logado_nao_dispara(monkeypatch, tmp_path):
    manager, fake = _supervised_manager(monkeypatch, tmp_path, running=False, sessions=[])
    manager.supervise_once()
    assert fake.launches == []


def test_manifesto_sem_ensure_running_nao_supervisiona(monkeypatch):
    reporter = FakeReporter({'packages': []})
    manager = PackageManager(reporter)
    manager.check_once()
    assert manager._supervised == []


def test_check_once_registra_specs_de_supervisao(tmp_path):
    pkg = {
        'name': 'sankhya',
        'extract_to': str(tmp_path),
        'ensure_running': {'process_path': 'x', 'command': 'y'},
    }
    manager = PackageManager(FakeReporter({'packages': [pkg]}))
    manager.check_once()
    assert manager._supervised == [('sankhya', {'process_path': 'x', 'command': 'y'})]


def test_apply_config_ignora_arquivo_inexistente(tmp_path):
    pkg = {'config_files': [{
        'path': str(tmp_path / 'nao_existe.ini'),
        'values': {'porta': 9096},
    }]}
    PackageManager(FakeReporter())._apply_config(pkg, Target(tmp_path, None))
