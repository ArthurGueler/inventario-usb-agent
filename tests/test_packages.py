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


def test_apply_config_ignora_arquivo_inexistente(tmp_path):
    pkg = {'config_files': [{
        'path': str(tmp_path / 'nao_existe.ini'),
        'values': {'porta': 9096},
    }]}
    PackageManager(FakeReporter())._apply_config(pkg, Target(tmp_path, None))
