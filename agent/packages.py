# agent/packages.py
"""
Instalacao remota de software nas maquinas ja gerenciadas pelo agente.

O servidor publica um manifesto em GET /api/agent/packages descrevendo o que
deve estar instalado no parque. Como o agente roda como LocalSystem, ele
consegue escrever em todos os perfis de usuario, criar regras de firewall e
gravar em HKLM — coisas que o usuario logado normalmente nao poderia fazer.

Fluxo por pacote:
    1. detecta se ja esta instalado (por perfil, quando scope=per-user)
    2. baixa o payload .zip e valida o sha256 (obrigatorio)
    3. extrai nos alvos que estiverem faltando
    4. reescreve as chaves de configuracao preservando o resto do arquivo
    5. garante a regra de firewall
    6. garante o autostart

Tudo e idempotente: rodar de novo numa maquina ja pronta nao faz nada.
"""

import hashlib
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, NamedTuple

logger = logging.getLogger(__name__)

CHECK_INTERVAL = 3600           # verifica o manifesto a cada 1 hora
FIRST_CHECK_DELAY = 120         # deixa o startup do servico respirar antes
MAX_PAYLOAD_BYTES = 1024 * 1024 * 1024
DOWNLOAD_TIMEOUT = 900          # payloads podem passar de 100 MB

_HKLM_RUN = r'Software\Microsoft\Windows\CurrentVersion\Run'

# Diretorios em C:\Users que nao sao perfis de gente
_SKIP_PROFILES = {'public', 'default', 'default user', 'all users', 'defaultuser0'}


class Target(NamedTuple):
    """Um destino de instalacao. profile e None quando o pacote e machine-wide."""
    root: Path
    profile: Path | None


# =============================================================================
# Helpers puros (sem I/O de rede — testaveis isoladamente)
# =============================================================================

def user_profiles() -> list[Path]:
    """Perfis de usuario reais em C:\\Users (os que tem NTUSER.DAT)."""
    base = Path(os.environ.get('SystemDrive', 'C:') + '\\Users')
    if not base.is_dir():
        return []
    profiles = []
    for entry in sorted(base.iterdir()):
        if not entry.is_dir() or entry.name.lower() in _SKIP_PROFILES:
            continue
        if not (entry / 'NTUSER.DAT').exists():
            continue
        profiles.append(entry)
    return profiles


def expand_path(template: str, profile: Path | None) -> Path:
    """Resolve %USERPROFILE% para o perfil alvo e demais variaveis do ambiente."""
    text = str(template)
    if profile is not None:
        text = text.replace('%USERPROFILE%', str(profile))
    return Path(os.path.expandvars(text))


def rewrite_config(text: str, values: dict[str, Any], fmt: str = 'jvm_args') -> str:
    """
    Reescreve apenas as chaves pedidas, preservando todas as outras linhas.

    Isso importa: o web_connection.l4j.ini mistura configuracao de servidor
    (skwHost, porta) com configuracao de hardware local (balancaPort=COM9).
    Sobrescrever o arquivo inteiro quebraria as maquinas que tem balanca.

    fmt='jvm_args'   -> linhas no formato -Dchave=valor  (web_connection.l4j.ini)
    fmt='properties' -> linhas no formato chave=valor    (snklocalapp.conf)
    """
    prefix = '-D' if fmt == 'jvm_args' else ''
    newline = '\r\n' if '\r\n' in text else '\n'
    lines = text.splitlines()
    pending = {str(k): str(v) for k, v in values.items()}

    for index, line in enumerate(lines):
        stripped = line.strip()
        for key in list(pending):
            token = f'{prefix}{key}='
            if stripped.startswith(token):
                lines[index] = f'{token}{pending.pop(key)}'
                break

    for key, value in pending.items():
        lines.append(f'{prefix}{key}={value}')

    return newline.join(lines) + newline


def _ps_quote(value: str) -> str:
    """Escapa uma string para dentro de aspas simples do PowerShell."""
    return str(value).replace("'", "''")


# =============================================================================
# PackageManager
# =============================================================================

class PackageManager:
    """
    Mantem o software do manifesto instalado e configurado.
    Roda em thread daemon — nunca bloqueia o servico.
    """

    def __init__(self, reporter: object, check_interval: int = CHECK_INTERVAL):
        self._reporter = reporter
        self._interval = check_interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._check_loop,
            name='PackagesThread',
            daemon=True,
        )
        self._thread.start()
        logger.debug('PackageManager iniciado (intervalo: %ds)', self._interval)

    def stop(self) -> None:
        self._stop_event.set()

    # -------------------------------------------------------------------------
    # Loop
    # -------------------------------------------------------------------------

    def _check_loop(self) -> None:
        if self._stop_event.wait(FIRST_CHECK_DELAY):
            return
        while not self._stop_event.is_set():
            self.check_once()
            self._stop_event.wait(self._interval)

    def check_once(self) -> None:
        try:
            resp = self._reporter.list_packages()  # type: ignore[attr-defined]
        except Exception as exc:
            # Servidor antigo sem a rota responde 404 — nao e erro, so nao ha pacotes
            logger.debug('Manifesto de pacotes indisponivel: %s', exc)
            return

        for pkg in self._unwrap(resp):
            name = pkg.get('name', '?')
            try:
                self.ensure_package(pkg)
            except Exception as exc:
                logger.warning('Falha ao aplicar pacote %s: %s', name, exc, exc_info=True)
                self._report('package_failed', 'error', name, str(exc))

    @staticmethod
    def _unwrap(resp: Any) -> list[dict[str, Any]]:
        """Aceita [...], {'packages': [...]} e {'data': {'packages': [...]}}."""
        data = (resp.get('data') or resp) if isinstance(resp, dict) else resp
        if isinstance(data, dict):
            data = data.get('packages') or []
        return list(data or [])

    # -------------------------------------------------------------------------
    # Aplicacao de um pacote
    # -------------------------------------------------------------------------

    def ensure_package(self, pkg: dict[str, Any]) -> None:
        name = pkg.get('name') or 'sem-nome'
        targets = self.targets(pkg)
        if not targets:
            logger.debug('Pacote %s: nenhum alvo aplicavel nesta maquina', name)
            return

        missing = [t for t in targets if not self.is_installed(pkg, t)]
        if missing:
            logger.info('Pacote %s: instalando em %d alvo(s)...', name, len(missing))
            payload = self._download(pkg)
            try:
                for target in missing:
                    self._extract(payload, target)
                    logger.info('Pacote %s extraido em %s', name, target.root)
            finally:
                payload.unlink(missing_ok=True)

        for target in targets:
            if self.is_installed(pkg, target):
                self._apply_config(pkg, target)

        self._apply_firewall(pkg)
        self._apply_autostart(pkg)

        if missing:
            self._report('package_installed', 'info', name,
                         f'instalado em {len(missing)} alvo(s)')

    def targets(self, pkg: dict[str, Any]) -> list[Target]:
        extract_to = pkg.get('extract_to')
        if not extract_to:
            raise ValueError('pacote sem extract_to')
        if pkg.get('scope') == 'per-user':
            return [Target(expand_path(extract_to, p), p) for p in user_profiles()]
        return [Target(expand_path(extract_to, None), None)]

    def is_installed(self, pkg: dict[str, Any], target: Target) -> bool:
        detect = pkg.get('detect_path')
        if not detect:
            return target.root.is_dir()
        return expand_path(detect, target.profile).exists()

    # -------------------------------------------------------------------------
    # Download e extracao
    # -------------------------------------------------------------------------

    def _download(self, pkg: dict[str, Any]) -> Path:
        import requests  # type: ignore[import]
        from urllib.parse import urljoin, urlparse

        url = pkg.get('payload_url')
        if not url:
            raise ValueError('pacote sem payload_url')
        if not urlparse(str(url)).scheme:
            base = getattr(self._reporter, '_base', '')
            url = urljoin(f'{base}/', str(url).lstrip('/'))

        expected = str(pkg.get('sha256') or '').lower()
        if not expected:
            # Sem checksum nao ha como saber se o payload foi adulterado em
            # transito — e isso aqui executa codigo em todo o parque.
            raise ValueError('pacote sem sha256 — recusando payload nao verificavel')

        session = getattr(self._reporter, '_session', requests)
        fd, tmp = tempfile.mkstemp(prefix='in9_pkg_', suffix='.zip')
        path = Path(tmp)
        digest = hashlib.sha256()
        total = 0

        try:
            with session.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT) as resp:
                resp.raise_for_status()
                with os.fdopen(fd, 'wb') as handle:
                    first_chunk = True
                    for chunk in resp.iter_content(chunk_size=65536):
                        if not chunk:
                            continue
                        if first_chunk:
                            if not chunk.startswith(b'PK'):
                                raise ValueError('payload nao e um arquivo zip')
                            first_chunk = False
                        total += len(chunk)
                        if total > MAX_PAYLOAD_BYTES:
                            raise ValueError('payload excede o limite permitido')
                        digest.update(chunk)
                        handle.write(chunk)

            actual = digest.hexdigest()
            if actual != expected:
                raise ValueError(f'checksum invalido: esperado {expected}, recebido {actual}')
            logger.info('Payload validado: %d bytes, sha256 %s', total, actual[:12])
            return path
        except Exception:
            path.unlink(missing_ok=True)
            raise

    def _extract(self, payload: Path, target: Target) -> None:
        import zipfile

        dest = target.root
        dest.mkdir(parents=True, exist_ok=True)
        resolved = dest.resolve()

        with zipfile.ZipFile(payload) as archive:
            for member in archive.namelist():
                out = (dest / member).resolve()
                # zip slip: entradas com ../ ou caminho absoluto escapariam do destino
                if out != resolved and resolved not in out.parents:
                    raise ValueError(f'entrada de zip fora do destino: {member}')
            archive.extractall(dest)

    # -------------------------------------------------------------------------
    # Configuracao
    # -------------------------------------------------------------------------

    def _apply_config(self, pkg: dict[str, Any], target: Target) -> None:
        for spec in pkg.get('config_files') or []:
            path = expand_path(spec.get('path', ''), target.profile)
            values = spec.get('values') or {}
            if not values:
                continue
            if not path.is_file():
                logger.warning('Config %s nao existe — pulando', path)
                continue

            # latin-1 faz round-trip de qualquer byte, entao as linhas que nao
            # tocamos voltam ao disco identicas (o snklocalapp.conf tem acentos
            # gravados em cp1252 pelo proprio Sankhya).
            encoding = spec.get('encoding', 'latin-1')
            fmt = spec.get('format', 'jvm_args')
            original = path.read_text(encoding=encoding)
            updated = rewrite_config(original, values, fmt)
            if updated == original:
                continue

            backup = path.with_suffix(path.suffix + '.in9bak')
            if not backup.exists():
                shutil.copy2(path, backup)
            path.write_text(updated, encoding=encoding)
            logger.info('Config atualizada: %s', path)

    # -------------------------------------------------------------------------
    # Firewall
    # -------------------------------------------------------------------------

    def _apply_firewall(self, pkg: dict[str, Any]) -> None:
        if sys.platform != 'win32':
            return
        for rule in pkg.get('firewall') or []:
            try:
                self._ensure_firewall_rule(rule)
            except Exception as exc:
                logger.warning('Falha ao aplicar regra de firewall %s: %s',
                               rule.get('name', '?'), exc)

    def _ensure_firewall_rule(self, rule: dict[str, Any]) -> None:
        name = rule.get('name')
        ports = rule.get('ports') or ([rule['port']] if rule.get('port') else [])
        if not name or not ports:
            return

        script: list[str] = []

        # Regras de bloqueio vencem regras de permissao no Firewall do Windows.
        # Quem instalou o app na mao e clicou "Cancelar" no prompt tem um block
        # gravado que anularia a nossa permissao — entao removemos antes.
        purge = rule.get('purge_blocking_rules_matching')
        if purge:
            script.append(
                "Get-NetFirewallRule -ErrorAction SilentlyContinue | "
                f"Where-Object {{ $_.Action -eq 'Block' -and $_.DisplayName -like '*{_ps_quote(purge)}*' }} | "
                "Remove-NetFirewallRule -ErrorAction SilentlyContinue;"
            )

        quoted = _ps_quote(name)
        direction = 'Inbound' if rule.get('direction', 'in') == 'in' else 'Outbound'
        protocol = rule.get('protocol', 'TCP')
        localports = ','.join(str(p) for p in ports)
        profiles = ','.join(rule.get('profiles') or ['Domain', 'Private'])
        script.append(
            f"if (-not (Get-NetFirewallRule -DisplayName '{quoted}' -ErrorAction SilentlyContinue)) {{ "
            f"New-NetFirewallRule -DisplayName '{quoted}' -Group 'IN9USBAgent' "
            f"-Direction {direction} -Action Allow -Protocol {protocol} "
            f"-LocalPort {localports} -Profile {profiles} | Out-Null }}"
        )

        self._powershell(' '.join(script))
        logger.info('Regra de firewall garantida: %s (%s %s)', name, protocol, localports)

    def _powershell(self, script: str) -> None:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive',
             '-ExecutionPolicy', 'Bypass', '-Command', script],
            capture_output=True,
            timeout=120,
        )
        if result.returncode != 0:
            detail = result.stderr.decode(errors='replace').strip()
            raise RuntimeError(f'powershell falhou ({result.returncode}): {detail}')

    # -------------------------------------------------------------------------
    # Autostart
    # -------------------------------------------------------------------------

    def _apply_autostart(self, pkg: dict[str, Any]) -> None:
        spec = pkg.get('autostart')
        if not spec or sys.platform != 'win32':
            return

        name = spec.get('name') or pkg.get('name')
        command = spec.get('command')
        if not name or not command:
            return

        # Uma entrada REG_EXPAND_SZ em HKLM\...\Run cobre todos os perfis: o
        # Windows expande %USERPROFILE% no logon de cada usuario. Evita ter que
        # montar a NTUSER.DAT de quem esta deslogado.
        import winreg  # type: ignore[import]

        try:
            with winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE, _HKLM_RUN, 0,
                winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE,
            ) as key:
                try:
                    current, kind = winreg.QueryValueEx(key, name)
                    if current == command and kind == winreg.REG_EXPAND_SZ:
                        return
                except FileNotFoundError:
                    pass
                winreg.SetValueEx(key, name, 0, winreg.REG_EXPAND_SZ, command)
            logger.info('Autostart configurado: %s', name)
        except OSError as exc:
            logger.warning('Falha ao gravar autostart %s: %s', name, exc)

    # -------------------------------------------------------------------------
    # Telemetria
    # -------------------------------------------------------------------------

    def _report(self, code: str, level: str, package: str, message: str) -> None:
        try:
            self._reporter.report_health(  # type: ignore[attr-defined]
                code=code, level=level, message=message,
                context={'package': package},
            )
        except Exception:
            pass
