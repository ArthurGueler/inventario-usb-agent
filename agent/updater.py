# agent/updater.py
"""
Auto-update do agente.

Verifica GET /api/agent/version periodicamente.
Se needs_update=True, baixa o novo .exe e substitui o executável atual.
Após substituição, sinaliza para o serviço reiniciar.
"""

import logging
import hashlib
import os
import sys
import threading
import tempfile
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

CHECK_INTERVAL = 3600  # verifica a cada 1 hora


class Updater:
    """
    Verifica e aplica atualizações do agente.
    Roda em thread daemon — não bloqueia o serviço.
    """

    def __init__(
        self,
        reporter: object,
        on_update_ready: Callable[[], None] | None = None,
    ):
        """
        reporter: instância de Reporter já configurada
        on_update_ready: callback chamado após substituir o .exe (para reiniciar o serviço)
        """
        self._reporter = reporter
        self._on_update_ready = on_update_ready
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._check_loop,
            name='UpdaterThread',
            daemon=True,
        )
        self._thread.start()
        logger.debug('Updater iniciado (intervalo: %ds)', CHECK_INTERVAL)

    def stop(self) -> None:
        self._stop_event.set()

    # -------------------------------------------------------------------------
    # Loop
    # -------------------------------------------------------------------------

    def _check_loop(self) -> None:
        # Primeira verificação após 60s (dar tempo ao serviço inicializar)
        if self._stop_event.wait(60):
            return

        while not self._stop_event.is_set():
            self._check_once()
            self._stop_event.wait(CHECK_INTERVAL)

    def _check_once(self) -> None:
        try:
            resp = self._reporter.check_version()  # type: ignore[attr-defined]
            data = resp.get('data') or resp
            if not data.get('needs_update'):
                logger.debug('Versão atual — sem update disponível')
                return

            current = data.get('current_version', '?')
            download_url = data.get('download_url')
            expected_sha256 = data.get('sha256')
            logger.info('Update disponível: v%s — baixando...', current)

            if not download_url:
                logger.warning('needs_update=True mas download_url ausente — abortando')
                return

            self._apply_update(download_url, expected_sha256)

        except Exception as exc:
            logger.warning('Verificação de update falhou: %s', exc)

    # -------------------------------------------------------------------------
    # Download e substituição do .exe
    # -------------------------------------------------------------------------

    def _apply_update(self, download_url: str, expected_sha256: str | None = None) -> None:
        import requests  # type: ignore[import]
        from urllib.parse import urljoin, urlparse

        current_exe = Path(sys.executable)
        if not urlparse(download_url).scheme:
            base_url = getattr(self._reporter, '_base', '')
            download_url = urljoin(f'{base_url}/', download_url.lstrip('/'))

        # Baixar para arquivo temporário no mesmo diretório
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=current_exe.parent,
            prefix='usb_agent_update_',
            suffix='.exe',
        )
        try:
            logger.info('Baixando update para %s...', tmp_path)
            session = getattr(self._reporter, '_session', requests)
            digest = hashlib.sha256()
            downloaded = 0
            first_chunk = True
            with session.get(download_url, stream=True, timeout=60) as r:
                r.raise_for_status()
                with os.fdopen(tmp_fd, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if not chunk:
                            continue
                        if first_chunk and not chunk.startswith(b'MZ'):
                            raise ValueError('download nao e um executavel PE valido')
                        first_chunk = False
                        digest.update(chunk)
                        downloaded += len(chunk)
                        f.write(chunk)

            if downloaded < 1024 * 1024:
                raise ValueError(f'download incompleto: {downloaded} bytes')
            actual_sha256 = digest.hexdigest()
            if expected_sha256 and actual_sha256.lower() != expected_sha256.lower():
                raise ValueError(
                    f'checksum invalido: esperado {expected_sha256}, recebido {actual_sha256}'
                )

            # Renomear executável atual para .bak e substituir
            # No Windows não é possível renomear um .exe em execução — usamos cmd /c
            # para executar a substituição após o processo encerrar
            if sys.platform == 'win32':
                self._schedule_replace_windows(current_exe, Path(tmp_path))
            else:
                bak_path = current_exe.with_suffix('.bak')
                if bak_path.exists():
                    bak_path.unlink()
                current_exe.rename(bak_path)
                Path(tmp_path).rename(current_exe)
                logger.info('Update aplicado — reiniciando...')
                if self._on_update_ready:
                    self._on_update_ready()

        except Exception as exc:
            logger.error('Falha ao aplicar update: %s', exc)
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _schedule_replace_windows(self, current_exe: Path, new_exe: Path) -> None:
        """
        Agenda a substituição do .exe via script .bat que roda após o processo encerrar.
        """
        bat_path = current_exe.parent / '_update_replace.bat'
        bak_path = current_exe.with_suffix('.bak')
        bat_content = f"""@echo off
sc stop IN9USBAgent >nul 2>&1
set tries=0
:retry
timeout /t 2 /nobreak >nul
set /a tries+=1
copy /y "{current_exe}" "{bak_path}" >nul 2>&1
move /y "{new_exe}" "{current_exe}" >nul 2>&1
if not exist "{new_exe}" goto updated
if %tries% LSS 30 goto retry
sc start IN9USBAgent >nul 2>&1
exit /b 1
:updated
sc start IN9USBAgent >nul 2>&1
del "%~f0"
"""
        bat_path.write_text(bat_content, encoding='utf-8')

        import subprocess
        subprocess.Popen(
            ['cmd', '/c', str(bat_path)],
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
        )

        logger.info('Script de substituicao agendado - o servico sera reiniciado pelo Windows')
