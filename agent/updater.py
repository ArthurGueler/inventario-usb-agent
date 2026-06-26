# agent/updater.py
"""
Auto-update do agente.

Verifica GET /api/agent/version periodicamente.
Se needs_update=True, baixa o novo .exe e substitui o executável atual.
Após substituição, sinaliza para o serviço reiniciar.
"""

import logging
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
            if not resp.get('needs_update'):
                logger.debug('Versão atual — sem update disponível')
                return

            current = resp.get('current_version', '?')
            download_url = resp.get('download_url')
            logger.info('Update disponível: v%s — baixando...', current)

            if not download_url:
                logger.warning('needs_update=True mas download_url ausente — abortando')
                return

            self._apply_update(download_url)

        except Exception as exc:
            logger.warning('Verificação de update falhou: %s', exc)

    # -------------------------------------------------------------------------
    # Download e substituição do .exe
    # -------------------------------------------------------------------------

    def _apply_update(self, download_url: str) -> None:
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
            with requests.get(download_url, stream=True, timeout=60) as r:
                r.raise_for_status()
                with os.fdopen(tmp_fd, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)

            # Renomear executável atual para .bak e substituir
            bak_path = current_exe.with_suffix('.bak')
            if bak_path.exists():
                bak_path.unlink()

            # No Windows não é possível renomear um .exe em execução — usamos cmd /c
            # para executar a substituição após o processo encerrar
            if sys.platform == 'win32':
                self._schedule_replace_windows(current_exe, Path(tmp_path))
            else:
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
        bat_content = f"""@echo off
timeout /t 3 /nobreak >nul
move /y "{new_exe}" "{current_exe}"
del "%~f0"
sc start IN9USBAgent
"""
        bat_path.write_text(bat_content, encoding='utf-8')

        import subprocess
        subprocess.Popen(
            ['cmd', '/c', str(bat_path)],
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
        )

        logger.info('Script de substituição agendado — sinalizando parada do serviço...')
        if self._on_update_ready:
            self._on_update_ready()
