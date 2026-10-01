# agent/tray.py
"""
Ícone na bandeja do sistema (system tray).

Roda como processo separado do usuário (não como serviço).
Iniciado pelo instalador via chave Run no registro do Windows.

Estados:
  verde   — serviço ativo, reportando normalmente (0 eventos pendentes)
  amarelo — offline, eventos sendo acumulados no buffer
  vermelho — serviço não está rodando

Depende de pystray + Pillow.
"""

import logging
import threading
from enum import Enum

logger = logging.getLogger(__name__)

ICON_SIZE  = 64   # pixels
POLL_INTERVAL = 15  # segundos entre verificações de status


class TrayStatus(Enum):
    ONLINE  = 'online'   # verde
    OFFLINE = 'offline'  # amarelo
    ERROR   = 'error'    # vermelho


_STATUS_COLORS: dict[TrayStatus, tuple[int, int, int]] = {
    TrayStatus.ONLINE:  (34,  197, 94),
    TrayStatus.OFFLINE: (234, 179, 8),
    TrayStatus.ERROR:   (239, 68,  68),
}

_STATUS_LABELS: dict[TrayStatus, str] = {
    TrayStatus.ONLINE:  'IN9 USB Agent — Ativo',
    TrayStatus.OFFLINE: 'IN9 USB Agent — Offline (buffer ativo)',
    TrayStatus.ERROR:   'IN9 USB Agent — Serviço parado',
}


def _make_icon_image(color: tuple[int, int, int]):
    from PIL import Image, ImageDraw  # type: ignore[import]
    img  = Image.new('RGBA', (ICON_SIZE, ICON_SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    m    = 4
    draw.ellipse([m, m, ICON_SIZE - m, ICON_SIZE - m], fill=(*color, 255))
    return img


def _service_is_running() -> bool:
    """Verifica se o serviço Windows IN9USBAgent está em execução."""
    try:
        import win32service  # type: ignore[import]
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        svc = win32service.OpenService(scm, 'IN9USBAgent', win32service.SERVICE_QUERY_STATUS)
        status = win32service.QueryServiceStatus(svc)
        win32service.CloseServiceHandle(svc)
        win32service.CloseServiceHandle(scm)
        return status[1] == win32service.SERVICE_RUNNING
    except Exception:
        return False


def _pending_events() -> int:
    """Lê a contagem de eventos pendentes no buffer local."""
    # The interactive tray must never open the token/event database.  Status
    # is derived solely from the Windows Service Control Manager.
    return 0


class TrayIcon:
    def __init__(self):
        self._icon = None
        self._available = False
        self._stop_event = threading.Event()

        try:
            import pystray          # type: ignore[import]
            from PIL import Image   # type: ignore[import]  # noqa: F401
            self._available = True
        except ImportError:
            logger.debug('pystray/Pillow não disponíveis — tray desabilitado')

    def set_status(self, status: TrayStatus, tooltip: str | None = None) -> None:
        if not self._available or self._icon is None:
            return
        try:
            self._icon.icon  = _make_icon_image(_STATUS_COLORS[status])
            self._icon.title = tooltip or _STATUS_LABELS[status]
        except Exception as exc:
            logger.debug('Falha ao atualizar ícone: %s', exc)

    def run(self) -> None:
        """Bloqueia a thread principal rodando o loop do tray."""
        if not self._available:
            return
        self._icon = self._build_icon()
        # Iniciar o poller de status em background
        threading.Thread(target=self._poll_status, daemon=True, name='TrayPoller').start()
        self._icon.run()

    def stop(self) -> None:
        self._stop_event.set()
        if self._icon:
            try:
                self._icon.stop()
            except Exception:
                pass

    def _build_icon(self):
        import pystray  # type: ignore[import]
        return pystray.Icon(
            name='IN9USBAgent',
            icon=_make_icon_image(_STATUS_COLORS[TrayStatus.ONLINE]),
            title=_STATUS_LABELS[TrayStatus.ONLINE],
        )

    def _poll_status(self) -> None:
        """Atualiza a cor do ícone periodicamente com base no estado real do serviço."""
        while not self._stop_event.wait(POLL_INTERVAL):
            if not _service_is_running():
                self.set_status(TrayStatus.ERROR)
            else:
                self.set_status(TrayStatus.ONLINE)
