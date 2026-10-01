# agent/service.py
"""
Windows Service — IN9USBAgent

Instala como serviço:
    python -m agent install
    python -m agent start

Remove:
    python -m agent remove

Roda standalone (sem serviço):
    python -m agent run
"""

import logging
import secrets
import threading
import time
import socket
from pathlib import Path
from typing import Any

import requests

from .local_db import LocalDB
from .reporter import Reporter
from .usb_monitor import UsbMonitor
from .hasher import compute_hash_id
from .classifier import classify_physical
from .specs import capture_machine_specs
from .updater import Updater
from .packages import PackageManager
from .commands import CommandWorker
from .security_data import (
    SECURITY_DATA_CAPABILITY,
    SECURITY_MARKER_KEY,
    SECURITY_ROTATION_NEW_KEY,
    SECURITY_ROTATION_OLD_KEY,
    SECURITY_ROTATION_PENDING_KEY,
    SecurityDataError,
    can_consume_remote_commands,
    canonical_server_url,
)

logger = logging.getLogger(__name__)

HEARTBEAT_INTERVAL = 300  # 5 minutos
FLUSH_INTERVAL = 30       # tenta enviar buffer offline a cada 30s
AGENT_VERSION = '1.3.27'
DEFAULT_SERVER_URL = 'https://inventario.in9automacao.com.br'


class AgentCore:
    """
    Lógica principal do agente — funciona tanto como Windows Service
    quanto em modo standalone (para desenvolvimento/teste).
    """

    def __init__(self, db: LocalDB, *, service_context: bool = False):
        self._db = db
        self._service_context = service_context
        self._security_ready = False
        self._reporter: Reporter | None = None
        self._monitor: UsbMonitor | None = None
        self._updater: Updater | None = None
        self._packages: PackageManager | None = None
        self._commands: CommandWorker | None = None
        self._remote_features_started = False
        self._remote_features_lock = threading.Lock()
        self._anydesk_thread_started = False
        self._stop_event = threading.Event()

    # -------------------------------------------------------------------------
    # Ciclo de vida
    # -------------------------------------------------------------------------

    def start(self) -> None:
        logger.info('IN9USBAgent v%s iniciando...', AGENT_VERSION)

        try:
            self._db.validate_security()
        except Exception as exc:
            logger.error('Diretorio de dados nao passou na validacao de seguranca: %s', type(exc).__name__)
            return
        self._ensure_base_config()

        reporter = self._build_reporter()
        if reporter is None:
            logger.error('Configuração incompleta — server_url ou token ausentes. '
                         'Execute o install.bat para configurar.')
            return

        self._reporter = reporter

        # Registro/update no servidor
        self._do_register()

        # Bootstrap registration uses the old token; remote updates and
        # command consumption stay gated until security enrollment succeeds.
        self._security_ready = self._ensure_security_enrollment(reporter)
        # Iniciar monitor USB
        self._monitor = UsbMonitor(
            on_event=self._handle_usb_event,
            on_snapshot=self._handle_usb_snapshot,
        )
        self._monitor.start()

        # Loops de heartbeat e flush offline em threads separadas
        self._start_remote_features(reporter)
        threading.Thread(target=self._heartbeat_loop, daemon=True, name='HeartbeatThread').start()
        threading.Thread(target=self._flush_loop, daemon=True, name='FlushThread').start()

        logger.info('Agente em execução. Monitorando eventos USB...')

    def _start_remote_features(self, reporter: Reporter | None = None) -> bool:
        """Start privileged remote workers once, after security enrollment.

        Enrollment may complete on a later heartbeat after a startup outage.
        Each component is retained after a successful start, so retrying this
        gate cannot create duplicate updater/package/command workers.
        """

        reporter = reporter or self._reporter
        if reporter is None or not self._security_ready:
            return False
        if not can_consume_remote_commands(service_context=self._service_context):
            return False

        with self._remote_features_lock:
            if not self._anydesk_thread_started:
                try:
                    threading.Thread(
                        target=self._try_install_anydesk,
                        daemon=True,
                        name='AnydeskInstallThread',
                    ).start()
                    self._anydesk_thread_started = True
                except Exception as exc:
                    logger.warning('Canal AnyDesk remoto indisponivel: %s', type(exc).__name__)

            if self._updater is None:
                try:
                    self._updater = Updater(reporter=reporter)
                    self._updater.start()
                except Exception as exc:
                    self._updater = None
                    logger.warning('Updater remoto indisponivel: %s', type(exc).__name__)

            if self._packages is None:
                try:
                    self._packages = PackageManager(reporter=reporter)
                    self._packages.start()
                except Exception as exc:
                    self._packages = None
                    logger.warning('Instalacao remota de pacotes indisponivel: %s', type(exc).__name__)

            if self._commands is None:
                try:
                    self._commands = CommandWorker(
                        db=self._db,
                        reporter=reporter,
                        agent_version=AGENT_VERSION,
                        enabled=True,
                        service_context=self._service_context,
                    )
                    self._commands.start()
                except Exception as exc:
                    self._commands = None
                    logger.warning('Canal de comandos remoto indisponivel: %s', type(exc).__name__)
                    try:
                        reporter.report_health(
                            code='command_worker_start_failed',
                            level='error',
                            message=type(exc).__name__,
                        )
                    except Exception:
                        pass

            self._remote_features_started = all(
                component is not None
                for component in (self._updater, self._packages, self._commands)
            )
            return self._remote_features_started

    def stop(self) -> None:
        logger.info('Parando IN9USBAgent...')
        self._stop_event.set()
        if self._commands:
            self._commands.stop()
        if self._monitor:
            self._monitor.stop()
        if self._updater:
            self._updater.stop()
        if self._packages:
            self._packages.stop()
        logger.info('Agente parado.')

    def wait(self) -> None:
        """Bloqueia até stop() ser chamado (uso em modo standalone)."""
        self._stop_event.wait()

    # -------------------------------------------------------------------------
    # Configuração
    # -------------------------------------------------------------------------

    def _ensure_base_config(self) -> None:
        if not self._db.server_url:
            self._db.server_url = DEFAULT_SERVER_URL
            logger.warning('URL do servidor ausente - usando %s', DEFAULT_SERVER_URL)
        if not self._db.token:
            self._db.token = secrets.token_hex(32)
            logger.warning('Token local ausente - nova credencial gerada para autorregistro')

    def _build_reporter(self) -> Reporter | None:
        server_url = self._db.server_url
        token = self._db.token
        if not server_url or not token:
            return None
        try:
            canonical_server_url(server_url)
        except SecurityDataError as exc:
            logger.error('URL do servidor rejeitada: %s', type(exc).__name__)
            return None
        return Reporter(server_url=server_url, token=token, enforce_origin=True)

    def _ensure_security_enrollment(self, reporter: Reporter) -> bool:
        """Rotate the bootstrap token and gate remote features until ack."""
        if self._db.get_config(SECURITY_MARKER_KEY) == SECURITY_DATA_CAPABILITY:
            self._db.delete_config(SECURITY_ROTATION_OLD_KEY)
            self._db.delete_config(SECURITY_ROTATION_NEW_KEY)
            self._db.delete_config(SECURITY_ROTATION_PENDING_KEY)
            return True
        old_token = self._db.get_config(SECURITY_ROTATION_OLD_KEY) or self._db.token
        new_token = self._db.get_config(SECURITY_ROTATION_NEW_KEY)
        if not old_token:
            return False
        if not new_token or self._db.get_config(SECURITY_ROTATION_PENDING_KEY) != '1':
            new_token = secrets.token_hex(32)
            # Durable before the first security-enroll request.
            self._db.set_config(SECURITY_ROTATION_OLD_KEY, old_token)
            self._db.set_config(SECURITY_ROTATION_NEW_KEY, new_token)
            self._db.set_config(SECURITY_ROTATION_PENDING_KEY, '1')
        try:
            response = reporter.security_enroll(
                agent_version=AGENT_VERSION,
                new_token=new_token,
            )
            data = response.get('data') if isinstance(response, dict) else None
            if (not isinstance(response, dict) or response.get('success') is not True
                    or not isinstance(data, dict)
                    or data.get('security_enrolled') is not True):
                return False
        except Exception as exc:
            logger.warning('Enrollment de seguranca pendente: %s', type(exc).__name__)
            return False

        self._db.token = new_token
        self._db.set_config(SECURITY_MARKER_KEY, SECURITY_DATA_CAPABILITY)
        self._db.delete_config(SECURITY_ROTATION_OLD_KEY)
        self._db.delete_config(SECURITY_ROTATION_NEW_KEY)
        self._db.delete_config(SECURITY_ROTATION_PENDING_KEY)
        reporter.set_token(new_token)
        return True

    # -------------------------------------------------------------------------
    # AnyDesk
    # -------------------------------------------------------------------------

    def _try_install_anydesk(self) -> None:
        """
        Garante que o servidor tenha o AnyDesk ID:
          - Se AnyDesk já instalado → captura ID e re-registra (caso 1)
          - Se não instalado → instala, captura e re-registra (caso 2)
        """
        assert self._reporter is not None
        try:
            from .anydesk import is_installed, ensure_anydesk
            from .specs import get_anydesk_id, capture_machine_specs

            already_installed = is_installed()
            if already_installed:
                anydesk_id = get_anydesk_id()
                logger.info('AnyDesk já instalado — ID capturado: %s', anydesk_id or 'não disponível')
            else:
                logger.info('AnyDesk não instalado — iniciando instalação...')
                anydesk_id = ensure_anydesk(self._reporter)
                if not anydesk_id:
                    self._reporter.report_health(
                        code='anydesk_install_failed',
                        level='warning',
                        message='Tentativa de instalar AnyDesk falhou (download ou install)',
                    )

            # Em ambos os casos, se temos um ID, garantir que o servidor saiba
            if anydesk_id:
                import socket
                specs = capture_machine_specs()
                hostname = specs.get('hostname') or socket.gethostname()
                try:
                    self._reporter.register(
                        hostname=hostname,
                        agent_version=AGENT_VERSION,
                        specs=specs,
                    )
                    logger.info('Servidor atualizado com AnyDesk ID: %s', anydesk_id)
                except Exception as reg_exc:
                    logger.warning('Falha ao re-registrar com AnyDesk ID: %s', reg_exc)
            elif already_installed:
                logger.warning('AnyDesk instalado mas service.conf ainda não tem ID — tentará novamente no próximo heartbeat')
                self._reporter.report_health(
                    code='anydesk_id_missing',
                    level='info',
                    message='AnyDesk instalado mas ID ainda não disponível',
                )
        except Exception as exc:
            logger.warning('Erro ao verificar/instalar AnyDesk: %s', exc, exc_info=True)
            try:
                self._reporter.report_health(
                    code='anydesk_check_exception',
                    level='error',
                    message=str(exc),
                )
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # Registro
    # -------------------------------------------------------------------------

    def _do_register(self) -> None:
        assert self._reporter is not None
        specs = capture_machine_specs()
        hostname = specs.get('hostname') or socket.gethostname()
        if not self._db.machine_id and self._recover_registration(specs, hostname):
            return
        try:
            resp = self._reporter.register(
                hostname=hostname,
                agent_version=AGENT_VERSION,
                specs=specs,
            )
            data = resp.get('data') or resp
            logger.info('Registro OK — status: %s', data.get('status'))
            if data.get('machine_id'):
                self._db.machine_id = data['machine_id']
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            if status in (401, 404):
                logger.warning('Token não reconhecido pelo servidor (HTTP %s) — o register-new original '
                               '(feito no instalador) deve ter falhado. Tentando registrar como máquina nova...',
                               status)
                self._recover_registration(specs, hostname)
            else:
                logger.warning('Falha no registro (tentará no próximo heartbeat): %s', exc)
        except Exception as exc:
            logger.warning('Falha no registro (tentará no próximo heartbeat): %s', exc)

    def _recover_registration(self, specs: dict[str, Any] | None = None, hostname: str | None = None) -> bool:
        """
        Chamado quando o servidor responde 401/404 pro token local — sinal de que o
        register-new original (rodado pelo instalador) nunca chegou a criar a máquina
        no servidor (rede fora do ar no momento da instalação, etc.). Sem isso, o
        agente ficaria retentando `register` pra sempre, sem nunca aparecer no portal.
        """
        assert self._reporter is not None
        if specs is None:
            specs = capture_machine_specs()
        if hostname is None:
            hostname = specs.get('hostname') or socket.gethostname()
        try:
            resp = self._reporter.register_new(
                hostname=hostname,
                mac_address=specs.get('mac_address'),
                bios_serial=specs.get('bios_serial'),
                collaborator_name=self._db.collaborator_name,
                anydesk_id=specs.get('anydesk_id'),
                agent_version=AGENT_VERSION,
                specs=specs,
                registration_reason='recovery',
            )
            data = resp.get('data') or resp
            if data.get('token'):
                self._db.token = data['token']
                self._reporter.set_token(data['token'])
            machine_id = data.get('machine_id')
            if not machine_id:
                raise ValueError('register-new respondeu sem machine_id')
            self._db.machine_id = machine_id
            logger.info('register-new de recuperação OK — machine_id: %s (pendente de aprovação no portal)',
                        machine_id)
            return True
        except Exception as exc:
            logger.warning('Falha ao recuperar registro via register-new (tentará no próximo heartbeat): %s', exc)
            return False

    # -------------------------------------------------------------------------
    # Heartbeat loop
    # -------------------------------------------------------------------------

    def _heartbeat_loop(self) -> None:
        while not self._stop_event.wait(HEARTBEAT_INTERVAL):
            if self._reporter:
                try:
                    if not self._security_ready:
                        self._security_ready = self._ensure_security_enrollment(self._reporter)
                    if not self._security_ready:
                        continue
                    self._start_remote_features(self._reporter)
                    if not self._db.machine_id:
                        self._recover_registration()
                    resp = self._reporter.heartbeat(agent_version=AGENT_VERSION)
                    data = resp.get('data', {})
                    if data.get('needs_update') and data.get('download_url'):
                        logger.info('Nova versão disponível: %s — iniciando auto-update', data.get('current_version'))
                    logger.debug('Heartbeat enviado')
                    self._sync_current_usb_snapshot()
                except requests.HTTPError as exc:
                    status = exc.response.status_code if exc.response is not None else None
                    if status in (401, 404):
                        logger.warning('Token não reconhecido pelo servidor (HTTP %s) no heartbeat — '
                                       'tentando registrar como máquina nova...', status)
                        self._recover_registration()
                    else:
                        logger.warning('Heartbeat falhou: %s', exc)
                except Exception as exc:
                    logger.warning('Heartbeat falhou: %s', exc)

            # Retry AnyDesk se ainda não instalado
            try:
                from .anydesk import is_installed
                if (self._security_ready
                        and can_consume_remote_commands(service_context=self._service_context)
                        and not is_installed() and self._reporter):
                    self._try_install_anydesk()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # Flush offline loop
    # -------------------------------------------------------------------------

    def _flush_loop(self) -> None:
        while not self._stop_event.wait(FLUSH_INTERVAL):
            pending = self._db.pending_count()
            if pending == 0 or self._reporter is None:
                continue
            if not self._reporter.is_online():
                logger.warning('%d evento(s) pendente(s) no buffer — servidor inacessível, tentando novamente em %ds',
                               pending, FLUSH_INTERVAL)
                continue
            self._flush_pending()

    def _flush_pending(self) -> None:
        assert self._reporter is not None
        batch = self._db.pop_pending_events()
        if not batch:
            return

        logger.info('Reenviando %d evento(s) do buffer offline...', len(batch))
        sent_ids: list[int] = []
        for event_id, payload in batch:
            try:
                self._reporter.send_usb_event(payload)
                sent_ids.append(event_id)
            except Exception as exc:
                logger.warning('Falha ao reenviar evento %d: %s', event_id, exc)
                break  # parar no primeiro erro — tentar novamente no próximo ciclo

        if sent_ids:
            self._db.mark_sent(sent_ids)
            logger.info('%d/%d evento(s) do buffer enviados com sucesso', len(sent_ids), len(batch))
        remaining = len(batch) - len(sent_ids)
        if remaining > 0:
            logger.warning('%d evento(s) permaneceram no buffer — nova tentativa em %ds', remaining, FLUSH_INTERVAL)

    # -------------------------------------------------------------------------
    # Processamento de evento USB
    # -------------------------------------------------------------------------

    def _build_usb_payload(self, raw_event: dict[str, Any]) -> dict[str, Any]:
        vid: str = raw_event.get('vid', '0000')
        pid: str = raw_event.get('pid', '0000')
        serial: str | None = raw_event.get('serial')
        friendly_name: str | None = raw_event.get('friendly_name')
        class_guid: str | None = raw_event.get('class_guid')

        compatible_ids: list[str] = raw_event.get('compatible_ids') or []
        hash_id, serial_is_stable = compute_hash_id(vid, pid, serial)
        device_type, classification_source = classify_physical(
            class_guid,
            friendly_name,
            vid,
            compatible_ids,
            raw_event.get('interfaces') or [],
        )

        return {
            'event_type':    raw_event.get('event_type', 'connected'),
            'event_time':    raw_event.get('event_time'),
            'vid':           vid,
            'pid':           pid,
            'serial':        serial,
            'friendly_name': friendly_name,
            'pnp_device_id': raw_event.get('pnp_device_id'),
            'manufacturer':  raw_event.get('manufacturer'),
            'description':   raw_event.get('description'),
            'service':       raw_event.get('service'),
            'class_guid':    class_guid,
            'pnp_class':     raw_event.get('pnp_class'),
            'hardware_ids':  raw_event.get('hardware_ids') or [],
            'compatible_ids': compatible_ids,
            'physical_instance_id': raw_event.get('physical_instance_id'),
            'container_id':   raw_event.get('container_id'),
            'bus_description': raw_event.get('bus_description'),
            'removal_policy': raw_event.get('removal_policy'),
            'is_removable': bool(raw_event.get('is_removable')),
            'interface_count': raw_event.get('interface_count', 0),
            'is_composite':   bool(raw_event.get('is_composite')),
            'classification_source': classification_source,
            'hash_id':       hash_id,
            'device_type':   device_type,
        }

    def _handle_usb_event(self, raw_event: dict[str, Any]) -> None:
        payload = self._build_usb_payload(raw_event)

        # Tentar envio imediato — só enfileira se offline ou se o envio falhar
        if self._reporter and self._reporter.is_online():
            try:
                resp = self._reporter.send_usb_event(payload)
                if resp.get('alert'):
                    logger.warning('ALERTA gerado: %s', resp['alert'].get('message'))
                return  # enviado com sucesso — não precisa enfileirar
            except Exception as exc:
                logger.warning('Falha ao enviar evento USB: %s — enfileirando no buffer', exc)
        else:
            logger.warning('Servidor offline — enfileirando evento no buffer local')

        self._db.enqueue_event(payload)
        logger.info('Buffer local: %d evento(s) pendente(s)', self._db.pending_count())

    def _handle_usb_snapshot(self, raw_devices: list[dict[str, Any]]) -> None:
        if not self._reporter:
            return
        devices = [self._build_usb_payload(device) for device in raw_devices]
        try:
            self._reporter.sync_usb_snapshot(devices)
            logger.info('Snapshot USB sincronizado: %d dispositivo(s) fisico(s)', len(devices))
        except Exception as exc:
            logger.warning('Falha ao sincronizar snapshot USB (tentara no heartbeat): %s', exc)

    def _sync_current_usb_snapshot(self) -> None:
        if self._monitor:
            self._handle_usb_snapshot(self._monitor.current_devices())


# =============================================================================
# Windows Service (pywin32)
# =============================================================================

try:
    import win32serviceutil   # type: ignore[import]
    import win32service       # type: ignore[import]
    import win32event         # type: ignore[import]
    import servicemanager     # type: ignore[import]

    class IN9USBAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = 'IN9USBAgent'
        _svc_display_name_ = 'IN9 USB Agent'
        _svc_description_ = 'Monitora conexões USB e reporta ao Inventário TI IN9 Automação'

        def __init__(self, args: Any):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_handle = win32event.CreateEvent(None, 0, 0, None)
            self._db = LocalDB(require_secure=True)
            self._core = AgentCore(self._db, service_context=True)

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._core.stop()
            win32event.SetEvent(self._stop_handle)

        def SvcDoRun(self) -> None:
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, '')
            )
            self._core.start()
            win32event.WaitForSingleObject(self._stop_handle, win32event.INFINITE)

    _HAS_WIN32 = True

except ImportError:
    _HAS_WIN32 = False
    IN9USBAgentService = None  # type: ignore[assignment,misc]
