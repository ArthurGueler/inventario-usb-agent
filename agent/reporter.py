# agent/reporter.py
"""
HTTP client para o servidor do Inventário TI.
Todas as chamadas incluem o header X-Agent-Token.
Nunca loga o token em texto claro — apenas os últimos 8 chars.
"""

import logging
import socket
from typing import Any

import requests

logger = logging.getLogger(__name__)

TIMEOUT = 10  # segundos por request


class Reporter:
    def __init__(self, server_url: str, token: str):
        self._base = server_url.rstrip('/')
        self._token = token
        self._session = requests.Session()
        self._session.headers.update({
            'X-Agent-Token': token,
            'Content-Type': 'application/json',
            'User-Agent': 'IN9USBAgent/1.0',
        })

    # -------------------------------------------------------------------------
    # Helpers internos
    # -------------------------------------------------------------------------

    def _token_hint(self) -> str:
        """Retorna apenas os últimos 8 chars do token para logs."""
        return f'...{self._token[-8:]}' if len(self._token) >= 8 else '***'

    def set_token(self, token: str) -> None:
        """Atualiza o token usado nas próximas requisições (ex: após um register-new de recuperação)."""
        self._token = token
        self._session.headers['X-Agent-Token'] = token

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f'{self._base}{path}'
        response = self._session.post(url, json=payload, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()

    def _get(self, path: str) -> dict[str, Any]:
        url = f'{self._base}{path}'
        response = self._session.get(url, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()

    # -------------------------------------------------------------------------
    # Rotas do agente
    # -------------------------------------------------------------------------

    def register_new(
        self,
        hostname: str,
        mac_address: str | None,
        bios_serial: str | None,
        collaborator_name: str | None = None,
        anydesk_id: str | None = None,
        agent_version: str | None = None,
        specs: dict[str, Any] | None = None,
        registration_reason: str | None = None,
    ) -> dict[str, Any]:
        """
        POST /api/agent/register/new — primeira instalação, sem token.
        Retorna machine_id e token gerado pelo servidor.
        """
        url = f'{self._base}/api/agent/register/new'
        payload: dict[str, Any] = {'hostname': hostname}
        if mac_address:
            payload['mac_address'] = mac_address
        if bios_serial:
            payload['bios_serial'] = bios_serial
        if collaborator_name:
            payload['collaborator_name'] = collaborator_name
        if anydesk_id:
            payload['anydesk_id'] = anydesk_id
        if agent_version:
            payload['agent_version'] = agent_version
        if specs:
            payload['specs'] = specs
        if registration_reason:
            payload['registration_reason'] = registration_reason

        # Esta rota é pública — não usa o header X-Agent-Token
        # O token é enviado no body para o servidor armazená-lo
        payload['token'] = self._token
        resp = requests.post(url, json=payload, timeout=TIMEOUT,
                             headers={'Content-Type': 'application/json',
                                      'User-Agent': 'IN9USBAgent/1.0'})
        resp.raise_for_status()
        return resp.json()

    def register(self, hostname: str, agent_version: str, specs: dict[str, Any]) -> dict[str, Any]:
        """POST /api/agent/register — atualiza specs e versão."""
        logger.debug('Registrando agente (token: %s)', self._token_hint())
        return self._post('/api/agent/register', {
            'hostname': hostname,
            'agent_version': agent_version,
            'specs': specs,
        })

    def heartbeat(self, agent_version: str | None = None) -> dict[str, Any]:
        """POST /api/agent/heartbeat — atualiza last_seen e envia runtime stats."""
        from .specs import get_runtime_stats
        logger.debug('Heartbeat (token: %s)', self._token_hint())
        payload = get_runtime_stats()
        if agent_version:
            payload['agent_version'] = agent_version
        return self._post('/api/agent/heartbeat', payload)

    def send_usb_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """POST /api/agent/usb-event — reporta um evento USB."""
        logger.debug('Enviando evento USB: %s %s', event.get('event_type'), event.get('friendly_name'))
        return self._post('/api/agent/usb-event', event)

    def sync_usb_snapshot(self, devices: list[dict[str, Any]]) -> dict[str, Any]:
        """POST /api/agent/usb-snapshot - reconcilia o estado USB fisico atual."""
        logger.debug('Sincronizando snapshot USB: %d dispositivo(s)', len(devices))
        return self._post('/api/agent/usb-snapshot', {'devices': devices})

    def check_version(self) -> dict[str, Any]:
        """GET /api/agent/version — verifica se há update disponível."""
        return self._get('/api/agent/version')

    def list_packages(self) -> dict[str, Any]:
        """GET /api/agent/packages — manifesto de software que deve estar instalado."""
        return self._get('/api/agent/packages')

    def report_health(self, code: str, level: str = 'info', message: str | None = None, context: dict[str, Any] | None = None) -> None:
        """POST /api/agent/health-report — reporta erro/evento interno. Falha silenciosa."""
        try:
            self._post('/api/agent/health-report', {
                'level':   level,
                'code':    code,
                'message': message,
                'context': context,
            })
        except Exception:
            pass  # Telemetria não pode quebrar o fluxo principal

    def download_anydesk(self, dest: 'Path') -> None:
        """GET /api/agent/download-anydesk — baixa o instalador do AnyDesk para dest."""
        from pathlib import Path as _Path
        url = f'{self._base}/api/agent/download-anydesk'
        with self._session.get(url, stream=True, timeout=120) as resp:
            resp.raise_for_status()
            with open(dest, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=65536):
                    f.write(chunk)

    # -------------------------------------------------------------------------
    # Utilitários de conectividade
    # -------------------------------------------------------------------------

    def is_online(self) -> bool:
        """Verifica conectividade básica com o servidor (TCP, sem auth)."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self._base)
            host = parsed.hostname or '127.0.0.1'
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            with socket.create_connection((host, port), timeout=3):
                return True
        except OSError:
            return False
