# agent/__main__.py
"""
Entry point do agente IN9USBAgent.

Uso:
    # Modo standalone (dev/teste) — com ícone na bandeja:
    python -m agent run

    # Instalar/gerenciar Windows Service:
    python -m agent install
    python -m agent start
    python -m agent stop
    python -m agent remove

    # Configurar antes de instalar:
    python -m agent config --url https://inventario.in9automacao.com.br --token <TOKEN>

    # Primeira instalação (cria novo registro no servidor):
    python -m agent register-new --url <URL> --token <TOKEN>

    # Ícone na bandeja (roda como processo do usuário, separado do serviço):
    python -m agent tray
"""

import argparse
import logging
import logging.handlers
import sys

# Forçar UTF-8 no stdout para evitar caracteres quebrados no console Windows
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


import os

_LOG_FILE = os.path.join(
    os.environ.get('PROGRAMFILES', 'C:\\Program Files'),
    'IN9Automacao', 'USBAgent', 'agent.log'
)

_fmt = logging.Formatter(
    fmt='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)

class _FlushHandler(logging.StreamHandler):
    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()

_handlers: list[logging.Handler] = [_FlushHandler(sys.stdout)]

try:
    _file_handler = logging.handlers.RotatingFileHandler(
        _LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=2, encoding='utf-8'
    )
    _file_handler.setFormatter(_fmt)
    _handlers.append(_file_handler)
except Exception:
    pass

for _h in _handlers:
    _h.setFormatter(_fmt)

logging.basicConfig(level=logging.INFO, handlers=_handlers)
logger = logging.getLogger('agent')


def _get_db():
    from .local_db import LocalDB
    return LocalDB()


# =============================================================================
# Dispatch como Windows Service (sem argumentos — chamado pelo SCM)
# =============================================================================

def _dispatch_as_service() -> None:
    """
    Chamado quando o Windows SCM inicia o serviço (exe rodando sem argumentos).
    Registra o handler do serviço e aguarda o SCM.
    """
    import servicemanager          # type: ignore[import]
    from .service import IN9USBAgentService

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(IN9USBAgentService)
    servicemanager.StartServiceCtrlDispatcher()


# =============================================================================
# Comandos CLI
# =============================================================================

def cmd_run(args: argparse.Namespace) -> None:
    """
    Roda o agente em modo standalone (foreground) sem instalar como serviço.
    Útil para testes. Não exibe ícone na bandeja — use 'tray' para isso.
    """
    from .local_db import LocalDB
    from .service import AgentCore

    db = LocalDB()
    core = AgentCore(db)
    core.start()
    try:
        core.wait()
    except KeyboardInterrupt:
        logger.info('Interrompido pelo usuário.')
        core.stop()


def cmd_tray(args: argparse.Namespace) -> None:
    """
    Exibe o ícone na bandeja do sistema.
    Deve ser iniciado como processo do usuário (não como serviço).
    Registrado no startup do Windows pelo instalador.
    """
    from .tray import TrayIcon

    tray = TrayIcon()
    if not tray._available:
        logger.error('pystray/Pillow não disponíveis — tray não pode iniciar.')
        sys.exit(1)

    tray.run()  # bloqueia na thread principal até o processo ser encerrado


def cmd_config(args: argparse.Namespace) -> None:
    """Salva server_url, token e nome do colaborador no SQLite local."""
    import secrets
    db = _get_db()
    if args.url:
        db.server_url = args.url
        print(f'server_url salvo: {args.url}')
    if args.token:
        db.token = args.token
        print(f'token salvo: ...{args.token[-8:]}')
    elif not db.token:
        token = secrets.token_hex(32)
        db.token = token
        print(f'token gerado automaticamente: ...{token[-8:]}')
    if args.user_name:
        db.collaborator_name = args.user_name
        print(f'nome do colaborador salvo: {args.user_name}')


def cmd_register_new(args: argparse.Namespace) -> None:
    """Cria novo registro no servidor (primeira instalação)."""
    import socket
    from .reporter import Reporter
    from .local_db import LocalDB
    from .specs import capture_machine_specs
    from .service import AGENT_VERSION

    db = LocalDB()
    url = args.url or db.server_url
    token = args.token or db.token

    if not url or not token:
        print('Erro: informe --url e --token (ou configure via "config")')
        sys.exit(1)

    db.server_url = url
    db.token = token

    reporter = Reporter(server_url=url, token=token)
    specs = capture_machine_specs()
    hostname = specs.get('hostname') or socket.gethostname()

    collaborator_name = db.collaborator_name

    try:
        resp = reporter.register_new(
            hostname=hostname,
            mac_address=specs.get('mac_address'),
            bios_serial=specs.get('bios_serial'),
            collaborator_name=collaborator_name,
            anydesk_id=specs.get('anydesk_id'),
            agent_version=AGENT_VERSION,
            specs=specs,
            registration_reason='installation',
        )
        print('Registro OK:', resp)
        data = resp.get('data') or resp
        if data.get('machine_id'):
            db.machine_id = data['machine_id']
        if data.get('token'):
            db.token = data['token']
            print(f'Token recebido: ...{data["token"][-8:]}')
    except Exception as exc:
        print(f'Erro ao registrar: {exc}')
        sys.exit(1)


def cmd_install_anydesk(args: argparse.Namespace) -> None:
    """
    Garante que o AnyDesk ID chegue ao servidor:
      Caso 1: AnyDesk já instalado → captura ID e re-registra
      Caso 2: AnyDesk não instalado → instala, captura ID e re-registra
    """
    import socket
    from .local_db import LocalDB
    from .reporter import Reporter
    from .anydesk import ensure_anydesk, is_installed
    from .specs import get_anydesk_id, capture_machine_specs

    db = LocalDB()
    url = db.server_url
    token = db.token
    if not url or not token:
        print('Erro: agente não configurado. Execute "config" primeiro.')
        sys.exit(1)

    reporter = Reporter(server_url=url, token=token)

    if is_installed():
        anydesk_id = get_anydesk_id()
        if anydesk_id:
            print(f'AnyDesk já instalado — ID: {anydesk_id}')
        else:
            print('AnyDesk instalado mas ID ainda não disponível em service.conf')
    else:
        print('Baixando e instalando AnyDesk...')
        anydesk_id = ensure_anydesk(reporter)
        if anydesk_id:
            print(f'AnyDesk instalado — ID: {anydesk_id}')
        else:
            print('AnyDesk não instalado (instalador pode não estar disponível no servidor).')

    # Sempre que tivermos um ID, re-registrar para garantir que o servidor saiba
    if anydesk_id:
        try:
            specs = capture_machine_specs()
            hostname = specs.get('hostname') or socket.gethostname()
            from .service import AGENT_VERSION
            reporter.register(
                hostname=hostname,
                agent_version=AGENT_VERSION,
                specs=specs,
            )
            print(f'Servidor atualizado com AnyDesk ID: {anydesk_id}')
        except Exception as exc:
            print(f'Aviso: falha ao re-registrar com AnyDesk ID ({exc}) — serviço retentará no heartbeat')


def cmd_service(args: argparse.Namespace) -> None:
    """Delega ao win32serviceutil para instalar/start/stop/remove o serviço."""
    from .service import _HAS_WIN32, IN9USBAgentService

    if not _HAS_WIN32:
        print('Erro: pywin32 não está disponível.')
        sys.exit(1)

    import win32serviceutil  # type: ignore[import]
    sys.argv = [sys.argv[0], args.action]
    win32serviceutil.HandleCommandLine(IN9USBAgentService)


# =============================================================================
# Entry point
# =============================================================================

def main() -> None:
    # Sem argumentos = Windows SCM iniciando o serviço
    if len(sys.argv) == 1:
        try:
            _dispatch_as_service()
        except Exception as exc:
            logger.error('Falha ao despachar serviço: %s', exc)
            sys.exit(1)
        return

    parser = argparse.ArgumentParser(prog='usb_agent', description='IN9USBAgent')
    sub = parser.add_subparsers(dest='command', required=True)

    sub.add_parser('run',  help='Roda em modo standalone (foreground)')
    sub.add_parser('tray', help='Exibe ícone na bandeja (processo do usuário)')

    p_cfg = sub.add_parser('config', help='Salva configurações locais')
    p_cfg.add_argument('--url',       help='URL do servidor')
    p_cfg.add_argument('--token',     help='Token do agente')
    p_cfg.add_argument('--user-name', help='Nome do colaborador responsável pela máquina')

    p_reg = sub.add_parser('register-new', help='Registra no servidor')
    p_reg.add_argument('--url',   help='URL do servidor')
    p_reg.add_argument('--token', help='Token do agente')

    sub.add_parser('install-anydesk', help='Baixa e instala AnyDesk do servidor')

    for action in ('install', 'start', 'stop', 'remove', 'restart'):
        p = sub.add_parser(action, help=f'Windows Service: {action}')
        p.set_defaults(action=action)

    args = parser.parse_args()

    if args.command == 'run':
        cmd_run(args)
    elif args.command == 'tray':
        cmd_tray(args)
    elif args.command == 'config':
        cmd_config(args)
    elif args.command == 'register-new':
        cmd_register_new(args)
    elif args.command == 'install-anydesk':
        cmd_install_anydesk(args)
    else:
        cmd_service(args)


if __name__ == '__main__':
    main()
