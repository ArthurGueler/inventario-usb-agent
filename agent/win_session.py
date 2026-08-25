# agent/win_session.py
"""
Primitivas para o servico (LocalSystem, sessao 0) agir dentro da sessao
interativa de quem esta logado.

Por que isso e necessario: um servico nao pode simplesmente dar Popen num app
de GUI. O processo nasceria na sessao 0, invisivel ao usuario — e, no caso do
Sankhya Web Connection, com o contexto de impressoras do SYSTEM em vez do
contexto do usuario, o que quebraria justamente a funcao do app.

A saida e CreateProcessAsUser com o token da sessao ativa.
"""

import logging
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger(__name__)


class Session(NamedTuple):
    id: int
    username: str          # 'DOMINIO\\usuario' ou apenas 'usuario'


def active_sessions() -> list[Session]:
    """
    Sessoes interativas com alguem logado. Cobre troca rapida de usuario e RDP,
    onde mais de uma pode estar ativa ao mesmo tempo.
    """
    try:
        import win32ts  # type: ignore[import]
    except ImportError:
        return []

    sessions: list[Session] = []
    try:
        enumerated = win32ts.WTSEnumerateSessions()
    except Exception as exc:
        logger.debug('WTSEnumerateSessions falhou: %s', exc)
        return []

    for entry in enumerated:
        if entry.get('State') != win32ts.WTSActive:
            continue
        session_id = entry['SessionId']
        try:
            user = win32ts.WTSQuerySessionInformation(
                win32ts.WTS_CURRENT_SERVER_HANDLE, session_id, win32ts.WTSUserName)
            domain = win32ts.WTSQuerySessionInformation(
                win32ts.WTS_CURRENT_SERVER_HANDLE, session_id, win32ts.WTSDomainName)
        except Exception:
            continue
        if not user:
            continue  # sessao ativa sem login (tela de bloqueio/console vazio)
        sessions.append(Session(session_id, f'{domain}\\{user}' if domain else user))

    return sessions


def user_token(session_id: int):
    """Token do usuario da sessao. Exige privilegio de SYSTEM. Feche com CloseHandle."""
    import win32ts  # type: ignore[import]
    return win32ts.WTSQueryUserToken(session_id)


def profile_dir(token) -> Path | None:
    """Pasta de perfil real do token — nem sempre bate com o nome da conta."""
    try:
        import win32profile  # type: ignore[import]
        return Path(win32profile.GetUserProfileDirectory(token))
    except Exception as exc:
        logger.debug('GetUserProfileDirectory falhou: %s', exc)
        return None


def is_running(exe_path: Path, username: str | None = None) -> bool:
    """
    Ha um processo rodando a partir de exe_path? Se username for informado,
    so conta se pertencer a ele — assim cada sessao e avaliada isoladamente.
    """
    try:
        import psutil  # type: ignore[import]
    except ImportError:
        return False

    target = str(exe_path).lower()
    wanted = username.lower() if username else None

    for proc in psutil.process_iter(['exe', 'username']):
        try:
            info = proc.info
            running = info.get('exe')
            if not running or running.lower() != target:
                continue
            if wanted and (info.get('username') or '').lower() != wanted:
                continue
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


def launch_as_user(token, command: str, cwd: Path | None = None) -> int | None:
    """
    Dispara `command` na sessao do token, no desktop interativo.
    Retorna o PID, ou None se falhar.
    """
    try:
        import win32con       # type: ignore[import]
        import win32process   # type: ignore[import]
        import win32profile   # type: ignore[import]
    except ImportError:
        return None

    environment = None
    try:
        environment = win32profile.CreateEnvironmentBlock(token, False)
    except Exception as exc:
        logger.debug('CreateEnvironmentBlock falhou (%s) — seguindo sem bloco', exc)

    startup = win32process.STARTUPINFO()
    # Sem isso o processo nasce sem desktop e nenhuma janela aparece
    startup.lpDesktop = 'winsta0\\default'

    flags = win32con.CREATE_NEW_CONSOLE
    if environment is not None:
        # Obrigatorio quando se passa um bloco vindo de CreateEnvironmentBlock
        flags |= win32con.CREATE_UNICODE_ENVIRONMENT

    try:
        handle, _thread, pid, _tid = win32process.CreateProcessAsUser(
            token,
            None,               # lpApplicationName — vem embutido em command
            command,
            None, None, False,
            flags,
            environment,
            str(cwd) if cwd else None,
            startup,
        )
        if handle:
            handle.Close()
        return pid
    except Exception as exc:
        logger.warning('CreateProcessAsUser falhou: %s', exc)
        return None
