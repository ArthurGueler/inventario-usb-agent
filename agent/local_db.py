# agent/local_db.py
"""
SQLite local — buffer de eventos offline + configurações do agente.

Tabelas:
  config  — pares chave/valor (server_url, token, machine_id)
  events  — fila de eventos USB pendentes de envio
"""

import sqlite3
import json
import logging
import threading
from pathlib import Path
from typing import Any

from .security_data import ensure_secure_data_dir

logger = logging.getLogger(__name__)

# Localização padrão:
#   Windows: C:\Program Files\IN9Automacao\USBAgent\data\agent.db
#   Linux/dev: subdiretório de dados do projeto (nunca o checkout inteiro)
def _default_db_path() -> Path:
    import sys
    if sys.platform == 'win32':
        base = Path(r'C:\Program Files\IN9Automacao\USBAgent\data')
    else:
        base = Path(__file__).parent.parent / 'data'
    return base / 'agent.db'

BATCH_SIZE = 50  # flush máximo de 50 eventos por vez


class LocalDB:
    def __init__(
        self,
        db_path: Path | None = None,
        *,
        require_secure: bool = False,
        security_backend: Any | None = None,
    ):
        self._path = db_path or _default_db_path()
        self._require_secure = require_secure
        self._security_backend = security_backend
        self._lock = threading.Lock()
        if require_secure:
            ensure_secure_data_dir(
                self._path.parent,
                backend=security_backend,
            )
        else:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        if require_secure:
            # SQLite may create -journal/WAL/SHM sidecars while opening the
            # database. Protect and verify them before the caller can network.
            ensure_secure_data_dir(
                self._path.parent,
                backend=security_backend,
            )

    @property
    def path(self) -> Path:
        return self._path

    @property
    def secure_required(self) -> bool:
        return self._require_secure

    def validate_security(self) -> None:
        if not self._require_secure:
            return
        # SQLite can create/recreate -journal, -wal and -shm files after the
        # initial database setup.  Repair and verify the complete tree here so
        # the service's pre-network check also covers those sidecars.
        ensure_secure_data_dir(
            self._path.parent,
            backend=self._security_backend,
        )

    # -------------------------------------------------------------------------
    # Inicialização
    # -------------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS config (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload     TEXT    NOT NULL,
                    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                    sent        INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_events_sent ON events(sent);
            """)

    def _connect(self) -> sqlite3.Connection:
        if self._require_secure:
            # Protect any sidecars left by the previous connection before a
            # new SQLite handle is opened.  This is deliberately fail-closed:
            # callers must not reach the network with an unverifiable store.
            ensure_secure_data_dir(
                self._path.parent,
                backend=self._security_backend,
            )
        conn = sqlite3.connect(str(self._path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # -------------------------------------------------------------------------
    # Config
    # -------------------------------------------------------------------------

    def get_config(self, key: str) -> str | None:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    'SELECT value FROM config WHERE key = ?', (key,)
                ).fetchone()
                return row['value'] if row else None

    def set_config(self, key: str, value: str) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    'INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)',
                    (key, value)
                )

    def delete_config(self, key: str) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute('DELETE FROM config WHERE key = ?', (key,))

    # Atalhos tipados
    @property
    def server_url(self) -> str | None:
        return self.get_config('server_url')

    @server_url.setter
    def server_url(self, value: str) -> None:
        self.set_config('server_url', value)

    @property
    def token(self) -> str | None:
        return self.get_config('token')

    @token.setter
    def token(self, value: str) -> None:
        self.set_config('token', value)

    @property
    def machine_id(self) -> str | None:
        return self.get_config('machine_id')

    @machine_id.setter
    def machine_id(self, value: str) -> None:
        self.set_config('machine_id', value)

    @property
    def agent_version(self) -> str:
        return self.get_config('agent_version') or '1.0.0'

    @agent_version.setter
    def agent_version(self, value: str) -> None:
        self.set_config('agent_version', value)

    @property
    def collaborator_name(self) -> str | None:
        return self.get_config('collaborator_name')

    @collaborator_name.setter
    def collaborator_name(self, value: str) -> None:
        self.set_config('collaborator_name', value)

    # -------------------------------------------------------------------------
    # Fila de eventos offline
    # -------------------------------------------------------------------------

    def enqueue_event(self, payload: dict[str, Any]) -> None:
        """Persiste um evento USB para envio posterior."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    'INSERT INTO events (payload) VALUES (?)',
                    (json.dumps(payload),)
                )
        logger.debug('Evento enfileirado (offline buffer): %s', payload.get('event_type'))

    def pop_pending_events(self) -> list[tuple[int, dict[str, Any]]]:
        """Retorna até BATCH_SIZE eventos não enviados. Retorna lista de (id, payload)."""
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    'SELECT id, payload FROM events WHERE sent = 0 ORDER BY id LIMIT ?',
                    (BATCH_SIZE,)
                ).fetchall()
                return [(row['id'], json.loads(row['payload'])) for row in rows]

    def mark_sent(self, event_ids: list[int]) -> None:
        """Marca eventos como enviados."""
        if not event_ids:
            return
        with self._lock:
            with self._connect() as conn:
                placeholders = ','.join('?' * len(event_ids))
                conn.execute(
                    f'UPDATE events SET sent = 1 WHERE id IN ({placeholders})',
                    event_ids
                )

    def pending_count(self) -> int:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    'SELECT COUNT(*) as n FROM events WHERE sent = 0'
                ).fetchone()
                return row['n']
