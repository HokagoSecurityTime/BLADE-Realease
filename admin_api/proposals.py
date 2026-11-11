"""Durable reanalysis context, events and human-reviewed proposals."""
from __future__ import annotations
from datetime import datetime, timezone
import json
import sqlite3
import time

from admin_api.store import Store, ConflictError, NotFoundError
from common.redis_policy import publish
from common.schema import Policy, PolicyStatus, policy_from_yaml, policy_to_yaml


def initialize(conn: sqlite3.Connection) -> None:
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS generation_contexts(policy_id TEXT PRIMARY KEY, context_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS reanalysis_events(id INTEGER PRIMARY KEY AUTOINCREMENT, policy_id TEXT NOT NULL, kind TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS reanalysis_jobs(policy_id TEXT PRIMARY KEY, lease_until REAL NOT NULL DEFAULT 0, last_rowid INTEGER NOT NULL DEFAULT 0, last_event INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS proposals(id INTEGER PRIMARY KEY AUTOINCREMENT, policy_id TEXT NOT NULL, base_version INTEGER NOT NULL, base_yaml TEXT NOT NULL, proposed_yaml TEXT NOT NULL, diff_summary TEXT NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING');
        CREATE UNIQUE INDEX IF NOT EXISTS one_pending_proposal ON proposals(policy_id) WHERE status='PENDING';
    ''')


class Proposals:
    def __init__(self, store: Store) -> None:
        self.store = store

    def list(self, policy_id: str) -> list[dict]:
        self.store.get(policy_id)
        with self.store.connection() as conn:
            return [dict(row) for row in conn.execute('SELECT * FROM proposals WHERE policy_id=? ORDER BY id DESC', (policy_id,))]

    def context(self, policy_id: str) -> dict | None:
        with self.store.connection() as conn:
            row = conn.execute('SELECT context_json FROM generation_contexts WHERE policy_id=?', (policy_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def inputs(self, policy_id: str) -> tuple[list[dict], int, int]:
        with self.store.connection() as conn:
            state = conn.execute('SELECT * FROM reanalysis_jobs WHERE policy_id=?', (policy_id,)).fetchone()
            last_row, last_event = (state['last_rowid'], state['last_event']) if state else (0, 0)
            rows = [dict(row) for row in conn.execute('SELECT rowid AS seq,* FROM detections WHERE policy_id=? AND rowid>? ORDER BY rowid LIMIT 10000', (policy_id, last_row))]
            event = conn.execute('SELECT MAX(id) FROM reanalysis_events WHERE policy_id=? AND id>?', (policy_id, last_event)).fetchone()[0]
        return rows, max([last_row] + [r['seq'] for r in rows]), event or last_event

    def rollback_pending(self, policy_id: str, event: int) -> bool:
        with self.store.connection() as conn:
            row = conn.execute('SELECT last_event FROM reanalysis_jobs WHERE policy_id=?', (policy_id,)).fetchone()
        return event > (row[0] if row else 0)

    def claim(self, policy_id: str) -> bool:
        with self.store.connection(write=True) as conn:
            if conn.execute("SELECT 1 FROM proposals WHERE policy_id=? AND status='PENDING'", (policy_id,)).fetchone():
                return False
            conn.execute('INSERT OR IGNORE INTO reanalysis_jobs(policy_id) VALUES (?)', (policy_id,))
            return conn.execute('UPDATE reanalysis_jobs SET lease_until=? WHERE policy_id=? AND lease_until<?',
                                (time.time()+600, policy_id, time.time())).rowcount == 1

    def finish(self, policy_id: str, rowid: int, event: int) -> None:
        with self.store.connection(write=True) as conn:
            conn.execute('UPDATE reanalysis_jobs SET lease_until=0,last_rowid=?,last_event=? WHERE policy_id=?', (rowid,event,policy_id))

    def release(self, policy_id: str) -> None:
        with self.store.connection(write=True) as conn:
            # Back off missing context/provider failures instead of hammering LLM.
            conn.execute('UPDATE reanalysis_jobs SET lease_until=? WHERE policy_id=?', (time.time()+60,policy_id))

    def create(self, original: Policy, proposed: Policy, reason: str) -> dict:
        changes = [key for key in ('label','params','confidence','evidence','evidence_refs')
                   if original.model_dump()[key] != proposed.model_dump()[key]]
        with self.store.connection(write=True) as conn:
            if policy_to_yaml(self.store._get(conn, original.id)) != policy_to_yaml(original):
                raise ConflictError('Policy changed during reanalysis')
            try:
                cursor = conn.execute('INSERT INTO proposals(policy_id,base_version,base_yaml,proposed_yaml,diff_summary,reason,created_at) VALUES (?,?,?,?,?,?,?)',
                    (original.id, original.version, policy_to_yaml(original), policy_to_yaml(proposed),
                     'Changed: '+', '.join(changes) if changes else 'No classification change', reason, datetime.now(timezone.utc).isoformat()))
            except sqlite3.IntegrityError as exc:
                raise ConflictError('A pending proposal already exists') from exc
            return dict(conn.execute('SELECT * FROM proposals WHERE id=?', (cursor.lastrowid,)).fetchone())

    def decide(self, identifier: int, accept: bool) -> dict | Policy:
        previous = {}
        with self.store.lock:
            try:
                with self.store.connection(write=True) as conn:
                    row = conn.execute('SELECT * FROM proposals WHERE id=?', (identifier,)).fetchone()
                    if row is None:
                        raise NotFoundError('Proposal not found')
                    if row['status'] != 'PENDING':
                        raise ConflictError('Proposal already decided')
                    if accept:
                        current = self.store._get(conn, row['policy_id'])
                        if current.status == PolicyStatus.REJECTED or policy_to_yaml(current) != row['base_yaml']:
                            raise ConflictError('Stale proposal; dismiss and request a new analysis')
                        proposed = policy_from_yaml(row['proposed_yaml'])
                        updated = proposed.model_copy(update=dict(id=current.id, endpoint=current.endpoint,
                            created_at=current.created_at, status=current.status, version=current.version+1, source='reanalysis', mode='observe'))
                        conn.execute('UPDATE policies SET yaml_text=?,updated_at=? WHERE id=?',
                                     (policy_to_yaml(updated), datetime.now(timezone.utc).isoformat(), updated.id))
                        self.store._mirror(updated, previous)
                    conn.execute('UPDATE proposals SET status=? WHERE id=?', ('ACCEPTED' if accept else 'DISMISSED', identifier))
            except Exception:
                self.store._restore(previous)
                raise
            if accept:
                publish(self.store.list_policies(PolicyStatus.ACTIVE))
                return updated
        return {**dict(row), 'status': 'DISMISSED'}
