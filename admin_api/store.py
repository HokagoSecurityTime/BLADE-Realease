"""SQLite is authoritative. Files are synchronized mirrors under the write lock."""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import json
import os
from threading import RLock

from common.schema import DetectionLog, Policy, PolicyStatus, policy_from_yaml, policy_to_yaml
from pipeline import generator
from common.features import enabled
from common.redis_policy import publish


class NotFoundError(ValueError):
    pass


class ConflictError(ValueError):
    pass


class Store:
    def __init__(self, db_path: str | Path, policy_dir: str | Path, detection_file: str | Path) -> None:
        self.db_path = Path(db_path)
        self.policy_dir = Path(policy_dir)
        self.detection_file = Path(detection_file)
        self.lock = RLock()

    @contextmanager
    def connection(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            if write:
                conn.execute('BEGIN IMMEDIATE')
            with conn:
                yield conn
        finally:
            conn.close()

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.policy_dir.mkdir(parents=True, exist_ok=True)
        self.detection_file.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS policies (
                    id TEXT PRIMARY KEY, yaml_text TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('PENDING','ACTIVE','REJECTED')),
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS detections (
                    ts TEXT NOT NULL, request_id TEXT NOT NULL, sub TEXT NOT NULL,
                    method TEXT NOT NULL, path TEXT NOT NULL, policy_id TEXT NOT NULL,
                    label TEXT NOT NULL, verdict TEXT NOT NULL CHECK(verdict IN ('PASS','BLOCK','OBSERVE')),
                    reason TEXT NOT NULL
                );
            ''')
            columns = {row['name'] for row in conn.execute('PRAGMA table_info(detections)')}
            for name, ddl in [('mode', "TEXT NOT NULL DEFAULT 'observe'"),
                              ('explanation', 'TEXT'), ('would_block', 'INTEGER NOT NULL DEFAULT 0')]:
                if enabled('BLADE_PHASE2_ENABLED') and name not in columns:
                    conn.execute(f'ALTER TABLE detections ADD COLUMN {name} {ddl}')
            if enabled('BLADE_PHASE2_ENABLED'):
                conn.executescript('''
                    CREATE INDEX IF NOT EXISTS detections_request_id ON detections(request_id);
                    CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS worker_cursors (name TEXT PRIMARY KEY, seq INTEGER NOT NULL);
                ''')
                from admin_api.proposals import initialize
                initialize(conn)

    def alert_settings(self) -> dict[str, str]:
        with self.connection() as conn:
            row = conn.execute("SELECT value FROM settings WHERE name='alerts'").fetchone()
        return json.loads(row['value']) if row else dict(slack_webhook=os.getenv('BLADE_SLACK_WEBHOOK', ''),
            discord_webhook=os.getenv('BLADE_DISCORD_WEBHOOK', ''), min_severity='observe')

    def save_alert_settings(self, value: dict[str, str]) -> dict[str, str]:
        with self.connection(write=True) as conn:
            conn.execute("INSERT INTO settings(name,value) VALUES ('alerts',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                         (json.dumps(value),))
        return value

    def set_explanation(self, identifier: str, explanation: str) -> DetectionLog:
        with self.connection(write=True) as conn:
            cursor = conn.execute('UPDATE detections SET explanation=? WHERE request_id=?', (explanation, identifier))
            if not cursor.rowcount:
                raise NotFoundError('Detection not found')
            row = conn.execute('SELECT * FROM detections WHERE request_id=? ORDER BY rowid DESC LIMIT 1', (identifier,)).fetchone()
        return DetectionLog.model_validate(dict(row))

    def worker_batch(self, name: str) -> list[tuple[int, DetectionLog]]:
        with self.connection(write=True) as conn:
            row = conn.execute('SELECT seq FROM worker_cursors WHERE name=?', (name,)).fetchone()
            if row is None:
                latest = conn.execute('SELECT COALESCE(MAX(rowid),0) FROM detections').fetchone()[0]
                conn.execute('INSERT INTO worker_cursors VALUES (?,?)', (name, latest))
                return []
            rows = conn.execute('SELECT rowid AS seq,* FROM detections WHERE rowid>? ORDER BY rowid LIMIT 100', (row['seq'],)).fetchall()
        return [(row['seq'], DetectionLog.model_validate({k: row[k] for k in row.keys() if k != 'seq'})) for row in rows]

    def checkpoint_worker(self, name: str, seq: int) -> None:
        with self.connection(write=True) as conn:
            conn.execute('UPDATE worker_cursors SET seq=? WHERE name=?', (seq, name))

    @staticmethod
    def _get(conn: sqlite3.Connection, identifier: str) -> Policy:
        row = conn.execute('SELECT yaml_text FROM policies WHERE id=?', (identifier,)).fetchone()
        if row is None:
            raise NotFoundError('Policy not found')
        return policy_from_yaml(row['yaml_text'])

    def get(self, identifier: str) -> Policy:
        with self.connection() as conn:
            return self._get(conn, identifier)

    def list_policies(self, status: PolicyStatus | None = None) -> list[Policy]:
        with self.connection() as conn:
            rows = conn.execute('SELECT yaml_text FROM policies WHERE (? IS NULL OR status=?) ORDER BY id',
                                (status, status)).fetchall()
        return [policy_from_yaml(row['yaml_text']) for row in rows]

    def insert_many(self, policies: list[Policy], contexts: dict[str, dict] | None = None) -> list[Policy]:
        with self.lock:
            previous: dict[Path, bytes | None] = {}
            try:
                with self.connection(write=True) as conn:
                    ids = [policy.id for policy in policies]
                    if len(ids) != len(set(ids)):
                        raise ConflictError('Generated policy ids collide')
                    if any(conn.execute('SELECT 1 FROM policies WHERE id=?', (identifier,)).fetchone() for identifier in ids):
                        raise ConflictError('Policy already exists; edit it through PUT')
                    for policy in policies:
                        conn.execute('INSERT INTO policies VALUES (?,?,?,?,?)', (
                            policy.id, policy_to_yaml(policy), policy.status.value,
                            policy.created_at.isoformat(), datetime.now(timezone.utc).isoformat()))
                        self._mirror(policy, previous)
                        if contexts and policy.id in contexts and enabled('BLADE_REANALYSIS_ENABLED'):
                            conn.execute('INSERT INTO generation_contexts VALUES (?,?)', (policy.id, json.dumps(contexts[policy.id], ensure_ascii=False)))
            except Exception:
                self._restore(previous)
                raise
        return policies

    def _mirror(self, policy: Policy, previous: dict[Path, bytes | None]) -> None:
        # Validate the id before constructing paths used for backup/restore.
        import re
        if not re.fullmatch(r'pol_[A-Za-z0-9_]+', policy.id):
            raise ValueError('Unsafe policy id')
        path = self.policy_dir / f'{policy.id}.yaml'
        previous[path] = path.read_bytes() if path.exists() else None
        generator.save_policy(policy, self.policy_dir)

    @staticmethod
    def _restore(previous: dict[Path, bytes | None]) -> None:
        for path, data in previous.items():
            if data is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(data)

    def update(self, identifier: str, changes: dict[str, object] | None = None,
               transition: tuple[PolicyStatus, PolicyStatus] | None = None,
               mode: str | None = None) -> Policy:
        with self.lock:
            previous: dict[Path, bytes | None] = {}
            try:
                with self.connection(write=True) as conn:
                    policy = self._get(conn, identifier)
                    if transition:
                        source, target = transition
                        if policy.status != source:
                            raise ConflictError(f'{policy.status.value} cannot transition to {target.value}')
                        policy = policy.model_copy(update={'status': target})
                        if source == PolicyStatus.ACTIVE and target == PolicyStatus.PENDING and enabled('BLADE_REANALYSIS_ENABLED'):
                            conn.execute('INSERT INTO reanalysis_events(policy_id,kind,created_at) VALUES (?,?,?)',
                                         (identifier,'rollback',datetime.now(timezone.utc).isoformat()))
                        if target == PolicyStatus.ACTIVE:
                            policy = policy.model_copy(update={'mode': 'observe'})
                    elif mode is not None:
                        if policy.status != PolicyStatus.ACTIVE:
                            raise ConflictError('Only ACTIVE policies can change mode')
                        policy = Policy.model_validate({**policy.model_dump(), 'mode': mode})
                    elif changes is not None:
                        if changes['id'] != identifier or changes['created_at'] != policy.created_at:
                            raise ConflictError('id and created_at are immutable')
                        if enabled('BLADE_PHASE2_ENABLED'):
                            if changes.get('mode', policy.mode) != policy.mode:
                                raise ConflictError('Use the mode endpoint to change mode')
                            changes = {**changes, 'mode': policy.mode, 'version': policy.version + 1, 'source': 'manual'}
                        policy = Policy.model_validate({**changes, 'status': policy.status})
                    conn.execute('UPDATE policies SET yaml_text=?,status=?,updated_at=? WHERE id=?', (
                        policy_to_yaml(policy), policy.status.value, datetime.now(timezone.utc).isoformat(), identifier))
                    self._mirror(policy, previous)
            except Exception:
                self._restore(previous)
                raise
            publish(self.list_policies(PolicyStatus.ACTIVE))
        return policy

    def append_detection(self, detection: DetectionLog) -> DetectionLog:
        self.append_detections([detection])
        return detection

    def append_detections(self, detections: list[DetectionLog], *, deduplicate: bool = False) -> None:
        """Commit a delivery batch atomically without changing the HTTP API."""
        with self.lock:
            with self.connection(write=True) as conn:
                if deduplicate:
                    unique = {d.request_id: d for d in detections}
                    placeholders = ','.join('?' for _ in unique)
                    existing = {r[0] for r in conn.execute(
                        f'SELECT request_id FROM detections WHERE request_id IN ({placeholders})', list(unique))}
                    detections = [d for key, d in unique.items() if key not in existing]
                    if not detections:
                        return
                # Keep file rollback inside the SQLite transaction on append errors.
                with self.detection_file.open('a+b') as stream:
                    stream.seek(0, 2)
                    old_size = stream.tell()
                    try:
                        columns = {row['name'] for row in conn.execute('PRAGMA table_info(detections)')}
                        extended = 'mode' in columns
                        fields = 'ts,request_id,sub,method,path,policy_id,label,verdict,reason'
                        if extended:
                            fields += ',mode,explanation,would_block'
                        placeholders = ','.join(':' + name for name in fields.split(','))
                        conn.executemany(f'INSERT INTO detections ({fields}) VALUES ({placeholders})',
                            [d.model_dump(mode='json', context={'storage': True}) for d in detections])
                        stream.write(''.join(d.model_dump_json(context={'storage': extended}) + '\n'
                            for d in detections).encode('utf-8'))
                        stream.flush()
                        conn.commit()
                    except Exception:
                        stream.truncate(old_size)
                        raise

    def list_detections(self, limit: int) -> list[DetectionLog]:
        with self.connection() as conn:
            rows = conn.execute('SELECT * FROM detections ORDER BY rowid DESC LIMIT ?', (limit,)).fetchall()
        return [DetectionLog.model_validate(dict(row)) for row in rows]
