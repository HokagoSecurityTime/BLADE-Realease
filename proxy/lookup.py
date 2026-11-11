import asyncio
import re
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs
from common.schema import OwnerLookup


class LookupError(RuntimeError):
    pass


class Lookup:
    def __init__(self, dsn: str) -> None:
        if not dsn.startswith('sqlite:///'):
            raise ValueError('This version supports read-only SQLite DSNs')
        location = dsn[len('sqlite:///'):]
        if location.startswith('file:'):
            path, _, query = location.partition('?')
            if parse_qs(query).get('mode') != ['ro']:
                raise ValueError('SQLite URI must use mode=ro')
            self.uri = path + '?mode=ro'
        else:
            self.uri = Path(location).resolve().as_uri() + '?mode=ro'

    async def get(self, spec: OwnerLookup, identifier: str) -> dict[str, object] | None:
        return await asyncio.to_thread(self._get, spec, identifier)

    def _get(self, spec: OwnerLookup, identifier: str) -> dict[str, object] | None:
        result = self._get_many([(spec, identifier)])[0]
        if isinstance(result, Exception):
            raise result
        return result

    def _get_many(self, requests: list[tuple[OwnerLookup, str]]) -> list[dict[str, object] | None | LookupError]:
        try:
            conn = sqlite3.connect(self.uri, uri=True, timeout=2)
            try:
                conn.row_factory = sqlite3.Row
                conn.execute('PRAGMA query_only=ON')
                results: list[dict[str, object] | None | LookupError] = []
                for spec, identifier in requests:
                    try:
                        results.append(self._query(conn, spec, identifier))
                    except (sqlite3.Error, LookupError):
                        results.append(LookupError('Ownership query unavailable'))
                return results
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise LookupError('Ownership database unavailable') from exc

    @staticmethod
    def _query(conn: sqlite3.Connection, spec: OwnerLookup, identifier: str) -> dict[str, object] | None:
        names = [spec.table, spec.id_col] + [c for c in (spec.owner_col, spec.tenant_col) if c]
        if any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name) for name in names):
            raise LookupError('Invalid lookup identifier')
        columns = list(dict.fromkeys(c for c in (spec.owner_col, spec.tenant_col) if c))
        if not columns:
            raise LookupError('Missing ownership columns')
        projection = ', '.join(f'"{column}"' for column in columns)
        row = conn.execute(f'SELECT {projection} FROM "{spec.table}" WHERE "{spec.id_col}"=?', (identifier,)).fetchone()
        return dict(row) if row else None


class BatchedLookup:
    """Share a read-only connection for requests arriving in the same loop turn."""
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        self.pending: list[tuple[OwnerLookup, str, asyncio.Future]] = []
        self.scheduled = False
        self.tasks: set[asyncio.Task] = set()

    async def get(self, spec: OwnerLookup, identifier: str) -> dict[str, object] | None:
        future = asyncio.get_running_loop().create_future()
        self.pending.append((spec, identifier, future))
        if not self.scheduled:
            self.scheduled = True
            task = asyncio.create_task(self._flush())
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
        return await asyncio.shield(future)

    async def _flush(self) -> None:
        batch, self.pending = self.pending, []
        self.scheduled = False
        try:
            source = Lookup(self.dsn)
            for offset in range(0, len(batch), 256):
                part = batch[offset:offset + 256]
                rows = await asyncio.to_thread(source._get_many, [(spec, key) for spec, key, _ in part])
                for (_, _, future), row in zip(part, rows):
                    if not future.done():
                        if isinstance(row, Exception):
                            future.set_exception(row)
                        else:
                            future.set_result(row)
        except Exception as exc:
            for _, _, future in batch:
                if not future.done(): future.set_exception(exc)

    async def close(self) -> None:
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
