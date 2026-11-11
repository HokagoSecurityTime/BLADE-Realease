"""Monotonic, rolling 60-second counters; recording performs no I/O."""
from collections import deque
from collections.abc import Callable
from time import monotonic


class Observability:
    def __init__(self, clock: Callable[[], float] = monotonic) -> None:
        self.clock = clock
        self.events: deque[tuple[float, bool, bool]] = deque()
        self.with_policy = 0
        self.lookup_ok = 0

    def _expire(self) -> None:
        cutoff = self.clock() - 60
        while self.events and self.events[0][0] <= cutoff:
            _, matched, lookup = self.events.popleft()
            self.with_policy -= matched
            self.lookup_ok -= lookup

    def record(self, matched: bool, lookup_ok: bool) -> None:
        self._expire()
        self.events.append((self.clock(), matched, matched and lookup_ok))
        self.with_policy += matched
        self.lookup_ok += matched and lookup_ok

    def snapshot(self) -> dict[str, int | float]:
        self._expire()
        total = len(self.events)
        return dict(total=total, with_policy=self.with_policy, lookup_ok=self.lookup_ok,
                    rate=self.with_policy / total if total else 0.0)
