"""Per-user rate limiting in fixed one-minute windows."""

import time
from collections.abc import Callable


class RateLimiter:
    def __init__(
        self, requests_per_minute: int | None, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._limit = requests_per_minute
        self._clock = clock
        self._windows: dict[str, tuple[int, int]] = {}  # user -> (minute, requests in it)

    def allow(self, user: str) -> bool:
        """Count one request; False if the user is over the limit. No limit means always True."""
        if self._limit is None:
            return True
        minute = int(self._clock() // 60)
        window, count = self._windows.get(user, (minute, 0))
        count = count + 1 if window == minute else 1
        self._windows[user] = (minute, count)
        return count <= self._limit
