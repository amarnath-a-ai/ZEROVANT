"""In-memory client IP rate limiter."""

import threading
import time
from collections import defaultdict


class InMemoryRateLimiter:
    """Thread-safe sliding-window rate limiter per client IP."""

    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self._lock = threading.Lock()
        self._requests: dict[str, list[float]] = defaultdict(list)

    def is_allowed(
        self,
        ip: str,
        limit: int | None = None,
        window_seconds: int = 60,
    ) -> tuple[bool, int]:
        """Check if an IP has exceeded the allowed request count within the window.

        Args:
            ip: Client IP address identifier.
            limit: Maximum requests allowed in the time window (defaults to self.requests_per_minute).
            window_seconds: Duration of the sliding window in seconds (default 60s).

        Returns:
            A tuple (allowed, retry_after_seconds).
        """
        max_requests = limit if limit is not None else self.requests_per_minute
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            timestamps = self._requests[ip]
            # Prune timestamps older than window
            valid_timestamps = [t for t in timestamps if t > cutoff]
            self._requests[ip] = valid_timestamps

            if len(valid_timestamps) >= max_requests:
                oldest = valid_timestamps[0]
                retry_after = max(1, int(oldest + window_seconds - now))
                return False, retry_after

            self._requests[ip].append(now)
            return True, 0

    def reset(self) -> None:
        """Clear all rate limit tracking records."""
        with self._lock:
            self._requests.clear()


# Global in-memory rate limiter instance
limiter = InMemoryRateLimiter()
