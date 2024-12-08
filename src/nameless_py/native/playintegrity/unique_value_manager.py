import os
import time
from typing import Optional, Dict

from fastapi import BackgroundTasks

# Type aliases for improved readability
Timestamp = int  # Number of nanoseconds since the epoch
Duration = int  # Number of nanoseconds that the duration represents
UniqueValue = bytes  # The unique value produced for Play Integrity

# Constants
UNIQUE_VALUE_SIZE: int = 32
UNIQUE_VALUE_VALID_DURATION_NS: Duration = 60 * 10**9  # 1 minute in nanoseconds


class UniqueValueManager:
    """
    Manages the creation, redemption, and invalidation of random unique values.
    """

    def __init__(self):
        self._internal_cache: Dict[UniqueValue, Timestamp] = {}

    def new_unique_value(self) -> UniqueValue:
        """
        Generates a new unique value, places it into the shared cache,
        and returns it. The value will be valid for a set period of time.
        """
        unique_value = os.urandom(UNIQUE_VALUE_SIZE)
        self._internal_cache[unique_value] = time.time_ns()
        return unique_value

    def redeem_unique_value(
        self,
        unique_value: UniqueValue,
        background_tasks: Optional[BackgroundTasks] = None,
    ) -> bool:
        """
        Attempts to redeem an existing unique value.

        Args:
            unique_value: The unique value to redeem.
            background_tasks: Optional BackgroundTasks instance for asynchronous cleanup.

        Returns:
            True if the value is valid and not expired, False otherwise.
        """
        creation_timestamp_ns = self._internal_cache.get(unique_value)

        if creation_timestamp_ns is None or _is_unique_value_expired(
            creation_timestamp_ns, UNIQUE_VALUE_VALID_DURATION_NS
        ):
            self._trigger_cache_cleanup(background_tasks)
            return False

        del self._internal_cache[unique_value]
        return True

    def _trigger_cache_cleanup(self, background_tasks: Optional[BackgroundTasks]):
        """
        Triggers the cache cleanup task, either synchronously or asynchronously.
        """
        if background_tasks:
            background_tasks.add_task(self._background_task_clear_cache)
        else:
            self._background_task_clear_cache()

    def _background_task_clear_cache(self):
        """
        Clears expired entries from the internal cache.
        """
        current_time = time.time_ns()
        expired_values = [
            value
            for value, timestamp in self._internal_cache.items()
            if _is_unique_value_expired(
                timestamp, UNIQUE_VALUE_VALID_DURATION_NS, current_time
            )
        ]
        for value in expired_values:
            del self._internal_cache[value]


def _is_unique_value_expired(
    creation_timestamp_ns: Timestamp,
    valid_duration_ns: Duration,
    current_time_ns: Optional[Timestamp] = None,
) -> bool:
    """
    Checks if a unique value has expired.

    Args:
        creation_timestamp_ns: The timestamp when the value was created.
        valid_duration_ns: The duration for which the value is valid.
        current_time_ns: The current time (optional, defaults to current time if not provided).

    Returns:
        True if the value has expired, False otherwise.
    """
    expiry_timestamp_ns = creation_timestamp_ns + valid_duration_ns
    return expiry_timestamp_ns < (current_time_ns or time.time_ns())
