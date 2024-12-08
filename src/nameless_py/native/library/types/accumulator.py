from typing import Callable, Optional, List
from dataclasses import dataclass
from nameless_py.ffi.nameless_rs import *
import json

# Type alias for a function that verifies an accumulator value and signature
AccumulatorVerifier = Callable[[AccumulatorValue, AccumulatorSignature], bool]


@dataclass
class NativeAccumulatorStoreEntry:
    """
    A single entry in the accumulator store containing an accumulator value and optional signature.

    Attributes:
        accumulator_value: The accumulator value
        accumulator_signature: Optional signature for the accumulator value
    """

    accumulator_value: AccumulatorValue
    accumulator_signature: Optional[AccumulatorSignature] = None

    def to_json(self) -> dict:
        """Convert entry to JSON-serializable dictionary"""
        raise NotImplementedError

    def to_bytes(self) -> bytes:
        """Convert entry to bytes representation"""
        raise NotImplementedError

    @classmethod
    def from_json(cls, data_dict: dict) -> "NativeAccumulatorStoreEntry":
        """Create entry from JSON dictionary"""
        raise NotImplementedError

    @classmethod
    def from_bytes(cls, data: bytes) -> "NativeAccumulatorStoreEntry":
        """Create entry from bytes representation"""
        raise NotImplementedError


class NativeAccumulatorStore:
    """
    Store for accumulator values and signatures that supports serialization.

    Provides list-like interface for storing and accessing accumulator entries.
    """

    def __init__(self) -> None:
        """Initialize empty accumulator store"""
        self.entries: List[NativeAccumulatorStoreEntry] = []

    def append(self, entry: NativeAccumulatorStoreEntry) -> None:
        """Add a new entry to the store"""
        self.entries.append(entry)

    def __getitem__(self, index: int) -> NativeAccumulatorStoreEntry:
        """Get entry at specified index"""
        return self.entries[index]

    def __len__(self) -> int:
        """Get number of entries in store"""
        return len(self.entries)

    def to_json(self) -> list:
        """Convert store to JSON-serializable list"""
        entries_data = [entry.to_json() for entry in self.entries]
        return entries_data

    def to_bytes(self) -> bytes:
        """
        Convert store to bytes representation.

        Returns:
            UTF-8 encoded JSON string of entries
        """
        entries_json = self.to_json()
        return json.dumps(entries_json).encode("utf8")

    @classmethod
    def from_json(cls, data_json: list) -> "NativeAccumulatorStore":
        """
        Create store from JSON list.

        Args:
            data_json: List of serialized entry data

        Returns:
            New NativeAccumulatorStore instance
        """
        instance = cls()
        for entry_data in data_json:
            instance.entries.append(NativeAccumulatorStoreEntry.from_json(entry_data))
        return instance

    @classmethod
    def from_bytes(cls, data: bytes) -> "NativeAccumulatorStore":
        """
        Create store from bytes representation.

        Args:
            data: UTF-8 encoded JSON string of entries

        Returns:
            New NativeAccumulatorStore instance
        """
        entries_data: List[str] = json.loads(data.decode("utf8"))
        return cls.from_json(entries_data)
