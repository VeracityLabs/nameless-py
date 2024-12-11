from nameless_py.ffi.nameless_rs import (
    Identifier,
    NamelessSignature,
)
from typing import Protocol


class OpeningProtocol(Protocol):
    """Protocol defining interface for identifying users from signatures"""

    def recover_identifier_from_signature(
        self, signature: NamelessSignature
    ) -> Identifier: ...
