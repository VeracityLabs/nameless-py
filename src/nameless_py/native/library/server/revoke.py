from nameless_py.ffi.nameless_rs import (
    Identifier,
)
from typing import Protocol


class RevocationProtocol(Protocol):
    """Protocol defining interface for revoking user credentials"""

    def revoke_credential_using_identifier(self, identifier: Identifier) -> None: ...
