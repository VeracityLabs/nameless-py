from nameless_py.ffi.nameless_rs import *
from typing import Protocol


class RevocationProtocol(Protocol):
    """Protocol defining interface for revoking user credentials"""

    def revoke_user(self, identifier: Identifier) -> None: ...
