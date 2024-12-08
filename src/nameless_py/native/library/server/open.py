from nameless_py.ffi.nameless_rs import *
from typing import Protocol


class OpeningProtocol(Protocol):
    """Protocol defining interface for identifying users from signatures"""

    def identify_user(self, nameless_signature: NamelessSignature) -> Identifier: ...
