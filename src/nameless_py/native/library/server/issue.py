from nameless_py.ffi.nameless_rs import (
    CredentialRequest,
    CredentialRequestAttributeList,
    PartialCredential,
    PublicKey,
    GroupParameters,
)
from typing import Protocol


class IssuingProtocol(Protocol):
    """Protocol defining interface for issuing credentials"""

    def read_attribute_list_from_credential_request(
        self, credential_request: CredentialRequest
    ) -> CredentialRequestAttributeList: ...

    def issue(self, credential_request: CredentialRequest) -> PartialCredential: ...

    def get_public_key(self) -> PublicKey: ...

    def get_group_parameters(self) -> GroupParameters: ...

    def get_max_attributes(self) -> int: ...
