from typing import TypedDict
from nameless_py.ffi.nameless_rs import (
    CredentialHolder,
    Credential,
    CredentialAttributeList,
    Identifier,
    PartialCredential,
    CredentialSecret,
    NamelessSignatureWithAccumulator,
)
from nameless_py.native.library.types.attributes import (
    NativeAttributeList,
)


###
# Exceptions
###


class CredentialHolderError(Exception):
    """Base exception for credential holder errors"""

    pass


class CredentialInitializationError(CredentialHolderError):
    """Error initializing credential holder"""

    pass


class AttributeListError(CredentialHolderError):
    """Error accessing or processing attribute list"""

    pass


class SignatureError(CredentialHolderError):
    """Error creating credential signature"""

    pass


class UpdateError(CredentialHolderError):
    """Error during credential update operations"""

    pass


###
# Credential Holder
###


class HolderParams(TypedDict):
    partial_credential: PartialCredential
    credential_attributes: CredentialAttributeList
    credential_secret: CredentialSecret


class NativeCredentialHolder:
    holder: CredentialHolder
    cached_attribute_list: NativeAttributeList

    def __init__(self, params: HolderParams) -> None:
        """Initialize a Holder from a PartialCredential, CredentialAttributeList, and CredentialSecret"""
        try:
            self.holder = CredentialHolder(
                params["partial_credential"],
                params["credential_attributes"],
                params["credential_secret"],
            )
        except ValueError as e:
            raise CredentialInitializationError(f"Invalid parameters: {e}")
        except Exception as e:
            raise CredentialInitializationError(f"Failed to initialize holder: {e}")

    @classmethod
    def import_cbor(cls, cbor: bytes) -> "NativeCredentialHolder":
        """Initialize a Holder from a CBOR-encoded credential"""
        try:
            instance = cls.__new__(cls)
            instance.holder = CredentialHolder.import_cbor(cbor)
            return instance
        except ValueError as e:
            raise CredentialInitializationError(f"Invalid CBOR: {e}")
        except Exception as e:
            raise CredentialInitializationError(f"Failed to initialize holder: {e}")

    def export_cbor(self) -> bytes:
        """Export the Holder as a CBOR-encoded credential"""
        try:
            return self.holder.export_cbor()
        except Exception as e:
            raise CredentialInitializationError(f"Failed to export holder: {e}")

    @staticmethod
    def _get_attribute_list_from_credential(
        credential: Credential,
    ) -> CredentialAttributeList:
        """Get the attribute list from the credential"""
        try:
            return credential.get_attribute_list()
        except AttributeError as e:
            raise AttributeListError("Credential not properly initialized")
        except Exception as e:
            raise AttributeListError(f"Failed to get attribute list: {e}")

    @staticmethod
    def _extract_attribute_list_from_credential(
        credential: Credential,
    ) -> NativeAttributeList:
        """Extract messages from the credential and return as NativeAttributeList"""
        try:
            attribute_list_json = credential.get_attribute_list().export_json()
            return NativeAttributeList.from_json(attribute_list_json)
        except ValueError as e:
            raise AttributeListError(f"Invalid attribute list format: {e}")
        except Exception as e:
            raise AttributeListError(f"Failed to extract attribute list: {e}")

    def read_attribute_list(self, unsafe: bool = False) -> NativeAttributeList:
        """Read credential messages, optionally hiding private messages"""
        try:
            message_list = self._extract_attribute_list_from_credential(
                self.holder.get_credential()
            )
            if unsafe:
                return message_list
            else:
                return NativeAttributeList.from_attribute_list(
                    message_list.get_public_attributes()
                )
        except AttributeListError:
            raise
        except Exception as e:
            raise AttributeListError(f"Failed to read credential attributes: {e}")

    def request_credential_update(self) -> Identifier:
        """Request a credential update"""
        try:
            return self.holder.get_identifier()
        except AttributeError:
            raise UpdateError("Credential not properly initialized")
        except Exception as e:
            raise UpdateError(f"Failed to request credential update: {e}")

    def import_credential_update(self, identifier: Identifier) -> None:
        """Import a credential update"""
        try:
            self.holder = self.holder.create_updated_credential(identifier)
        except ValueError as e:
            raise UpdateError(f"Invalid update identifier: {e}")
        except Exception as e:
            raise UpdateError(f"Failed to import credential update: {e}")

    def sign_with_credential(
        self, data_to_prove: bytes, public_indices: list[int]
    ) -> NamelessSignatureWithAccumulator:
        """Create a signature revealing only the specified public indices"""
        try:
            signature = self.holder.create_signature_with_accumulator(
                data_to_prove, public_indices
            )
            return signature
        except ValueError as e:
            raise SignatureError(f"Invalid signature parameters: {e}")
        except Exception as e:
            raise SignatureError(f"Failed to create signature: {e}")
