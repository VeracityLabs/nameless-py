from nameless_py.ffi.nameless_rs import (
    MonolithicIssuer,
    CredentialRequest,
    CredentialRequestAttributeList,
    PartialCredential,
    PublicKey,
    GroupParameters,
    Identifier,
    NamelessSignature,
    AccumulatorValue,
)
from nameless_py.native.library.types.accumulator import (
    NativeAccumulatorStore,
    NativeAccumulatorStoreEntry,
)
from nameless_py.native.library.server.revoke import RevocationProtocol
from nameless_py.native.library.server.open import OpeningProtocol
from nameless_py.native.library.server.issue import IssuingProtocol


###
# Exceptions
###


class IssuerError(Exception):
    """Base exception for issuer errors"""

    pass


class CredentialIssuanceError(IssuerError):
    """Error issuing credentials"""

    pass


class CredentialUpdateError(IssuerError):
    """Error updating credentials"""

    pass


class CredentialExportError(IssuerError):
    """Error exporting credentials"""

    pass


class AccumulatorError(IssuerError):
    """Error accessing accumulator store"""

    pass


class KeyAccessError(IssuerError):
    """Error accessing keys or parameters"""

    pass


class RevocationError(IssuerError):
    """Error revoking credentials"""

    pass


class IdentificationError(IssuerError):
    """Error identifying users from signatures"""

    pass


class NativeMonolithicIssuer(RevocationProtocol, OpeningProtocol, IssuingProtocol):
    """
    Native implementation of a monolithic credential issuer.

    Handles issuing credentials, revoking users, and identifying users from signatures.
    Maintains an accumulator store for revocation.
    """

    def __init__(self, max_messages: int) -> None:
        """
        Initialize a new issuer with specified maximum number of messages.

        Args:
            max_messages: Maximum number of attributes that can be included in credentials
        """
        self.issuer: MonolithicIssuer = MonolithicIssuer(max_messages)
        self.accumulator_store: NativeAccumulatorStore = NativeAccumulatorStore()
        self.max_messages: int = self.issuer.get_num_attributes()

    @classmethod
    def from_issuer(cls, issuer: MonolithicIssuer) -> "NativeMonolithicIssuer":
        """
        Create a NativeMonolithicIssuer from an existing MonolithicIssuer.

        Args:
            issuer: Existing MonolithicIssuer instance to wrap

        Returns:
            New NativeMonolithicIssuer instance wrapping the provided issuer

        Raises:
            AccumulatorError: If copying accumulator values fails
        """
        instance = cls(issuer.get_num_attributes())
        instance.issuer = issuer
        instance.accumulator_store = NativeAccumulatorStore()
        instance.max_messages = instance.issuer.get_num_attributes()

        try:
            # Copy accumulator values from the existing issuer
            # TODO: optimize by using a single call to get_accumulator_store(), getting the JSON, then deserializing it.
            accumulator_store = instance.issuer.get_accumulator_store()
            number_of_epochs = accumulator_store.get_current_epoch()
            for epoch in range(number_of_epochs):
                instance.accumulator_store.append(
                    NativeAccumulatorStoreEntry(
                        accumulator_store.get_previous_accumulator(epoch)
                    )
                )
            return instance
        except Exception as e:
            raise AccumulatorError(f"Failed to copy accumulator values: {e}")

    @classmethod
    def import_cbor(cls, cbor: bytes) -> "NativeMonolithicIssuer":
        """Initialize a NativeMonolithicIssuer from a CBOR-encoded credential"""
        instance = cls(0)
        instance.issuer = MonolithicIssuer.import_cbor(cbor)
        return instance

    def export_cbor(self) -> bytes:
        """Export the NativeMonolithicIssuer as a CBOR-encoded credential"""
        try:
            return self.issuer.export_cbor()
        except Exception as e:
            raise CredentialExportError(f"Failed to export issuer: {e}")

    def get_issuer(self) -> MonolithicIssuer:
        """Get the underlying MonolithicIssuer instance"""
        return self.issuer

    def read_attribute_list_from_credential_request(
        self, credential_request: CredentialRequest
    ) -> CredentialRequestAttributeList:
        """
        Extract public attributes from a credential request.

        Args:
            credential_request: The credential request to extract from

        Returns:
            List of public attributes from the request
        """
        return credential_request.get_attribute_list()

    def issue(self, credential_request: CredentialRequest) -> PartialCredential:
        """
        Issue a credential in response to a request.

        Args:
            credential_request: The credential request to process

        Returns:
            PartialCredential for constructing the credential

        Raises:
            CredentialIssuanceError: If credential issuance fails
        """
        try:
            # request.verify(self.issuer.get_group_parameters()) # TODO: Should We Check This?
            return self.issuer.issue(credential_request)
        except Exception as e:
            raise CredentialIssuanceError(f"Failed to issue credential: {e}")

    def update_credential(self, current_identifier: Identifier) -> Identifier:
        """
        Update an existing credential.

        Args:
            current_identifier: Current identifier to update

        Returns:
            Updated identifier

        Raises:
            CredentialUpdateError: If update fails
        """
        try:
            accumulator_store = self.issuer.get_accumulator_store()
            return accumulator_store.get_updated_identifier(current_identifier)
        except Exception as e:
            raise CredentialUpdateError(f"Failed to update credential: {e}")

    def get_current_epoch(self) -> int:
        """
        Get the current epoch number from the accumulator store.

        Returns:
            Current epoch number

        Raises:
            AccumulatorError: If retrieving epoch fails
        """
        try:
            return self.issuer.get_accumulator_store().get_current_epoch()
        except Exception as e:
            raise AccumulatorError(f"Failed to get current epoch: {e}")

    def get_current_accumulator(self) -> AccumulatorValue:
        """
        Get the current accumulator value.

        Returns:
            Current accumulator value

        Raises:
            AccumulatorError: If retrieving accumulator fails
        """
        try:
            return self.issuer.get_accumulator_store().get_current_accumulator()
        except Exception as e:
            raise AccumulatorError(f"Failed to get current accumulator: {e}")

    def _get_accumulator_store(self) -> NativeAccumulatorStore:
        """Get the native accumulator store"""
        return self.accumulator_store

    def get_public_key(self) -> PublicKey:
        """
        Get the issuer's public key.

        Returns:
            Issuer's public key

        Raises:
            KeyAccessError: If retrieving public key fails
        """
        try:
            return self.issuer.get_public_key()
        except Exception as e:
            raise KeyAccessError(f"Failed to get public key: {e}")

    def get_group_parameters(self) -> GroupParameters:
        """
        Get the group parameters used by the issuer.

        Returns:
            Group parameters

        Raises:
            KeyAccessError: If retrieving parameters fails
        """
        try:
            return self.issuer.get_group_parameters()
        except Exception as e:
            raise KeyAccessError(f"Failed to get group parameters: {e}")

    def get_max_attributes(self) -> int:
        """Get the maximum number of attributes supported by this issuer"""
        return self.max_messages

    def revoke_credential_using_identifier(self, identifier: Identifier) -> None:
        """
        Revoke a user's credentials.

        Args:
            identifier: Identifier of the user to revoke

        Raises:
            RevocationError: If revocation fails
        """
        try:
            self.issuer.revoke_from_identifier(identifier)
            return
        except Exception as e:
            raise RevocationError(f"Failed to revoke credential: {e}")

    def recover_identifier_from_signature(
        self, signature: NamelessSignature
    ) -> Identifier:
        """
        Recover a user's identity from their signature.

        Args:
            signature: The signature to identify

        Returns:
            Identifier of the user who created the signature

        Raises:
            IdentificationError: If identification fails
        """
        try:
            return self.issuer.recover_identifier(signature)
        except Exception as e:
            raise IdentificationError(f"Failed to recover identifier: {e}")
