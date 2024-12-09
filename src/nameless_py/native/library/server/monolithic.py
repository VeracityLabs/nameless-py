from nameless_py.ffi.nameless_rs import *
from nameless_py.native.library.types.accumulator import (
    NativeAccumulatorStore,
    NativeAccumulatorStoreEntry,
)
from nameless_py.native.library.server.revoke import RevocationProtocol
from nameless_py.native.library.server.open import OpeningProtocol
from nameless_py.native.library.server.issue import IssuingProtocol
from nameless_py.native.library.types.aliases import RequestedCredential


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
        """
        instance = cls(issuer.get_num_attributes())
        instance.issuer = issuer
        instance.accumulator_store = NativeAccumulatorStore()
        instance.max_messages = instance.issuer.get_num_attributes()

        # Copy accumulator values from the existing issuer
        accumulator_store = instance.issuer.get_accumulator_store()
        number_of_epochs = accumulator_store.get_current_epoch()
        for epoch in range(number_of_epochs):
            instance.accumulator_store.append(
                NativeAccumulatorStoreEntry(
                    accumulator_store.get_previous_accumulator(epoch)
                )
            )
        return instance

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
        return credential_request.get_public_attributes()

    def issue(self, credential_request: CredentialRequest) -> RequestedCredential:
        """
        Issue a credential in response to a request.

        Args:
            credential_request: The credential request to process

        Returns:
            HolderBuilder for constructing the credential

        Raises:
            RuntimeError: If credential issuance fails
        """
        try:
            # request.verify(self.issuer.get_group_parameters()) # TODO: Should We Check This?
            return self.issuer.issue(credential_request)
        except Exception as e:
            raise RuntimeError(f"Failed to produce signature: {e}")

    def update_credential(self, request: None) -> None:
        """
        Update an existing credential (not implemented).

        Args:
            request: Credential update request

        Raises:
            NotImplementedError: Always, as this is not yet implemented
        """
        try:
            # TODO: I Haven't Figured Out How To Update Credentials Yet!
            raise NotImplementedError
        except Exception as e:
            raise RuntimeError(f"Failed to receive credential update request: {e}")

    def get_current_epoch(self) -> int:
        """
        Get the current epoch number from the accumulator store.

        Returns:
            Current epoch number

        Raises:
            RuntimeError: If retrieving epoch fails
        """
        try:
            return self.issuer.get_accumulator_store().get_current_epoch()
        except Exception as e:
            raise RuntimeError(f"Failed to get current epoch: {e}")

    def get_current_accumulator(self) -> AccumulatorValue:
        """
        Get the current accumulator value.

        Returns:
            Current accumulator value

        Raises:
            RuntimeError: If retrieving accumulator fails
        """
        try:
            return self.issuer.get_accumulator_store().get_current_accumulator()
        except Exception as e:
            raise RuntimeError(f"Failed to get accumulator entry: {e}")

    def _get_accumulator_store(self) -> NativeAccumulatorStore:
        """Get the native accumulator store"""
        return self.accumulator_store

    def get_public_key(self) -> PublicKey:
        """
        Get the issuer's public key.

        Returns:
            Issuer's public key

        Raises:
            RuntimeError: If retrieving public key fails
        """
        try:
            return self.issuer.get_public_key()
        except Exception as e:
            raise RuntimeError(f"Failed to get server public key: {e}")

    def get_group_parameters(self) -> GroupParameters:
        """
        Get the group parameters used by the issuer.

        Returns:
            Group parameters

        Raises:
            RuntimeError: If retrieving parameters fails
        """
        try:
            return self.issuer.get_group_parameters()
        except Exception as e:
            raise RuntimeError(f"Failed to get server group parameters: {e}")

    def get_max_attributes(self) -> int:
        """Get the maximum number of attributes supported by this issuer"""
        return self.max_messages

    def revoke_credential_using_identifier(self, identifier: Identifier) -> None:
        """
        Revoke a user's credentials.

        Args:
            identifier: Identifier of the user to revoke

        Raises:
            RuntimeError: If revocation fails
        """
        try:
            self.issuer.revoke_from_identifier(identifier)
            return
        except Exception as e:
            raise RuntimeError(f"Failed to revoke user: {e}")

    def recover_identifier_from_signature(
        self, signature: NamelessSignature
    ) -> Identifier:
        """
        Recover a user's identity from their signature.

        Args:
            nameless_signature: The signature to identify

        Returns:
            Identifier of the user who created the signature

        Raises:
            RuntimeError: If identification fails
        """
        try:
            return self.issuer.recover_identifier(signature)
        except Exception as e:
            raise RuntimeError(f"Failed to recover user ID: {e}")
