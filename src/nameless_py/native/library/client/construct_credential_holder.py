from nameless_py.ffi.nameless_rs import *
from nameless_py.native.library.types.message_list import (
    NativeAttributeList,
    PublicMessage,
    PrivateMessage,
)
from nameless_py.native.library.client.credential_holder import NativeHolder
from typing import List


def set_credential_attribute_type(
    attribute_type: AttributeType, credential_attribute: CredentialAttribute
) -> CredentialAttribute:
    """
    Switch the AttributeType of a CredentialAttribute if it is not already the desired type.

    Args:
        attribute_type: The desired AttributeType (PUBLIC or PRIVATE)
        credential_attribute: The CredentialAttribute to modify

    Returns:
        The CredentialAttribute with the desired AttributeType
    """
    current_attribute_type: AttributeType = credential_attribute.get_type()
    if current_attribute_type != attribute_type:
        credential_attribute.switch()

    return credential_attribute


def convert_message_list(
    messages: NativeAttributeList,
) -> List[CredentialAttribute]:
    """
    Convert a NativeAttributeList into a list of CredentialAttributes.

    Args:
        messages: A NativeAttributeList containing public and private messages

    Returns:
        A list of CredentialAttributes with appropriate attribute types
    """
    # Extract public and private messages from the NativeAttributeList
    public_messages: List[PublicMessage] = messages.get_public_message_list()
    private_messages: List[PrivateMessage] = messages.get_private_message_list()

    credential_attributes: List[CredentialAttribute] = []

    # Convert public messages to CredentialAttributes
    for public_message in public_messages:
        attribute = CredentialAttribute.from_be_bytes_mod_order(public_message.value)
        credential_attributes.append(
            set_credential_attribute_type(AttributeType.PUBLIC, attribute)
        )

    # Convert private messages to CredentialAttributes
    for private_message in private_messages:
        attribute = CredentialAttribute.from_be_bytes_mod_order(private_message.value)
        credential_attributes.append(
            set_credential_attribute_type(AttributeType.PRIVATE, attribute)
        )

    return credential_attributes


class NativeCredentialHolderConstructor:
    """
    Class for constructing a NativeHolder.

    This class handles the initialization of credential attributes and secrets,
    generating credential requests, and creating holder instances.
    """

    def __init__(
        self, group_parameters: GroupParameters, messages: NativeAttributeList
    ) -> None:
        """
        Initialize a new HolderBuilder with group parameters and generate required secrets.

        Args:
            group_parameters: The group parameters for the credential system
            messages: A NativeAttributeList containing the credential attributes

        Raises:
            RuntimeError: If initialization fails
        """
        try:
            self.group_parameters = group_parameters
            self.credential_secret = CredentialSecret()
            self.credential_attributes = CredentialAttributeList(
                convert_message_list(messages)
            )
        except Exception as e:
            raise RuntimeError(f"Failed to initialize holder builder: {e}")

    def request_credential(self) -> CredentialRequest:
        """
        Generate a credential request.

        Returns:
            A CredentialRequest object containing the request data

        Raises:
            RuntimeError: If request preparation fails
        """
        try:
            return self.credential_attributes.clone_to_credential_request(
                self.group_parameters, self.credential_secret
            )
        except Exception as e:
            raise RuntimeError(f"Failed to prepare credential request: {e}")

    def create_holder(self, holder_builder: HolderBuilder) -> "NativeHolder":
        """
        Process the issuer's response to create a NativeHolder instance.

        Args:
            holder_builder: The HolderBuilder containing the issuer's response

        Returns:
            A new NativeHolder instance

        Raises:
            RuntimeError: If holder creation fails
        """
        try:
            return NativeHolder(
                {
                    "holder_builder": holder_builder,
                    "credential_attributes": self.credential_attributes,
                    "credential_secret": self.credential_secret,
                }
            )
        except Exception as e:
            raise RuntimeError(f"Failed to process credential response: {e}")
