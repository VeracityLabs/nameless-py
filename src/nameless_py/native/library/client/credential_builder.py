from nameless_py.ffi.nameless_rs import (
    CredentialAttribute,
    CredentialAttributeList,
    CredentialRequest,
    PartialCredential,
    GroupParameters,
    CredentialSecret,
    AttributeType,
)
from nameless_py.native.library.types.attributes import (
    NativeAttributeList,
    AttributeTypes,
)
from nameless_py.native.library.client.credential_holder import NativeCredentialHolder
from typing import List, TypedDict, Optional
import sys

# Determine System Endianness
endianness = "le" if sys.byteorder == "little" else "be"

###
# Exceptions
###


class CredentialBuilderError(Exception):
    """Base exception for credential builder errors"""

    pass


class AttributeConversionError(CredentialBuilderError):
    """Error converting between attribute types"""

    pass


class CredentialRequestError(CredentialBuilderError):
    """Error generating credential request"""

    pass


class HolderCreationError(CredentialBuilderError):
    """Error creating credential holder"""

    pass


###
# Utility Functions
###


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

    Raises:
        AttributeConversionError: If switching attribute type fails
    """
    try:
        current_attribute_type: AttributeType = credential_attribute.get_type()
        if current_attribute_type != attribute_type:
            credential_attribute.switch()

        return credential_attribute
    except Exception as e:
        raise AttributeConversionError(f"Failed to set attribute type: {e}")


def convert_message_list(
    messages: NativeAttributeList,
) -> List[CredentialAttribute]:
    """
    Convert a NativeAttributeList into a list of CredentialAttributes.

    Args:
        messages: A NativeAttributeList containing public and private messages

    Returns:
        A list of CredentialAttributes with appropriate attribute types

    Raises:
        AttributeConversionError: If conversion of any attribute fails
    """
    try:
        # Extract list of attributes from the NativeAttributeList
        native_attributes: List[AttributeTypes] = messages.get_attribute_list()
        credential_attributes: List[CredentialAttribute] = []

        # Determine conversion function based on system endianness
        def convert_to_credential_attribute(value: bytes) -> CredentialAttribute:
            return (
                CredentialAttribute.from_le_bytes_mod_order(value)
                if endianness == "le"
                else CredentialAttribute.from_be_bytes_mod_order(value)
            )

        # Convert attributes to CredentialAttributes based on visibility
        for attribute in native_attributes:
            if attribute.visibility == "Public":
                credential_attribute = convert_to_credential_attribute(attribute.value)
                credential_attributes.append(
                    set_credential_attribute_type(
                        AttributeType.PUBLIC, credential_attribute
                    )
                )
            else:
                credential_attribute = convert_to_credential_attribute(attribute.value)
                credential_attributes.append(
                    set_credential_attribute_type(
                        AttributeType.PRIVATE, credential_attribute
                    )
                )

        return credential_attributes
    except AttributeConversionError:
        raise
    except Exception as e:
        raise AttributeConversionError(f"Failed to convert message list: {e}")


###
# Credential Builder
###


class NativeCredentialBuilderParams(TypedDict):
    group_parameters: GroupParameters
    attribute_list: NativeAttributeList
    credential_secret: Optional[CredentialSecret]


class NativeCredentialBuilder:
    """
    Class for constructing a NativeCredentialHolder.

    This class handles the initialization of credential attributes and secrets,
    generating credential requests, and creating holder instances.
    """

    def __init__(self, params: NativeCredentialBuilderParams) -> None:
        """
        Initialize a new CredentialHolderConstructor with group parameters and generate required secrets.

        Args:
            group_parameters: The group parameters for the credential system
            messages: A NativeAttributeList containing the credential attributes

        Raises:
            CredentialBuilderError: If initialization fails
            AttributeConversionError: If attribute conversion fails
        """
        try:
            self.group_parameters: GroupParameters = params["group_parameters"]
            self.credential_secret: CredentialSecret = (
                params["credential_secret"]
                if params["credential_secret"] is not None
                else CredentialSecret()
            )
            self.credential_attributes = CredentialAttributeList(
                convert_message_list(params["attribute_list"])
            )
        except AttributeConversionError:
            raise
        except Exception as e:
            raise CredentialBuilderError(f"Failed to initialize holder builder: {e}")

    def request_credential(self) -> CredentialRequest:
        """
        Generate a credential request.

        Returns:
            A CredentialRequest object containing the request data

        Raises:
            CredentialRequestError: If request preparation fails
        """
        try:
            return self.credential_attributes.clone_to_credential_request(
                self.group_parameters, self.credential_secret
            )
        except Exception as e:
            raise CredentialRequestError(f"Failed to prepare credential request: {e}")

    def create_holder(
        self, partial_credential: PartialCredential
    ) -> "NativeCredentialHolder":
        """
        Process the issuer's response to create a NativeCredentialHolder instance.

        Args:
            partial_credential: The PartialCredential containing the issuer's response

        Returns:
            A new NativeCredentialHolder instance

        Raises:
            HolderCreationError: If holder creation fails
        """
        try:
            return NativeCredentialHolder(
                {
                    "partial_credential": partial_credential,
                    "credential_attributes": self.credential_attributes,
                    "credential_secret": self.credential_secret,
                }
            )
        except Exception as e:
            raise HolderCreationError(f"Failed to process credential response: {e}")
