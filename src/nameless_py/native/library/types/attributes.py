from typing import Union, cast, Protocol, Literal, Annotated, List
from pydantic import BaseModel, ConfigDict, Field, RootModel
from nameless_py.native.util.bytes.hex_string import HexStringUtil, HexString
import json

###
# This file implements utilities for managing collections of attributes across various contexts:
#
# - Attribute types:
#   - PublicMessage: Will Be Shown At Signing-Time, Is Not Encrypted.
#   - PrivateMessage: Marked For Encryption At Signing-Time, But Is Not Encrypted.
#
# - Container classes:
#   - NativeAttributeList: Main container for managing lists of attributes.
#   - AttributeListModel: Pydantic model for deserialization of NativeAttributeList from JSON.
#
# The file provides functionality to:
# - Convert between different message visibility types
# - Serialize and deserialize attribute lists to/from JSON
# - Validate attribute lists using Pydantic models
###

###
# Exceptions
###


class AttributeError(Exception):
    """Base exception for attribute-related errors"""

    pass


class AttributeValidationError(AttributeError):
    """Error validating attribute data"""

    pass


class AttributeSerializationError(AttributeError):
    """Error serializing/deserializing attributes"""

    pass


class AttributeTypeError(AttributeError):
    """Error with attribute type"""

    pass


class AttributeIndexError(AttributeError):
    """Error accessing attribute by index"""

    pass


###
# Pydantic Models (For Serialization)
###


class AttributeModel(BaseModel):
    value: Annotated[
        List[Annotated[int, Field(ge=0, le=255)]],
        Field(min_length=32, max_length=32),
    ]
    attribute_type: Literal["Public", "Private"]


class AttributeListModel(RootModel):
    root: List[AttributeModel]


###
# Native Types
###


class Message(Protocol):
    """Protocol defining interface for credential messages.

    All message types must implement this interface to ensure consistent behavior.
    """

    visibility: Literal["Public", "Private"]
    value: bytes

    def to_dict(self) -> dict:
        """Convert message to dictionary representation.

        Returns:
            dict: Dictionary containing message data
        """
        ...

    def set_value(self, new_value: bytes) -> None: ...


class BaseMessageImpl:
    """Base implementation for message types."""

    def __init__(self, value: bytes, visibility: Literal["Public", "Private"]) -> None:
        """Initialize message.

        Args:
            value (bytes): Raw message data
            visibility (Literal["Public", "Private"]): Message visibility type

        Raises:
            ValueError: If value exceeds 32 bytes
        """
        if len(value) > 32:
            raise ValueError("Message value cannot exceed 32 bytes")
        self.visibility = visibility
        self.value = value

    def set_value(self, new_value: bytes) -> None:
        """Set the raw message value.

        Args:
            new_value (bytes): New raw message data

        Raises:
            ValueError: If new_value exceeds 32 bytes
        """
        if len(new_value) > 32:
            raise ValueError("Message value cannot exceed 32 bytes")
        self.value = new_value

    def to_dict(self) -> dict:
        """Convert message to dictionary format.

        Returns:
            dict: Dictionary with visibility and hex-encoded value
        """
        return {
            "visibility": self.visibility,
            "value": HexStringUtil.bytes_to_str(self.value),
        }

    def to_model(self) -> AttributeModel:
        """Convert BaseMessageImpl to AttributeModel instance."""
        return AttributeModel(
            value=list(self.value),
            attribute_type=self.visibility,
        )

    def __str__(self) -> str:
        """String representation of the message."""
        try:
            decoded = self.value.decode("ascii")
            return f"{self.visibility}: {decoded}"
        except UnicodeDecodeError:
            return f"{self.visibility}: {HexStringUtil.bytes_to_str(self.value)}"


class PublicMessage(BaseMessageImpl, Message):
    """Message type for public (unencrypted) data."""

    def __init__(self, value: bytes) -> None:
        """Initialize public message.

        Args:
            value (bytes): Raw message data
        """
        super().__init__(value, "Public")


class PrivateMessage(BaseMessageImpl, Message):
    """Message type for private (encrypted) data."""

    def __init__(self, value: bytes) -> None:
        """Initialize private message.

        Args:
            value (bytes): Raw message data
        """
        super().__init__(value, "Private")


# Type alias for all possible message types
AttributeTypes = Union[PublicMessage, PrivateMessage]


###
# Native Attribute List
###


class NativeAttributeList:
    """Container class for managing a list of messages with different visibility levels."""

    def __init__(self) -> None:
        """Initialize empty message list."""
        self.messages: list[AttributeTypes] = []

    def __str__(self) -> str:
        """String representation of the attribute list."""
        if not self.messages:
            return "NativeAttributeList(empty)"

        attributes = "\n".join(
            f"  {i}: {str(msg)}" for i, msg in enumerate(self.messages)
        )
        return f"NativeAttributeList(\n{attributes}\n)"

    def __repr__(self) -> str:
        """Detailed string representation of the attribute list."""
        return self.__str__()

    @classmethod
    def from_attribute_list(
        cls, messages: list[AttributeTypes] | list[PublicMessage] | list[PrivateMessage]
    ) -> "NativeAttributeList":
        """Initialize message list from list of messages."""
        instance = cls()
        instance.messages = [cast(AttributeTypes, msg) for msg in messages]
        return instance

    def get_attribute_list(self) -> list[AttributeTypes]:
        """Get full list of messages.

        Returns:
            list[AttributeTypes]: List of all messages
        """
        return self.messages

    def to_dict(self) -> dict:
        """Convert message list to AttributeListModel instance."""
        return {"messages": [msg.to_dict() for msg in self.messages]}

    def to_json(self) -> str:
        """Convert message list to JSON string."""
        try:
            return json.dumps(self.to_dict())
        except Exception as e:
            raise AttributeSerializationError(f"Failed to serialize to JSON: {e}")

    @classmethod
    def from_json(cls, json_str: str) -> "NativeAttributeList":
        """Convert JSON string to NativeAttributeList instance.

        Args:
            json_str: JSON string containing attribute list data

        Returns:
            NativeAttributeList: New instance populated with attributes from JSON

        Raises:
            AttributeSerializationError: If JSON parsing fails
            AttributeValidationError: If attribute validation fails
        """
        try:
            # Parse and validate JSON using AttributeListModel
            attr_list = AttributeListModel.model_validate_json(json_str)
            return cls.from_model(attr_list)
        except json.JSONDecodeError as e:
            raise AttributeSerializationError(f"Invalid JSON format: {e}")
        except Exception as e:
            raise AttributeValidationError(f"Failed to validate attribute list: {e}")

    def to_model(self) -> AttributeListModel:
        """Convert NativeAttributeList to AttributeListModel instance."""
        return AttributeListModel(root=[attr.to_model() for attr in self.messages])

    @classmethod
    def from_model(cls, attr_list: AttributeListModel) -> "NativeAttributeList":
        """Convert AttributeListModel to NativeAttributeList instance.

        Args:
            attr_list: AttributeListModel instance

        Returns:
            NativeAttributeList: New instance populated with attributes from model

        Raises:
            AttributeTypeError: If attribute type is invalid
            AttributeValidationError: If attribute data is invalid
        """
        instance = cls()

        try:
            for attr in attr_list.root:
                value = bytes(attr.value)

                if attr.attribute_type == "Public":
                    instance.append_public_attribute(value)
                elif attr.attribute_type == "Private":
                    instance.append_private_attribute(value)
                else:
                    raise AttributeTypeError(
                        f"Invalid attribute type: {attr.attribute_type}"
                    )

            return instance
        except (TypeError, ValueError) as e:
            raise AttributeValidationError(f"Invalid attribute data: {e}")

    def get_public_attributes(self) -> list[PublicMessage]:
        """Get list of public messages only.

        Returns:
            list[PublicMessage]: List of public messages
        """
        return [msg for msg in self.messages if isinstance(msg, PublicMessage)]

    def get_private_attributes(self) -> list[PrivateMessage]:
        """Get list of private messages only.

        Returns:
            list[PrivateMessage]: List of private messages
        """
        return [msg for msg in self.messages if isinstance(msg, PrivateMessage)]

    def get_attributes_raw(self) -> list[bytes]:
        """Get raw values of all messages that have values.

        Returns:
            list[bytes]: List of raw message values
        """
        return [msg.value for msg in self.messages if hasattr(msg, "value")]

    def append_private_attribute(self, message: bytes) -> None:
        """Add a new private message.

        Args:
            message (bytes): Raw message data
        """
        self.messages.append(PrivateMessage(message))

    def append_public_attribute(self, message: bytes) -> None:
        """Add a new public message.

        Args:
            message (bytes): Raw message data
        """
        self.messages.append(PublicMessage(message))

    def _get_public_attribute(self, index: int) -> PublicMessage:
        """Get public message at specified index.

        Args:
            index (int): Index of message to retrieve

        Returns:
            PublicMessage: Public message at index

        Raises:
            AttributeIndexError: If index is out of range
            AttributeTypeError: If message at index is not a PublicMessage
        """
        if index >= len(self.messages):
            raise AttributeIndexError(f"Index {index} out of range")
        if not isinstance(self.messages[index], PublicMessage):
            raise AttributeTypeError("Message at index is not a PublicMessage")
        return cast(PublicMessage, self.messages[index])

    def _get_private_attribute(self, index: int) -> PrivateMessage:
        """Get private message at specified index.

        Args:
            index (int): Index of message to retrieve

        Returns:
            PrivateMessage: Private message at index

        Raises:
            AttributeIndexError: If index is out of range
            AttributeTypeError: If message at index is not a PrivateMessage
        """
        if index >= len(self.messages):
            raise AttributeIndexError(f"Index {index} out of range")
        if not isinstance(self.messages[index], PrivateMessage):
            raise AttributeTypeError("Message at index is not a PrivateMessage")
        return cast(PrivateMessage, self.messages[index])

    def make_attribute_private(self, index: int) -> None:
        """Convert public message to private at specified index.

        Args:
            index (int): Index of message to convert
        """
        try:
            public_message = self._get_public_attribute(index)
            self.messages[index] = PrivateMessage(public_message.value)
        except (AttributeIndexError, AttributeTypeError):
            pass

    def make_attribute_public(self, index: int) -> None:
        """Convert private message to public at specified index.

        Args:
            index (int): Index of message to convert
        """
        try:
            private_message = self._get_private_attribute(index)
            self.messages[index] = PublicMessage(private_message.value)
        except (AttributeIndexError, AttributeTypeError):
            pass

    def remove_attribute(self, index: int) -> None:
        """Remove message at specified index.

        Args:
            index (int): Index of message to remove

        Raises:
            AttributeIndexError: If index is out of range
        """
        if index >= len(self.messages):
            raise AttributeIndexError(f"Index {index} out of range")
        self.messages.pop(index)
