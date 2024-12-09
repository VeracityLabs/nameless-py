from typing import Union, cast, Protocol, Literal
from pydantic import BaseModel, Field, field_validator
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
# Pydantic Models (For Serialization)
###


class BaseMessage(BaseModel):
    """Base Pydantic model for all messages."""

    visibility: Literal["public", "private"]
    value: HexString

    class Config:
        frozen = True
        # arbitrary_types_allowed = True


## Public Attribute
class PublicMessageModel(BaseMessage):
    """Pydantic model for public messages."""

    visibility: Literal["public"]
    value: HexString

    def to_message(self) -> "PublicMessage":
        """Convert model to PublicMessage instance."""
        return PublicMessage(HexStringUtil.str_to_bytes(self.value).unwrap())

    @classmethod
    def from_message(cls, message: "PublicMessage") -> "PublicMessageModel":
        """Create model from PublicMessage instance."""
        return cls(visibility="public", value=HexStringUtil.bytes_to_str(message.value))


## Private Attribute
class PrivateMessageModel(BaseMessage):
    """Pydantic model for private messages."""

    visibility: Literal["private"]
    value: HexString

    def to_message(self) -> "PrivateMessage":
        """Convert model to PrivateMessage instance."""
        return PrivateMessage(HexStringUtil.str_to_bytes(self.value).unwrap())

    @classmethod
    def from_message(cls, message: "PrivateMessage") -> "PrivateMessageModel":
        """Create model from PrivateMessage instance."""
        return cls(
            visibility="private", value=HexStringUtil.bytes_to_str(message.value)
        )


###
# Native Types
###


class Message(Protocol):
    """Protocol defining interface for credential messages.

    All message types must implement this interface to ensure consistent behavior.
    """

    visibility: Literal["public", "private"]
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

    def __init__(self, value: bytes, visibility: Literal["public", "private"]) -> None:
        """Initialize message.

        Args:
            value (bytes): Raw message data
            visibility (Literal["public", "private"]): Message visibility type
        """
        self.visibility = visibility
        self.value = value

    def set_value(self, new_value: bytes) -> None:
        """Set the raw message value.

        Args:
            new_value (bytes): New raw message data
        """
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


class PublicMessage(BaseMessageImpl, Message):
    """Message type for public (unencrypted) data."""

    def __init__(self, value: bytes) -> None:
        """Initialize public message.

        Args:
            value (bytes): Raw message data
        """
        super().__init__(value, "public")


class PrivateMessage(BaseMessageImpl, Message):
    """Message type for private (encrypted) data."""

    def __init__(self, value: bytes) -> None:
        """Initialize private message.

        Args:
            value (bytes): Raw message data
        """
        super().__init__(value, "private")


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
        return json.dumps(self.to_dict())

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
            ValueError: If message at index is not a PublicMessage
        """
        if index < len(self.messages) and isinstance(
            self.messages[index], PublicMessage
        ):
            return cast(PublicMessage, self.messages[index])
        raise ValueError("Message at index is not a PublicMessage")

    def _get_private_attribute(self, index: int) -> PrivateMessage:
        """Get private message at specified index.

        Args:
            index (int): Index of message to retrieve

        Returns:
            PrivateMessage: Private message at index

        Raises:
            ValueError: If message at index is not a PrivateMessage
        """
        if index < len(self.messages) and isinstance(
            self.messages[index], PrivateMessage
        ):
            return cast(PrivateMessage, self.messages[index])
        raise ValueError("Message at index is not a PrivateMessage")

    def make_message_private(self, index: int) -> None:
        """Convert public message to private at specified index.

        Args:
            index (int): Index of message to convert
        """
        if index < len(self.messages):
            try:
                public_message = self._get_public_attribute(index)
                self.messages[index] = PrivateMessage(public_message.value)
            except ValueError:
                pass

    def make_attribute_public(self, index: int) -> None:
        """Convert private message to public at specified index.

        Args:
            index (int): Index of message to convert
        """
        if index < len(self.messages):
            try:
                private_message = self._get_private_attribute(index)
                self.messages[index] = PublicMessage(private_message.value)
            except ValueError:
                pass

    def remove_attribute(self, index: int) -> None:
        """Remove message at specified index.

        Args:
            index (int): Index of message to remove
        """
        self.messages.pop(index)


###
# Attribute List Model (Used For Parsing And Validating A Stored NativeAttributeList)
###


class AttributeListModel(BaseModel):
    """Pydantic model for message list.

    Example:
        >>> data = {
        ...     "messages": [
        ...         {"visibility": "public", "value": "0x0123"},
        ...         {"visibility": "private", "value": "0x4567"},
        ...         {"visibility": "hidden", "index": 2}
        ...     ]
        ... }
        >>> model = AttributeListModel.model_validate(data)  # Validates the data
        >>> attr_list = model.to_attribute_list()  # Converts to NativeAttributeList
    """

    messages: list[Union[PublicMessageModel, PrivateMessageModel]]

    class Config:
        frozen = True

    def to_attribute_list(self) -> NativeAttributeList:
        """Convert model to NativeAttributeList instance."""
        return NativeAttributeList.from_attribute_list(
            [msg.to_message() for msg in self.messages]
        )

    @classmethod
    def from_attribute_list(
        cls, attribute_list: NativeAttributeList
    ) -> "AttributeListModel":
        """Convert NativeAttributeList instance to AttributeListModel instance."""
        public_messages = [
            PublicMessageModel.from_message(msg)
            for msg in attribute_list.get_public_attributes()
        ]
        private_messages = [
            PrivateMessageModel.from_message(msg)
            for msg in attribute_list.get_private_attributes()
        ]
        return cls(messages=public_messages + private_messages)
