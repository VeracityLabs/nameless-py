from typing import Union, cast, Protocol


class Message(Protocol):
    """Protocol defining interface for credential messages.

    All message types must implement this interface to ensure consistent behavior.
    """

    visibility: str

    def to_dict(self) -> dict:
        """Convert message to dictionary representation.

        Returns:
            dict: Dictionary containing message data
        """
        ...

    @classmethod
    def from_dict(cls, data: dict) -> "Message":
        """Create message instance from dictionary data.

        Args:
            data (dict): Dictionary containing message data

        Returns:
            Message: New message instance
        """
        ...


class PublicMessage(Message):
    """Message type for public (unencrypted) data."""

    def __init__(self, value: bytes) -> None:
        """Initialize public message.

        Args:
            value (bytes): Raw message data
        """
        self.visibility = "public"
        self._value = value

    @property
    def value(self) -> bytes:
        """Get the raw message value.

        Returns:
            bytes: Raw message data
        """
        return self._value

    @value.setter
    def value(self, new_value: bytes) -> None:
        """Set the raw message value.

        Args:
            new_value (bytes): New raw message data

        Raises:
            ValueError: If new_value is not bytes
        """
        if not isinstance(new_value, bytes):
            raise ValueError("Value must be bytes")
        self._value = new_value

    def to_dict(self) -> dict:
        """Convert message to dictionary format.

        Returns:
            dict: Dictionary with visibility and hex-encoded value
        """
        return {"visibility": self.visibility, "value": self._value.hex()}

    @classmethod
    def from_dict(cls, data: dict) -> "PublicMessage":
        """Create PublicMessage from dictionary data.

        Args:
            data (dict): Dictionary containing message data

        Returns:
            PublicMessage: New public message instance

        Raises:
            ValueError: If visibility is not 'public' or value is invalid
        """
        if data.get("visibility") != "public":
            raise ValueError("PublicMessage visibility must be 'public'")
        value = data.get("value")
        if not isinstance(value, str):
            raise ValueError("Value must be a hexadecimal string")
        return cls(bytes.fromhex(value))


class PrivateMessage(Message):
    """Message type for private (encrypted) data."""

    def __init__(self, value: bytes) -> None:
        """Initialize private message.

        Args:
            value (bytes): Raw message data
        """
        self.visibility = "private"
        self._value = value

    @property
    def value(self) -> bytes:
        """Get the raw message value.

        Returns:
            bytes: Raw message data
        """
        return self._value

    @value.setter
    def value(self, new_value: bytes) -> None:
        """Set the raw message value.

        Args:
            new_value (bytes): New raw message data

        Raises:
            ValueError: If new_value is not bytes
        """
        if not isinstance(new_value, bytes):
            raise ValueError("Value must be bytes")
        self._value = new_value

    def to_dict(self) -> dict:
        """Convert message to dictionary format.

        Returns:
            dict: Dictionary with visibility and hex-encoded value
        """
        return {"visibility": self.visibility, "value": self._value.hex()}

    @classmethod
    def from_dict(cls, data: dict) -> "PrivateMessage":
        """Create PrivateMessage from dictionary data.

        Args:
            data (dict): Dictionary containing message data

        Returns:
            PrivateMessage: New private message instance

        Raises:
            ValueError: If visibility is not 'private' or value is invalid
        """
        if data.get("visibility") != "private":
            raise ValueError("PrivateMessage visibility must be 'private'")
        value = data.get("value")
        if not isinstance(value, str):
            raise ValueError("Value must be a hexadecimal string")
        return cls(bytes.fromhex(value))


class HiddenMessage(Message):
    """Message type for hidden messages that only store an index."""

    def __init__(self, index: int) -> None:
        """Initialize hidden message.

        Args:
            index (int): Index of original message
        """
        self.visibility = "hidden"
        self.index = index

    def to_dict(self) -> dict:
        """Convert message to dictionary format.

        Returns:
            dict: Dictionary with visibility and index
        """
        return {"visibility": self.visibility, "index": self.index}

    @classmethod
    def from_dict(cls, data: dict) -> "HiddenMessage":
        """Create HiddenMessage from dictionary data.

        Args:
            data (dict): Dictionary containing message data

        Returns:
            HiddenMessage: New hidden message instance

        Raises:
            ValueError: If visibility is not 'hidden' or index is invalid
        """
        if data.get("visibility") != "hidden":
            raise ValueError("HiddenMessage visibility must be 'hidden'")
        index = data.get("index")
        if not isinstance(index, int):
            raise ValueError("Index must be an integer")
        return cls(index)


# Type alias for all possible message types
MessageTypes = Union[PublicMessage, PrivateMessage, HiddenMessage]


class NativeAttributeList:
    """Container class for managing a list of messages with different visibility levels."""

    def __init__(self) -> None:
        """Initialize empty message list."""
        self.messages: list[MessageTypes] = []

    def get_message_list(self) -> list[MessageTypes]:
        """Get full list of messages.

        Returns:
            list[MessageTypes]: List of all messages
        """
        return self.messages

    def get_public_message_list(self) -> list[PublicMessage]:
        """Get list of public messages only.

        Returns:
            list[PublicMessage]: List of public messages
        """
        return [msg for msg in self.messages if isinstance(msg, PublicMessage)]

    def get_private_message_list(self) -> list[PrivateMessage]:
        """Get list of private messages only.

        Returns:
            list[PrivateMessage]: List of private messages
        """
        return [msg for msg in self.messages if isinstance(msg, PrivateMessage)]

    def get_all_messages_raw(self) -> list[bytes]:
        """Get raw values of all messages that have values.

        Returns:
            list[bytes]: List of raw message values
        """
        return [msg.value for msg in self.messages if hasattr(msg, "value")]

    def append_private_message(self, message: bytes) -> None:
        """Add a new private message.

        Args:
            message (bytes): Raw message data
        """
        self.messages.append(PrivateMessage(message))

    def append_public_message(self, message: bytes) -> None:
        """Add a new public message.

        Args:
            message (bytes): Raw message data
        """
        self.messages.append(PublicMessage(message))

    def append_hidden_message(self, index: int) -> None:
        """Add a new hidden message.

        Args:
            index (int): Index reference for the message
        """
        self.messages.append(HiddenMessage(index))

    def _get_public_message(self, index: int) -> PublicMessage:
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

    def _get_private_message(self, index: int) -> PrivateMessage:
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
                public_message = self._get_public_message(index)
                self.messages[index] = PrivateMessage(public_message.value)
            except ValueError:
                pass

    def make_message_public(self, index: int) -> None:
        """Convert private message to public at specified index.

        Args:
            index (int): Index of message to convert
        """
        if index < len(self.messages):
            try:
                private_message = self._get_private_message(index)
                self.messages[index] = PublicMessage(private_message.value)
            except ValueError:
                pass

    def make_message_hidden(self, index: int) -> None:
        """Convert message to hidden at specified index.

        Args:
            index (int): Index of message to convert
        """
        if index < len(self.messages):
            self.messages[index] = HiddenMessage(index)

    def remove_message(self, index: int) -> None:
        """Remove message at specified index.

        Args:
            index (int): Index of message to remove
        """
        self.messages.pop(index)

    def recover_message_list(self, message_list: list[dict]) -> None:
        """Recover message list from list of dictionaries.

        Args:
            message_list (list[dict]): List of message dictionaries

        Raises:
            ValueError: If message list is invalid
        """
        backup_messages = self.messages.copy()
        try:
            self.messages = [self._message_from_dict(msg) for msg in message_list]
        except ValueError:
            self.messages = backup_messages
            raise ValueError("Invalid message list.")

    def _message_from_dict(self, data: dict) -> MessageTypes:
        """Create appropriate message type from dictionary data.

        Args:
            data (dict): Dictionary containing message data

        Returns:
            MessageTypes: New message instance

        Raises:
            ValueError: If message visibility is invalid
        """
        visibility = data["visibility"]
        if visibility == "public":
            return PublicMessage.from_dict(data)
        elif visibility == "private":
            return PrivateMessage.from_dict(data)
        elif visibility == "hidden":
            return HiddenMessage.from_dict(data)
        else:
            raise ValueError("Invalid message visibility")

    def hide_private_messages(self) -> "NativeAttributeList":
        """Create new NativeAttributeList with private messages converted to hidden.

        Returns:
            NativeAttributeList: New message list with hidden private messages
        """
        message_list = NativeAttributeList()
        for i, msg in enumerate(self.messages):
            if isinstance(msg, PrivateMessage):
                message_list.append_hidden_message(i)
            else:
                message_list.messages.append(msg)
        return message_list
