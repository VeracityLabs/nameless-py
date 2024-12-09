from typing import TypedDict
from pydantic import BaseModel
from nameless_py.ffi.nameless_rs import *
from nameless_py.native.library.types.message_list import NativeAttributeList
import json

# TODO: I'm Not Sure If This Is The Correct Schema.
class ParsedCredentialAttribute(BaseModel):
    value: str
    attribute_type: AttributeType


class HolderParams(TypedDict):
    holder_builder: HolderBuilder
    credential_attributes: CredentialAttributeList
    credential_secret: CredentialSecret


class NativeCredentialHolder:
    def __init__(self, params: HolderParams) -> None:
        """Initialize a Holder from a HolderBuilder, CredentialAttributeList, and CredentialSecret"""
        try:
            self.holder = Holder(
                params["holder_builder"],
                params["credential_attributes"],
                params["credential_secret"],
            )
        except Exception as e:
            raise RuntimeError(f"Failed to initialize holder: {e}")

    def _get_attribute_list_from_credential(self) -> CredentialAttributeList:
        """Get the attribute list from the credential"""
        try:
            credential = self.holder.get_credential()
            return credential.get_credential_attribute_list()
        except Exception as e:
            raise RuntimeError(f"Failed to get attribute list: {e}")

    def _parse_and_validate_attribute_list(self, attribute_list: CredentialAttributeList) -> list[ParsedCredentialAttribute]:
        """Validate the message format"""
        try:
            # TODO: I'm Not Sure If I'm Validating And Parsing The Attribute List Correctly
            messages_json_str = attribute_list.export_json()
            messages_json = json.loads(messages_json_str)
            return [ParsedCredentialAttribute(**msg) for msg in messages_json]
        except ValueError as e:
            raise RuntimeError(f"Failed to validate credential messages: {e}")
        except TypeError as e:
            raise RuntimeError(f"Invalid message format in credential: {e}")

    def _format_messages(self, validated_messages: list[ParsedCredentialAttribute]) -> list[dict]:
        """Format messages with visibility and value"""
        try:
            return [
                {
                    "visibility": (
                        "public"
                        if msg.attribute_type == AttributeType.PUBLIC
                        else "private"
                    ),
                    "value": msg.value,
                }
                for msg in validated_messages
            ]
        except Exception as e:
            raise RuntimeError(f"Failed to format credential messages: {e}")

    def _create_message_list(self, formatted_messages: list[dict]) -> NativeAttributeList:
        """Create a NativeAttributeList from formatted messages"""
        try:
            message_list = NativeAttributeList()
            message_list.recover_message_list(formatted_messages)
            return message_list
        except Exception as e:
            raise RuntimeError(f"Failed to recover message list: {e}")

    def _extract_messages_from_credential(self) -> NativeAttributeList:
        """Extract messages from the credential and return as NativeAttributeList"""
        attribute_list = self._get_attribute_list_from_credential()
        validated_messages = self._parse_and_validate_attribute_list(attribute_list)
        formatted_messages = self._format_messages(validated_messages)
        return self._create_message_list(formatted_messages)

    def read_credential(self, unsafe: bool = False) -> NativeAttributeList:
        """Read credential messages, optionally hiding private messages"""
        try:
            message_list = self._extract_messages_from_credential()
            if unsafe:
                return message_list.hide_private_messages()
            else:
                return message_list
        except Exception as e:
            raise RuntimeError(f"Failed to read credential safely: {e}")

    def request_credential_update(self) -> bytes:
        """Request a credential update"""
        raise NotImplementedError("request_credential_update not implemented")

    def import_credential_update(self, credential_update: bytes) -> None:
        """Import a credential update"""
        raise NotImplementedError("import_credential_update not implemented")

    def sign_with_credential(
        self, data_to_prove: bytes, public_indices: list[int]
    ) -> bytes:
        """Create a signature revealing only the specified public indices"""
        try:
            signature = self.holder.create_signature_with_accumulator(data_to_prove)
            return signature.export_cbor()
        except Exception as e:
            raise RuntimeError(f"Failed to sign with credential: {e}")
