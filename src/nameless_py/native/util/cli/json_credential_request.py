from nameless_py.native.library.types.attributes import (
    NativeAttributeList,
    AttributeListModel,
)
from nameless_py.native.util.bytes.hex_string import HexString, HexStringUtil
from nameless_py.native.library.client.credential_builder import (
    NativeCredentialBuilder,
    NativeCredentialHolder,
)
from nameless_py.ffi.nameless_rs import (
    PublicKey,
    GroupParameters,
    CredentialRequest,
    CredentialSecret,
    PartialCredential,
)
from typing import Optional, TypedDict
from pydantic import BaseModel
import os
import json


###
# Exceptions
###


class CredentialError(Exception):
    """Base exception for credential-related errors."""

    pass


class CredentialRequestError(CredentialError):
    """Base exception for credential request errors."""

    pass


class CredentialAlreadyRequestedError(CredentialRequestError):
    """Raised when attempting to request a credential that has already been requested."""

    pass


class CredentialNotRequestedError(CredentialRequestError):
    """Raised when attempting to use a credential that hasn't been requested yet."""

    pass


class CredentialStorageError(CredentialError):
    """Base exception for credential storage errors."""

    pass


class CredentialStorageIOError(CredentialStorageError):
    """Base exception for credential storage I/O errors."""

    pass


class CredentialStorageDirectoryError(CredentialStorageIOError):
    """Raised when there are errors creating/accessing the credentials directory."""

    pass


class CredentialStorageFileError(CredentialStorageIOError):
    """Raised when there are errors reading/writing credential files."""

    pass


class CredentialStoragePermissionError(CredentialStorageError):
    """Raised when there are permission errors accessing credential storage."""

    pass


class CredentialConfigError(CredentialError):
    """Base exception for credential configuration errors."""

    pass


class CredentialConfigFormatError(CredentialConfigError):
    """Raised when the credential configuration format is invalid."""

    pass


class CredentialConfigValidationError(CredentialConfigError):
    """Raised when credential configuration validation fails."""

    pass


class CredentialConfigSerializationError(CredentialConfigError):
    """Raised when serializing/deserializing credential configuration fails."""

    pass


###
# JSON Credential Builder
###


class JSONCredentialBuilderParams(TypedDict):
    """Parameters for initializing a JSONCredentialBuilder.

    Attributes:
        public_key: The issuer's public key
        group_parameters: Group parameters for the credential
        attribute_list: List of attributes to include in credential
        credential_secret: Secret used in credential generation
        issuer_metadata: Optional metadata about the issuer
        endpoint: Optional endpoint URL for the issuer
        is_requested: Whether credential has been requested
    """

    public_key: PublicKey
    group_parameters: GroupParameters
    attribute_list: NativeAttributeList
    credential_secret: CredentialSecret
    issuer_metadata: Optional[str]
    endpoint: Optional[str]
    is_requested: Optional[bool]


class JSONCredentialBuilder:
    """Builder class for managing credential configuration and requests.

    Handles storing credential parameters, making requests, and creating holders.
    """

    def __init__(self, params: JSONCredentialBuilderParams) -> None:
        """Initialize the credential builder with the given parameters.

        Args:
            params: Dictionary of required parameters
        """
        self.public_key: PublicKey = params["public_key"]
        self.group_parameters: GroupParameters = params["group_parameters"]
        self.attribute_list: NativeAttributeList = params["attribute_list"]
        self.credential_secret: CredentialSecret = CredentialSecret()
        self.issuer_metadata: Optional[str] = params["issuer_metadata"]
        self.endpoint: Optional[str] = params["endpoint"]
        self.is_requested: bool = (
            params["is_requested"] if params["is_requested"] is not None else False
        )

    def set_attribute_list(self, attribute_list: NativeAttributeList) -> None:
        """Set the list of attributes for the credential.

        Args:
            attribute_list: New list of attributes to use
        """
        self.attribute_list = attribute_list

    def set_group_parameters(self, group_parameters: GroupParameters) -> None:
        """Set the group parameters for the credential.

        Args:
            group_parameters: New group parameters to use
        """
        self.group_parameters = group_parameters

    def set_issuer_metadata(self, issuer_metadata: str) -> None:
        """Set the issuer metadata.

        Args:
            issuer_metadata: New issuer metadata string
        """
        self.issuer_metadata = issuer_metadata

    def set_endpoint(self, endpoint: str) -> None:
        """Set the issuer endpoint URL.

        Args:
            endpoint: New endpoint URL string
        """
        self.endpoint = endpoint

    def get_credential_request(self) -> CredentialRequest:
        """Generate a credential request.

        Returns:
            A new credential request object

        Raises:
            CredentialAlreadyRequestedError: If credential was already requested
        """
        if self.is_requested:
            raise CredentialAlreadyRequestedError(
                "You've Already Requested A Credential."
            )

        credential_builder = NativeCredentialBuilder(
            {
                "group_parameters": self.group_parameters,
                "attribute_list": self.attribute_list,
                "credential_secret": self.credential_secret,
            }
        )

        self.credential_secret = credential_builder.credential_secret
        self.is_requested = True
        return credential_builder.request_credential()

    def create_holder(
        self, requested_credential: PartialCredential
    ) -> NativeCredentialHolder:
        """Create a credential holder from a requested credential.

        Args:
            requested_credential: The object returned by the issuer when you request a credential

        Returns:
            A new credential holder object

        Raises:
            CredentialNotRequestedError: If credential has not been requested yet
        """
        if not self.is_requested:
            raise CredentialNotRequestedError("You've Not Requested A Credential Yet.")
        credential_builder = NativeCredentialBuilder(
            {
                "group_parameters": self.group_parameters,
                "attribute_list": self.attribute_list,
                "credential_secret": self.credential_secret,
            }
        )
        return credential_builder.create_holder(requested_credential)


###
# Serialization and Deserialization of JSONCredentialBuilder to JSON
###


class JSONCredentialBuilderModel(BaseModel):
    """Pydantic model representing the JSON structure of a JSONCredentialBuilder."""

    public_key: HexString
    group_parameters: HexString
    attribute_list: AttributeListModel
    credential_secret: HexString
    issuer_metadata: Optional[str] = None
    endpoint: Optional[str] = None
    is_requested: bool


class JSONCredentialBuilderIO:
    @staticmethod
    def recover_from_file(path: str) -> JSONCredentialBuilder:
        """Load credential configuration from a JSON file.

        Args:
            path (str): Path to JSON config file

        Raises:
            FileNotFoundError: If the config file does not exist
            CredentialConfigFormatError: If the JSON format is invalid
            CredentialConfigValidationError: If the config data is invalid
            CredentialConfigSerializationError: If CBOR serialization fails
            CredentialStoragePermissionError: If lacking required permissions
        """
        try:
            if not os.path.exists(path):
                raise FileNotFoundError(f"Configuration file not found: {path}")

            # Load JSON File
            try:
                with open(path, "r") as f:
                    config = json.load(f)
            except json.JSONDecodeError as e:
                raise CredentialConfigFormatError(
                    f"Invalid JSON format in config file: {e}"
                )

            # Validate Against Model
            try:
                result = JSONCredentialBuilderModel.model_validate(config)
            except Exception as e:
                raise CredentialConfigValidationError(f"Config validation failed: {e}")

            # Decode Hex Strings
            try:
                public_key_bytes = HexStringUtil.str_to_bytes(
                    result.public_key
                ).unwrap()
                group_parameters_bytes = HexStringUtil.str_to_bytes(
                    result.group_parameters
                ).unwrap()
                credential_secret_bytes = HexStringUtil.str_to_bytes(
                    result.credential_secret
                ).unwrap()
            except Exception as e:
                raise CredentialConfigSerializationError(
                    f"Failed to decode hex strings: {e}"
                )

            # Deserialize CBOR Items
            try:
                public_key = PublicKey.import_cbor(public_key_bytes)
                group_parameters = GroupParameters.import_cbor(group_parameters_bytes)
                credential_secret = CredentialSecret.import_cbor(
                    credential_secret_bytes
                )
            except Exception as e:
                raise CredentialConfigSerializationError(
                    f"Failed to deserialize CBOR data: {e}"
                )

            # Convert Attribute List
            try:
                attribute_list = NativeAttributeList.from_model(result.attribute_list)
            except Exception as e:
                raise CredentialConfigSerializationError(
                    f"Failed to convert attribute list: {e}"
                )

            return JSONCredentialBuilder(
                {
                    "public_key": public_key,
                    "group_parameters": group_parameters,
                    "attribute_list": attribute_list,
                    "credential_secret": credential_secret,
                    "issuer_metadata": result.issuer_metadata,
                    "endpoint": result.endpoint,
                    "is_requested": result.is_requested,
                }
            )

        except (
            FileNotFoundError,
            CredentialConfigError,
            CredentialStoragePermissionError,
        ) as e:
            raise
        except Exception as e:
            raise RuntimeError(f"Unexpected error loading configuration: {e}")

    @staticmethod
    def dump_to_file(json_credential_builder: JSONCredentialBuilder, path: str) -> None:
        """Save credential configuration to a JSON file.

        Args:
            json_credential_builder: The credential builder to save
            path (str): Path to save JSON config

        Raises:
            CredentialConfigValidationError: If the credential configuration is invalid
            CredentialConfigSerializationError: If serialization fails
            CredentialStorageFileError: If unable to write the config file
            CredentialStoragePermissionError: If lacking required permissions
        """
        try:
            # Export CBOR Items To Bytes
            try:
                public_key_bytes = json_credential_builder.public_key.export_cbor()
                group_parameters_bytes = (
                    json_credential_builder.group_parameters.export_cbor()
                )
                credential_secret_bytes = (
                    json_credential_builder.credential_secret.export_cbor()
                )
            except Exception as e:
                raise CredentialConfigSerializationError(
                    f"Failed to export CBOR data: {e}"
                )

            # Convert To Hex Strings
            try:
                public_key_hex = HexStringUtil.bytes_to_str(public_key_bytes)
                group_parameters_hex = HexStringUtil.bytes_to_str(
                    group_parameters_bytes
                )
                credential_secret_hex = HexStringUtil.bytes_to_str(
                    credential_secret_bytes
                )
            except Exception as e:
                raise CredentialConfigSerializationError(
                    f"Failed to convert bytes to hex strings: {e}"
                )

            # Convert Attribute List
            try:
                attribute_list_model = json_credential_builder.attribute_list.to_model()
            except Exception as e:
                raise CredentialConfigSerializationError(
                    f"Failed to convert attribute list: {e}"
                )

            # Create And Validate Config Model
            try:
                config = JSONCredentialBuilderModel(
                    public_key=public_key_hex,
                    group_parameters=group_parameters_hex,
                    credential_secret=credential_secret_hex,
                    attribute_list=attribute_list_model,
                    issuer_metadata=json_credential_builder.issuer_metadata,
                    endpoint=json_credential_builder.endpoint,
                    is_requested=json_credential_builder.is_requested,
                )
            except Exception as e:
                raise CredentialConfigValidationError(
                    f"Failed to create config model: {e}"
                )

            # Save To File
            try:
                with open(path, "w") as f:
                    json.dump(config.model_dump(), f, indent=2)
            except PermissionError as e:
                raise CredentialStoragePermissionError(
                    f"Insufficient permissions to write config file: {e}"
                )
            except OSError as e:
                raise CredentialStorageFileError(f"Failed to write config file: {e}")

        except (CredentialConfigError, CredentialStorageError) as e:
            raise
        except Exception as e:
            raise RuntimeError(f"Unexpected error saving configuration: {e}")
