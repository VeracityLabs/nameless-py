import base64
import json
from typing import Literal, TypedDict, List
from pydantic import BaseModel, Field, ValidationError
from nameless_py.native.library.client.credential_holder import NativeCredentialHolder
from nameless_py.native.library.client.verify import (
    VerifiableSignature,
    VerifiableSignatureType,
    AccumulatorVerifier,
)
from nameless_py.ffi.nameless_rs import (
    PublicKey,
    GroupParameters,
    NamelessSignatureWithAccumulator,
)
from nameless_py.native.util.bytes.hex_string import HexStringUtil

###
# Exceptions
###


class JWSError(Exception):
    """Base exception class for JWS-related errors"""

    pass


class JWSDecodingError(JWSError):
    """Error raised when decoding JWS data fails"""

    pass


class JWSEncodingError(JWSError):
    """Error raised when encoding JWS data fails"""

    pass


class JWSValidationError(JWSError):
    """Error raised when JWS data validation fails"""

    pass


class JWSVerificationError(JWSError):
    """Error raised when JWS signature verification fails"""

    pass


###
# Helper Functions
###


def _decode_base64url(data: str) -> bytes:
    """
    Decode a base64url-encoded string.

    Args:
        data (str): The base64url-encoded string to decode

    Returns:
        bytes: The decoded bytes

    Raises:
        JWSDecodingError: If decoding fails
    """
    padding_needed = 4 - (len(data) % 4)
    if padding_needed and padding_needed != 4:
        data += "=" * padding_needed
    try:
        return base64.urlsafe_b64decode(data)
    except Exception as e:
        raise JWSDecodingError(f"Invalid base64url encoding: {e}")


def _encode_base64url(data: bytes) -> str:
    """
    Encode a bytes object to a base64url-encoded string.

    Args:
        data (bytes): The bytes to encode

    Returns:
        str: The base64url-encoded string

    Raises:
        JWSEncodingError: If encoding fails
    """
    try:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")
    except Exception as e:
        raise JWSEncodingError(f"Failed to encode data to base64url: {e}")


###
# Models
###


class JWSHeader(BaseModel):
    """
    Model for JWS header parameters.

    Attributes:
        alg (str): Algorithm used for signing, fixed to "nameless_bbs_2024"
        typ (str): Type of token, fixed to "JWS"
        kid (str): Group public key
        gpr (str): Group parameters
    """

    alg: Literal["nameless_bbs_2024"] = Field(
        "nameless_bbs_2024", description="Algorithm Used for Signing"
    )
    typ: Literal["JWS"] = Field("JWS", description="Type of Token")
    kid: str = Field(..., description="Public Key")
    gpr: str = Field(..., description="Group Parameters")


class JWSModel(BaseModel):
    """
    Model for JWS tokens.

    Attributes:
        header (JWSHeader): The JWS header containing metadata
        payload (bytes): The payload data
        signature (bytes): The cryptographic signature
    """

    header: JWSHeader
    payload: bytes
    signature: bytes

    @classmethod
    def decode(cls, jws_string: str) -> "JWSModel":
        """
        Parse a JWS compact serialization string into a JWSModel instance.

        Args:
            jws_string (str): The JWS string to decode

        Returns:
            JWSModel: The decoded JWS model

        Raises:
            JWSValidationError: If the input format is invalid
            JWSDecodingError: If decoding components fails
        """
        if not isinstance(jws_string, str):
            raise JWSValidationError("JWS input must be a string")

        parts = jws_string.split(".")
        if len(parts) != 3:
            raise JWSValidationError(
                "Invalid JWS format: must contain exactly two dots"
            )

        header_b64, payload_b64, signature_b64 = parts

        try:
            # Decode each part
            header_bytes = _decode_base64url(header_b64)
            payload_bytes = _decode_base64url(payload_b64)
            signature_bytes = _decode_base64url(signature_b64)

            # Parse header JSON
            header_json = header_bytes.decode("utf-8")
            header_data = json.loads(header_json)
            header = JWSHeader(**header_data)

        except JWSDecodingError as e:
            raise JWSDecodingError(f"Failed to decode JWS components: {e}")
        except UnicodeDecodeError as e:
            raise JWSDecodingError(f"Invalid header encoding: {e}")
        except json.JSONDecodeError as e:
            raise JWSValidationError(f"Invalid JSON in header: {e}")
        except ValidationError as e:
            raise JWSValidationError(f"Header validation error: {e}")

        return cls(header=header, payload=payload_bytes, signature=signature_bytes)

    def encode(self) -> str:
        """
        Encode the JWSModel into a compact serialization string.

        Returns:
            str: The encoded JWS string

        Raises:
            JWSEncodingError: If encoding fails
        """
        try:
            header_json = json.dumps(self.header.model_dump(), separators=(",", ":"))
            header_b64 = _encode_base64url(header_json.encode("utf-8"))
            payload_b64 = _encode_base64url(self.payload)
            signature_b64 = _encode_base64url(self.signature)
            return f"{header_b64}.{payload_b64}.{signature_b64}"
        except (JWSEncodingError, UnicodeEncodeError, TypeError) as e:
            raise JWSEncodingError(f"Failed to encode JWS: {e}")


###
# Main Class
###


class JWSSigningParams(TypedDict):
    """
    Parameters required for signing a JWS token.

    Attributes:
        credential_holder (NativeCredentialHolder): The credential holder for signing
        public_indices (List[int]): List of public indices to use
        bytes_to_sign (bytes): The data to sign
    """

    credential_holder: NativeCredentialHolder
    public_indices: List[int]
    bytes_to_sign: bytes


class NamelessJWS:
    """
    Class for handling Nameless JWS operations.

    This class provides functionality for signing and verifying JWS tokens
    using the Nameless signature scheme.
    """

    def __init__(self, public_key: PublicKey, group_parameters: GroupParameters):
        """
        Initialize a NamelessJWS instance.

        Args:
            public_key (PublicKey): The public key for signing/verification
            group_parameters (GroupParameters): The group parameters

        Raises:
            JWSError: If initialization fails
        """
        try:
            self.public_key: str = HexStringUtil.bytes_to_str(public_key.export_cbor())
            self.group_parameters: str = HexStringUtil.bytes_to_str(
                group_parameters.export_cbor()
            )
        except Exception as e:
            raise JWSError(f"Failed to initialize NamelessJWS: {e}")

    def sign(self, params: JWSSigningParams) -> str:
        """
        Sign data and create a JWS token.

        Args:
            params (JWSSigningParams): Parameters for signing

        Returns:
            str: The signed JWS token string

        Raises:
            JWSError: If signing fails
            TypeError: If parameters are of incorrect type
        """
        try:
            bytes_to_sign = params["bytes_to_sign"]
            credential_holder = params["credential_holder"]
            public_indices = params["public_indices"]

            if not isinstance(credential_holder, NativeCredentialHolder):
                raise TypeError(
                    "credential_holder must be a NativeCredentialHolder instance"
                )
            if not isinstance(public_indices, list):
                raise TypeError("public_indices must be a list of integers")
            if not isinstance(bytes_to_sign, bytes):
                raise TypeError("bytes_to_sign must be bytes")

            signature_bytes = credential_holder.sign_with_credential(
                bytes_to_sign, public_indices
            ).export_cbor()
            return JWSModel(
                header=JWSHeader(
                    kid=self.public_key,
                    gpr=self.group_parameters,
                    alg="nameless_bbs_2024",
                    typ="JWS",
                ),
                payload=bytes_to_sign,
                signature=signature_bytes,
            ).encode()
        except KeyError as e:
            raise JWSError(f"Missing required parameter: {e}")
        except Exception as e:
            raise JWSError(f"Signing failed: {e}")

    @staticmethod
    def verify(jws_string: str, accumulator_verifier: AccumulatorVerifier) -> bool:
        """
        Verify a JWS token.

        Args:
            jws_string (str): The JWS token to verify
            accumulator_verifier (AccumulatorVerifier): The verifier to use

        Returns:
            bool: True if verification succeeds, False otherwise

        Raises:
            JWSVerificationError: If an unexpected error occurs during verification
        """
        try:
            jws_model = JWSModel.decode(jws_string)

            public_key_str = jws_model.header.kid
            public_key_bytes = HexStringUtil.str_to_bytes(public_key_str).unwrap()
            public_key = PublicKey.import_cbor(public_key_bytes)

            group_parameters_str = jws_model.header.gpr
            group_parameters_bytes = HexStringUtil.str_to_bytes(
                group_parameters_str
            ).unwrap()
            group_parameters = GroupParameters.import_cbor(group_parameters_bytes)

            payload = jws_model.payload
            signature = NamelessSignatureWithAccumulator.import_cbor(
                jws_model.signature
            )

            verifiable_object: VerifiableSignatureType = VerifiableSignature(
                signature, payload, accumulator_verifier
            )

            return verifiable_object.verify(public_key, group_parameters)

        except JWSError:
            return False
        except ValueError:
            return False
        except Exception as e:
            raise JWSVerificationError(f"Unexpected error during verification: {e}")
