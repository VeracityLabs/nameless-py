from nameless_py.ffi.nameless_rs import (
    NamelessSignature,
    PublicKey,
    GroupParameters,
    AccumulatorValue,
    AccumulatorSignature,
    NamelessSignatureWithAccumulator,
    NamelessSignature,
)
from nameless_py.native.library.types.attributes import NativeAttributeList
from nameless_py.native.library.types.accumulator import AccumulatorVerifierType
from dataclasses import dataclass
from typing import Protocol, Union, TypedDict
from pydantic import BaseModel
import json

###
# Exceptions
###


class VerifierError(Exception):
    """Base exception for verifier errors"""

    pass


class SignatureVerificationError(VerifierError):
    """Error verifying signature"""

    pass


class AccumulatorVerificationError(VerifierError):
    """Error verifying accumulator"""

    pass


class AttributeListError(VerifierError):
    """Error accessing or processing attribute list"""

    pass


class VerifierInitializationError(VerifierError):
    """Error initializing verifier"""

    pass


###
# Utilities And Protocols For Verifying Nameless Signatures
###


# TODO: Use Of Protocol Is Not Working As Expected, It Doesn't Seem To Be Enforcing.
### Interface For Verifying Nameless Signatures
class VerifiableSignatureProtocol(Protocol):
    def get_signature_of_data(self) -> NamelessSignature: ...

    def get_hash_of_data(self) -> bytes: ...

    def get_accumulator_value(self) -> AccumulatorValue: ...

    def get_accumulator_signature(self) -> AccumulatorSignature: ...

    def get_accumulator_verifier(self) -> AccumulatorVerifierType: ...

    def get_attribute_list(self) -> NativeAttributeList: ...

    def verify(
        self, public_key: PublicKey, group_parameters: GroupParameters
    ) -> bool: ...


### Implementations Of The VerifiableSignatureProtocol Protocol
@dataclass
class VerifiableSignatureWithoutAccumulator(VerifiableSignatureProtocol):
    signature: NamelessSignature
    data_hash: bytes
    accumulator_value: AccumulatorValue
    accumulator_signature: AccumulatorSignature
    accumulator_verifier: AccumulatorVerifierType

    def get_signature_of_data(self) -> NamelessSignature:
        return self.signature

    def get_hash_of_data(self) -> bytes:
        return self.data_hash

    def get_accumulator_value(self) -> AccumulatorValue:
        return self.accumulator_value

    def get_accumulator_signature(self) -> AccumulatorSignature:
        return self.accumulator_signature

    def get_accumulator_verifier(self) -> AccumulatorVerifierType:
        return self.accumulator_verifier

    def get_attribute_list(self) -> NativeAttributeList:
        try:
            attribute_list_json = self.signature.get_attribute_list().export_json()
            return NativeAttributeList.from_json(attribute_list_json)
        except ValueError as e:
            raise AttributeListError(f"Invalid attribute list format: {e}")
        except Exception as e:
            raise AttributeListError(f"Failed to extract attribute list: {e}")

    def verify(self, public_key: PublicKey, group_parameters: GroupParameters) -> bool:
        try:
            signature = self.get_signature_of_data()
            data_hash = self.get_hash_of_data()
            accumulator_value = self.get_accumulator_value()
            accumulator_signature = self.get_accumulator_signature()

            try:
                is_valid_accumulator = self.get_accumulator_verifier()(
                    accumulator_value, accumulator_signature
                )
            except Exception as e:
                raise AccumulatorVerificationError(f"Failed to verify accumulator: {e}")

            try:
                is_valid_signature = signature.verify(
                    public_key, group_parameters, accumulator_value, data_hash
                )
            except Exception as e:
                raise SignatureVerificationError(f"Failed to verify signature: {e}")

            return is_valid_accumulator & is_valid_signature

        except (AccumulatorVerificationError, SignatureVerificationError):
            raise
        except Exception as e:
            raise VerifierError(f"Unexpected error during verification: {e}")


### Implementation Of The VerifiableSignatureProtocol Protocol
@dataclass
class VerifiableSignature(VerifiableSignatureProtocol):
    signature: NamelessSignatureWithAccumulator
    data_hash: bytes
    accumulator_verifier: AccumulatorVerifierType

    def get_signature_of_data(self) -> NamelessSignature:
        return self.signature.get_signature()

    def get_hash_of_data(self) -> bytes:
        return self.data_hash

    def get_accumulator_value(self) -> AccumulatorValue:
        return self.signature.get_accumulator().get_value()

    def get_accumulator_signature(self) -> AccumulatorSignature:
        return self.signature.get_accumulator().get_signature()

    def get_accumulator_verifier(self) -> AccumulatorVerifierType:
        return self.accumulator_verifier

    def get_attribute_list(self) -> NativeAttributeList:
        try:
            attribute_list_json = self.signature.get_attribute_list().export_json()
            return NativeAttributeList.from_json(attribute_list_json)
        except ValueError as e:
            raise AttributeListError(f"Invalid attribute list format: {e}")
        except Exception as e:
            raise AttributeListError(f"Failed to extract attribute list: {e}")

    def verify(self, public_key: PublicKey, group_parameters: GroupParameters) -> bool:
        try:
            signature = self.get_signature_of_data()
            data_hash = self.get_hash_of_data()
            accumulator_value = self.get_accumulator_value()
            accumulator_signature = self.get_accumulator_signature()

            try:
                is_valid_accumulator = self.get_accumulator_verifier()(
                    accumulator_value, accumulator_signature
                )
            except Exception as e:
                raise AccumulatorVerificationError(f"Failed to verify accumulator: {e}")

            try:
                is_valid_signature = signature.verify(
                    public_key, group_parameters, accumulator_value, data_hash
                )
            except Exception as e:
                raise SignatureVerificationError(f"Failed to verify signature: {e}")

            return is_valid_accumulator & is_valid_signature

        except (AccumulatorVerificationError, SignatureVerificationError):
            raise
        except Exception as e:
            raise VerifierError(f"Unexpected error during verification: {e}")


###
# Helpful Types
###

### Union Of All Data Types Which Implement Features Needed For Signature Verification (VerifiableSignatureProtocol)
VerifiableSignatureType = Union[
    VerifiableSignatureWithoutAccumulator,
    VerifiableSignature,
]


### Parameters For Constructing A NativeVerifier
class NativeVerifierParams(TypedDict):
    public_key: PublicKey
    group_parameters: GroupParameters


### Pydantic Model For Validating Signature Attributes
class ParsedSignatureAttribute(BaseModel):
    value: bytes


###
# Native Implementation Of A Nameless Signature Verifier
###


class NativeVerifier:

    def __init__(self, params: NativeVerifierParams) -> None:
        try:
            self.public_key = params["public_key"]
            self.group_parameters = params["group_parameters"]
        except KeyError as e:
            raise VerifierInitializationError(f"Missing required parameter: {e}")
        except Exception as e:
            raise VerifierInitializationError(f"Failed to initialize verifier: {e}")

    def verify_signature(self, params: VerifiableSignatureType) -> bool:
        try:
            return params.verify(self.public_key, self.group_parameters)
        except (
            AccumulatorVerificationError,
            SignatureVerificationError,
            VerifierError,
        ):
            raise
        except Exception as e:
            raise VerifierError(f"Unexpected error during verification: {e}")

    def read_attribute_list(
        self, params: VerifiableSignatureType
    ) -> NativeAttributeList:
        try:
            return params.get_attribute_list()
        except AttributeListError:
            raise
        except Exception as e:
            raise AttributeListError(f"Failed to read attribute list: {e}")
