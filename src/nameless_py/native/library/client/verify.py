from nameless_py.ffi.nameless_rs import *
from nameless_py.native.library.types.attributes import NativeAttributeList
from nameless_py.native.library.types.accumulator import AccumulatorVerifier
from dataclasses import dataclass
from typing import Protocol, Union, TypedDict
from pydantic import BaseModel
import json

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

    def get_accumulator_verifier(self) -> AccumulatorVerifier: ...

    def verify(
        self, public_key: PublicKey, group_parameters: GroupParameters
    ) -> bool: ...


### Implementations Of The VerifiableSignatureProtocol Protocol
@dataclass
class VerifiableNamelessSignatureWithoutAccumulator(VerifiableSignatureProtocol):
    signature: NamelessSignature
    data_hash: bytes
    accumulator_value: AccumulatorValue
    accumulator_signature: AccumulatorSignature
    accumulator_verifier: AccumulatorVerifier

    def get_signature_of_data(self) -> NamelessSignature:
        return self.signature

    def get_hash_of_data(self) -> bytes:
        return self.data_hash

    def get_accumulator_value(self) -> AccumulatorValue:
        return self.accumulator_value

    def get_accumulator_signature(self) -> AccumulatorSignature:
        return self.accumulator_signature

    def get_accumulator_verifier(self) -> AccumulatorVerifier:
        return self.accumulator_verifier

    def verify(self, public_key: PublicKey, group_parameters: GroupParameters) -> bool:
        try:
            signature = self.get_signature_of_data()
            data_hash = self.get_hash_of_data()
            accumulator_value = self.get_accumulator_value()
            accumulator_signature = self.get_accumulator_signature()
            is_valid_accumulator = self.get_accumulator_verifier()(
                accumulator_value, accumulator_signature
            )
            return is_valid_accumulator & signature.verify(
                public_key, group_parameters, accumulator_value, data_hash
            )
        except Exception as e:
            raise RuntimeError(f"Failed to verify proof: {e}")


### Implementation Of The VerifiableSignatureProtocol Protocol
@dataclass
class VerifiableNamelessSignatureWithAccumulator(VerifiableSignatureProtocol):
    signature: NamelessSignatureWithAccumulator
    data_hash: bytes
    accumulator_verifier: AccumulatorVerifier

    def get_signature_of_data(self) -> NamelessSignature:
        return self.signature.get_signature()

    def get_hash_of_data(self) -> bytes:
        return self.data_hash

    def get_accumulator_value(self) -> AccumulatorValue:
        return self.signature.get_accumulator().get_value()

    def get_accumulator_signature(self) -> AccumulatorSignature:
        return self.signature.get_accumulator().get_signature()

    def get_accumulator_verifier(self) -> AccumulatorVerifier:
        return self.accumulator_verifier

    def verify(self, public_key: PublicKey, group_parameters: GroupParameters) -> bool:
        try:
            signature = self.get_signature_of_data()
            data_hash = self.get_hash_of_data()
            accumulator_value = self.get_accumulator_value()
            accumulator_signature = self.get_accumulator_signature()
            is_valid_accumulator = self.get_accumulator_verifier()(
                accumulator_value, accumulator_signature
            )
            return is_valid_accumulator & signature.verify(
                public_key, group_parameters, accumulator_value, data_hash
            )
        except Exception as e:
            raise RuntimeError(f"Failed to verify proof: {e}")


###
# Helpful Types
###

### Union Of All Data Types Which Implement Features Needed For Signature Verification (VerifiableSignatureProtocol)
VerifiableSignatureObject = Union[
    VerifiableNamelessSignatureWithoutAccumulator,
    VerifiableNamelessSignatureWithAccumulator,
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
        self.public_key = params["public_key"]
        self.group_parameters = params["group_parameters"]

    def verify_signature(self, params: VerifiableSignatureObject) -> bool:
        try:
            return params.verify(self.public_key, self.group_parameters)
        except Exception as e:
            raise RuntimeError(f"Failed to verify proof: {e}")

    def read_attribute_list(
        self, params: VerifiableSignatureObject
    ) -> NativeAttributeList:
        raise NotImplementedError("read_attribute_list not implemented")
