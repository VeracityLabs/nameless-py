##
# This is an example of how to use the see3_python library
# to create a custom script for the see3 server
##

from nameless_py.ffi.nameless_rs import (
    PartialCredential,
    Identifier,
    NamelessSignature,
)
from nameless_py.native.server import IssueChecks, RevokeChecks, OpenChecks
from result import Result, Ok, Err
from nameless_py.native.playintegrity.unique_value_manager import UNIQUE_VALUE_SIZE
from typing import Optional, Callable, TypeAlias
from fastapi import APIRouter
from typing import Literal
import os
import binascii

###
# Required Functions:

# issue(request: PartialCredential, auxiliary: Optional[object]) -> Result[Literal[True], str]
# revoke(request: Identifier, auxiliary: Optional[object]) -> Result[Literal[True], str]
# open(request: NamelessSignature, auxiliary: Optional[object]) -> Result[Literal[True], str]

# You can define any arbitrary conditions and return a Result with True if the checks pass,
# or an error message string if they fail.
###


# Ensure that the required functions are typed as Callable[[Optional[bytes], Optional[object]], dict]

def issue(
    request: PartialCredential,
    auxiliary: Optional[object],
) -> Result[Literal[True], str]:
    try:
        if not request:
            return Err("Request is required")
        return Ok(True)
    except Exception as e:
        return Err(f"Validation Error: {e}")


def revoke(
    request: Identifier,
    auxiliary: Optional[object],
) -> Result[Literal[True], str]:
    try:
        if not request:
            return Err("Request is required")
        return Ok(True)
    except Exception as e:
        return Err(f"Validation Error: {e}")



def open(
    request: NamelessSignature,
    auxiliary: Optional[object],
) -> Result[Literal[True], str]:
    try:
        if not request:
            return Err("Request is required")
        return Ok(True)
    except Exception as e:
        return Err(f"Validation Error: {e}")

###
# Optional Capabilities:

# You can extend the nameless server with additional routes and capabilities.
# This is useful for adding custom logic to the nameless server.
###

# This is the router for the additional routes.
additional_routes = APIRouter()

@additional_routes.get("/playintegrity/unique_value")
def get_playintegrity_unique_value() -> bytes:
    """
    Generates a new unique value (32 random bytes), and returns the
    URL-safe Base64-encoded representation of those bytes.
    """
    unique_value_bytes = os.urandom(UNIQUE_VALUE_SIZE)
    unique_value_string = binascii.hexlify(unique_value_bytes)
    return unique_value_string
