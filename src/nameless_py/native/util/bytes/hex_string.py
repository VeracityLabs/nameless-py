from result import Result, Ok, Err
from typing import Annotated
from pydantic import BeforeValidator

###
# Exceptions
###


class HexStringError(Exception):
    """Base exception class for hex string related errors."""

    pass


class HexStringPrefixError(HexStringError):
    """Raised when hex string is missing required 0x prefix."""

    pass


class HexStringFormatError(HexStringError):
    """Raised when hex string contains invalid characters."""

    pass


class HexStringConversionError(HexStringError):
    """Raised when conversion between hex string and bytes fails."""

    pass


###
# Validation
###


def validate_hex_string(v: str) -> str:
    """Validate Hex String.

    Args:
        v (str): The hex string to validate

    Returns:
        str: The validated hex string with 0x prefix

    Raises:
        HexStringPrefixError: If string doesn't start with 0x prefix
        HexStringFormatError: If string contains invalid hex characters
    """

    if not v.startswith("0x"):
        raise HexStringPrefixError("Hex string must start with 0x prefix")

    hex_str = v[2:]

    try:
        bytes.fromhex(hex_str)
        return f"0x{hex_str}"
    except ValueError:
        raise HexStringFormatError("Invalid hexadecimal characters in string")


# Custom Type For Validated Hex Strings, Needed for Pydantic
HexString = Annotated[str, BeforeValidator(validate_hex_string)]


###
# Util
###


class HexStringUtil:
    @staticmethod
    def bytes_to_str(value: bytes) -> str:
        """Convert bytes to hex string with 0x prefix.

        Args:
            value (bytes): Bytes to convert

        Returns:
            str: Hex string with 0x prefix
        """
        return "0x" + value.hex()

    @staticmethod
    def str_to_bytes(value: str) -> Result[bytes, str]:
        """Parse hex string with optional 0x prefix to bytes.

        Args:
            value (str): Hex string to parse

        Returns:
            Result[bytes, str]: Success with bytes value or error message
        """
        try:
            hex_str = value[2:] if value.startswith("0x") else value
            return Ok(bytes.fromhex(hex_str))
        except ValueError:
            return Err("Invalid hex string format")
