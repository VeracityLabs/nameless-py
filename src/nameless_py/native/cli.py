from nameless_py.native.util.bytes.hex_string import HexString, HexStringUtil
from nameless_py.native.library.types.attributes import (
    NativeAttributeList,
)
from nameless_py.ffi.nameless_rs import (
    PublicKey,
    GroupParameters,
    CredentialSecret,
    NamelessSignatureWithAccumulator,
)
from nameless_py.native.library.client.verify import (
    AccumulatorVerifier,
    VerifiableSignatureType,
    VerifiableSignature,
)
from nameless_py.native.library.client.credential_holder import NativeCredentialHolder
from nameless_py.native.util.cli.json_credential_request import (
    JSONCredentialBuilderParams,
    JSONCredentialBuilder,
    JSONCredentialBuilderIO,
)
from nameless_py.native.util.cli.jws import (
    NamelessJWS,
    JWSModel,
    JWSError,
    JWSDecodingError,
    JWSValidationError,
    JWSVerificationError,
)
from typing import Optional, List
from nameless_py.config import CREDENTIALS_DIR
import click
import os
import random
import string

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
# Utility Functions
###


def save_credential(user_id: str, credential: bytes) -> None:
    """Save a credential to disk.

    Args:
        user_id: Unique identifier for the credential owner
        credential: Raw credential bytes to save

    Raises:
        CredentialStorageDirectoryError: If unable to create/access credentials directory
        CredentialStorageFileError: If unable to write credential file
        CredentialStoragePermissionError: If lacking required permissions
    """
    try:
        if not os.path.exists(CREDENTIALS_DIR):
            os.makedirs(CREDENTIALS_DIR)
    except PermissionError as e:
        raise CredentialStoragePermissionError(
            f"Insufficient permissions to create credentials directory: {e}"
        )
    except OSError as e:
        raise CredentialStorageDirectoryError(
            f"Failed to create credentials directory: {e}"
        )

    try:
        with open(os.path.join(CREDENTIALS_DIR, f"{user_id}.cred"), "wb") as f:
            f.write(credential)
    except PermissionError as e:
        raise CredentialStoragePermissionError(
            f"Insufficient permissions to write credential file: {e}"
        )
    except OSError as e:
        raise CredentialStorageFileError(f"Failed to write credential file: {e}")


def generate_random_name(length: int = 8) -> str:
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


@click.group(help="CLI tool for managing anonymous credentials.")
def cli() -> None:
    pass


def _interactive_attribute_list() -> NativeAttributeList:
    """Interactively create a list of attributes with ASCII validation.

    Returns:
        NativeAttributeList: List of validated attributes

    Raises:
        click.ClickException: If there are issues with attribute validation or encoding
    """
    attribute_list = NativeAttributeList()
    while True:
        try:
            attr = click.prompt(
                "Enter an Attribute (or empty to finish)", type=str, default=""
            )
            if not attr:
                if len(attribute_list.messages) == 0:
                    click.echo("Error: Must provide at least one attribute")
                    continue
                break

            if not attr.strip():
                click.echo("Error: Attribute cannot be empty or just whitespace")
                continue

            if not attr.isascii():
                click.echo("Error: Attribute must contain only ASCII characters")
                continue

            try:
                encoded_attr = attr.encode("ascii")
            except UnicodeEncodeError:
                click.echo("Error: Failed to encode attribute as ASCII")
                continue

            if len(encoded_attr) > 30:
                click.echo(
                    "Error: Attribute must be 30 bytes or less when encoded as ASCII"
                )
                continue

            visibility = click.prompt(
                "Should this attribute be public or private?",
                type=click.Choice(["public", "private"]),
                default="public",
            )

            try:
                if visibility == "public":
                    attribute_list.append_public_attribute(encoded_attr)
                else:
                    attribute_list.append_private_attribute(encoded_attr)
            except Exception as e:
                click.echo(f"Error adding attribute: {str(e)}")
                continue

        except click.Abort:
            raise click.ClickException("Aborted by user")
        except Exception as e:
            click.echo(f"Unexpected error: {str(e)}")
            continue

    return attribute_list


@click.command(help="Helps you setup a credential request configuration file.")
@click.argument("output_path", type=click.Path())
@click.option("--interactive", is_flag=True, help="Run the setup interactively.")
@click.option(
    "--public_attributes",
    type=str,
    multiple=True,
    help="Attributes to include in the credential request.",
)
@click.option(
    "--private_attributes",
    type=str,
    multiple=True,
    help="Private attributes to include in the credential request.",
)
@click.option("--public_key", type=str, help="Issuer's public key (hex).")
@click.option("--group_parameters", type=str, help="Issuer's group parameters (hex).")
@click.option(
    "--issuer_metadata", type=str, default="", help="Issuer metadata (optional)."
)
@click.option("--endpoint", type=str, help="Issuer's endpoint URL.")
def setup_credential_request(
    output_path: str,
    interactive: bool,
    public_attributes: List[str],
    private_attributes: List[str],
    public_key: str,
    group_parameters: str,
    issuer_metadata: str,
    endpoint: str,
) -> None:
    # Validate Attributes
    if len(public_attributes) > 0 or len(private_attributes) > 0 or not interactive:
        attribute_list = NativeAttributeList()
        for attr in public_attributes:
            try:
                encoded_attr = attr.encode("ascii")
                if len(encoded_attr) > 30:
                    raise click.ClickException(
                        f"Public attribute '{attr}' exceeds 30 bytes when encoded"
                    )
                attribute_list.append_public_attribute(encoded_attr)
            except UnicodeEncodeError:
                raise click.ClickException(
                    f"Public attribute '{attr}' contains non-ASCII characters"
                )

        for attr in private_attributes:
            try:
                encoded_attr = attr.encode("ascii")
                if len(encoded_attr) > 30:
                    raise click.ClickException(
                        f"Private attribute '{attr}' exceeds 30 bytes when encoded"
                    )
                attribute_list.append_private_attribute(encoded_attr)
            except UnicodeEncodeError:
                raise click.ClickException(
                    f"Private attribute '{attr}' contains non-ASCII characters"
                )
    else:
        attribute_list = _interactive_attribute_list()

    # Validate Public Key And Group Parameters
    public_key_bytes = HexStringUtil.str_to_bytes(public_key).unwrap()
    group_parameters_bytes = HexStringUtil.str_to_bytes(group_parameters).unwrap()

    public_key_type = PublicKey.import_cbor(public_key_bytes)
    group_parameters_type = GroupParameters.import_cbor(group_parameters_bytes)

    # Create credential builder params
    params: JSONCredentialBuilderParams = {
        "public_key": public_key_type,
        "group_parameters": group_parameters_type,
        "attribute_list": attribute_list,
        "credential_secret": CredentialSecret(),
        "issuer_metadata": issuer_metadata if issuer_metadata else None,
        "endpoint": endpoint if endpoint else None,
        "is_requested": None,
    }

    try:
        # Create credential builder with params
        builder = JSONCredentialBuilder(params)
    except ValueError as e:
        raise click.ClickException(f"Invalid hex string: {e}")

    # Save configuration
    try:
        JSONCredentialBuilderIO.dump_to_file(builder, output_path)
        click.echo(f"Credential request configuration saved to {output_path}")
    except Exception as e:
        raise click.ClickException(f"Failed to save configuration: {e}")


@click.command(help="Request a credential using the provided configuration file.")
@click.argument("config_path", type=click.Path(exists=True))
def request_credential(config_path: str) -> None:
    """Request a credential using the provided configuration file.

    Args:
        config_path: Path to the credential request configuration file
    """
    try:
        # Load the credential builder from config file
        builder = JSONCredentialBuilderIO.recover_from_file(config_path)

        # Get the credential request
        request = builder.get_credential_request()

        # Save updated builder state back to file
        JSONCredentialBuilderIO.dump_to_file(builder, config_path)

        # Export the request as CBOR and print as hex
        request_bytes = request.export_cbor()
        request_hex = HexStringUtil.bytes_to_str(request_bytes)

        # TODO: automatically send request to given endpoint.
        click.echo(request_hex)

    except CredentialAlreadyRequestedError as e:
        raise click.ClickException(str(e))
    except Exception as e:
        raise click.ClickException(f"Failed to request credential: {e}")


@click.command(help="Verify a signature using the provided data or a file.")
@click.option(
    "--from-file",
    type=click.Path(exists=True),
    required=False,
    help="Path to a CBOR-serialized file containing the Signature data.",
)
@click.argument("signature", required=False, type=str)
@click.option(
    "--show_attributes",
    is_flag=True,
    default=True,
    help="Dump the attributes of the signature.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Only Print If Signature Is Valid.",
)
@click.argument("public_key", required=False, type=str)
@click.argument("group_parameters", required=False, type=str)
@click.argument("data_hash", required=False, type=str)
def verify_raw_signature(
    from_file: Optional[str],
    signature: Optional[str],
    show_attributes: bool,
    quiet: bool,
    public_key: str,
    group_parameters: str,
    data_hash: str,
) -> None:
    """Verify a signature using provided data or from a file.

    Args:
        from_file: Optional path to CBOR file containing signature
        show_attributes: Whether to display signature attributes
        quiet: Only show if signature is valid
        public_key: Hex string of public key
        signature: Hex string of signature
        data_hash: Hex string of data hash to verify against
    """
    try:
        if from_file:
            # Load signature from CBOR file
            with open(from_file, "rb") as f:
                signature_bytes = f.read()
                signature_obj = NamelessSignatureWithAccumulator.import_cbor(
                    signature_bytes
                )
        elif signature:
            # Parse signature hex string
            signature_bytes = HexStringUtil.str_to_bytes(signature).unwrap()
            signature_obj = NamelessSignatureWithAccumulator.import_cbor(
                signature_bytes
            )
        else:
            raise click.UsageError(
                "Must provide either --from-file or signature argument"
            )

        if not all([public_key, data_hash]):
            raise click.UsageError(
                "Must provide public_key, signature and data_hash arguments if not using --from-file"
            )

        # Decode Data Hash and Public Key
        data_hash_bytes = HexStringUtil.str_to_bytes(data_hash).unwrap()
        public_key_bytes = HexStringUtil.str_to_bytes(public_key).unwrap()
        group_parameters_bytes = HexStringUtil.str_to_bytes(group_parameters).unwrap()

        # Import Public Key
        public_key_type = PublicKey.import_cbor(public_key_bytes)
        group_parameters_type = GroupParameters.import_cbor(group_parameters_bytes)

        # Dummy Accumulator Verifier
        accumulator_verifier: AccumulatorVerifier = lambda *args, **kwargs: True

        # Verify the signature
        verifiable_object: VerifiableSignatureType = VerifiableSignature(
            signature_obj, data_hash_bytes, accumulator_verifier
        )

        # Verify Signature
        is_valid = verifiable_object.verify(public_key_type, group_parameters_type)

        if not quiet:
            if show_attributes:
                click.echo(
                    f"Signature attributes: {verifiable_object.get_attribute_list()}"
                )
            click.echo(f"Signature verification: {'VALID' if is_valid else 'INVALID'}")
        elif is_valid:
            click.echo("VALID")
        else:
            click.echo("INVALID", err=True)
            exit(1)

    except Exception as e:
        raise click.ClickException(f"Failed to verify signature: {e}")


@click.command(help="Verify a JWS-encoded Nameless signature.")
@click.argument("jws_file", type=click.Path(exists=True))
@click.option(
    "--show-attributes",
    is_flag=True,
    help="Show the public attributes included in the signature",
)
@click.option(
    "--show-issuer",
    is_flag=True,
    help="Show the public key of the issuer",
)
@click.option(
    "--quiet",
    is_flag=True,
    help="Only output VALID/INVALID",
)
def verify_jws_signature(
    jws_file: str, show_attributes: bool, show_issuer: bool, quiet: bool
) -> None:
    """Verify a JWS-encoded Nameless signature from a file.

    Args:
        jws_file: Path to the file containing the JWS token
        show_attributes: Whether to show the public attributes in the signature
        show_issuer: Whether to show the issuer's public key
        quiet: Only output VALID/INVALID

    Raises:
        click.ClickException: If verification fails
    """
    try:
        # Read JWS token from file
        try:
            with open(jws_file, "r") as f:
                jws_token = f.read().strip()
        except (IOError, OSError) as e:
            raise click.ClickException(f"Failed to read JWS file: {e}")

        if not jws_token:
            raise click.ClickException("JWS file is empty")

        # Dummy accumulator verifier for now
        accumulator_verifier: AccumulatorVerifier = lambda *args, **kwargs: True

        try:
            # Decode JWS model first to validate format
            jws_model = JWSModel.decode(jws_token)
        except JWSDecodingError as e:
            raise click.ClickException(f"Invalid JWS token format: {e}")
        except JWSValidationError as e:
            raise click.ClickException(f"JWS token validation failed: {e}")

        try:
            # Verify the JWS token
            is_valid = NamelessJWS.verify(jws_token, accumulator_verifier)
        except JWSVerificationError as e:
            raise click.ClickException(f"JWS signature verification failed: {e}")

        if not quiet:
            # Show issuer public key if requested
            if show_issuer:
                try:
                    click.echo(f"Issuer Public Key: {jws_model.header.kid}")
                except AttributeError as e:
                    raise click.ClickException(f"Failed to read issuer public key: {e}")

            # Show attributes if requested
            if show_attributes and is_valid:
                try:
                    signature = NamelessSignatureWithAccumulator.import_cbor(
                        jws_model.signature
                    )
                    verifiable_object = VerifiableSignature(
                        signature, jws_model.payload, accumulator_verifier
                    )
                    click.echo(
                        f"Signature attributes: {verifiable_object.get_attribute_list()}"
                    )
                except (ValueError, TypeError) as e:
                    raise click.ClickException(
                        f"Failed to decode signature attributes: {e}"
                    )

            click.echo(f"Signature verification: {'VALID' if is_valid else 'INVALID'}")
        elif is_valid:
            click.echo("VALID")
        else:
            click.echo("INVALID", err=True)
            exit(1)

    except JWSError as e:
        # Catch any other JWS-specific errors
        raise click.ClickException(f"JWS error: {e}")
    except Exception as e:
        # Catch any other unexpected errors
        raise click.ClickException(f"Unexpected error verifying JWS token: {str(e)}")


@click.command(help="Sign data with a credential.")
@click.argument("credential_id", type=str)
@click.argument("data_to_sign", type=str)
@click.argument("public_indices", type=str)
@click.option(
    "--output",
    type=click.Path(),
    help="Path to the output file where the signature will be saved.",
)
def sign_with_credential(
    credential_id: str, data_to_sign: str, public_indices: str, output: Optional[str]
) -> None:
    """Sign data using a stored credential.

    Args:
        credential_id: ID of the credential to use for signing
        data_to_sign: Data to sign (as hex string)
        public_indices: Comma-separated list of attribute indices to make public
        output: Optional path to save signature to file

    Raises:
        click.ClickException: If signing fails
    """
    try:
        # Load credential from file
        cred_path = os.path.join(CREDENTIALS_DIR, f"{credential_id}.cred")
        if not os.path.exists(cred_path):
            raise click.ClickException(f"Credential file not found: {cred_path}")

        # Parse public indices
        try:
            indices = [int(i.strip()) for i in public_indices.split(",")]
        except ValueError:
            raise click.ClickException(
                "Public indices must be comma-separated integers"
            )

        # Read and decode data
        try:
            data_bytes = HexStringUtil.str_to_bytes(data_to_sign).unwrap()
        except Exception as e:
            raise click.ClickException(f"Invalid data format: {e}")

        # Read credential and create signature
        try:
            with open(cred_path, "rb") as f:
                credential_bytes = f.read()
                credential_holder = NativeCredentialHolder.import_cbor(credential_bytes)
                signature = credential_holder.sign_with_credential(data_bytes, indices)
                signature_bytes = signature.export_cbor()
        except Exception as e:
            raise click.ClickException(f"Failed to create signature: {e}")

        # Save or output signature
        if output:
            try:
                with open(output, "wb") as f:
                    f.write(signature_bytes)
                click.echo(f"Signature saved to {output}")
            except Exception as e:
                raise click.ClickException(f"Failed to save signature: {e}")
        else:
            click.echo(HexStringUtil.bytes_to_str(signature_bytes))

    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(f"Unexpected error: {e}")


cli.add_command(setup_credential_request)
cli.add_command(request_credential)
cli.add_command(verify_raw_signature)
cli.add_command(verify_jws_signature)
cli.add_command(sign_with_credential)

if __name__ == "__main__":
    cli()
