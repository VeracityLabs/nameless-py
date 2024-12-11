from nameless_py.config import SERVER_DATA_DIR
from nameless_py.native.util.logging import logger
from nameless_py.native.util.server.data_manager import (
    ServerDataManager,
    ServerDataError,
)
from nameless_py.native.util.filesystem.symlink_manager import SymlinkUtil, SymlinkError
from nameless_py.native.util.encryption.salt_manager import SaltManager, SaltError
from rich.console import Console
import os
import base64
import click

console = Console()

###
# Exceptions
###


class ServerManagerError(Exception):
    """Base exception for server manager errors."""

    pass


class ServerIDFormatError(ServerManagerError):
    """Raised when server ID format is invalid."""

    pass


class ServerNotFoundError(ServerManagerError):
    """Raised when server data is not found."""

    pass


class ServerDecodeError(ServerManagerError):
    """Raised when server ID cannot be decoded."""

    pass


###
# CLI
###


@click.group()
@click.option("--server_dir", type=click.Path(), help="Path to server data directory")
@click.pass_context
def cli(ctx, server_dir):
    ctx.ensure_object(dict)
    ctx.obj["SERVER_DIR"] = server_dir or SERVER_DATA_DIR


@cli.command()
@click.pass_context
def list(ctx):
    server_dir = ctx.obj["SERVER_DIR"]
    if not os.path.exists(server_dir):
        console.print("No server data directory found.", style="bold")
        return

    server_files = [
        f
        for f in os.listdir(server_dir)
        if f != "default" and os.path.isfile(os.path.join(server_dir, f))
    ]

    if not server_files:
        console.print("No servers found.", style="bold")
        return

    console.print("Server IDs:", style="bold")
    for encrypted_name in server_files:
        try:
            server_id = base64.b64decode(encrypted_name).decode("ascii")
            console.print(server_id)
        except base64.binascii.Error as e:
            raise ServerDecodeError(
                f"Invalid base64 encoding for server ID {encrypted_name}: {e}"
            )
        except UnicodeDecodeError as e:
            raise ServerDecodeError(
                f"Invalid ASCII characters in server ID {encrypted_name}: {e}"
            )


@cli.command()
@click.argument("server_id")
@click.pass_context
def change_default(ctx, server_id):
    try:
        if not server_id.isalnum():
            raise ServerIDFormatError("Server ID must be alphanumeric.")

        server_dir = ctx.obj["SERVER_DIR"]
        encrypted_name = base64.b64encode(server_id.encode("ascii")).decode("ascii")
        server_data_path = os.path.join(server_dir, encrypted_name)
        default_path = os.path.join(server_dir, "default")

        if not os.path.exists(server_data_path):
            raise ServerNotFoundError(
                f"No server data found for server ID: {server_id}"
            )

        SymlinkUtil._create_symlink(server_data_path, default_path)
        console.print(f"Default server changed to: {server_id}")

    except (ServerIDFormatError, ServerNotFoundError) as e:
        console.print("Error:", e, style="bold red")
    except SymlinkError as e:
        console.print("Symlink Error:", e, style="bold red")
    except Exception as e:
        logger.error(f"Unexpected error in change_default: {e}")
        console.print("Unexpected Error:", e, style="bold red")


@click.command()
@click.argument("server_id")
@click.argument("output_filename")
@click.option("--password", prompt=True, hide_input=True, help="Decryption password")
@click.pass_context
def decrypt(ctx, server_id, output_filename, password):
    try:
        if not server_id.isalnum():
            raise ServerIDFormatError("Server ID must be alphanumeric.")

        server_dir = ctx.obj["SERVER_DIR"]
        salt_manager = SaltManager(os.path.join(server_dir, "salt", "saltfile"))
        data_manager = ServerDataManager()

        # Get salt
        try:
            salt = salt_manager.fetch_or_create()
        except SaltError as e:
            raise ServerManagerError(f"Failed to get salt: {e}")

        # Prepare encrypted name
        encrypted_name = base64.b64encode(server_id.encode("ascii")).decode("ascii")

        # Decrypt server data
        try:
            decrypted_data = data_manager.decrypt(
                {
                    "server_data_dir": server_dir,
                    "encrypted_name": encrypted_name,
                    "salt": salt,
                    "password": password,
                }
            )
        except ServerDataError as e:
            raise ServerManagerError(f"Failed to decrypt server data: {e}")

        # Write to output file
        try:
            with open(output_filename, "wb") as f:
                f.write(decrypted_data)
        except IOError as e:
            raise ServerManagerError(f"Failed to write decrypted data: {e}")

        console.print(
            f"Server data successfully decrypted to: {output_filename}", style="green"
        )

    except (ServerIDFormatError, ServerManagerError) as e:
        console.print("Error:", e, style="bold red")
    except Exception as e:
        logger.error(f"Unexpected error in decrypt: {e}")
        console.print("Unexpected Error:", e, style="bold red")


if __name__ == "__main__":
    cli()
