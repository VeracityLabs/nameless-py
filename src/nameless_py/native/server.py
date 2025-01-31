from nameless_py.config import SERVER_DATA_DIR, SALT_FILE_PATH
from nameless_py.ffi.nameless_rs import PartialCredential, Identifier, NamelessSignature
from nameless_py.native.library.server.monolithic import NativeMonolithicIssuer
from nameless_py.native.util.server.data_manager import (
    ServerDataManager,
    SaveServerParams,
    LoadServerParams,
    CreateServerParams,
)
from nameless_py.native.util.server.interactive_setup import (
    ServerDataInteraction,
)
from nameless_py.native.util.logging import logger
from fastapi import FastAPI, HTTPException, Request, APIRouter, Depends
from contextlib import asynccontextmanager
from pydantic import BaseModel, Field
from dataclasses import dataclass
from typing import Optional, Callable, Literal, Any, TypedDict
from result import Result, Ok, Err
import click
import uvicorn
import asyncio
import importlib.util
import logging
import getpass
import sys


# Custom exceptions
class ServerInitializationError(Exception):
    """Raised when server initialization fails"""

    pass


class AuthenticationError(Exception):
    """Raised when authentication fails"""

    pass


class ScriptImportError(Exception):
    """Raised when script import fails"""

    pass


class InvalidRequestError(Exception):
    """Raised when request validation fails"""

    pass


class IssuerOperationError(Exception):
    """Raised when issuer operations fail"""

    pass


class DataManagerError(Exception):
    """Raised when data manager operations fail"""

    pass


# Router Of Server
router = APIRouter()

###
# Request Models
###


class RevokeUserRequest(BaseModel):
    user_id: str = Field(..., description="The ID of the user to revoke")
    auxiliary: Any = Field({}, description="Additional data for the revocation process")


class CredentialRequest(BaseModel):
    request: str = Field(..., description="The credential request data")
    auxiliary: Any = Field({}, description="Additional data for the credential request")


class CredentialUpdateRequest(BaseModel):
    request: str = Field(..., description="The credential update request data")


class RecoverUserIdRequest(BaseModel):
    request: str = Field(..., description="The user ID recovery request data")
    auxiliary: Any = Field(
        {}, description="Additional data for the user ID recovery request"
    )


###
# Check Types
###

# A Function That Checks If A Credential Should Be Issued
IssueChecks = Callable[
    # Takes A PartialCredential (Request For A Credential) And Optional Additional Data
    [PartialCredential, Optional[object]],
    # .. And Returns A Result With A Literal True If The Checks Pass, And An Error Message If They Fail
    Result[Literal[True], str],
]

# A Function That Checks If A User Should Be Revoked
RevokeChecks = Callable[
    # Takes An Identifier (The User ID) And Optional Additional Data
    [Identifier, Optional[object]],
    # .. And Returns A Result With A Literal True If The Checks Pass, And An Error Message If They Fail
    Result[Literal[True], str],
]

# A Function That Checks If A User Should Be Identified From Their Signature
OpenChecks = Callable[
    # Takes A NamelessSignature And Optional Additional Data
    [NamelessSignature, Optional[object]],
    # .. And Returns A Result With A Literal True If The Checks Pass, And An Error Message If They Fail
    Result[Literal[True], str],
]

###
# Simple HTTP Success And Error Responses
###


def success_response(body: Any) -> dict[str, Any]:
    return {"status": "success", "body": body}


def error_response(detail: str) -> dict[str, Any]:
    return {"status": "error", "detail": detail}


###
# Server Config
###


@dataclass
class ServerConfig:
    """Implementation of the ServerConfig protocol."""

    issuer: NativeMonolithicIssuer
    data_manager: ServerDataManager
    issue_checks: IssueChecks
    revoke_checks: RevokeChecks
    open_checks: OpenChecks

    def update_issuer(self, params: SaveServerParams):
        """Update the issuer using its from_bytes method."""
        try:
            self.data_manager.save(params)
        except Exception as e:
            raise DataManagerError(f"Failed to update issuer: {e}")


def get_server_config(request: Request) -> ServerConfig:
    """Dependency to retrieve the server configuration from the request state."""
    if not hasattr(request.app.state, "server_config"):
        raise ServerInitializationError("Server configuration not initialized")
    return request.app.state.server_config


###
# Lifespan (What Server Does When It Starts And Stops)
###


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for the FastAPI application."""
    try:
        # Initialize The Server Data Manager
        app.state.data_manager = ServerDataManager()

        # Initial State Of The Server Data (Used Later To Determine If The Server Data Has Changed)
        initial_server_data = app.state.initial_server_data

        # Initialize The Server Config
        app.state.server_config = ServerConfig(
            issuer=app.state.issuer,
            data_manager=app.state.data_manager,
            issue_checks=app.state.issue_checks,
            revoke_checks=app.state.revoke_checks,
            open_checks=app.state.open_checks,
        )
        logger.info("Authentication Successful. Server is Running.")

        # Yield To The Server (The Rest Is What The Server Does When It Is Shutting Down)
        ####
        yield
        ####

        # Get The Final Server Data
        final_server_data = app.state.server_config.issuer.export_cbor()

        # Save The Server Data If It Has Changed
        if initial_server_data != final_server_data:
            logger.info("Server Data Has Changed. Saving...")
            save_params: SaveServerParams = {
                "server_name": "default",
                "server_data": final_server_data,
                "password": app.state.password,
            }
            try:
                app.state.data_manager.save(save_params)
            except Exception as e:
                raise DataManagerError(f"Failed to save server data: {e}")
        else:
            logger.info("Server Data Has Not Changed. Skipping Save.")

    except asyncio.CancelledError:
        logger.info("Server Shutting Down.")
    except (AuthenticationError, DataManagerError, IssuerOperationError) as e:
        logger.error(f"Server initialization failed: {e}")
        raise ServerInitializationError(str(e))
    except Exception as e:
        logger.error(f"Unexpected error during app lifespan: {e}")
        raise ServerInitializationError(f"Unexpected error: {e}")
    finally:
        app.state.server_config = None


###
# API Routes
###


@router.get("/get_public_key")
async def api_get_public_key(config: ServerConfig = Depends(get_server_config)):
    """
    Retrieve the server's public key.

    Args:
        config (ServerConfig): The server configuration.

    Returns:
        dict: A dictionary containing the public key as a hexadecimal string.

    Raises:
        HTTPException: If the issuer is not initialized.
    """
    logger.info("Received Request For Public Key.")
    try:
        key = config.issuer.get_public_key().export_cbor()
        return success_response(key.hex())
    except Exception as e:
        logger.error(f"Failed to get public key: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/get_current_epoch")
async def api_get_current_epoch(
    config: ServerConfig = Depends(get_server_config),
):
    """
    Retrieve the current accumulator from the server.

    Args:
        config (ServerConfig): The server configuration.

    Returns:
        dict: A dictionary containing the current accumulator as a hexadecimal string.

    Raises:
        HTTPException: If the issuer is not initialized.
    """
    logger.info("Received Request For Current Accumulator.")
    try:
        accumulator = config.issuer.get_current_accumulator().export_cbor()
        return success_response(accumulator.hex())
    except Exception as e:
        logger.error(f"Failed to get current accumulator: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class AccumulatorQuery(BaseModel):
    start: int
    end: int


@router.post("/fetch_accumulators")
async def fetch_accumulators(
    accumulator_query: AccumulatorQuery,
    config: ServerConfig = Depends(get_server_config),
):
    """
    Fetch a range of accumulator entries from the store.

    Args:
        accumulator_query (AccumulatorQuery): Query parameters specifying start and end indices
        config (ServerConfig): The server configuration

    Returns:
        dict: A dictionary containing the status and accumulator entries

    Raises:
        HTTPException: If the range is invalid or an error occurs
    """
    try:
        db = config.issuer._get_accumulator_store().entries
        if accumulator_query.start < 0 or accumulator_query.end > len(db):
            raise InvalidRequestError("Invalid query range")
        entries = db[accumulator_query.start : accumulator_query.end]
        return success_response([entry.to_json() for entry in entries])
    except InvalidRequestError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to fetch accumulators: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/issue_requested_credential")
async def api_issue_requested_credential(
    cred_request: CredentialRequest, config: ServerConfig = Depends(get_server_config)
):
    """
    Issue a requested credential to a user.

    Args:
        cred_request (CredentialRequest): The credential request data.
        config (ServerConfig): The server configuration.


    Returns:
        dict: A dictionary containing the issued credential as a hexadecimal string.

    Raises:
        HTTPException: If the issuer or issue checks are not initialized, or if an error occurs during processing.
    """
    logger.info("Received Request To Issue Requested Credential.")

    # Issues From Bytes
    def issue_func(request_bytes: bytes) -> Result[bytes, str]:
        try:
            credential_request = PartialCredential.import_cbor(request_bytes)
            passes_checks = config.issue_checks(
                credential_request, cred_request.auxiliary
            )
            if passes_checks.is_err():
                return Err(passes_checks.unwrap_err())
            return Ok(config.issuer.issue(credential_request).export_cbor())
        except ValueError as e:
            raise InvalidRequestError(f"Invalid credential request: {e}")
        except Exception as e:
            raise IssuerOperationError(f"Failed to issue credential: {e}")

    try:
        credential_request_bytes = bytes.fromhex(cred_request.request)
        result = issue_func(credential_request_bytes)

        if result.is_ok():
            return success_response(result.unwrap().hex())
        else:
            raise InvalidRequestError(result.unwrap_err())

    except (InvalidRequestError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except IssuerOperationError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/update_requested_credential")
async def api_update_requested_credential(
    cred_update_request: CredentialUpdateRequest,
    config: ServerConfig = Depends(get_server_config),
):
    """
    Update a requested credential for a user.

    Args:
        cred_update_request (CredentialUpdateRequest): The credential update request data.
        config (ServerConfig): The server configuration.

    Returns:
        dict: A dictionary containing the updated credential as a hexadecimal string.

    Raises:
        HTTPException: If the issuer is not initialized, or if an error occurs during processing.
    """
    logger.info("Received Request To Update Requested Credential.")
    try:
        update_request_bytes = bytes.fromhex(cred_update_request.request)
        credential = PartialCredential.import_cbor(update_request_bytes)
        result = config.issuer.update_credential(credential)
        result_bytes = result.export_cbor()
        return success_response(result_bytes.hex())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid request format: {e}")
    except Exception as e:
        logger.error(f"Failed to update credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/revoke_user")
async def api_revoke_user(
    revoke_request: RevokeUserRequest, config: ServerConfig = Depends(get_server_config)
):
    """
    Revoke a user's credentials.

    Args:
        revoke_request (RevokeUserRequest): The user revocation request data.
        config (ServerConfig): The server configuration.

    Returns:
        dict: A dictionary containing the revocation result as a hexadecimal string.

    Raises:
        HTTPException: If the issuer or revoke checks are not initialized, or if an error occurs during processing.
    """
    logger.info(f"Received Request To Revoke User With ID: {revoke_request.user_id}")

    def revoke_func(request_bytes: bytes) -> Result[None, str]:
        try:
            identifier = Identifier.import_cbor(request_bytes)
            passes_checks = config.revoke_checks(identifier, revoke_request.auxiliary)
            if passes_checks.is_err():
                return Err(passes_checks.unwrap_err())
            config.issuer.revoke_credential_using_identifier(identifier)
            return Ok(None)
        except ValueError as e:
            raise InvalidRequestError(f"Invalid revocation request: {e}")
        except Exception as e:
            raise IssuerOperationError(f"Failed to revoke credential: {e}")

    try:
        revoke_request_bytes = bytes.fromhex(revoke_request.user_id)
        result = revoke_func(revoke_request_bytes)

        if result.is_ok():
            return success_response("Credential Revoked Successfully")
        else:
            raise InvalidRequestError(result.unwrap_err())

    except (InvalidRequestError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except IssuerOperationError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/recover_user_id")
async def api_recover_user_id(
    recover_request: RecoverUserIdRequest,
    config: ServerConfig = Depends(get_server_config),
):
    """
    Recover a user's ID from a proof.

    Args:
        recover_request (RecoverUserIdRequest): The user ID recovery request data.
        config (ServerConfig): The server configuration.

    Returns:
        dict: A dictionary containing the recovered user ID as a hexadecimal string.

    Raises:
        HTTPException: If the issuer or open checks are not initialized, or if an error occurs during processing.
    """
    logger.info("Received Request To Recover User ID.")

    def recover_func(request_bytes: bytes) -> Result[bytes, str]:
        try:
            signature = NamelessSignature.import_cbor(request_bytes)
            passes_checks = config.open_checks(signature, recover_request.auxiliary)
            if passes_checks.is_err():
                return Err(passes_checks.unwrap_err())
            identifier = config.issuer.recover_identifier_from_signature(signature)
            return Ok(identifier.export_cbor())
        except ValueError as e:
            raise InvalidRequestError(f"Invalid recovery request: {e}")
        except Exception as e:
            raise IssuerOperationError(f"Failed to recover identifier: {e}")

    try:
        recover_request_bytes = bytes.fromhex(recover_request.request)
        result = recover_func(recover_request_bytes)

        if result.is_ok():
            return success_response(result.unwrap().hex())
        else:
            raise InvalidRequestError(result.unwrap_err())

    except (InvalidRequestError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except IssuerOperationError as e:
        raise HTTPException(status_code=500, detail=str(e))


###
# Utility Functions
###


# TODO: Check If This Is The Best Way To Import A Script, Improve Typing
# Import A Script
def import_script(script_path: str) -> Any:
    """Import a script using importlib."""
    try:
        spec = importlib.util.spec_from_file_location("module.name", script_path)
        if spec is None:
            raise ScriptImportError(f"Failed to import script from {script_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules["module.name"] = module
        if spec.loader is None:
            raise ScriptImportError(f"Failed to load script from {script_path}")
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        raise ScriptImportError(f"Failed to import script: {e}")


# A TypeDict That Contains The Functions And Additional Routes From A Script
class ScriptContent(TypedDict):
    issue: IssueChecks
    revoke: RevokeChecks
    open: OpenChecks
    additional_routes: Optional[APIRouter]


# Get The Functions And Additional Routes From A Script
def get_extensions_from_script(script_path: str) -> Result[ScriptContent, str]:
    """Get functions and routes from a script."""
    try:
        module = import_script(script_path)

        if not all(hasattr(module, attr) for attr in ["issue", "revoke", "open"]):
            raise ScriptImportError(
                "Script must have 'issue', 'revoke', and 'open' functions"
            )

        issue_func = getattr(module, "issue")
        revoke_func = getattr(module, "revoke")
        open_func = getattr(module, "open")
        additional_routes = getattr(module, "additional_routes", None)

        # Check If The Functions Are Callable
        if not callable(issue_func):
            return Err("The 'issue' function must be callable.")
        if not callable(revoke_func):
            return Err("The 'revoke' function must be callable.")
        if not callable(open_func):
            return Err("The 'open' function must be callable.")

        # Create The Script Content
        script_content = ScriptContent(
            issue=issue_func,
            revoke=revoke_func,
            open=open_func,
            additional_routes=additional_routes,
        )
        return Ok(script_content)
    except ScriptImportError as e:
        return Err(str(e))
    except Exception as e:
        return Err(f"Unexpected error loading script: {e}")


###
# State Generation
###


class InitialServerState:
    def __init__(
        self,
        data_manager: ServerDataManager,
        issuer: NativeMonolithicIssuer,
        issue_checks: IssueChecks,
        revoke_checks: RevokeChecks,
        open_checks: OpenChecks,
        password: str,
        initial_server_data: bytes,
    ):
        self.initial_server_data = initial_server_data
        self.data_manager = data_manager
        self.issuer = issuer
        self.issue_checks = issue_checks
        self.revoke_checks = revoke_checks
        self.open_checks = open_checks
        self.password = password


class InitialStateBuilder(TypedDict):
    extensions: ScriptContent
    is_silent: bool
    password: Optional[str]
    max_messages: Optional[int]


def generate_initial_state(builder: InitialStateBuilder) -> InitialServerState:
    """Generate the initial state for the server."""

    issue_checks = builder["extensions"]["issue"]
    revoke_checks = builder["extensions"]["revoke"]
    open_checks = builder["extensions"]["open"]

    data_manager = ServerDataManager()

    def load_default_server_data(password: str) -> bytes:
        load_params: LoadServerParams = {
            "server_name": "default",
            "password": password,
        }
        return data_manager.decrypt(load_params)

    def create_default_server_data(password: str) -> bytes:
        return data_manager.create_default_if_not_exists(
            CreateServerParams(
                server_name=data_manager.generate_server_name(),
                password=password,
                max_messages=builder["max_messages"] or 2,
            )
        )

    def get_password_silently(password: Optional[str]) -> str:
        if not password:
            logger.error(
                "Silent Authentication Failed: Password is Required in Silent Mode"
            )
            raise AuthenticationError("Password is Required in Silent Mode")
        logger.info("Silent authentication successful.")
        return password

    def get_password_interactively() -> str:
        password = getpass.getpass("Enter Server Password: ")
        logger.info("Password Read Successfully.")
        return password

    def create_server_interactively(data_manager: ServerDataManager) -> bytes:
        automatic_setup_tool = ServerDataInteraction(data_manager)
        generated_server = automatic_setup_tool.interactive_setup()
        return generated_server["server_data"]

    # Check If The Default Server Exists
    default_server_exists = data_manager.exists("default")

    if builder["is_silent"]:
        password = get_password_silently(builder["password"])
        if default_server_exists:
            initial_server_data = load_default_server_data(password)
        else:
            initial_server_data = create_default_server_data(password)
    else:
        if default_server_exists:
            password = get_password_interactively()
            initial_server_data = load_default_server_data(password)
        else:
            initial_server_data = create_server_interactively(data_manager)

    try:
        issuer = NativeMonolithicIssuer.import_cbor(initial_server_data)
    except Exception as e:
        raise IssuerOperationError(f"Failed to initialize issuer: {e}")

    # Set The Server State
    return InitialServerState(
        initial_server_data=initial_server_data,
        data_manager=data_manager,
        issuer=issuer,
        issue_checks=issue_checks,
        revoke_checks=revoke_checks,
        open_checks=open_checks,
        password=password,
    )


###
# CLI
###


@click.command()
@click.option("--script_path", required=True, help="Path To Conditional Script")
@click.option("--port", default=8000, help="Port to run the server on")
@click.option("--log_path", type=click.Path(), help="Path to log file")
@click.option("--server_dir", type=click.Path(), help="Path to server data directory")
@click.option("--silent", is_flag=True, help="Run in silent mode")
@click.option("--password", help="Password for the server (required in silent mode)")
@click.option(
    "--max_messages",
    type=int,
    help="Maximum number of messages (optional in silent mode)",
)
def main(
    script_path: str,
    port: int,
    log_path: Optional[str],
    server_dir: Optional[str],
    silent: bool,
    password: Optional[str],
    max_messages: Optional[int],
) -> None:
    if log_path:
        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        logger.addHandler(file_handler)

    try:
        # Get The Extensions From The Script
        extensions_result = get_extensions_from_script(script_path)
        if extensions_result.is_err():
            logger.error(extensions_result.unwrap_err())
            raise click.Abort()

        # Unwrap The Extensions
        extensions = extensions_result.unwrap()

        # Build Server State Ahead Of Time
        builder: InitialStateBuilder = {
            "extensions": extensions,
            "is_silent": silent,
            "password": password,
            "max_messages": max_messages,
        }
        initial_state = generate_initial_state(builder)

        # Initialize The Server With The State
        app = FastAPI(lifespan=lifespan)
        for key, value in vars(initial_state).items():
            setattr(app.state, key, value)

        # Include The Routes
        app.include_router(router)

        # Include The Additional Routes, If They Exist
        if extensions["additional_routes"]:
            app.include_router(extensions["additional_routes"])

        logger.info(f"Server Is Initialized At Port {port}.")
        uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")

    except (ScriptImportError, AuthenticationError) as e:
        logger.error(str(e))
        raise click.Abort()
    except Exception as e:
        logger.error(f"Unexpected error starting server: {e}")
        raise click.Abort()


if __name__ == "__main__":
    main()
