# see3_python

see3_python is a solution for anonymous credentials.

It provides everything you need to generate, manage, and use anonymous credentials.

This includes:

- A library for working with anonymous credentials.
- A server for issuing and revoking anonymous credentials.
- A CLI for generating, managing, and using anonymous credentials.

see3_python is part of the See3 SDK, which is implemented for Kotlin, Swift, Expo, TypeScript (Node.js and WASM), Python and Rust. It supports iOS, Android, Linux, MacOS and Windows.

Every library in the SDK is compatible with the Python-based See3 server, and they are all [bindings](https://en.wikipedia.org/wiki/Language_binding) to the [Rust implementation](https://github.com/VeracityLabs/see3_rust).

## Features

- **Anonymous Credentials**: Generate and manage anonymous credentials.
- **Signing**: Use credentials to sign messages and other data.
- **Credential Issuance**: Issue credentials using the built-in `see3-server` command.
- **Server Management**: Manage server data with the `see3-server-manager` command.
- **Development Tools**: Includes tox for automated testing and building across Python environments.

## Installation

To install the library, use pip:

```bash
pip install see3_python
```

## Building

You need to install the required dependencies within a virtual environment using pipenv:

```bash
pipenv install
```

You can then build the project using tox:

```bash
pipenv run tox -e build
```

## Docker Container

```docker build -t see3-server .
docker run -p 8000:8000 \
  -e PLAY_INTEGRITY_DECRYPTION_KEY="KEY_HERE" \
  -e PLAY_INTEGRITY_VERIFICATION_KEY="KEY_HERE" \
  -e SERVER_PASSWORD="SERVER_PASSWORD_HERE" \
  -e MAX_CREDENTIAL_MESSAGES="MAX_CREDENTIAL_MESSAGES_HERE" \
  see3-server```

## Library

Here's a quick example of how to use the library:

See the [library documentation](docs/lib.md) for more information.

## Commands

### see3-cli

The `see3-cli` command is a versatile tool for managing anonymous credentials. It includes the following functionalities:

- `setup_credential_request <output_path>`: Helps you set up a credential request configuration file.
- `request_credential <config_path>`: Requests a credential using the provided configuration file.
- `verify_signature [--from-file <path>] <public_key> <proof> <accumulator> <data>`: Verifies a signature.
- `sign_with_credential <credential_id> <data_to_sign> <public_indices> [--output <path>]`: Signs data using a credential.

### see3-server-manager

The `see3-server-manager` command is used to manage server data. It includes the following functionalities:

- `list`: List all server IDs.
- `change_default <server_id>`: Change the default server.
- `decrypt <server_id> <output_path>`: Decrypt the server data.

### see3-server

The `see3-server` command is used to start the server. It takes one argument:

- `--port`: Set the port for the server.

You must also provide the path to a script conditional.

The CLI will prompt you to generate a server configuration, which will be encrypted. All server configurations are stored in the `~/.veracity_server` directory.

#### What Is A Script Conditional?

It's a Python script that the server will use to determine whether a credential should be issued or revoked, when the corresponding endpoint is called. 

The use of a Script Conditional keeps the issuing-related logic, key-management separate and server configuration separate from the business logic of your application.

The Script Conditional must have three functions:

- `issue(credential_request: bytes, auxiliary_data: object, issue_function: Callable[[bytes], bytes]) -> dict`: Determines whether a credential should be issued.
- `revoke(user_id: bytes, auxiliary_data: object, revoke_function: Callable[[bytes], bytes]) -> dict`: Determines whether a credential should be revoked.
- `open(proof_data: bytes, auxiliary_data: object, open_function: Callable[[bytes], bytes]) -> dict`: Determines whether the User ID should be extracted from the proof.

The `dict` returned by each function will be returned to the client when the function is called. 

We strongly recommend that the `dict` you return is consistent with the HTTP `Result` type, as follows:

```python
def issue(credential_request: bytes, auxiliary_data: object, issue_function: Callable[[bytes], bytes]) -> dict:
    if success:
        return {"status": 200, "result": {}}
    else:
        return {"status": 400, "error": {"message": "Error Message"}}
```

`see3-server` will automatically infer the status code from the `Result`, when possible.

#### What Else Can I Do?

You can also define additional endpoints, featuring your own endpoints and your own business logic, in the Script Conditional.

#### Why Script Conditionals?

We understand that there will be many different applications for anonymous credentials. Therefore, we have made this server as flexible as possible. With script conditionals, it becomes trivial to integrate anonymous credentials into your application.

#### Give Me An Example

We recommend that you look at the [example script conditional](examples/test_script.py). It's designed to be super simple.