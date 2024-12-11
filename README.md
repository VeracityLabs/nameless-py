# nameless_py

nameless_py is a solution for anonymous credentials.

It provides everything you need to generate, manage, and use anonymous credentials.

This includes:

- A library for working with anonymous credentials.
- A server for issuing and revoking anonymous credentials.
- A CLI for generating, managing, and using anonymous credentials.

nameless_py is part of the See3 SDK, which is implemented for Kotlin, Swift, Expo, TypeScript (Node.js and WASM), Python and Rust. It supports iOS, Android, Linux, MacOS and Windows.

Every library in the SDK is compatible with the Python-based Nameless server, and they are all [bindings](https://en.wikipedia.org/wiki/Language_binding) to the [Rust implementation](https://github.com/VeracityLabs/nameless_rs).

## Features



- **Trusted Issuer**: A designated authority verifies all user attributes (details like name or age). This trusted verification allows users to later prove that the information is correct when sharing it with third parties, if they choose to.

- **Complete Anonymity**: There are points of traceability, even when credentials are reused. When you use `nameless-rs` to share verified details, your actions are completely indistinguishable from those of any other user with the same details. 

- **Selective Disclosure**: You can prove specific details (like being over a certain age) without revealing personal data you'd prefer to keep private (such as your exact birth-date or name).

- **Use-Specific Proofs**: Every proof you generate is uniquely tied to the data it was generated for. This prevents others from reusing your proofs to authorize data which is not yours using your identity.

- **Accountable Privacy**: A cryptographically-secure majority vote among trusted authorities is required to:
  - Identify problematic credentials in cases of abuse
  - Enable banning of credentials (moderation) when necessary
  - Prevent any single corrupt authority from compromising privacy

- **Efficient Revocation**: Our system allows for quick and scalable cancellation of credentials without relying on large revocation lists or frequent status checks (ie, RL or OCSP).

## Installation

To install the library, use pip:

```bash
pip install nameless_py
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

```bash
docker build -t nameless-server .
docker run -p 8000:8000 \
  -e PLAY_INTEGRITY_DECRYPTION_KEY="KEY_HERE" \
  -e PLAY_INTEGRITY_VERIFICATION_KEY="KEY_HERE" \
  -e SERVER_PASSWORD="SERVER_PASSWORD_HERE" \
  -e MAX_CREDENTIAL_MESSAGES="MAX_CREDENTIAL_MESSAGES_HERE" \
  nameless-server
```

## Library

Here's a quick example of how to use the library:

See the [library documentation](docs/lib.md) for more information.

## Commands

### nameless-cli

The `nameless-cli` command is a versatile tool for managing anonymous credentials. It includes the following functionalities:

- `setup-credential-request <output_path>`: Helps you set up a credential request configuration file.
- `request-credential <config_path>`: Requests a credential using the provided configuration file.
- `verify-raw-signature [--from-file <path>] <public_key> <proof> <accumulator> <data>`: Verifies a raw signature.
- `verify-jws-signature`: Verifies a JWS-encoded Nameless signature.
- `sign-with-credential <credential_id> <data_to_sign> <public_indices> [--output <path>]`: Signs data using a credential.

### nameless-server-manager

The `nameless-server-manager` command is used to manage server data. It includes the following functionalities:

- `list`: List all server IDs.
- `change-default <server_id>`: Change the default server.
- `decrypt <server_id> <output_path>`: Decrypt the server data.

You can optionally specify a custom server directory with `--server_dir PATH`.

### nameless-server

The `nameless-server` command is used to start the server. It requires the following arguments:

- `--script_path`: Path to the conditional script [required]
- `--port`: Port to run the server on [optional]
- `--log_path`: Path to log file [optional]
- `--server_dir`: Path to server data directory [optional]
- `--silent`: Run in silent mode [optional]
- `--password`: Password for the server (required in silent mode)
- `--max_messages`: Maximum number of messages (required in silent mode)

The server configuration will be encrypted and stored in the specified server directory.

#### What Is A Script Conditional?

It's a Python script that the server will use to determine whether a credential should be issued or revoked, when the corresponding endpoint is called. 

The use of a Script Conditional keeps the issuing-related logic, key-management and server configuration separate from the business logic of your application.

The Script Conditional must have three functions: issue, revoke, and open.

Here are the types for the functions:

```python
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
```

#### What Else Can I Do?

You can also define additional endpoints, featuring your own endpoints and your own business logic, in the Script Conditional.

#### Why Script Conditionals?

We understand that there will be many different applications for anonymous credentials. Therefore, we have made this server as flexible as possible. With script conditionals, it becomes trivial to integrate anonymous credentials into your application.

#### Give Me An Example

We recommend that you look at the [example script conditional](script_examples/test_script.py). It's designed to be super simple.
