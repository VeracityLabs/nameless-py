from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Self, Optional, Union

from joserfc import jwe, jws
from joserfc.rfc7518.ec_key import ECKey
from joserfc.rfc7518.jws_algs import ECAlgModel
from joserfc.rfc7518.oct_key import OctKey
from result import Result, Ok, do, Err

from see3_python.playintegrity.integrity_verdict import PlayIntegrityVerdict
from see3_python.playintegrity.unique_value_manager import (
    UniqueValue,
    UniqueValueManager,
)


class InvalidPlayIntegrityAesKeyError(Exception):
    """An error that occurs when the supplied A256KW decryption key bytes aren't valid"""

    def __init__(self, cause: Exception):
        self._cause = cause
        super().__init__(
            f"The provided A256KW decryption key bytes are invalid: {cause}"
        )


class InvalidPlayIntegrityEcKeyError(Exception):
    """An error that occurs when the supplied ES256 verification key bytes aren't valid"""

    def __init__(self, cause: Exception):
        self._cause = cause
        super().__init__(
            f"The provided ES256 verification key bytes are invalid: {cause}"
        )


def _make_aes256kw_private_key(
    data: bytes,
) -> Result[OctKey, InvalidPlayIntegrityAesKeyError]:
    try:
        return Ok(
            OctKey.import_key(
                data,
                {
                    "key_ops": ["decrypt", "unwrapKey"],
                    "alg": "A256KW",
                },
            )
        )
    except Exception as e:
        return Err(
            InvalidPlayIntegrityAesKeyError(
                f"Failed to create AES256KW private key: {e}"
            )
        )


def _make_es256_public_key(
    data: bytes,
) -> Result[ECKey, InvalidPlayIntegrityEcKeyError]:
    try:
        ec_key: ECKey = ECKey.import_key(data, {"alg": "ES256"})
        if ec_key.curve_name != "P-256":
            raise ValueError(
                f"Expected EC curve to be 'P-256', but is instead '{ec_key.curve_name}'"
            )
        return Ok(ec_key)
    except Exception as e:
        return Err(
            InvalidPlayIntegrityEcKeyError(f"Failed to create ES256 public key: {e}")
        )


class InvalidPlayIntegrityOuterCompactJWEToken(Exception):
    """An error that occurs when the provided (outer) compact JWE token is invalid"""

    def __init__(self, cause: Exception):
        self._cause = cause
        super().__init__(f"The provided (outer) compact JWE token is invalid: {cause}")


class InvalidPlayIntegrityInnerCompactJWSToken(Exception):
    """An error that occurs when the provided (inner) compact JWS token is invalid"""

    def __init__(self, cause: Exception):
        self._cause = cause
        super().__init__(f"The provided (inner) compact JWS token is invalid: {cause}")


class InvalidPlayIntegrityVerdictFormat(Exception):
    """An error that occurs when the provided integrity token fails to adhere to the appropriate schema"""

    def __init__(self, cause: Exception):
        self._cause = cause
        super().__init__(
            f"The provided integrity token failed to adhere to the appropriate schema: {cause}"
        )


class UniqueValueNotFound(Exception):
    """An error that occurs when the provided unique value is not found in the unique value in-memory-cache"""

    def __init__(self, unique_value: bytes):
        self._unique_value = unique_value
        super().__init__(
            f"The provided unique value is not found in the unique value in-memory-cache: {unique_value!r}"
        )


class UniqueValueMismatchError(Exception):
    """An error that occurs when the provided unique value doesn't match the one associated with the integrity token"""

    def __init__(self, unique_value: bytes):
        self._unique_value = unique_value
        super().__init__(
            f"The provided unique value doesn't match the one associated with the integrity token: {unique_value!r}"
        )


# Play Integrity service definition
class PlayIntegrityService:
    """
    A service responsible for facilitating interaction with Play Integrity functionality,
    such as issuing unique values, and verifying protected messages against verdict tokens.
    """

    _ES256_JWS_ALGORITHM = ECAlgModel("ES256", "P-256", 256, True)

    def __init__(
        self,
        aeskw_jwe_decryption_key: OctKey,
        ecdsa_jws_verification_key: ECKey,
        unique_value_manager: Optional[UniqueValueManager] = None,
    ):
        """
        WARNING: this class should not be instantiated directly!
        Instead, use the provided factory method `try_new_from_key_bytes`
        """

        self._aeskw_jwe_decryption_key = aeskw_jwe_decryption_key
        self._ecdsa_jws_verification_key = ecdsa_jws_verification_key
        self._unique_value_manager = unique_value_manager or UniqueValueManager()

    @classmethod
    def try_new_from_key_bytes(
        cls,
        aeskw_jwe_decryption_key_bytes: bytes,
        ecdsa_jws_verification_key_bytes: bytes,
        unique_value_manager: Optional[UniqueValueManager] = None,
    ) -> Result[
        Self, Union[InvalidPlayIntegrityAesKeyError, InvalidPlayIntegrityEcKeyError]
    ]:
        return do(
            Ok(
                cls(
                    aeskw_jwe_decryption_key,
                    ecdsa_jws_verification_key,
                    unique_value_manager,
                )
            )
            for aeskw_jwe_decryption_key in _make_aes256kw_private_key(
                aeskw_jwe_decryption_key_bytes
            )
            for ecdsa_jws_verification_key in _make_es256_public_key(
                ecdsa_jws_verification_key_bytes
            )
        )

    def new_unique_value(self) -> UniqueValue:
        """
        Generates a new unique value, which will be placed into shared cache
        and valid for some period of time - before expiring.
        """

        return self._unique_value_manager.new_unique_value()

    def obtain_integrity_verdict(
        self, unique_value: UniqueValue, protected_message: bytes, integrity_token: str
    ) -> Result[
        PlayIntegrityVerdict,
        Union[
            InvalidPlayIntegrityOuterCompactJWEToken,
            InvalidPlayIntegrityInnerCompactJWSToken,
            InvalidPlayIntegrityVerdictFormat,
            UniqueValueNotFound,
            UniqueValueMismatchError,
        ],
    ]:
        """
        Checks that a protected message is valid against a verdict token, and returns the integrity verdict.

        Returns errors if the integrity token is malformed, doesn't match the server's cryptographic credentials,
        or if there is a unique value mismatch between the protected message and integrity token.
        """

        try:
            decrypted_token = jwe.decrypt_compact(
                integrity_token, self._aeskw_jwe_decryption_key
            )
            if decrypted_token.plaintext is None:
                raise ValueError("Decrypted token plaintext is None")
            jws_compact_signature = jws.extract_compact(decrypted_token.plaintext)
        except Exception as e:
            return Err(
                InvalidPlayIntegrityOuterCompactJWEToken(
                    f"Failed to decrypt or extract JWE token: {e}"
                )
            )

        try:
            if not jws.verify_compact(
                jws_compact_signature,
                PlayIntegrityService._ES256_JWS_ALGORITHM,
                self._ecdsa_jws_verification_key,
            ):
                return Err(
                    InvalidPlayIntegrityOuterCompactJWEToken(
                        ValueError(
                            "The verification failed, the token doesn't correspond to server credentials"
                        )
                    )
                )
            integrity_verdict_dict = json.loads(
                jws_compact_signature.payload.decode("utf-8")
            )
        except json.JSONDecodeError as e:
            return Err(
                InvalidPlayIntegrityInnerCompactJWSToken(
                    f"Failed to decode JSON payload: {e}"
                )
            )
        except Exception as e:
            return Err(
                InvalidPlayIntegrityInnerCompactJWSToken(
                    f"Failed to verify or process JWS token: {e}"
                )
            )

        integrity_verdict_result = PlayIntegrityVerdict.try_from_dict(
            integrity_verdict_dict
        )
        if integrity_verdict_result.is_err():
            return Err(
                InvalidPlayIntegrityVerdictFormat(
                    f"Failed to parse integrity verdict: {integrity_verdict_result.err_value}"
                )
            )
        integrity_verdict: PlayIntegrityVerdict = integrity_verdict_result.ok_value

        if not self._unique_value_manager.redeem_unique_value(unique_value):
            return Err(UniqueValueNotFound(unique_value))

        protected_message_structure: bytes = unique_value + protected_message
        digest_bytes = hashlib.sha256(protected_message_structure).digest()
        try:
            nonce_bytes = base64.urlsafe_b64decode(
                integrity_verdict.request_details.nonce
            )
        except Exception as e:
            return Err(
                InvalidPlayIntegrityVerdictFormat(f"Failed to decode nonce: {e}")
            )
        if digest_bytes != nonce_bytes:
            return Err(UniqueValueMismatchError(unique_value))

        return Ok(integrity_verdict)


def create_playintegrity_manager_from_json(path: str) -> PlayIntegrityService:
    """
    Returns a configured PlayIntegrityManager instance,
    given a path to a config file.
    """
    try:
        with open(path, "r") as config_file:
            config: dict = json.load(config_file)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse JSON from file '{path}': {e}")
    except IOError as e:
        raise ValueError(f"Failed to read configuration file '{path}': {e}")

    if "playIntegrity" not in config:
        raise ValueError(
            f"Configuration file '{path}' must have the 'playIntegrity' key"
        )

    return create_playintegrity_manager_from_object(config["playIntegrity"])


def create_playintegrity_manager_from_object(
    playintegrity_config: dict,
) -> PlayIntegrityService:
    """
    Returns a configured PlayIntegrityManager instance,
    given a dictionary containing the configuration.
    """
    if not isinstance(playintegrity_config, dict):
        raise TypeError(
            f"The 'playIntegrity' key must point to an object, got {type(playintegrity_config)}"
        )

    for key in ["decryptionKey", "verificationKey"]:
        if key not in playintegrity_config:
            raise ValueError(f"Configuration must have the 'playIntegrity.{key}' key")
        if not isinstance(playintegrity_config[key], str):
            raise TypeError(
                f"The 'playIntegrity.{key}' key must point to a string, got {type(playintegrity_config[key])}"
            )

    try:
        decryption_key_bytes = base64.b64decode(playintegrity_config["decryptionKey"])
    except Exception as e:
        raise ValueError(f"Failed to decode decryption key: {e}")

    try:
        verification_key_bytes = base64.b64decode(
            playintegrity_config["verificationKey"]
        )
    except Exception as e:
        raise ValueError(f"Failed to decode verification key: {e}")

    result = PlayIntegrityService.try_new_from_key_bytes(
        decryption_key_bytes, verification_key_bytes
    )
    if result.is_err():
        raise result.err_value
    return result.unwrap()


def create_playintegrity_manager_from_env() -> PlayIntegrityService:
    """
    Returns a configured PlayIntegrityManager instance,
    using environment variables for configuration.
    """
    decryption_key = os.environ.get("PLAY_INTEGRITY_DECRYPTION_KEY")
    verification_key = os.environ.get("PLAY_INTEGRITY_VERIFICATION_KEY")
    if not decryption_key:
        raise ValueError(
            "Environment variable PLAY_INTEGRITY_DECRYPTION_KEY must be set"
        )
    if not verification_key:
        raise ValueError(
            "Environment variable PLAY_INTEGRITY_VERIFICATION_KEY must be set"
        )

    playintegrity_config = {
        "decryptionKey": decryption_key,
        "verificationKey": verification_key,
    }

    return create_playintegrity_manager_from_object(playintegrity_config)
