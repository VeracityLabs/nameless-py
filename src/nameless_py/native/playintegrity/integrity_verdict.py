from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Dict, Any

from result import Result, Err, Ok


class AppRecognitionVerdict(Enum):
    """
    Enumeration representing the verdict for app recognition.
    """

    PLAY_RECOGNIZED = "PLAY_RECOGNIZED"
    UNRECOGNIZED_VERSION = "UNRECOGNIZED_VERSION"
    UNEVALUATED = "UNEVALUATED"

    @classmethod
    def try_from_str(cls, value: str) -> Result["AppRecognitionVerdict", ValueError]:
        try:
            return Ok(cls(value))
        except ValueError:
            return Err(ValueError(f"Unknown recognition verdict: {value}"))


class AppLicensingVerdict(Enum):
    """
    Enumeration representing the verdict for app licensing.
    """

    LICENSED = "LICENSED"
    UNLICENSED = "UNLICENSED"
    UNEVALUATED = "UNEVALUATED"

    @classmethod
    def try_from_str(cls, value: str) -> Result["AppLicensingVerdict", ValueError]:
        try:
            return Ok(cls(value))
        except ValueError:
            return Err(ValueError(f"Unknown licensing verdict: {value}"))


@dataclass
class RequestDetails:
    """
    Represents request details in the Play Integrity verdict.
    """

    request_package_name: str
    nonce: str
    timestamp_millis: int

    @classmethod
    def try_from_dict(
        cls, data: Dict[str, Any]
    ) -> Result["RequestDetails", ValueError]:
        try:
            request_package_name = data["requestPackageName"]
            nonce = data["nonce"]
            timestamp_millis = int(data["timestampMillis"])
            return Ok(cls(request_package_name, nonce, timestamp_millis))
        except KeyError as e:
            return Err(
                ValueError(f"Missing key {e.args[0]} in request details: {data}")
            )
        except (TypeError, ValueError) as e:
            return Err(ValueError(f"Invalid data in request details: {data} - {e}"))


@dataclass
class AppIntegrity:
    """
    Represents app integrity information in the Play Integrity verdict.
    """

    app_recognition_verdict: AppRecognitionVerdict
    package_name: Optional[str] = None
    certificate_sha256_digest: Optional[List[str]] = None
    version_code: Optional[str] = None

    @classmethod
    def try_from_dict(cls, data: Dict[str, Any]) -> Result["AppIntegrity", ValueError]:
        try:
            verdict_result = AppRecognitionVerdict.try_from_str(
                data["appRecognitionVerdict"]
            )
            if verdict_result.is_err():
                return verdict_result
            app_recognition_verdict = verdict_result.ok()

            # Initialize optional fields
            package_name = data.get("packageName")
            certificate_sha256_digest = data.get("certificateSha256Digest")
            version_code = data.get("versionCode")

            if app_recognition_verdict != AppRecognitionVerdict.UNEVALUATED:
                if not package_name or not isinstance(package_name, str):
                    return Err(
                        ValueError("Field 'packageName' must be a non-empty string")
                    )
                if not certificate_sha256_digest or not isinstance(
                    certificate_sha256_digest, list
                ):
                    return Err(
                        ValueError(
                            "Field 'certificateSha256Digest' must be a list of strings"
                        )
                    )
                if not all(isinstance(item, str) for item in certificate_sha256_digest):
                    return Err(
                        ValueError(
                            "All items in 'certificateSha256Digest' must be strings"
                        )
                    )
                if not version_code or not isinstance(version_code, str):
                    return Err(
                        ValueError("Field 'versionCode' must be a non-empty string")
                    )
            else:
                package_name = None
                certificate_sha256_digest = None
                version_code = None

            return Ok(
                cls(
                    app_recognition_verdict=app_recognition_verdict,
                    package_name=package_name,
                    certificate_sha256_digest=certificate_sha256_digest,
                    version_code=version_code,
                )
            )
        except KeyError as e:
            return Err(
                ValueError(f"Missing key {e.args[0]} in app integrity data: {data}")
            )
        except ValueError as e:
            return Err(ValueError(f"Invalid value in app integrity data: {e}"))


@dataclass
class AccountDetails:
    """
    Represents account details in the Play Integrity verdict.
    """

    app_licensing_verdict: AppLicensingVerdict

    @classmethod
    def try_from_dict(
        cls, data: Dict[str, Any]
    ) -> Result["AccountDetails", ValueError]:
        try:
            verdict_result = AppLicensingVerdict.try_from_str(
                data["appLicensingVerdict"]
            )
            if verdict_result.is_err():
                return verdict_result
            app_licensing_verdict = verdict_result.ok()
            return Ok(cls(app_licensing_verdict=app_licensing_verdict))
        except KeyError as e:
            return Err(
                ValueError(f"Missing key {e.args[0]} in account details: {data}")
            )
        except ValueError as e:
            return Err(ValueError(f"Invalid value in account details: {e}"))


@dataclass
class PlayIntegrityVerdict:
    """
    Represents the full Play Integrity verdict.
    """

    request_details: RequestDetails
    app_integrity: AppIntegrity
    device_integrity: Dict[str, Any]
    account_details: AccountDetails
    environment_details: Optional[Dict[str, Any]] = None

    @classmethod
    def try_from_dict(
        cls, data: Dict[str, Any]
    ) -> Result["PlayIntegrityVerdict", ValueError]:
        try:
            # Parse request details
            request_details_result = RequestDetails.try_from_dict(
                data["requestDetails"]
            )
            if request_details_result.is_err():
                return request_details_result
            request_details = request_details_result.ok()

            # Parse app integrity
            app_integrity_result = AppIntegrity.try_from_dict(data["appIntegrity"])
            if app_integrity_result.is_err():
                return app_integrity_result
            app_integrity = app_integrity_result.ok()

            # Retrieve device integrity
            device_integrity = data.get("deviceIntegrity", {})
            if not isinstance(device_integrity, dict):
                return Err(ValueError("Field 'deviceIntegrity' must be a dictionary"))

            # Parse account details
            account_details_result = AccountDetails.try_from_dict(
                data["accountDetails"]
            )
            if account_details_result.is_err():
                return account_details_result
            account_details = account_details_result.ok()

            # Retrieve environment details if available
            environment_details = data.get("environmentDetails")
            if environment_details is not None and not isinstance(
                environment_details, dict
            ):
                return Err(
                    ValueError(
                        "Field 'environmentDetails' must be a dictionary or null"
                    )
                )

            return Ok(
                cls(
                    request_details=request_details,
                    app_integrity=app_integrity,
                    device_integrity=device_integrity,
                    account_details=account_details,
                    environment_details=environment_details,
                )
            )
        except KeyError as e:
            return Err(
                ValueError(f"Missing key {e.args[0]} in Play Integrity verdict: {data}")
            )
        except ValueError as e:
            return Err(ValueError(f"Invalid value in Play Integrity verdict: {e}"))
