"""
NFCU Device Fingerprint module.

The NFCU mobile app sends a ``deviceFingerprint`` field in every authentication
request.  Understanding this field was critical to reverse-engineering the API.

Format (outermost → innermost):
  1. Prefix ``_v02`` is prepended to identify the encoding version.
  2. The payload is a URL-style query string of device parameters, e.g.:
       fpdt=2&mfos=Android&mfov=14&...&mfec=<signature>
  3. Every byte of the query string is XOR'd with 0x55.
  4. The result is standard base64-encoded.

The ``mfec`` parameter at the end is a 256-byte (2048-bit) RSA signature over
all other parameters (the string that precedes ``&mfec=``).  The private key is
embedded in the NFCU Android APK.  The signature changes every request because
the ``fpts`` (timestamp in milliseconds) is part of the signed payload.

Practical notes for the module:
  • The static parameters (device model, OS, hardware ID, etc.) are specific to
    the physical or emulated device that was used during traffic capture.
  • The dynamic parameters are ``fpts`` (current time in ms) and ``mfec``
    (RSA signature over all params including ``fpts``).
  • Without the RSA private key we cannot generate a fresh, valid signature.
    The captured emulator fingerprint is provided as a safe default for
    development/testing; production use should supply a fresh fingerprint from a
    real device intercepted with mitmproxy (see intercept/start.sh).

Known query-string parameters
  fpdt    – fingerprint data type (always "2")
  mfos    – mobile OS name ("Android")
  mfov    – OS version ("14")
  mfwa    – WiFi MAC address
  mfsc    – screen size "WxH" pipe-separated ("2209|1080")
  fpln    – locale ("en_US")
  mfgc    – GPS coordinates "lat|lon" ("00.0000|00.0000" when unavailable)
  mfpv    – protocol version ("2")
  fpts    – Unix timestamp in milliseconds at request time
  mfappid – app bundle ID ("com.navyfederal.android")
  mfa_isrooted – root detection result ("false")
  mfa_id  – Android hardware ID (Settings.Secure.ANDROID_ID)
  mfa_bd  – Android Build.DEVICE
  mfa_br  – Android Build.BRAND
  mfa_ca1 – primary CPU ABI
  mfa_fp  – Android Build.FINGERPRINT
  mfa_dv  – Android Build.DEVICE (short variant)
  mfa_dp  – full build description string
  mfa_mf  – Android Build.MANUFACTURER
  mfa_md  – Android Build.MODEL
  mfa_tags – Android Build.TAGS
  mfa_bl  – Android Build.BOOTLOADER
  mfa_hw  – Android Build.HARDWARE
  mfa_sci – SIM country ISO code
  mfa_spn – SIM carrier name
  mfa_so  – SIM operator numeric code
  mfec    – RSA-2048 signature (base64) of all preceding parameters
"""
from __future__ import annotations

import base64

# ── Encoding constants ───────────────────────────────────────────────────────

# Single-byte XOR key applied to every byte of the query string before base64.
_XOR_KEY: int = 0x55

# Version prefix prepended to the base64-encoded, XOR'd payload.
_VERSION_PREFIX: str = "_v02"


# ── Emulator device parameters ───────────────────────────────────────────────
# These were captured from the NFCU Android app v2026.2.1 running on a
# Pixel 2 emulator (sdk_gphone64_arm64, API 34/Android 14) via mitmproxy.
# They represent the *static* device identity portion of the fingerprint.
# The ``mfec`` (RSA signature) and ``fpts`` (timestamp) cannot be regenerated
# without the APK's embedded private key; the full captured fingerprint is
# stored in EMULATOR_FINGERPRINT below.

EMULATOR_DEVICE_PARAMS: dict[str, str] = {
    "fpdt": "2",
    "mfos": "Android",
    "mfov": "14",
    "mfwa": "02:00:00:00:00:00",  # emulator WiFi MAC (always all-zeros)
    "mfsc": "2209|1080",           # screen width|height in pixels
    "fpln": "en_US",
    "mfgc": "00.0000|00.0000",     # GPS lat|lon (unavailable in emulator)
    "mfpv": "2",
    # fpts and mfec are dynamic; omitted here, added at encode time
    "mfappid": "com.navyfederal.android",
    "mfa_isrooted": "false",
    "mfa_id": "3212038e3f2f8791",  # Android ID (hardware identifier)
    "mfa_bd": "goldfish_arm64",
    "mfa_br": "google",
    "mfa_ca1": "arm64-v8a",
    "mfa_fp": (
        "google/sdk_gphone64_arm64/emu64a:14/UE1A.230829.050/"
        "12077443:userdebug/dev-keys"
    ),
    "mfa_dv": "emu64a",
    "mfa_dp": (
        "sdk_gphone64_arm64-userdebug 14 UE1A.230829.050 12077443 dev-keys"
    ),
    "mfa_mf": "Google",
    "mfa_md": "sdk_gphone64_arm64",
    "mfa_tags": "dev-keys",
    "mfa_bl": "unknown",
    "mfa_hw": "ranchu",
    "mfa_sci": "us",
    "mfa_spn": "T-Mobile",
    "mfa_so": "310260",
}

# ── Full captured fingerprint ────────────────────────────────────────────────
# This is the complete _v02 fingerprint as sent by the NFCU app during session 1
# of the traffic capture (timestamp 1772171439981, Feb 27 2026).  It includes
# the RSA-2048 mfec signature which cannot be regenerated without the APK key.
# Use this as the default ``device_fingerprint`` argument for NFCU().
EMULATOR_FINGERPRINT: str = (
    "_v02MyUxIWhnczgzOiZoFDsxJzo8MXM4MzojaGRhczgzIjRoZWdvZWVvZWVvZWVvZWVv"
    "ZWVzODMmNmhnZ2VsKWRlbWVzMyU5O2gwOwoABnM4MzI2aGVle2VlZWUpZWV7ZWVlZXM4"
    "MyUjaGdzMyUhJmhkYmJnZGJkYWZsbG1kczgzNCUlPDFoNjo4ezs0IywzMDEwJzQ5ezQ7"
    "MSc6PDFzODM0CjwmJzo6ITAxaDM0OSYwczgzNAo8MWhmZ2RnZWZtMGYzZzNtYmxkczgz"
    "NAo3MWgyOjkxMzwmPQo0JzhjYXM4MzQKNydoMjo6MjkwczgzNAo2NGRoNCc4Y2F4I200"
    "czgzNAozJWgyOjoyOTB6JjE+CjIlPTo7MGNhCjQnOGNhejA4IGNhNG9kYXoAEGQUe2dm"
    "ZW1nbHtlYGV6ZGdlYmJhYWZvICYwJzEwNyAyejEwI3g+MCwmczgzNAoxI2gwOCBjYTRz"
    "ODM0CjElaCYxPgoyJT06OzBjYQo0JzhjYXggJjAnMTA3IDJ1ZGF1ABBkFHtnZmVtZ2x7"
    "ZWBldWRnZWJiYWFmdTEwI3g+MCwmczgzNAo4M2gSOjoyOTBzODM0CjgxaCYxPgoyJT06"
    "OzBjYQo0JzhjYXM4MzQKITQyJmgxMCN4PjAsJnM4MzQKNzloIDs+OzoiO3M4MzQKPSJo"
    "JzQ7Nj0gczgzNAomNjxoICZzODM0CiYlO2gBeBg6Nzw5MHM4MzQKJjpoZmRlZ2Nlczgz"
    "MDZoBGcFODI3JQUzJBceYAcRH2cBJ3omDTQtP3okMSQmMy03HhR6PDM6OjMHYx8zIB8d"
    "fjghbS0XJB8bDBM3LwwnJRttDDcgGD00PDIaNyUhGh08NBBmYGIPBCAceiQdB2MxfhRj"
    "HyAdLAMGFnoEBxQfEgQlLRczGSZ6BjYfJSMPMiE5EQwDFBliARsTAxo+Ozk/Jgw4YWMh"
    "JGIHOxgQLCMvIAQSODMhB2M4MT4fEyZiMmQAGAdhYDoCLDEyIzpkIRocFAIFPiwaPDNl"
    "YQEeER0yDHoTHhlnMCEUGgUsERshMDEPIGYdMjcSYwUjOjgdJCIxYC0xZ2wRHDYxGix6"
    "I2c/OBohfhQ7GDcjMiU2GxIhDRtsLDttLCI4MHolDTEjMjNsJD48JAY5D2wiN2UXPwMm"
    "DGQ5Ih0iIwZtJTBlBzQbAAFnYGc0JBhiFiUHfh1jGjZ6EhYCJBYEaGg="
)


# ── Public helpers ────────────────────────────────────────────────────────────

def encode(plaintext: str) -> str:
    """Encode a query-string payload into a _v02 fingerprint string.

    Args:
        plaintext: URL query string, e.g. ``fpdt=2&mfos=Android&...``

    Returns:
        ``_v02`` + base64(XOR(plaintext, 0x55))

    Example::

        params = build_params(EMULATOR_DEVICE_PARAMS, fpts=1234567890000,
                              mfec="<base64-rsa-sig>")
        fp = encode(params)
    """
    xored = bytes(b ^ _XOR_KEY for b in plaintext.encode("utf-8"))
    return _VERSION_PREFIX + base64.b64encode(xored).decode("ascii")


def decode(fingerprint: str) -> str:
    """Decode a _v02 fingerprint back to the plaintext query string.

    Args:
        fingerprint: ``_v02...`` fingerprint as sent in the API request body.

    Returns:
        Plaintext URL query string.

    Raises:
        ValueError: If the string does not start with ``_v02``.
    """
    if not fingerprint.startswith(_VERSION_PREFIX):
        raise ValueError(
            f"Unknown fingerprint version; expected '{_VERSION_PREFIX}' prefix"
        )
    raw = base64.b64decode(fingerprint[len(_VERSION_PREFIX):] + "==")
    return bytes(b ^ _XOR_KEY for b in raw).decode("utf-8", errors="replace")


def build_params(device_params: dict[str, str], fpts: int, mfec: str) -> str:
    """Assemble the query-string payload for a fingerprint.

    The order of parameters must match the order expected by the server (as
    observed in the captured traffic).  ``fpts`` and ``mfec`` are placed at
    their required positions.

    Args:
        device_params: Static device fields (see ``EMULATOR_DEVICE_PARAMS``).
        fpts: Current Unix time in milliseconds (int).
        mfec: Base64-encoded RSA-2048 signature of all preceding parameters.

    Returns:
        URL query string ready to be passed to :func:`encode`.
    """
    # Build ordered params; fpts is inserted after mfpv, mfec comes last
    ordered = {}
    for k, v in device_params.items():
        ordered[k] = v
        if k == "mfpv":
            ordered["fpts"] = str(fpts)
    ordered["mfec"] = mfec
    # urlencode with safe chars to match how the app encodes the string
    return "&".join(f"{k}={v}" for k, v in ordered.items())
