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


# ── Akamai Bot Manager sensor data ────────────────────────────────────────────
# The NFCU authn endpoint is protected by Akamai Bot Manager (formerly mPulse).
# The Android app includes the Akamai BM SDK which generates a device attestation
# blob sent in the ``x-acf-sensor-data`` request header.  Without this header
# the Akamai edge returns a synthetic HTTP 200 with LGN014 ("remember your
# device") instead of forwarding the request to the NFCU backend.
#
# This value was captured from the emulator during traffic analysis and must be
# sent with every POST /api/auth/mobile/authn request.
#
# Format:  ``6,a,<RSA-signed-blob>,...``  (Akamai BM SDK v6 format)
#   - The blob is RSA-signed by Akamai's SDK using a key embedded in the app.
#   - It contains device fingerprint data, timing, and behavioural signals.
#   - It was observed to remain valid for at least 1.5 hours after capture.
#
# To refresh: run ``intercept/start.sh``, log in with the NFCU app, then
# extract the x-acf-sensor-data value from the captured authn flow.
EMULATOR_SENSOR_DATA: str = (
    "6,a,MNqI7YfCExY9IKhyFtlqGsCs29ew5yaUULzXSV+GKnBKEn5niQVEfN8bodmcjFACf/"
    "xSwGtUoyKwC+eVGsEdrE1wVb48CjSuQ2tG1P8tA5om3CZLVdYIRZdclh8HLcAKqax5UYBP"
    "LtDvQdjKJ7mHpU6xdLmjzUsKcJ89BQKdeek=,OWeBf+iTCYVELXPEUOiR5zyN3Y49XibbQ"
    "W7fVshstx+nkW4q8zLxfm9ocERqXM2txZISS6BIhi+mm3+m9U/V3VCa78QN91cudM4R6FA"
    "yia8yP5yXIbjIfx4xI14TDNRyh3br+ICjwV9wBPzMPXslwWw3L0vw0OzhQe/uwWFaDJM=$"
    "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"
    "Vbvn6sRHSQJRuT6Q==$237,9,20$$$AAQAAAAF%2f%2f%2f%2f%2f1Q1lEi1splmg9BeEN"
    "YnKlRTOKpTQ%2fasL47NniCqJtkC6p9PJJ00%2fzqAYxJP+wXhcYaD9TnnchSXzx4AD+T+"
    "3QWJfXNSdwjekAKlInBySJoTTEKhWIl6+3Kc0Ry%2fk3bgh4WLBtR%2fPdZl+Qr947szym"
    "KoqUN1taSYRWGTpGISfss2krqJDxq4VW3IDugoegpYeKHrp+3EmIkSwvGvhS1nqt2gt6NJ"
    "+2Wn+ZGDVNUbRsmIi3vB3k%2fGBxM4Ra%2f1SOo9+kQupdTeTiJtPoWLgNn%2fPu1Pbo9Q"
    "qfNLm2O0plFOFTrm4qnZi%2f0ZluLDW8PKSWXFDZE3XqJxS4iYTU0i"
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
