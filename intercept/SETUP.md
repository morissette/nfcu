# Traffic Interception Setup Guide

This guide walks through the complete setup for intercepting NFCU mobile app
traffic using mitmproxy and an Android emulator.  This is how the API
documented in [docs/API.md](../docs/API.md) was reverse-engineered.

---

## Overview

```
NFCU Android App
      │  HTTPS
      ▼
Android Emulator  ──proxy──►  mitmproxy (port 8080)
                               │ decrypted traffic
                               ▼
                          mitmweb UI (port 8081)
                          /flows JSON API
                          intercept/capture.mitm (raw dump)
```

The emulator sends all HTTPS traffic through mitmproxy.  mitmproxy presents its
own CA certificate, which Android must trust as a **system** CA (not user CA) to
intercept certificate-pinned apps.  The emulator is created **without Google Play
Store** so it can be rooted and its `/system` partition remounted writeable.

---

## Prerequisites

### macOS (Apple Silicon)

```bash
# Java (required by Android emulator)
brew install openjdk
export JAVA_HOME="/opt/homebrew/opt/openjdk"

# Android SDK command-line tools
brew install android-commandlinetools
export ANDROID_HOME="/opt/homebrew/share/android-commandlinetools"
export PATH="$ANDROID_HOME/emulator:$ANDROID_HOME/platform-tools:$PATH"

# mitmproxy
brew install mitmproxy
# Verify: mitmproxy --version  (should show 12.x or later)

# Android system image (API 28 = Android 9, no Play Store = rootable)
sdkmanager "system-images;android-28;google_apis;x86_64"
sdkmanager "emulator"
sdkmanager "platform-tools"
```

> **Why API 28 (Android 9)?**  Android 9 and below allow user CA certificates
> to intercept traffic without extra work.  Android 10+ restricts this to
> system CAs.  We install the mitmproxy cert as a system CA, which requires a
> writable system partition — only possible on a non-Play-Store image.

---

## One-Time Setup

### 1. Create the AVD

```bash
avdmanager create avd \
  --name nfcu_intercept \
  --package "system-images;android-28;google_apis;x86_64" \
  --device "pixel_2"
```

### 2. Generate the mitmproxy CA certificate

Run mitmproxy once to let it create its certificates:

```bash
mitmproxy --version   # generates ~/.mitmproxy/ if not present
ls ~/.mitmproxy/      # should show mitmproxy-ca-cert.cer among others
```

### 3. Compute the Android certificate hash

Android stores system CAs with a filename derived from the certificate's
subject hash.

```bash
openssl x509 -inform PEM -subject_hash_old \
  -in ~/.mitmproxy/mitmproxy-ca-cert.cer | head -1
# Example output: c8750f0d
```

Note this hash — the `start.sh` script computes it automatically each run.

---

## Starting a Capture Session

```bash
cd /path/to/nfcu
bash intercept/start.sh
```

The script:
1. Starts `mitmweb` on port 8080 (proxy) and 8081 (UI)
2. Boots the `nfcu_intercept` AVD with the proxy configured
3. Waits for the device to boot
4. Roots the emulator (`adb root`)
5. Remounts `/system` as writeable (`adb remount`)
6. Pushes the mitmproxy CA cert to `/system/etc/security/cacerts/`
7. Prints a summary and waits (Ctrl-C to shut down)

Browse to **http://localhost:8081** to see the mitmweb UI.

### Known Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Address already in use` on port 8080 | Another mitmproxy still running | `pkill -f mitmproxy` |
| `Address already in use` on port 8081 | Another mitmweb still running | Same fix |
| `emulator: ERROR: unknown virtual device` | AVD not created | Run `avdmanager create avd ...` above |
| `adb: error: remount failed` | Emulator already running without `-writable-system` | Kill emulator, re-run `start.sh` |
| `adb root: adbd cannot run as root` | Play Store image selected (has security restrictions) | Recreate AVD with `google_apis` image (not `google_play_store`) |
| mitmweb REST API returns 403 | mitmweb 12+ requires token auth | Fetch `http://localhost:8081/?token=<token>` first to get session cookie (token shown in mitmweb startup output) |
| `capture.mitm` starts at zero bytes | mitmproxy didn't create file before we push | Wait a few seconds after `start.sh` finishes |

---

## Installing the NFCU App

1. Download the NFCU Android APK from a reputable mirror such as
   [APKMirror](https://www.apkmirror.com/apk/navy-federal/navy-federal-mobile/)
2. Drag the `.apk` onto the running emulator window, **or** run:
   ```bash
   adb install path/to/navy-federal.apk
   ```
3. Open the NFCU app from the emulator home screen and log in

The mitmweb UI at `http://localhost:8081` will begin showing flows immediately.

---

## Extracting a Device Fingerprint

After a successful login, use the mitmweb REST API to extract the fingerprint:

```bash
# 1. Authenticate to mitmweb (token shown in startup output)
TOKEN="your-mitmweb-token"
curl -c /tmp/mitmweb.txt "http://localhost:8081/?token=$TOKEN" -o /dev/null

# 2. Fetch flows and extract the deviceFingerprint
curl -s -b /tmp/mitmweb.txt "http://localhost:8081/flows" | python3 - << 'EOF'
import sys, json, base64, re

flows = json.load(sys.stdin)
# Find POST /api/auth/mobile/authn flows
for f in flows:
    req = f.get("request", {})
    if req.get("path", "").endswith("/authn") and req.get("method") == "POST":
        content = req.get("content", "")
        if content:
            body = base64.b64decode(content).decode("utf-8", errors="replace")
            m = re.search(r'"deviceFingerprint":"([^"]+)"', body)
            if m:
                print(m.group(1))
EOF
```

### Decoding a fingerprint

```python
from nfcu.fingerprint import decode

fp = "_v02MyUx..."
print(decode(fp))
# fpdt=2&mfos=Android&mfov=14&mfwa=02:00:00:...&mfec=<base64-rsa-sig>
```

---

## How mitmproxy Intercepts Certificate-Pinned Traffic

### Why it works on API 28

Android 9 and below trust user CA certificates for system apps.  By installing
the mitmproxy CA as a **system** CA (in `/system/etc/security/cacerts/`), the
NFCU app trusts it when verifying the TLS certificate presented by mitmproxy.

### Why it may not work on API 29+

Android 10 introduced **network security config** changes: user-installed CAs
are no longer trusted for apps targeting API 29+.  Even a system CA install
may not work if the app has certificate pinning (hardcoded public key hashes).

If you need to intercept a newer app version:
1. Try Frida + `ssl_pinning_bypass.js` script to disable pinning at runtime
2. Or patch the APK to remove the network security config, then re-sign it

---

## Directory Structure

```
intercept/
├── start.sh         # Launch script (mitmproxy + emulator + cert install)
├── SETUP.md         # This file
└── capture.mitm     # Raw mitmproxy flow dump (gitignored, generated at runtime)
```

---

## Next Steps After Capture

Once you have traffic captures:

1. **Identify new endpoints** — look for paths under `digitalomni.navyfederal.org`
2. **Decode fingerprints** — use `nfcu.fingerprint.decode()` to inspect params
3. **Extract tokens** — Bearer tokens in `authorization` response headers
4. **Test endpoints** — replay requests with `curl` using the captured token:

```bash
TOKEN="eyJ..."  # from authorization header in authn response
curl -s -H "authorization: Bearer $TOKEN" \
     -H "cid: Mobile" \
     -H "platform: AND" \
     -H "appversion: 2026.2.1" \
     "https://digitalomni.navyfederal.org/api/user-manager/client-api/v2/users/me"
```

5. **Update the module** — add any newly discovered endpoints to `nfcu/__init__.py`
   and document them in `docs/API.md`
