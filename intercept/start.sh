#!/usr/bin/env bash
# Starts mitmproxy and the Android emulator wired together for traffic capture.
# Run this script, install the NFCU app, log in, then check mitmweb at
# http://localhost:8081 to see the captured requests.
set -euo pipefail

export JAVA_HOME="/opt/homebrew/opt/openjdk"
export ANDROID_HOME="/opt/homebrew/share/android-commandlinetools"
export PATH="$ANDROID_HOME/emulator:$ANDROID_HOME/platform-tools:$JAVA_HOME/bin:$PATH"

PROXY_HOST="127.0.0.1"
PROXY_PORT="8080"
MITMWEB_PORT="8081"
AVD_NAME="nfcu_intercept"
CERT_DIR="$HOME/.mitmproxy"

echo "==> Starting mitmweb on port $MITMWEB_PORT (UI: http://localhost:$MITMWEB_PORT)..."
mitmweb --listen-port "$PROXY_PORT" --web-port "$MITMWEB_PORT" \
  --save-stream-file intercept/capture.mitm &
MITM_PID=$!
echo "    mitmweb PID: $MITM_PID"

echo "==> Waiting for mitmproxy to generate certificates..."
sleep 3

# Generate the hashed cert filename Android expects
CERT_SRC="$CERT_DIR/mitmproxy-ca-cert.cer"
if [ ! -f "$CERT_SRC" ]; then
  echo "ERROR: mitmproxy cert not found at $CERT_SRC"
  echo "       Run mitmproxy once manually to generate certs, then re-run this script."
  kill "$MITM_PID"
  exit 1
fi
CERT_HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$CERT_SRC" | head -1)
CERT_DST="/system/etc/security/cacerts/${CERT_HASH}.0"

echo "==> Starting emulator (proxy: $PROXY_HOST:$PROXY_PORT)..."
emulator -avd "$AVD_NAME" \
  -http-proxy "$PROXY_HOST:$PROXY_PORT" \
  -no-snapshot-save \
  -writable-system &
EMU_PID=$!
echo "    emulator PID: $EMU_PID"

echo "==> Waiting for device to boot..."
adb wait-for-device
adb shell 'while [[ -z $(getprop sys.boot_completed) ]]; do sleep 2; done'
echo "    Device ready."

echo "==> Installing mitmproxy CA cert as system cert..."
adb root
sleep 2
adb remount
adb push "$CERT_SRC" "$CERT_DST"
adb shell "chmod 644 $CERT_DST"
echo "    Certificate installed: $CERT_DST"

echo ""
echo "======================================================"
echo " Setup complete!"
echo " mitmweb UI : http://localhost:$MITMWEB_PORT"
echo " Next steps :"
echo "   1. Drag the NFCU APK onto the emulator window to install"
echo "      (Download from: https://www.apkmirror.com/apk/navy-federal/navy-federal-mobile/)"
echo "   2. Open the NFCU app and log in"
echo "   3. Watch requests in mitmweb — look for navyfcu.org endpoints"
echo "   4. Raw capture saved to: intercept/capture.mitm"
echo "======================================================"

# Keep script running; Ctrl-C shuts everything down cleanly
trap 'echo "Shutting down..."; kill $MITM_PID $EMU_PID 2>/dev/null' INT TERM
wait
