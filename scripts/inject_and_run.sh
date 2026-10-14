#!/usr/bin/env zsh
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DYLIB_PATH="${PROJECT_DIR}/build/libDDRevoke.dylib"
ORIG_APP="/Applications/DingTalk.app"
ISOLATED_APP="/tmp/DingTalk-DDRevoke.app"
MODE="direct"

if [[ "${1:-}" == "--isolated" ]]; then
    MODE="isolated"
fi

if [[ ! -f "${DYLIB_PATH}" ]]; then
    echo "[*] Building libDDRevoke.dylib..."
    make -C "${PROJECT_DIR}"
fi

echo "[*] Verifying target binary signatures..."
python3 "${PROJECT_DIR}/scripts/verify_target.py"

if [[ "${MODE}" == "direct" ]]; then
    echo "[+] Launching official DingTalk directly (/Applications/DingTalk.app)..."
    echo "[+] Official Alibaba Team ID & all macOS system authorizations (Mic, Camera, Notifications, Screen Capture, Keychain) 100% preserved!"
    echo "[+] Tail /tmp/ddrevoke.log to observe recall interception events."
    DYLD_INSERT_LIBRARIES="${DYLIB_PATH}" \
        "${ORIG_APP}/Contents/MacOS/DingTalk"
else
    echo "[*] Launching isolated copy at ${ISOLATED_APP}..."
    if [[ ! -d "${ISOLATED_APP}" ]]; then
        echo "[*] Creating isolated test copy at ${ISOLATED_APP}..."
        ditto "${ORIG_APP}" "${ISOLATED_APP}"
        cp -f "${DYLIB_PATH}" "${ISOLATED_APP}/Contents/MacOS/libDDRevoke.dylib"
        xattr -cr "${ISOLATED_APP}" || true
        codesign --force --deep --sign - "${ISOLATED_APP}"
    else
        cp -f "${DYLIB_PATH}" "${ISOLATED_APP}/Contents/MacOS/libDDRevoke.dylib"
        codesign --force --sign - "${ISOLATED_APP}/Contents/MacOS/libDDRevoke.dylib"
        codesign --force --sign - "${ISOLATED_APP}/Contents/MacOS/DingTalk"
    fi
    DYLD_INSERT_LIBRARIES="${ISOLATED_APP}/Contents/MacOS/libDDRevoke.dylib" \
        "${ISOLATED_APP}/Contents/MacOS/DingTalk"
fi
