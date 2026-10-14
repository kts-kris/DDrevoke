#!/usr/bin/env python3
"""
verify_target.py
Verifies that the installed /Applications/DingTalk.app/Contents/MacOS/DingTalk
matches the expected arm64 UUID and 16-byte instruction prologs used by DDRevoke.mm.
"""

import os
import struct
import sys

BIN_PATH = "/Applications/DingTalk.app/Contents/MacOS/DingTalk"
VM_BASE = 0x100000000
EXPECTED_UUID = bytes.fromhex("3A164B985BBA3B608ADF7D9DA894025A")

EXPECTED_PROLOGS = [
    ("IMMessageCache::UpdateRecallStatus",   0x1019A16F0, (0xA9BA6FFC, 0xA90167FA, 0xA9025FF8, 0xA90357F6)),
    ("RecallMessageByMsgId",                 0x101A7136C, (0xA9BA6FFC, 0xA90167FA, 0xA9025FF8, 0xA90357F6)),
    ("SyncRecallCache::InRecallCache",       0x101AD0808, (0xA9BD57F6, 0xA9014FF4, 0xA9027BFD, 0x910083FD)),
    ("OnRecallMsgV3Success",                 0x101C206A8, (0xD10583FF, 0xA91357F6, 0xA9144FF4, 0xA9157BFD)),
    ("IMMessageCache::FindMessage",          0x10199CD78, (0xA9BC6FFC, 0xA90157F6, 0xA9024FF4, 0xA9037BFD)),
    ("std::shared_ptr<DTMessage>::~dtor",    0x1000078A8, (0xA9BE4FF4, 0xA9017BFD, 0x910043FD, 0xAA0003F3)),
    ("GetGlobalAuthCtx",                     0x1000226F8, (0xD10143FF, 0xA9034FF4, 0xA9047BFD, 0x910103FD)),
    ("InitCppString",                        0x100004470, (0xA9BC5FF8, 0xA90157F6, 0xA9024FF4, 0xA9037BFD)),
    ("FreeCppStringHeap",                    0x106CFD72C, (0xB0015E90, 0xF944B210, 0xD61F0200, 0xB0015E90)),
    ("GetNameService",                       0x10380CBEC, (0xD100C3FF, 0xA9027BFD, 0x910083FD, 0xB0035128)),
    ("GetUserDisplayName",                   0x1002E1258, (0xD10143FF, 0xA9034FF4, 0xA9047BFD, 0x910103FD)),
    ("IMMessage::GetExtension",              0x101D4B894, (0xA9BD57F6, 0xA9014FF4, 0xA9027BFD, 0x910083FD)),
]


def find_arm64_slice(fp):
    fp.seek(0)
    magic = struct.unpack(">I", fp.read(4))[0]
    if magic == 0xCAFEBABE:
        nfat = struct.unpack(">I", fp.read(4))[0]
        for _ in range(nfat):
            cputype, cpusubtype, offset, size, align = struct.unpack(">IIIII", fp.read(20))
            if cputype == 0x0100000C:  # CPU_TYPE_ARM64
                return offset, size
        raise RuntimeError("No arm64 slice found in fat binary")
    elif magic == 0xCFFAEDFE:
        fp.seek(0, os.SEEK_END)
        return 0, fp.tell()
    else:
        raise RuntimeError(f"Unsupported Mach-O magic: 0x{magic:08x}")


def main():
    if not os.path.exists(BIN_PATH):
        print(f"[-] Binary not found: {BIN_PATH}", file=sys.stderr)
        return 1

    with open(BIN_PATH, "rb") as fp:
        slice_off, slice_size = find_arm64_slice(fp)
        print(f"[+] Found arm64 slice at file offset {slice_off} (0x{slice_off:x}), size {slice_size} bytes")

        # Parse Mach-O header for LC_UUID
        fp.seek(slice_off)
        hdr = fp.read(32)
        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack("<IIIIIIII", hdr)
        cmds = fp.read(sizeofcmds)
        pos = 0
        uuid_bytes = None
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", cmds, pos)
            if cmd == 0x1B:  # LC_UUID
                uuid_bytes = cmds[pos + 8 : pos + 24]
                break
            pos += cmdsize

        if uuid_bytes:
            match_str = "MATCH" if uuid_bytes == EXPECTED_UUID else "MISMATCH"
            print(f"[+] arm64 LC_UUID: {uuid_bytes.hex().upper()} ({match_str})")

        all_ok = True
        for name, va, expected in EXPECTED_PROLOGS:
            file_pos = slice_off + (va - VM_BASE)
            fp.seek(file_pos)
            actual = struct.unpack("<IIII", fp.read(16))
            ok = actual == expected
            status = "OK" if ok else "MISMATCH"
            print(
                f"    [{status}] {name:36s} @ 0x{va:09x}: "
                f"{' '.join(f'0x{x:08x}' for x in actual)}"
            )
            if not ok:
                all_ok = False

    if not all_ok:
        print("[-] Prolog verification failed!", file=sys.stderr)
        return 1
    print("[+] All target function prologs verified successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
