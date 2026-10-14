#!/usr/bin/env python3
#
# insert_dylib.py
# Pure Python Mach-O LC_LOAD_DYLIB injector for DingTalk on macOS
#

import sys
import struct
import os

def insert_dylib(binary_path, dylib_payload_path):
    if not os.path.isfile(binary_path):
        print(f"[-] Error: Binary not found at {binary_path}", file=sys.stderr)
        return False

    with open(binary_path, "r+b") as f:
        magic = struct.unpack(">I", f.read(4))[0]
        f.seek(0)
        slices = []
        if magic in (0xcafebabe, 0xbebafeca):
            f.seek(4)
            nfat = struct.unpack(">I", f.read(4))[0]
            for _ in range(nfat):
                cputype, cpusubtype, offset, size, align = struct.unpack(">IIIII", f.read(20))
                slices.append((offset, size))
        elif magic in (0xfeedfacf, 0xcffaedfe):
            slices.append((0, os.path.getsize(binary_path)))
        else:
            print("[-] Error: Unsupported Mach-O magic", file=sys.stderr)
            return False

        dylib_bytes = dylib_payload_path.encode("utf-8") + b"\x00"
        cmd_size = 24 + len(dylib_bytes)
        if cmd_size % 8 != 0:
            cmd_size += 8 - (cmd_size % 8)

        LC_LOAD_DYLIB = 0x0c

        modified = False
        all_already = True

        for offset, size in slices:
            f.seek(offset)
            m_magic = struct.unpack("<I", f.read(4))[0]
            if m_magic != 0xfeedfacf:
                continue

            cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack("<IIIIIII", f.read(28))

            # Check if dylib is already inserted
            f.seek(offset + 32)
            already_inserted = False
            for _ in range(ncmds):
                cmd, csize = struct.unpack("<II", f.read(8))
                if cmd in (0x0c, 0x8000001c): # LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB
                    f.seek(f.tell() - 8)
                    cmd_data = f.read(csize)
                    if dylib_payload_path.encode("utf-8") in cmd_data:
                        already_inserted = True
                        break
                else:
                    f.seek(f.tell() + csize - 8)

            if already_inserted:
                print(f"[+] Dylib already inserted in slice at offset {hex(offset)}")
                continue

            all_already = False
            cmd_insert_pos = offset + 32 + sizeofcmds
            f.seek(cmd_insert_pos)
            padding = f.read(cmd_size)
            if len(padding) < cmd_size or any(b != 0 for b in padding):
                print(f"[-] Error: Insufficient zero padding in header for slice {hex(offset)}", file=sys.stderr)
                return -1

            dylib_cmd = struct.pack("<IIIIII", LC_LOAD_DYLIB, cmd_size, 24, 0, 0x10000, 0x10000) + dylib_bytes
            dylib_cmd += b"\x00" * (cmd_size - len(dylib_cmd))

            f.seek(cmd_insert_pos)
            f.write(dylib_cmd)

            f.seek(offset + 16)
            f.write(struct.pack("<II", ncmds + 1, sizeofcmds + cmd_size))
            modified = True
            print(f"[+] Successfully inserted {dylib_payload_path} into slice at {hex(offset)}")

    if modified:
        return 0  # Newly modified
    elif all_already:
        return 2  # Already inserted, no modification needed
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 insert_dylib.py <target_binary> <dylib_path>")
        sys.exit(1)
    ret = insert_dylib(sys.argv[1], sys.argv[2])
    if ret == -1:
        sys.exit(1)
    elif ret == 2:
        sys.exit(2)
    else:
        sys.exit(0)
