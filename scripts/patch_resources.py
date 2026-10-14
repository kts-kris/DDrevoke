#!/usr/bin/env python3
"""
DDrevoke Resource Bundle Patcher & Verifier for DingTalk macOS
Supports:
1. Patching / restoring /Applications/DingTalk.app/Contents/Resources/webcontent/webcontent.dat (LZFSE archive)
2. Verifying JS transformations with `node --check`
"""

import argparse
import ctypes
import ctypes.util
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile

MARKER = "/* DDREVOKE_PATCHED_V1 */"

STYLE_INJECTION_JS = (
    "/* DDREVOKE_PATCHED_V1 */\n"
    "(function(){try{"
    "var inject=function(){"
    "if(!document||!document.head||document.getElementById('ddrevoke-style'))return;"
    "var s=document.createElement('style');"
    "s.id='ddrevoke-style';"
    "s.textContent='"
    ".msg-group-content.ddrevoke-recalled{position:relative;}"
    ".msg-group-content.ddrevoke-recalled>.msg-bubble-list .msg-bubble-content,.msg-group-content.ddrevoke-recalled>.msg-bubble-list .msg-content{outline:1.5px dashed rgba(255,82,25,0.55)!important;outline-offset:2px;border-radius:8px;}"
    ".msg-group-content.ddrevoke-recalled>.msg-recall-hint,.msg-recall-hint.ddrevoke-badge{display:block!important;width:fit-content!important;max-width:85%!important;margin:4px auto 8px auto!important;padding:3px 10px!important;border-radius:6px!important;background:rgba(255,82,25,0.10)!important;border:1px solid rgba(255,82,25,0.30)!important;color:#e64500!important;font-size:12px!important;line-height:18px!important;text-align:center!important;}"
    ".msg-bubble-group-item.other-msg .msg-group-content.ddrevoke-recalled>.msg-recall-hint{margin-left:56px!important;margin-right:auto!important;text-align:left!important;}"
    ".msg-bubble-group-item.my-msg .msg-group-content.ddrevoke-recalled>.msg-recall-hint{margin-right:56px!important;margin-left:auto!important;text-align:right!important;}"
    "[data-dingtalk-theme=dark] .msg-group-content.ddrevoke-recalled>.msg-recall-hint,[data-dingtalk-theme=dark] .msg-recall-hint.ddrevoke-badge{background:rgba(255,106,51,0.16)!important;border-color:rgba(255,106,51,0.40)!important;color:#ff8559!important;}"
    ".msg-group-content.ddrevoke-recalled>.msg-recall-hint *{color:inherit!important;}"
    ".msg-group-content.ddrevoke-recalled>.msg-recall-hint a.msg-recall-hint-re-edit{color:#007fff!important;margin-left:6px!important;font-weight:500!important;}"
    ".msg-group-content.ddrevoke-recalled>.msg-recall-hint:not(.ddrevoke-badge)::before{content:\"\\u26A0\\uFE0F [防撤回已保留] \";font-weight:600;}"
    ".ddrevoke-tag{font-weight:600;}';"
    "document.head.appendChild(s);"
    "console.log('[DDrevoke] 钉钉防撤回样式已注入');"
    "};"
    "if(document.head)inject();else window.addEventListener('DOMContentLoaded',inject);"
    "setInterval(inject,2000);"
    "}catch(e){}})();\n"
)

RULES = [
    (
        "Rule1_isRecall",
        re.compile(r"\{isRecall:(\w+)\.isRecalled\(\),isSystem:\1\.isSystemMsg\(\),"),
        r"{isRecall:!1,isSystem:\1.isSystemMsg(),",
    ),
    (
        "Rule2_dualRender",
        re.compile(
            r'null!==(\w+)\?\1:(\w+)\.createElement\("div",\{className:"msg-group-content"\},(\2\.createElement\("ul",\{className:"msg-bubble-list"\},(?:\w+|\(0,\w+\.\w+\)\(this\.props\.baseConversation\)\?\2\.createElement\(\w+,Object\.assign\(\{\},\w+\)\):\2\.createElement\(\w+,Object\.assign\(\{\},\w+\)\))\))\)'
        ),
        r'null!==\1&&!(\1.props&&\1.props.RecallName)?\1:\2.createElement("div",{className:"msg-group-content"+(\1?" ddrevoke-recalled":"")},\3,\1)',
    ),
    (
        "Rule3_badge",
        re.compile(
            r'return (\w+)\.createElement\("div",\{className:"msg-recall-hint","data-msg-id":(\w+)\.baseMessage\.messageId\},(\w+),this\.renderReEdit\(\)\)'
        ),
        r'return \1.createElement("div",{className:"msg-recall-hint ddrevoke-badge","data-msg-id":\2.baseMessage.messageId},\1.createElement("span",{className:"ddrevoke-tag"},"⚠️ [防撤回已保留] "),(\3),((\2.baseMessage&&\2.baseMessage.extension&&(\2.baseMessage.extension.recallMessageTime||\2.baseMessage.extension.shieldMessageTime))?" ("+new Date(Number(\2.baseMessage.extension.recallMessageTime||\2.baseMessage.extension.shieldMessageTime)).toLocaleTimeString()+")":""),this.renderReEdit())',
    ),
    (
        "Rule4A_replyText",
        re.compile(
            r'if\((\w+)\)return (\w+\.createElement\("div",\{className:"origin-content-text"\},\w+\.createElement\([^,]+,\{text:\w+\.i18next\.t\("dt_im_msg_has_recalled"\),presetFontSize:"12"\}\)\));'
        ),
        r"if(!1&&\1)return \2;",
    ),
    (
        "Rule4B_replyImg",
        re.compile(
            r"case (\w+\.\w+\.IMG):case (\w+\.\w+\.SAFETY_CRYPTO_IMG):return!(\w+)&&!(\w+)&&(\w+)\|\|(\w+\.imgMsgSDK\.photoContent)\?"
        ),
        r"case \1:case \2:return!\4&&\5||\6?",
    ),
    (
        "Rule5_footerReply",
        re.compile(
            r"(\.HIDE_RECALLED_MSG_IN_FOOTER_BAR_FRONTEND\))&&(\w+\.baseMessage\.recallStatus===\w+\.\w+\.done)"
        ),
        r"\1&&!1&&\2",
    ),
    (
        "Rule6_comboSame",
        re.compile(
            r"=e=>\{const t=(\w+)\(e\)\|\|\[\];if\(Array\.isArray\(t\)&&t\.length>0\)return t\.filter\(\(e=>(\w+)\(e\)\)\)\}"
        ),
        r"=e=>{const t=\1(e)||[];if(Array.isArray(t)&&t.length>0){const s=t.filter((e=>\2(e)));return s.length>0?s:t}}",
    ),
]


def patch_content(name: str, raw_bytes: bytes) -> tuple[bytes, dict]:
    is_chatbox_js = name.startswith("assets/chatbox/") and name.endswith(".js")
    is_chatbox_html = name == "chatbox.html"
    if not is_chatbox_js and not is_chatbox_html:
        return raw_bytes, {}

    text = raw_bytes.decode("utf-8", errors="ignore")
    if MARKER in text:
        return raw_bytes, {"already_patched": 1}

    if is_chatbox_html:
        if "</head>" in text:
            patched = text.replace("</head>", f"<script>{STYLE_INJECTION_JS}</script></head>", 1)
            return patched.encode("utf-8"), {"html_style": 1}
        return raw_bytes, {}

    counts = {}
    for rule_name, pat, repl in RULES:
        text, n = pat.subn(repl, text)
        if n:
            counts[rule_name] = n

    if counts or "chatbox-index." in name:
        text = STYLE_INJECTION_JS + text
        return text.encode("utf-8"), counts

    return raw_bytes, {}


def load_lzfse():
    lib = ctypes.CDLL(ctypes.util.find_library("compression"))
    return lib


def lzfse_decompress(lib, data: bytes, orig_size: int) -> bytes:
    buf = ctypes.create_string_buffer(orig_size + 4096)
    n = lib.compression_decode_buffer(buf, len(buf), data, len(data), None, 0x801)
    if n <= 0:
        raise RuntimeError("LZFSE decompression failed")
    return buf.raw[:n]


def lzfse_compress(lib, data: bytes) -> bytes:
    buf = ctypes.create_string_buffer(len(data) + max(4096, len(data) // 4))
    n = lib.compression_encode_buffer(buf, len(buf), data, len(data), None, 0x801)
    if n <= 0:
        raise RuntimeError("LZFSE compression failed")
    return buf.raw[:n]


def patch_webcontent_dat(dat_path: str) -> bool:
    if not os.path.exists(dat_path):
        print(f"[!] File not found: {dat_path}")
        return False

    bak_path = dat_path + ".ddrevoke.bak"
    if not os.path.exists(bak_path):
        shutil.copy2(dat_path, bak_path)
        print(f"[+] Created backup: {bak_path}")

    with open(bak_path, "rb") as f:
        raw = f.read()

    plen = struct.unpack("<I", raw[:4])[0]
    pl = plistlib.loads(raw[4 : 4 + plen])
    objs = pl["$objects"]
    payload_start = 4 + plen

    lib = load_lzfse()

    # Locate the files dict in NSKeyedArchiver $objects
    root_uid = pl["$top"]["root"].data
    root_obj = objs[root_uid]
    files_uid = None
    for k_uid, v_uid in zip(root_obj["NS.keys"], root_obj["NS.objects"]):
        if objs[k_uid.data] == "files":
            files_uid = v_uid.data
            break

    if files_uid is None:
        raise RuntimeError("Could not find 'files' dictionary in webcontent.dat")

    files_dict_obj = objs[files_uid]
    new_payload_chunks = []
    current_offset = 0
    patched_files = 0

    for k_uid, v_uid in zip(files_dict_obj["NS.keys"], files_dict_obj["NS.objects"]):
        fname = objs[k_uid.data]
        meta_obj = objs[v_uid.data]

        # Extract offset, compressedSize, originalSize indices
        idx_map = {}
        for mk_uid, mv_uid in zip(meta_obj["NS.keys"], meta_obj["NS.objects"]):
            idx_map[objs[mk_uid.data]] = mv_uid.data

        orig_offset = objs[idx_map["offset"]]
        orig_csize = objs[idx_map["compressedSize"]]
        orig_osize = objs[idx_map["originalSize"]]

        comp_chunk = raw[payload_start + orig_offset : payload_start + orig_offset + orig_csize]

        if (fname.startswith("assets/chatbox/") and fname.endswith(".js")) or fname == "chatbox.html":
            decomp = lzfse_decompress(lib, comp_chunk, orig_osize)
            new_decomp, counts = patch_content(fname, decomp)
            if counts:
                if fname.endswith(".js"):
                    with tempfile.NamedTemporaryFile("wb", suffix=".js", delete=False) as tf:
                        tf.write(new_decomp)
                        tname = tf.name
                    res = subprocess.run(["node", "--check", tname], capture_output=True)
                    os.unlink(tname)
                    if res.returncode != 0:
                        raise RuntimeError(f"JS syntax check failed for {fname}")
                comp_chunk = lzfse_compress(lib, new_decomp)
                orig_csize = len(comp_chunk)
                orig_osize = len(new_decomp)
                patched_files += 1
                print(f"[+] Patched in webcontent.dat: {fname} -> {counts}")

        # Update NSKeyedArchiver integer objects
        objs[idx_map["offset"]] = current_offset
        objs[idx_map["compressedSize"]] = orig_csize
        objs[idx_map["originalSize"]] = orig_osize

        new_payload_chunks.append(comp_chunk)
        current_offset += orig_csize

    new_plist_bytes = plistlib.dumps(pl, fmt=plistlib.FMT_BINARY)
    with open(dat_path, "wb") as f:
        f.write(struct.pack("<I", len(new_plist_bytes)))
        f.write(new_plist_bytes)
        for chunk in new_payload_chunks:
            f.write(chunk)

    print(f"[+] Successfully updated {dat_path} ({patched_files} files patched)")
    return True


def restore_webcontent_dat(dat_path: str) -> bool:
    bak_path = dat_path + ".ddrevoke.bak"
    if os.path.exists(bak_path):
        shutil.copy2(bak_path, dat_path)
        print(f"[+] Restored {dat_path} from {bak_path}")
        return True
    print(f"[i] No backup found at {bak_path}")
    return False


def main():
    parser = argparse.ArgumentParser(description="DDrevoke Resource Patcher")
    parser.add_argument(
        "--webcontent",
        default="/Applications/DingTalk.app/Contents/Resources/webcontent/webcontent.dat",
        help="Path to webcontent.dat",
    )
    parser.add_argument("--restore", action="store_true", help="Restore backup")
    args = parser.parse_args()

    if args.restore:
        restore_webcontent_dat(args.webcontent)
    else:
        patch_webcontent_dat(args.webcontent)


if __name__ == "__main__":
    main()
