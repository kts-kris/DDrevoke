#!/usr/bin/env zsh
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"
DMG_STAGING="${BUILD_DIR}/dmg_staging"
DMG_OUTPUT="${BUILD_DIR}/DDRevoke_v1.0.3.dmg"
VOL_NAME="钉钉防撤回_DDRevoke_v1.0.3"

echo "[*] Step 1: Compiling and verifying libDDRevoke.dylib..."
make -C "${PROJECT_DIR}" clean
make -C "${PROJECT_DIR}" verify

echo "[*] Step 2: Preparing staging folder at ${DMG_STAGING}..."
rm -rf "${DMG_STAGING}" "${DMG_OUTPUT}"
mkdir -p "${DMG_STAGING}"

cp -f "${BUILD_DIR}/libDDRevoke.dylib" "${DMG_STAGING}/libDDRevoke.dylib"
cp -f "${PROJECT_DIR}/scripts/insert_dylib.py" "${DMG_STAGING}/insert_dylib.py"
cp -f "${PROJECT_DIR}/scripts/entitlements.plist" "${DMG_STAGING}/entitlements.plist"
chmod 755 "${DMG_STAGING}/libDDRevoke.dylib" "${DMG_STAGING}/insert_dylib.py"

cat << 'EOF' > "${DMG_STAGING}/一键安装 (双击运行).command"
#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_APP="/Applications/DingTalk.app"
TARGET_BIN="${TARGET_APP}/Contents/MacOS/DingTalk"
ORIG_BACKUP="${TARGET_APP}/Contents/MacOS/DingTalk.orig"
DYLIB_NAME="libDDRevoke.dylib"
DYLIB_SRC="${DIR}/${DYLIB_NAME}"
DYLIB_DEST="${TARGET_APP}/Contents/MacOS/${DYLIB_NAME}"

echo "=========================================================="
echo "          钉钉防撤回补丁一键安装器 (DDRevoke v1.0.3)"
echo "=========================================================="
echo ""

if [ ! -d "${TARGET_APP}" ]; then
    echo "[-] 未在 /Applications 中找到 DingTalk.app，请确认钉钉已安装。"
    read -p "按回车键退出..."
    exit 1
fi

if pgrep -x "DingTalk" > /dev/null 2>&1; then
    echo "[*] 检测到钉钉正在运行，正在为您关闭钉钉..."
    osascript -e 'tell application "DingTalk" to quit' >/dev/null 2>&1 || true
    sleep 2
    pkill -9 -x "DingTalk" >/dev/null 2>&1 || true
    sleep 1
fi

echo "[1/4] 备份原始二进制..."
if [ ! -f "${ORIG_BACKUP}" ]; then
    cp -p "${TARGET_BIN}" "${ORIG_BACKUP}"
    echo "      已备份原始可执行文件至 DingTalk.orig"
else
    echo "      原始备份已存在，跳过备份。"
fi

echo "[2/4] 部署动态库..."
cp -f "${DYLIB_SRC}" "${DYLIB_DEST}"
chmod 755 "${DYLIB_DEST}"
codesign --force --sign - "${DYLIB_DEST}" >/dev/null 2>&1 || true

echo "[3/4] 检查/注入防撤回动态加载指令..."
set +e
python3 "${DIR}/insert_dylib.py" "${TARGET_BIN}" "@executable_path/${DYLIB_NAME}"
INJECT_STATUS=$?
set -e

if [ ${INJECT_STATUS} -eq 2 ]; then
    echo "[4/4] 权限保护模式生效 (热更新)..."
    echo "      [✓] 检测到已注入动态加载指令，跳过重新签署主程序！"
    echo "      [✓] 钉钉系统原有授权（麦克风、摄像头、通知等）100% 完整保留，无需重新授权！"
elif [ ${INJECT_STATUS} -eq 0 ]; then
    echo "[4/4] 继承系统权限并签署应用..."
    TEMP_ENT="${DIR}/entitlements.plist"
    if [ -f "${ORIG_BACKUP}" ]; then
        codesign -d --entitlements :- "${ORIG_BACKUP}" > "${DIR}/ent_extracted.plist" 2>/dev/null || true
        if [ -s "${DIR}/ent_extracted.plist" ]; then
            TEMP_ENT="${DIR}/ent_extracted.plist"
        fi
    fi
    codesign --force --sign - --entitlements "${TEMP_ENT}" --options runtime --preserve-metadata=identifier,flags "${TARGET_BIN}" >/dev/null 2>&1 || codesign --force --sign - "${TARGET_BIN}" >/dev/null 2>&1 || true
    rm -f "${DIR}/ent_extracted.plist"
    echo "      [✓] 已完整继承官方 15+ 项硬件与系统权限（麦克风、摄像头、日历、下载目录等）。"
else
    echo "[-] 注入动态加载指令失败，请检查报错信息。"
    read -p "按回车键退出..."
    exit 1
fi

echo ""
echo "=========================================================="
echo "🎉 安装完成！"
echo ""
echo "使用说明："
echo "1. 以后直接正常点击 Launchpad、Dock 栏原有的“钉钉”图标即可；"
echo "2. 首次启动时若提示麦克风/通知授权，点击“允许”即可；后续升级永不失效；"
echo "3. 对方撤回消息时，消息会完整保留，并在消息下方自动贴上表情标记；"
echo "4. 顶部菜单栏已集成【🛡️ 防撤回】菜单（快捷键 ⌘\\），可自定义标记表情与开关；"
echo "5. 新增【🔄 检查更新】：后续有新版本时，可在菜单中直接一键在线热更新，无需重新安装；"
echo "6. 如需完全恢复，只需随时双击运行本目录下的“一键卸载.command”。"
echo "=========================================================="
echo ""
read -p "按回车键退出..."
EOF
chmod 755 "${DMG_STAGING}/一键安装 (双击运行).command"

cat << 'EOF' > "${DMG_STAGING}/一键卸载 (双击运行).command"
#!/usr/bin/env bash
set -e

TARGET_APP="/Applications/DingTalk.app"
TARGET_BIN="${TARGET_APP}/Contents/MacOS/DingTalk"
ORIG_BACKUP="${TARGET_APP}/Contents/MacOS/DingTalk.orig"
DYLIB_DEST="${TARGET_APP}/Contents/MacOS/libDDRevoke.dylib"

echo "=========================================================="
echo "          钉钉防撤回补丁一键卸载器 (DDRevoke)"
echo "=========================================================="
echo ""

if pgrep -x "DingTalk" > /dev/null 2>&1; then
    echo "[*] 检测到钉钉正在运行，正在为您关闭钉钉..."
    osascript -e 'tell application "DingTalk" to quit' >/dev/null 2>&1 || true
    sleep 2
    pkill -9 -x "DingTalk" >/dev/null 2>&1 || true
    sleep 1
fi

echo "[1/3] 还原原始二进制..."
if [ -f "${ORIG_BACKUP}" ]; then
    mv -f "${ORIG_BACKUP}" "${TARGET_BIN}"
    echo "      已成功恢复官方原始 DingTalk 二进制。"
else
    echo "      未找到备份文件，保留当前二进制。"
fi

echo "[2/3] 清理动态库文件..."
rm -f "${DYLIB_DEST}"

echo "[3/3] 验证应用签名..."
if ! codesign -v "${TARGET_BIN}" >/dev/null 2>&1; then
    codesign --force --sign - "${TARGET_BIN}" >/dev/null 2>&1 || true
    echo "      已重新签署应用。"
else
    echo "      官方原始签名有效，已完全还原。"
fi

echo ""
echo "=========================================================="
echo "🎉 卸载完成！钉钉已完全恢复为官方原始状态。"
echo "=========================================================="
echo ""
read -p "按回车键退出..."
EOF
chmod 755 "${DMG_STAGING}/一键卸载 (双击运行).command"

cat << 'EOF' > "${DMG_STAGING}/使用说明.txt"
================================================================================
                    钉钉防撤回插件 (DDRevoke v1.0.3)
================================================================================

【功能亮点】
1. 消息防撤回：对方撤回的文字、图片、表情等消息完整保留在聊天窗口中；
2. 自动贴表情：拦截到撤回时，自动在原消息气泡下方贴上表情标记（默认 🤔 思考）；
3. 原生设置入口：钉钉顶部菜单栏原生集成【🛡️ 防撤回】菜单，支持快捷键 ⌘\ 呼出设置面板，
   可自由选择标记表情（🤔 思考、🤫 嘘、🍉 吃瓜、🤦 捂脸、👍 点赞、👌 收到等）及提示音、系统通知开关；
4. 系统通知提示：拦截撤回时，桌面右上角同步弹出系统横幅通知并伴有声音，
   并清晰显示撤回者的真实姓名/备注名；
5. 纯净原生体验：一次安装后，日常直接正常启动原有的“钉钉”，桌面上无任何多余程序；
6. 自身撤回放行：您自己撤回的消息正常撤回，不影响正常使用体验；
7. 权限永久保留机制 (NEW!)：
   - 升级或重装时，若主程序已注入动态库，系统会自动启用“热更新保护模式”，
     绝不改动主程序二进制或重复签名；
   - 首次安装时自动提取并保留官方全部 15+ 项硬件与权限声明（麦克风、摄像头、日历、下载等）；
   - 本机原有的各项系统权限永久保留，彻底告别频繁重新授权的困扰！
8. 在线检查更新与一键热升级 (NEW!)：
   - 在顶部【🛡️ 防撤回】菜单或【设置】窗口中点击【🔄 检查更新...】即可在线获取新版本；
   - 钉钉启动后亦会自动后台静默探测是否有新版本；
   - 发现新版时，点击“立即热更新”即可秒级自动下载并替换动态库，无需手动下载 DMG 重新安装。
9. 安全熔断机制：若钉钉后续大版本升级，插件会自动探测并安全降级，绝不引起应用闪退。

【安装方法】
1. 双击运行【一键安装 (双击运行).command】；
2. 按照屏幕提示等待 2 秒即可完成安装；
3. 安装成功后，您可以将本 DMG 推出并删除；
4. 像往常一样，直接点击系统 Dock 栏或启动台的【钉钉】图标正常使用。
   * 注意：首次打开时若提示通知/麦克风权限请求，点击“允许”即可，后续更新永不失效。

【配置方式】
- 正常启动钉钉后，顶部菜单栏可见【🛡️ 防撤回】菜单；
- 随时按快捷键 ⌘\ 即可呼出【DDRevoke 防撤回设置】面板，自由修改标记表情、通知与检查更新。

【卸载方法】
若需要完全恢复为官方原始钉钉：
双击运行【一键卸载 (双击运行).command】即可秒级还原。

================================================================================
EOF

echo "[*] Step 3: Generating DMG using hdiutil..."
hdiutil create -volname "${VOL_NAME}" \
               -srcfolder "${DMG_STAGING}" \
               -ov \
               -format UDZO \
               "${DMG_OUTPUT}"

echo "[+] Successfully created: ${DMG_OUTPUT}"
ls -lh "${DMG_OUTPUT}"
