#!/bin/bash
#
# 建置量測 App、裝到連接的裝置上、跑起來，並收集結果。
#
#     ./run.sh <TEAM_ID> [BUNDLE_ID] [DEVICE_UDID]
#
# 例：
#     ./run.sh ABCDE12345                      # 用下面的預設 bundle ID
#     ./run.sh ABCDE12345 com.example.probe    # 指定自己的
#
# TEAM_ID 是你們 Apple Developer 帳號的 10 碼 Team ID。
#
# App 啟動後會自動跑完量測，結果同時顯示在手機畫面和 os_log。
# 這個腳本會把 log 收下來印出來。

set -euo pipefail

TEAM_ID="${1:?需要 TEAM_ID，例如 ABCDE12345}"
BUNDLE_ID="${2:-tw.com.appattest.probe}"
DEVICE="${3:-}"

cd "$(dirname "$0")"

# 沒指定裝置就抓第一台連線中的實機。
#
# 注意：要用**硬體 UDID**（00008120-… 這種），不是 devicectl list devices
# 顯示的 CoreDevice UUID（EAFAB627-… 這種）。xcodebuild 只認前者，而
# devicectl 兩種都收 —— 用錯會得到一串「找不到 destination」然後列出一堆
# 模擬器，訊息完全看不出真正的原因。
if [ -z "$DEVICE" ]; then
    # 只取 "== Devices ==" 區塊（排除 Offline 與模擬器），抓括號裡的硬體 UDID。
    DEVICE=$(xcrun xctrace list devices 2>/dev/null \
        | sed -n '/^== Devices ==/,/^== Devices Offline ==/p' \
        | sed -n 's/.*(\(000[0-9A-F]*-[0-9A-F]*\))$/\1/p' \
        | head -1) || true
fi

if [ -z "$DEVICE" ]; then
    echo "找不到已連接的 iPhone。請插上、解鎖、並信任這台電腦。"
    echo "目前 xcrun xctrace list devices 看到的："
    xcrun xctrace list devices 2>&1 | head -20
    exit 1
fi

echo "裝置   : $DEVICE"
echo "team   : $TEAM_ID"
echo "bundle : $BUNDLE_ID"
echo

echo "==> 產生 Xcode 專案"
xcodegen generate --quiet

echo "==> 建置"
xcodebuild \
    -project AttestProbe.xcodeproj \
    -scheme AttestProbe \
    -configuration Debug \
    -destination "id=$DEVICE" \
    -derivedDataPath build \
    DEVELOPMENT_TEAM="$TEAM_ID" \
    PRODUCT_BUNDLE_IDENTIFIER="$BUNDLE_ID" \
    -allowProvisioningUpdates \
    build 2>&1 | tail -5

APP_PATH="build/Build/Products/Debug-iphoneos/AttestProbe.app"

if [ ! -d "$APP_PATH" ]; then
    echo "建置失敗：找不到 $APP_PATH"
    exit 1
fi

echo "==> 安裝"
xcrun devicectl device install app --device "$DEVICE" "$APP_PATH" 2>&1 | tail -3

echo "==> 啟動（結果會顯示在手機畫面上，同時寫進 log）"
xcrun devicectl device process launch \
    --device "$DEVICE" \
    --console \
    "$BUNDLE_ID" 2>&1 | grep -E 'PROBE|error|Error' || true

echo
echo "如果上面沒看到 PROBE 開頭的行，改用這個指令收 log："
echo "  xcrun devicectl device console --device $DEVICE | grep PROBE"
