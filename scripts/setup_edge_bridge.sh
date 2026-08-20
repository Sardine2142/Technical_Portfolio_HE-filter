#!/usr/bin/env bash
# ============================================================================
# setup_edge_bridge.sh — Windows Edge <-> WSL 데몬 다리 설치 (WSL 안에서 실행)
#
# 하는 일:
#   1) WSL 측 데몬 런처(wsl_daemon.sh) 를 ~/lookup 에 생성 (LF 보장)
#   2) Windows 측 배치 래퍼(.bat) 와 매니페스트(.json) 를 Windows 홈에 생성
#   3) Edge/Chrome 레지스트리에 매니페스트 경로 등록 (reg.exe, HKCU)
#
# 사용법 (WSL 안에서):
#   ./setup_edge_bridge.sh <확장ID>
#   확장 ID 는 edge://extensions 에서 "압축을 푼 확장 로드" 후 표시되는 값
# ============================================================================

set -e

# ---- 인자 ----
if [ -z "$1" ]; then
    echo "사용법: $0 <확장ID>   (edge://extensions 에서 확인)"
    exit 1
fi
EXT_ID="$1"

# ---- 경로 계산 ----
LOOKUP_DIR="$HOME/lookup"
DAEMON_BIN="$LOOKUP_DIR/lookup_daemon"

# 데몬 존재 확인
if [ ! -x "$DAEMON_BIN" ]; then
    echo "오류: 데몬이 없습니다 -> $DAEMON_BIN (먼저 데몬 빌드)"
    exit 1
fi

# Windows 사용자 홈을 WSL 경로로 확인 (배치/매니페스트를 여기에 둔다)
# cmd.exe 로 %USERPROFILE% 를 얻어 wslpath 로 변환
WIN_HOME_RAW="$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r')"
WIN_HOME_WSL="$(wslpath "$WIN_HOME_RAW")"
BRIDGE_DIR="$WIN_HOME_WSL/lookup-bridge"
mkdir -p "$BRIDGE_DIR"

# ---- 1) WSL 측 데몬 런처 (반드시 LF) ----
cat > "$LOOKUP_DIR/wsl_daemon.sh" << 'EOF'
#!/usr/bin/env bash
# Windows Edge 가 wsl.exe 를 통해 실행하는 데몬 런처.
# stdout 은 네이티브 메시징 채널이므로 로그는 stderr 로만.
export LD_LIBRARY_PATH="$HOME/local/lib:$LD_LIBRARY_PATH"
export LOOKUP_SERVER="127.0.0.1:8080"
exec "$HOME/lookup/lookup_daemon"
EOF
chmod +x "$LOOKUP_DIR/wsl_daemon.sh"
# LF 보장 (혹시 모를 CRLF 제거)
sed -i 's/\r$//' "$LOOKUP_DIR/wsl_daemon.sh"

# WSL 스크립트의 리눅스 절대경로 (wsl.exe -e 에 넘길 값)
DAEMON_LAUNCHER="$LOOKUP_DIR/wsl_daemon.sh"

# ---- 2) Windows 배치 래퍼 (.bat, CRLF) ----
# Edge 가 직접 실행. wsl.exe 로 런처를 호출.
BAT_WSL="$BRIDGE_DIR/lookup_host.bat"
printf '@echo off\r\nwsl.exe -d Ubuntu -e %s\r\n' "$DAEMON_LAUNCHER" > "$BAT_WSL"
# 배치의 Windows 경로 (매니페스트 path 에 넣을 값)
BAT_WIN="$(wslpath -w "$BAT_WSL")"

# ---- 3) 네이티브 메시징 매니페스트 (.json) ----
MANIFEST_WSL="$BRIDGE_DIR/com.hexlab.lookup.json"
# JSON 안의 Windows 경로는 백슬래시를 이스케이프해야 함
BAT_WIN_JSON="$(printf '%s' "$BAT_WIN" | sed 's/\\/\\\\/g')"
cat > "$MANIFEST_WSL" << EOF
{
  "name": "com.hexlab.lookup",
  "description": "Private phishing lookup daemon (HE, via WSL)",
  "path": "$BAT_WIN_JSON",
  "type": "stdio",
  "allowed_origins": [ "chrome-extension://$EXT_ID/" ]
}
EOF
MANIFEST_WIN="$(wslpath -w "$MANIFEST_WSL")"

# ---- 4) 레지스트리 등록 (reg.exe, HKCU — 관리자 권한 불필요) ----
# Edge
reg.exe add "HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.hexlab.lookup" \
    /ve /t REG_SZ /d "$MANIFEST_WIN" /f >/dev/null
echo "등록(Edge): $MANIFEST_WIN"
# Chrome (있으면 함께 — 없어도 무해)
reg.exe add "HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\com.hexlab.lookup" \
    /ve /t REG_SZ /d "$MANIFEST_WIN" /f >/dev/null 2>&1 && echo "등록(Chrome): $MANIFEST_WIN" || true

echo ""
echo "완료. 확인 순서:"
echo "  1) WSL 에서 서버가 떠 있는지: ./lookup_server --values feed_hv.csv --port 8080"
echo "  2) Edge 완전 종료 후 재실행 (작업관리자로 msedge 잔여 프로세스까지 종료 권장)"
echo "  3) 일반 사이트 방문 -> 정상 / 피드의 도메인 방문 -> 경고 페이지"
echo ""
echo "디버깅: Edge 확장의 '서비스 워커' 콘솔에서 연결 오류 확인."
echo "        데몬 로그는 wsl_daemon.sh 의 stderr — 필요시 exec 앞에 로그 리다이렉트 추가."
