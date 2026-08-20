#!/usr/bin/env bash
# ============================================================================
# install_extension_host.sh — 데몬 빌드 + Chrome 네이티브 호스트 등록
#
# 순서 (닭-달걀 주의):
#   1) chrome://extensions -> 개발자 모드 -> "압축해제된 확장 프로그램 로드"
#      -> extension/ 디렉터리 선택 -> 표시되는 확장 ID 복사
#   2) ./install_extension_host.sh <확장ID>
#   3) Chrome 완전 재시작 후 브라우징
#
# 서버 주소를 바꾸려면 (기본 127.0.0.1:8080):
#   래퍼가 LOOKUP_SERVER 환경 변수를 데몬에 넘긴다 — 아래 WRAPPER 부분 수정
# ============================================================================

# 오류 시 즉시 중단
set -e

# ---- 인자 확인: 확장 ID 를 하나 이상 받는다 ----
# (Chrome 과 Edge 에 같은 폴더를 로드해도 ID 가 다를 수 있으므로
#  두 브라우저를 함께 쓰면 두 ID 를 모두 전달)
if [ -z "$1" ]; then
    echo "사용법: $0 <확장ID> [확장ID2 ...]"
    echo "  Chrome: chrome://extensions / Edge: edge://extensions 에서 확인"
    exit 1
fi

# allowed_origins JSON 배열 구성
ORIGINS=""
for ID in "$@"; do
    if [ -n "$ORIGINS" ]; then
        ORIGINS="$ORIGINS, "
    fi
    ORIGINS="$ORIGINS\"chrome-extension://$ID/\""
done

# ---- 경로 설정 (로컬 기계 기준) ----
OPENFHE_INC=/home/user/local/include/openfhe
OPENFHE_LIB=/home/user/local/lib
INSTALL_DIR="$HOME/.local/share/lookup-daemon"

# ---- 1) 데몬 빌드 ----
g++ -O2 -std=c++17 lookup_daemon.cpp -o lookup_daemon \
    -I"$OPENFHE_INC" \
    -I"$OPENFHE_INC/core" \
    -I"$OPENFHE_INC/pke" \
    -I"$OPENFHE_INC/binfhe" \
    -I"$OPENFHE_INC/third-party/include" \
    -L"$OPENFHE_LIB" \
    -lOPENFHEpke \
    -lOPENFHEbinfhe \
    -lOPENFHEcore \
    -fopenmp \
    -Wl,-rpath,"$OPENFHE_LIB" \
    -pthread
echo "빌드 완료: lookup_daemon"

# ---- 2) 설치 디렉터리에 배치 + 서버 주소 래퍼 생성 ----
mkdir -p "$INSTALL_DIR"
cp lookup_daemon "$INSTALL_DIR/"

# 래퍼: 서버 주소를 여기서 지정 (VPS 로 옮기면 이 한 줄만 변경)
cat > "$INSTALL_DIR/run_daemon.sh" << WRAPPER
#!/usr/bin/env bash
export LOOKUP_SERVER="127.0.0.1:8080"
exec "$INSTALL_DIR/lookup_daemon"
WRAPPER
chmod +x "$INSTALL_DIR/run_daemon.sh"

# ---- 3) 네이티브 메시징 호스트 매니페스트 등록 ----
# Chromium 계열별 등록 경로 (설치된 브라우저에만 쓰임)
# Edge 도 chrome-extension:// 스킴과 동일 매니페스트 형식을 사용한다
for DIR in "$HOME/.config/google-chrome/NativeMessagingHosts" \
           "$HOME/.config/chromium/NativeMessagingHosts" \
           "$HOME/.config/microsoft-edge/NativeMessagingHosts"; do
    # 브라우저 설정 디렉터리가 있는 경우에만
    PARENT=$(dirname "$DIR")
    if [ -d "$PARENT" ]; then
        mkdir -p "$DIR"
        cat > "$DIR/com.hexlab.lookup.json" << MANIFEST
{
  "name": "com.hexlab.lookup",
  "description": "Private phishing lookup daemon (HE)",
  "path": "$INSTALL_DIR/run_daemon.sh",
  "type": "stdio",
  "allowed_origins": [ $ORIGINS ]
}
MANIFEST
        echo "등록: $DIR/com.hexlab.lookup.json"
    fi
done

echo ""
echo "완료. Chrome 을 완전히 재시작한 뒤:"
echo "  1) 서버 실행 확인: ./lookup_server --values feed_hv.csv --port 8080"
echo "  2) 브라우저에서 아무 사이트 방문 -> 정상"
echo "  3) 피드에 있는 도메인 방문 시도 -> 경고 페이지"
echo "데몬 로그 확인: Chrome 을 터미널에서 실행하면 stderr 에 [daemon] 로그가 보임"