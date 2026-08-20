#!/usr/bin/env bash
# ============================================================================
# vps_setup.sh (재작성판) — VPS 초기 구축: 도구 -> (조건부) 스왑 -> OpenFHE 1.5.1
#                            -> 환경 변수 -> (소스 있으면) 서버 빌드
#
# 대상: Ubuntu 24.04 (aarch64 / x86_64 겸용 — 빌드 절차는 아키텍처 무관)
# 실행: 일반 사용자로 (sudo 는 스크립트 내부에서 필요한 곳만 사용)
#   chmod +x vps_setup.sh && ./vps_setup.sh
#
# 재실행 안전: 각 단계는 이미 완료돼 있으면 건너뛴다.
# ============================================================================

# 오류 발생 시 즉시 중단
set -e

# OpenFHE 설치 목적지 (run_measure.sh / run_p3.sh 와 동일 규약)
PREFIX="$HOME/local"
# 사용할 OpenFHE 버전 (직렬화 호환 조건 — 반드시 1.5.1 유지)
OPENFHE_TAG="v1.5.1"

echo "== 0. 시스템 정보 =="
# 아키텍처와 메모리를 출력한다 (기록용)
uname -m
free -h | head -2

echo "== 1. 빌드 도구 설치 =="
# 패키지 목록 갱신
sudo apt-get update -y
# 컴파일러/도구 설치 (이미 있으면 apt 가 알아서 건너뜀)
sudo apt-get install -y build-essential cmake git g++ python3 autoconf libtool

echo "== 2. 스왑 (램 8GB 미만일 때만) =="
# 총 메모리(kB)를 읽는다
MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
# 스왑이 이미 있는지 본다
SWAP_KB=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
if [ "$MEM_KB" -lt 8000000 ] && [ "$SWAP_KB" -lt 1000000 ]; then
    # 소형 인스턴스: OpenFHE 컴파일이 메모리를 크게 먹으므로 4GB 스왑을 만든다
    echo "램 8GB 미만 + 스왑 없음 -> 4GB 스왑 생성"
    sudo fallocate -l 4G /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    # 재부팅 후에도 유지되도록 fstab 에 등록한다 (중복 등록 방지)
    grep -q "/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab
else
    # A1.Flex 24GB 같은 대형 인스턴스는 스왑이 불필요하다
    echo "램 충분 또는 스왑 존재 -> 스왑 단계 건너뜀"
fi

echo "== 3. OpenFHE $OPENFHE_TAG 빌드 -> $PREFIX =="
if [ -f "$PREFIX/lib/libOPENFHEcore.so" ]; then
    # 이미 설치돼 있으면 건너뛴다
    echo "설치본 존재 -> 빌드 건너뜀"
else
    # 소스를 받는다 (해당 태그만 얕게)
    cd "$HOME"
    if [ ! -d openfhe-development ]; then
        git clone --branch "$OPENFHE_TAG" --depth 1 https://github.com/openfheorg/openfhe-development.git
    fi
    cd openfhe-development
    # 빌드 디렉터리를 만든다
    mkdir -p build
    cd build
    # 구성: 시험/예제/벤치마크 제외 (빌드 시간 절약), 설치 위치 지정
    cmake .. \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_UNITTESTS=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_BENCHMARKS=OFF
    # 컴파일: 코어 수만큼 병렬 (aarch64 도 동일 절차)
    make -j"$(nproc)"
    # 설치
    make install
fi

echo "== 4. 라이브러리 경로 등록 =="
# rpath 만으로 부족한 경우가 있어 LD_LIBRARY_PATH 를 .bashrc 에 넣는다 (중복 방지)
LINE="export LD_LIBRARY_PATH=$PREFIX/lib:\$LD_LIBRARY_PATH"
grep -qF "$LINE" "$HOME/.bashrc" || echo "$LINE" >> "$HOME/.bashrc"
# 현재 셸에도 즉시 적용한다
export LD_LIBRARY_PATH="$PREFIX/lib:$LD_LIBRARY_PATH"

echo "== 5. 서버 빌드 (소스가 있으면) =="
# 배포 파일을 두기로 한 위치
WORKDIR="$HOME/lookup"
if [ -f "$WORKDIR/lookup_server.cpp" ] && [ -f "$WORKDIR/lookup_common.h" ]; then
    cd "$WORKDIR"
    # run_p3.sh / run_measure.sh 와 동일한 플래그 구성
    g++ -O2 -std=c++17 lookup_server.cpp -o lookup_server \
        -I"$PREFIX/include/openfhe" \
        -I"$PREFIX/include/openfhe/core" \
        -I"$PREFIX/include/openfhe/pke" \
        -I"$PREFIX/include/openfhe/binfhe" \
        -I"$PREFIX/include/openfhe/third-party/include" \
        -L"$PREFIX/lib" \
        -lOPENFHEpke -lOPENFHEbinfhe -lOPENFHEcore \
        -fopenmp -Wl,-rpath,"$PREFIX/lib" -pthread
    echo "빌드 완료: $WORKDIR/lookup_server"
else
    # 소스를 아직 안 올렸으면 안내만 하고 정상 종료한다
    echo "$WORKDIR 에 서버 소스 없음 -> scp 로 올린 뒤 이 스크립트를 다시 실행하면 빌드만 수행"
fi

echo "== 완료 =="
echo "다음: DEPLOY_DAY.md 의 순서를 따를 것"
