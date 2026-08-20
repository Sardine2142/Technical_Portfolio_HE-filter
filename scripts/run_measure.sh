#!/usr/bin/env bash
# ============================================================================
# run_measure.sh — 측정 클라이언트 빌드 스크립트
#
# run_p3.sh 의 빌드 플래그를 그대로 쓰되, OpenFHE 경로만 $HOME/local 기준으로 일반화
# (WSL 의 /home/dhlee/local, VPS 의 /home/ubuntu/local 어느 쪽에서도 동작).
# 다른 위치에 설치했다면 환경 변수로 재정의:
#   OPENFHE_HOME=/다른/경로 ./run_measure.sh
#
# 빌드 후 실행 (서버가 떠 있는 상태에서):
#   ./measure_client 127.0.0.1:8080 30 --listed $(head -1 feed_hv.csv | cut -d, -f1)
# VPS 측정 시에는 주소만 교체:
#   ./measure_client <VPS공인IP>:8080 30 --listed $(head -1 feed_hv.csv | cut -d, -f1)
# ============================================================================

# 오류 발생 시 즉시 중단
set -e

# ---- 경로 설정 (기본: $HOME/local, 환경 변수로 재정의 가능) ----
OPENFHE_HOME="${OPENFHE_HOME:-$HOME/local}"
OPENFHE_INC="$OPENFHE_HOME/include/openfhe"
OPENFHE_LIB="$OPENFHE_HOME/lib"

# 설치본이 있는지 먼저 확인한다
if [ ! -d "$OPENFHE_INC" ]; then
    echo "OpenFHE 헤더를 찾지 못함: $OPENFHE_INC"
    echo "OPENFHE_HOME 환경 변수로 설치 경로를 지정할 것"
    exit 1
fi

# ---- 공통 컴파일 플래그 (run_p3.sh 와 동일) ----
FLAGS=(
    -O2 -std=c++17
    -I"$OPENFHE_INC"
    -I"$OPENFHE_INC/core"
    -I"$OPENFHE_INC/pke"
    -I"$OPENFHE_INC/binfhe"
    -I"$OPENFHE_INC/third-party/include"
    -L"$OPENFHE_LIB"
    -lOPENFHEpke
    -lOPENFHEbinfhe
    -lOPENFHEcore
    -fopenmp
    -Wl,-rpath,"$OPENFHE_LIB"
    -pthread
)

# ---- 측정 클라이언트 빌드 ----
g++ measure_client.cpp -o measure_client "${FLAGS[@]}"
echo "빌드 완료: measure_client"

echo "다음: ./measure_client 127.0.0.1:8080 30 --listed \$(head -1 feed_hv.csv | cut -d, -f1)"
