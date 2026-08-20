# ============================================================================
# HE-filter Makefile — 서버 / 데몬 / 조회 클라이언트 / 측정 클라이언트 빌드
#
# 전제: OpenFHE 1.5.1 이 $(OPENFHE_HOME) 에 설치되어 있음 (기본 $HOME/local).
#       다른 경로에 설치했다면:  OPENFHE_HOME=/다른/경로 make
# ============================================================================

# OpenFHE 설치 경로 (환경 변수로 재정의 가능)
OPENFHE_HOME ?= $(HOME)/local
OPENFHE_INC   = $(OPENFHE_HOME)/include/openfhe
OPENFHE_LIB   = $(OPENFHE_HOME)/lib

# 공통 컴파일 플래그 (기존 빌드 스크립트와 동일 구성 + 공유 헤더 경로)
CXX      = g++
CXXFLAGS = -O2 -std=c++17 \
           -Iinclude \
           -I$(OPENFHE_INC) \
           -I$(OPENFHE_INC)/core \
           -I$(OPENFHE_INC)/pke \
           -I$(OPENFHE_INC)/binfhe \
           -I$(OPENFHE_INC)/third-party/include
LDFLAGS  = -L$(OPENFHE_LIB) \
           -lOPENFHEpke -lOPENFHEbinfhe -lOPENFHEcore \
           -fopenmp -Wl,-rpath,$(OPENFHE_LIB) -pthread

# 기본 목표: 네 바이너리 전부
all: lookup_server lookup_daemon lookup_client measure_client

# 조회 서버
lookup_server: server/lookup_server.cpp include/lookup_common.h
	$(CXX) $(CXXFLAGS) server/lookup_server.cpp -o $@ $(LDFLAGS)

# 로컬 데몬 (브라우저 확장과 네이티브 메시징으로 연결)
lookup_daemon: client/lookup_daemon.cpp include/lookup_common.h
	$(CXX) $(CXXFLAGS) client/lookup_daemon.cpp -o $@ $(LDFLAGS)

# 명령행 조회 클라이언트
lookup_client: client/lookup_client.cpp include/lookup_common.h
	$(CXX) $(CXXFLAGS) client/lookup_client.cpp -o $@ $(LDFLAGS)

# 측정 클라이언트 (단계 분해 계측)
measure_client: client/measure_client.cpp include/lookup_common.h
	$(CXX) $(CXXFLAGS) client/measure_client.cpp -o $@ $(LDFLAGS)

# 빌드 산출물 제거
clean:
	rm -f lookup_server lookup_daemon lookup_client measure_client

.PHONY: all clean
