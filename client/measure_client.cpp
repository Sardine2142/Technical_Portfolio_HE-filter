// ============================================================================
// measure_client.cpp — 원격/로컬 측정 클라이언트 (rev.1)
//
// 목적: lookup_daemon 과 "완전히 같은 경로"(lookup_common.h + 동일 HTTP 형식)로
//       질의 1회를 단계 분해 계측한다. 데몬/서버는 무수정.
//
// 사용법:
//   ./measure_client <host:port> [반복수=30] [--listed <목록에 있는 도메인>]
//   예) ./measure_client 127.0.0.1:8080 30 --listed $(head -1 feed_hv.csv | cut -d, -f1)
//
// 측정 단계 (반복마다):
//   keygen   : 요청별 새 키 생성
//   encrypt  : 암호화 + 직렬화 (EncryptQuery + ToBytes)
//   http     : 연결 + 업로드 + 서버 평가 + 다운로드 (왕복 전체)
//   deser    : 응답 역직렬화 (FromBytes)
//   decrypt  : 복호화 + 판정 (DecryptAndCheck)
//
// 겸사 확인:
//   - 무작위 도메인(존재 확률 0) 질의는 전부 listed=false 여야 함 (거짓 양성 감시)
//   - --listed 도메인 질의는 listed=true 여야 함 (거짓 음성 감시)
//
// 출력:
//   - 콘솔: 단계별 min / 중앙값 / 평균 / p95 표 + 크기 + 정확성 결과
//   - measure_log.csv 에 한 줄 추가 (문서의 로컬/원격 비교표 원천)
// ============================================================================

#include "lookup_common.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <random>
#include <string>
#include <vector>

// POSIX 소켓
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// 최소 HTTP 클라이언트 (lookup_daemon.cpp 와 동일 로직 — 같은 경로 보장)
// ---------------------------------------------------------------------------

// host:port 로 TCP 연결 (실패 시 -1)
static int Connect(const std::string& host, const std::string& port)
{
    // 주소 해석
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0)
    {
        return -1;
    }
    // 첫 후보로 연결
    int fd = -1;
    for (addrinfo* p = res; p != nullptr; p = p->ai_next)
    {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0)
        {
            continue;
        }
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0)
        {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

// 요청 전송 후 응답 본문 수신 (데몬과 동일)
static bool HttpRequest(const std::string& host, const std::string& port,
                        const std::string& request, std::string& outBody)
{
    // 연결
    int fd = Connect(host, port);
    if (fd < 0)
    {
        return false;
    }
    // 요청 전송
    size_t sent = 0;
    while (sent < request.size())
    {
        ssize_t n = send(fd, request.data() + sent, request.size() - sent, 0);
        if (n <= 0)
        {
            close(fd);
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    // 헤더 끝까지 수신
    std::string buf;
    char tmp[65536];
    while (buf.find("\r\n\r\n") == std::string::npos)
    {
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0)
        {
            close(fd);
            return false;
        }
        buf.append(tmp, static_cast<size_t>(n));
    }
    // 헤더/본문 분리 + Content-Length
    size_t hEnd = buf.find("\r\n\r\n");
    std::string headers = buf.substr(0, hEnd + 4);
    outBody = buf.substr(hEnd + 4);
    size_t need = 0;
    {
        std::string key = "Content-Length:";
        size_t p = headers.find(key);
        if (p != std::string::npos)
        {
            need = static_cast<size_t>(std::stoul(headers.substr(p + key.size())));
        }
    }
    // 본문 나머지 수신
    while (outBody.size() < need)
    {
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0)
        {
            close(fd);
            return false;
        }
        outBody.append(tmp, static_cast<size_t>(n));
    }
    close(fd);
    // 상태 200 확인
    return headers.rfind("HTTP/1.1 200", 0) == 0;
}

// ---------------------------------------------------------------------------
// 통계 도우미
// ---------------------------------------------------------------------------

// 밀리초 벡터에서 (min, 중앙값, 평균, p95) 를 계산한다
struct Stats
{
    double minv;    // 최솟값
    double med;     // 중앙값
    double mean;    // 평균
    double p95;     // 95백분위
};

static Stats Summarize(std::vector<double> v)
{
    // 정렬한다 (중앙값/백분위 계산용)
    std::sort(v.begin(), v.end());
    // 결과 구조체
    Stats s{};
    // 표본 수
    const size_t n = v.size();
    // 최솟값
    s.minv = v.front();
    // 중앙값: 홀수면 가운데, 짝수면 가운데 두 값의 평균
    if (n % 2 == 1)
    {
        s.med = v[n / 2];
    }
    else
    {
        s.med = (v[n / 2 - 1] + v[n / 2]) / 2.0;
    }
    // 평균
    double sum = 0.0;
    for (double x : v)
    {
        sum += x;
    }
    s.mean = sum / static_cast<double>(n);
    // p95: ceil(0.95 * n) 번째 (1-기반) 값
    size_t idx = static_cast<size_t>(std::max<long>(0, static_cast<long>(std::ceil(0.95 * n)) - 1));
    s.p95 = v[idx];
    return s;
}

// steady_clock 두 시점의 차이를 밀리초(double)로 돌려준다
static double MsBetween(std::chrono::steady_clock::time_point a,
                        std::chrono::steady_clock::time_point b)
{
    return std::chrono::duration<double, std::milli>(b - a).count();
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char** argv)
{
    // ---- 인자 해석 ----
    if (argc < 2)
    {
        std::cerr << "사용법: " << argv[0] << " <host:port> [반복수=30] [--listed <도메인>]\n";
        return 1;
    }
    // 서버 주소 분해
    std::string server = argv[1];
    size_t colon = server.rfind(':');
    if (colon == std::string::npos)
    {
        std::cerr << "주소는 host:port 형식이어야 함\n";
        return 1;
    }
    std::string host = server.substr(0, colon);
    std::string port = server.substr(colon + 1);
    // 반복 수 (기본 30)
    int iterations = 30;
    // 목록에 있는 도메인 (양성 확인용, 선택)
    std::string listedDomain = "";
    // 나머지 인자를 순회한다
    for (int i = 2; i < argc; i++)
    {
        std::string arg = argv[i];
        if (arg == "--listed" && i + 1 < argc)
        {
            listedDomain = argv[++i];
        }
        else
        {
            iterations = std::atoi(arg.c_str());
            if (iterations <= 0)
            {
                std::cerr << "반복수는 양의 정수여야 함\n";
                return 1;
            }
        }
    }

    std::cerr << "[measure] 서버: " << server << ", 반복: " << iterations
              << (listedDomain.empty() ? "" : (", 양성 확인: " + listedDomain)) << "\n";

    // ---- 컨텍스트 + 워밍업 (데몬과 동일 — 첫 회 지연이 통계를 오염시키지 않게) ----
    CryptoContext<DCRTPoly> cc = MakeContext();
    {
        KeyPair<DCRTPoly> warm = cc->KeyGen();
        Ciphertext<DCRTPoly> w = EncryptQuery(cc, warm.publicKey, 1);
        (void)w;
    }
    std::cerr << "[measure] 워밍업 완료\n";

    // ---- 무작위 도메인 생성기 (존재 확률 0 인 형태) ----
    std::mt19937_64 rng{ std::random_device{}() };
    auto RandomDomain = [&rng]() {
        // 16자리 16진수 난수 문자열을 만든다
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%016llx",
                      static_cast<unsigned long long>(rng()));
        // 측정 전용 형태의 가짜 도메인을 만든다
        return std::string("measure-") + buf + ".invalid-example.net";
    };

    // ---- 단계별 시간 저장소 ----
    std::vector<double> tKeygen;    // 키 생성
    std::vector<double> tEncrypt;   // 암호화 + 직렬화
    std::vector<double> tHttp;      // HTTP 왕복 전체
    std::vector<double> tDeser;     // 역직렬화
    std::vector<double> tDecrypt;   // 복호화 + 판정
    std::vector<double> tTotal;     // 합계
    // 크기 (모든 반복에서 동일해야 정상 — 마지막 값만 보관)
    size_t queryBytes = 0;
    size_t replyBytes = 0;
    // 정확성 집계
    int negTotal = 0;      // 음성(무작위) 질의 수
    int negWrong = 0;      // 그중 listed=true 로 나온 수 (거짓 양성)
    bool posOk = true;     // 양성 질의가 listed=true 로 나왔는가 (--listed 없으면 true 유지)
    // 실패(서버 불가 등) 집계
    int failures = 0;

    // ---- 질의 1회를 수행하고 각 단계 시간을 기록하는 함수 ----
    auto RunOne = [&](const std::string& domain, bool expectListed) -> bool {
        // (버킷, 값) 유도 — 해시라 비용 무시 수준이므로 계측 항목에서 제외
        DomainKey dk = DeriveKey(domain);

        // 단계 1: 요청별 새 키
        auto t0 = std::chrono::steady_clock::now();
        KeyPair<DCRTPoly> keys = cc->KeyGen();
        auto t1 = std::chrono::steady_clock::now();

        // 단계 2: 암호화 + 직렬화
        Ciphertext<DCRTPoly> query = EncryptQuery(cc, keys.publicKey, dk.value);
        std::string payload = ToBytes(query);
        auto t2 = std::chrono::steady_clock::now();

        // 단계 3: HTTP 왕복 (요청 조립 문자열 연결 포함 — 실사용 경로와 동일)
        std::string req = "POST /query HTTP/1.1\r\nHost: " + host + "\r\n"
                          "X-Bucket: " + std::to_string(dk.bucket) + "\r\n"
                          "Content-Type: application/octet-stream\r\n"
                          "Content-Length: " + std::to_string(payload.size()) + "\r\n"
                          "Connection: close\r\n\r\n" + payload;
        std::string replyRaw;
        if (!HttpRequest(host, port, req, replyRaw))
        {
            // 왕복 실패는 통계에 넣지 않고 실패로 센다
            failures++;
            return false;
        }
        auto t3 = std::chrono::steady_clock::now();

        // 단계 4: 역직렬화
        Ciphertext<DCRTPoly> reply;
        FromBytes(reply, replyRaw);
        auto t4 = std::chrono::steady_clock::now();

        // 단계 5: 복호화 + 판정
        bool listed = DecryptAndCheck(cc, keys.secretKey, { reply });
        auto t5 = std::chrono::steady_clock::now();

        // 시간 기록
        tKeygen.push_back(MsBetween(t0, t1));
        tEncrypt.push_back(MsBetween(t1, t2));
        tHttp.push_back(MsBetween(t2, t3));
        tDeser.push_back(MsBetween(t3, t4));
        tDecrypt.push_back(MsBetween(t4, t5));
        tTotal.push_back(MsBetween(t0, t5));
        // 크기 기록
        queryBytes = payload.size();
        replyBytes = replyRaw.size();

        // 정확성 기록
        if (expectListed)
        {
            // 양성 질의: listed=true 여야 한다
            if (!listed)
            {
                posOk = false;
            }
        }
        else
        {
            // 음성 질의: listed=false 여야 한다
            negTotal++;
            if (listed)
            {
                negWrong++;
            }
        }
        return true;
    };

    // ---- 본 측정: 무작위(음성) 도메인 iterations 회 ----
    for (int i = 0; i < iterations; i++)
    {
        RunOne(RandomDomain(), false);
        // 진행 표시 (5회마다)
        if ((i + 1) % 5 == 0)
        {
            std::cerr << "[measure] " << (i + 1) << "/" << iterations << "\n";
        }
    }

    // ---- 양성 확인 1회 (--listed 지정 시; 시간 통계에도 포함) ----
    if (!listedDomain.empty())
    {
        RunOne(listedDomain, true);
    }

    // 표본이 없으면 실패로 종료한다
    if (tTotal.empty())
    {
        std::cerr << "[measure] 유효 표본 없음 (실패 " << failures << "회) — 서버 상태 확인 필요\n";
        return 1;
    }

    // ---- 통계 계산 ----
    Stats sKeygen  = Summarize(tKeygen);
    Stats sEncrypt = Summarize(tEncrypt);
    Stats sHttp    = Summarize(tHttp);
    Stats sDeser   = Summarize(tDeser);
    Stats sDecrypt = Summarize(tDecrypt);
    Stats sTotal   = Summarize(tTotal);

    // ---- 콘솔 표 출력 ----
    std::printf("\n서버 %s, 표본 %zu (실패 %d)\n", server.c_str(), tTotal.size(), failures);
    std::printf("%-10s %10s %10s %10s %10s\n", "단계", "min", "중앙값", "평균", "p95");
    std::printf("%-10s %9.1f %9.1f %9.1f %9.1f\n", "keygen",  sKeygen.minv,  sKeygen.med,  sKeygen.mean,  sKeygen.p95);
    std::printf("%-10s %9.1f %9.1f %9.1f %9.1f\n", "encrypt", sEncrypt.minv, sEncrypt.med, sEncrypt.mean, sEncrypt.p95);
    std::printf("%-10s %9.1f %9.1f %9.1f %9.1f\n", "http",    sHttp.minv,    sHttp.med,    sHttp.mean,    sHttp.p95);
    std::printf("%-10s %9.1f %9.1f %9.1f %9.1f\n", "deser",   sDeser.minv,   sDeser.med,   sDeser.mean,   sDeser.p95);
    std::printf("%-10s %9.1f %9.1f %9.1f %9.1f\n", "decrypt", sDecrypt.minv, sDecrypt.med, sDecrypt.mean, sDecrypt.p95);
    std::printf("%-10s %9.1f %9.1f %9.1f %9.1f\n", "total",   sTotal.minv,   sTotal.med,   sTotal.mean,   sTotal.p95);
    std::printf("크기: 질의 %zu 바이트, 응답 %zu 바이트\n", queryBytes, replyBytes);
    std::printf("정확성: 음성 %d/%d 정상", negTotal - negWrong, negTotal);
    if (!listedDomain.empty())
    {
        std::printf(", 양성 %s", posOk ? "정상" : "실패(거짓 음성!)");
    }
    std::printf("\n");

    // ---- CSV 로그 추가 (없으면 헤더부터 만든다) ----
    {
        // 파일 존재 여부를 확인한다
        FILE* probe = std::fopen("measure_log.csv", "r");
        bool exists = (probe != nullptr);
        if (probe != nullptr)
        {
            std::fclose(probe);
        }
        // 추가 모드로 연다
        FILE* f = std::fopen("measure_log.csv", "a");
        if (f != nullptr)
        {
            // 첫 생성이면 헤더를 쓴다
            if (!exists)
            {
                std::fprintf(f, "date,server,n,failures,"
                                "keygen_med,encrypt_med,http_med,deser_med,decrypt_med,"
                                "total_med,total_p95,query_bytes,reply_bytes,"
                                "neg_ok,neg_total,pos_ok\n");
            }
            // 날짜 문자열을 만든다
            char datebuf[32];
            std::time_t now = std::time(nullptr);
            std::strftime(datebuf, sizeof(datebuf), "%Y-%m-%d %H:%M", std::localtime(&now));
            // 한 줄을 기록한다
            std::fprintf(f, "%s,%s,%zu,%d,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%zu,%zu,%d,%d,%s\n",
                         datebuf, server.c_str(), tTotal.size(), failures,
                         sKeygen.med, sEncrypt.med, sHttp.med, sDeser.med, sDecrypt.med,
                         sTotal.med, sTotal.p95, queryBytes, replyBytes,
                         negTotal - negWrong, negTotal,
                         listedDomain.empty() ? "n/a" : (posOk ? "ok" : "FAIL"));
            std::fclose(f);
            std::printf("measure_log.csv 에 기록 완료\n");
        }
    }

    // 정확성 실패가 있으면 0 이 아닌 코드로 종료한다 (스크립트 연동용)
    if (negWrong > 0 || !posOk)
    {
        return 2;
    }
    return 0;
}
