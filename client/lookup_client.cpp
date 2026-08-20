// ============================================================================
// lookup_client.cpp — rev.6 클라이언트 CLI
//
// 하는 일:
//   - GET /params 로 서버 파라미터 확인 (로컬 상수와 불일치하면 중단)
//   - 도메인 질의: 정규화 -> 해시 -> (버킷, 값) -> 요청별 새 키 생성 -> 암호화
//                  -> POST /query (X-Bucket 헤더) -> 응답 복호화 -> 판정
//   - 대화 모드(--loop): 한 줄에 도메인 하나씩 입력, 세션 캐시로 재질의 생략
//   - 매 질의의 단계별 시간과 업로드/다운로드 크기 표시
//
// 사용법:
//   ./lookup_client --server 127.0.0.1:8080 example.com phishing-site.tld
//   ./lookup_client --server <VPS주소>:8080 --loop
// ============================================================================

#include "lookup_common.h"

#include <chrono>
#include <iostream>
#include <map>

// POSIX 소켓
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// 최소 HTTP 클라이언트
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

// 요청 전송 후 응답 본문 수신 (Content-Length 기반)
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
    // 응답 수신: 헤더 끝까지
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
    // 헤더/본문 분리 + Content-Length 파싱
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
    // 상태 코드 200 확인
    return headers.rfind("HTTP/1.1 200", 0) == 0;
}

// ---------------------------------------------------------------------------
// /params 검증
// ---------------------------------------------------------------------------

// "key=value;..." 텍스트에서 정수 값 하나 추출
static int64_t ParamValue(const std::string& text, const std::string& key)
{
    size_t p = text.find(key + "=");
    if (p == std::string::npos)
    {
        return -1;
    }
    return std::stoll(text.substr(p + key.size() + 1));
}

// 서버 공지 파라미터가 로컬 상수와 일치하는지 확인
static bool CheckParams(const std::string& host, const std::string& port)
{
    // GET /params
    std::string req = "GET /params HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
    std::string body;
    if (!HttpRequest(host, port, req, body))
    {
        std::cerr << "/params 요청 실패\n";
        return false;
    }
    // 필드별 비교
    bool ok = true;
    ok = ok && (ParamValue(body, "t") == kPlainModulus);
    ok = ok && (ParamValue(body, "ring") == kRingDim);
    ok = ok && (ParamValue(body, "depth") == kDepth);
    ok = ok && (ParamValue(body, "group") == kGroup);
    ok = ok && (ParamValue(body, "shards") == kShards);
    ok = ok && (ParamValue(body, "k") == kPrefixBits);
    if (!ok)
    {
        std::cerr << "서버 파라미터가 클라이언트와 불일치:\n" << body;
        return false;
    }
    // 리스트 정보 표시
    std::cout << "서버 확인: 리스트 " << ParamValue(body, "count")
              << "건, 버전 " << ParamValue(body, "version") << "\n";
    return true;
}

// ---------------------------------------------------------------------------
// 질의 1회
// ---------------------------------------------------------------------------

static bool QueryDomain(const CryptoContext<DCRTPoly>& cc,
                        const std::string& host, const std::string& port,
                        const std::string& domainRaw, bool& outListed)
{
    using clock = std::chrono::steady_clock;

    // 정규화 + 키 유도
    std::string domain = NormalizeHostname(domainRaw);
    if (domain.empty() || domain.find('.') == std::string::npos)
    {
        std::cerr << "  올바른 도메인이 아님: " << domainRaw << "\n";
        return false;
    }
    DomainKey dk = DeriveKey(domain);

    // 요청별 새 키 생성 (연결 불가능성 설계)
    auto t0 = clock::now();
    KeyPair<DCRTPoly> keys = cc->KeyGen();
    auto t1 = clock::now();

    // 질의 암호화
    Ciphertext<DCRTPoly> query = EncryptQuery(cc, keys.publicKey, dk.value);
    auto t2 = clock::now();

    // 직렬화 + 전송
    std::string payload = ToBytes(query);
    std::string req = "POST /query HTTP/1.1\r\nHost: " + host + "\r\n"
                      "X-Bucket: " + std::to_string(dk.bucket) + "\r\n"
                      "Content-Type: application/octet-stream\r\n"
                      "Content-Length: " + std::to_string(payload.size()) + "\r\n"
                      "Connection: close\r\n\r\n" + payload;
    std::string replyBytes;
    if (!HttpRequest(host, port, req, replyBytes))
    {
        std::cerr << "  질의 전송 실패\n";
        return false;
    }
    auto t3 = clock::now();

    // 응답 역직렬화 + 복호화 판정
    Ciphertext<DCRTPoly> reply;
    FromBytes(reply, replyBytes);
    outListed = DecryptAndCheck(cc, keys.secretKey, { reply });
    auto t4 = clock::now();

    // 단계별 시간 계산
    auto ms = [](clock::time_point a, clock::time_point b)
    {
        return std::chrono::duration<double, std::milli>(b - a).count();
    };

    // 결과 출력
    std::cout << "  " << domain << " -> "
              << (outListed ? "[차단 리스트에 있음]" : "[리스트에 없음]") << "\n";
    std::cout << "    버킷 " << dk.bucket
              << " | 키 " << std::fixed << std::setprecision(1) << ms(t0, t1) << "ms"
              << " | 암호화 " << ms(t1, t2) << "ms"
              << " | 왕복 " << ms(t2, t3) << "ms"
              << " | 복호화 " << ms(t3, t4) << "ms"
              << " | 업로드 " << (payload.size() / 1024) << "KB"
              << " | 다운로드 " << (replyBytes.size() / 1024) << "KB\n";
    return true;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char** argv)
{
    // ---- 인자 ----
    std::string server = "127.0.0.1:8080";
    bool loopMode = false;
    std::vector<std::string> domains;
    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--server" && i + 1 < argc)
        {
            server = argv[++i];
        }
        else if (a == "--loop")
        {
            loopMode = true;
        }
        else
        {
            domains.push_back(a);
        }
    }
    // host:port 분리
    size_t colon = server.rfind(':');
    if (colon == std::string::npos)
    {
        std::cerr << "--server 형식은 host:port\n";
        return 1;
    }
    std::string host = server.substr(0, colon);
    std::string port = server.substr(colon + 1);

    // ---- 컨텍스트 (서버와 동일 파라미터로 생성) ----
    CryptoContext<DCRTPoly> cc = MakeContext();

    // ---- 서버 파라미터 검증 ----
    if (!CheckParams(host, port))
    {
        return 1;
    }

    // ---- 세션 캐시: 이번 실행에서 확인한 도메인의 판정 저장 ----
    std::map<std::string, bool> cache;

    // 질의 실행 헬퍼 (캐시 우선)
    auto runOne = [&](const std::string& raw)
    {
        // 정규화된 형태로 캐시 조회
        std::string norm = NormalizeHostname(raw);
        auto it = cache.find(norm);
        if (it != cache.end())
        {
            std::cout << "  " << norm << " -> "
                      << (it->second ? "[차단 리스트에 있음]" : "[리스트에 없음]")
                      << " (캐시)\n";
            return;
        }
        // 실제 질의
        bool listed = false;
        if (QueryDomain(cc, host, port, raw, listed))
        {
            cache[norm] = listed;
        }
    };

    // ---- 인자 도메인 처리 ----
    for (const auto& d : domains)
    {
        runOne(d);
    }

    // ---- 대화 모드 ----
    if (loopMode)
    {
        std::cout << "대화 모드: 한 줄에 도메인 하나 (빈 줄 입력 시 종료)\n";
        std::string line;
        while (std::getline(std::cin, line))
        {
            if (line.empty())
            {
                break;
            }
            runOne(line);
        }
    }

    return 0;
}
