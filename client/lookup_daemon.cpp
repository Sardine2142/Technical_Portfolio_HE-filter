// ============================================================================
// lookup_daemon.cpp — rev.7 네이티브 메시징 데몬
//
// Chrome 확장이 connectNative 로 이 프로세스를 띄워 stdio 로 통신한다.
// 메시지 프레이밍(네이티브 메시징 규격): [4바이트 길이(호스트 바이트 순서)][JSON]
//
// 수신: {"id":N,"domain":"example.com"}
// 응답: {"id":N,"domain":"...","listed":true|false,"cached":true|false,"ms":123}
//       오류 시: {"id":N,"error":"..."}  (확장은 오류를 "차단 안 함" 으로 처리 — fail-open)
//
// 동작:
//   - 기동 시 컨텍스트 생성 + 워밍업 1회 (첫 질의 지연 제거)
//   - 서버 주소: 환경 변수 LOOKUP_SERVER, 없으면 127.0.0.1:8080
//   - 세션 캐시: 프로세스 수명 동안 도메인별 판정 저장
//   - 표준 출력은 프로토콜 전용 — 로그는 반드시 stderr 로
// ============================================================================

#include "lookup_common.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>

// POSIX 소켓
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// 최소 HTTP 클라이언트 (lookup_client 와 동일 로직)
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

// 요청 전송 후 응답 본문 수신
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
// 네이티브 메시징 프레이밍
// ---------------------------------------------------------------------------

// stdin 에서 메시지 하나 수신 (EOF 면 false)
static bool ReadMessage(std::string& out)
{
    // 4바이트 길이 (호스트 바이트 순서 — Chrome 규격)
    uint32_t len = 0;
    if (fread(&len, 4, 1, stdin) != 1)
    {
        return false;
    }
    // 비정상 길이 방어
    if (len == 0 || len > (1u << 20))
    {
        return false;
    }
    // 본문 수신
    out.resize(len);
    if (fread(&out[0], 1, len, stdin) != len)
    {
        return false;
    }
    return true;
}

// stdout 으로 메시지 하나 송신
static void WriteMessage(const std::string& msg)
{
    // 길이 + 본문 + 즉시 플러시 (버퍼링되면 확장이 응답을 못 받음)
    uint32_t len = static_cast<uint32_t>(msg.size());
    fwrite(&len, 4, 1, stdout);
    fwrite(msg.data(), 1, msg.size(), stdout);
    fflush(stdout);
}

// ---------------------------------------------------------------------------
// 초소형 JSON 추출 (이 프로토콜의 두 필드 전용 — 범용 파서 아님)
// ---------------------------------------------------------------------------

// "key":"value" 형태의 문자열 값 추출
static bool JsonString(const std::string& j, const std::string& key, std::string& out)
{
    // 키 위치
    size_t p = j.find("\"" + key + "\"");
    if (p == std::string::npos)
    {
        return false;
    }
    // 값 여는 따옴표
    size_t q1 = j.find('"', j.find(':', p) + 1);
    if (q1 == std::string::npos)
    {
        return false;
    }
    // 값 닫는 따옴표
    size_t q2 = j.find('"', q1 + 1);
    if (q2 == std::string::npos)
    {
        return false;
    }
    out = j.substr(q1 + 1, q2 - q1 - 1);
    return true;
}

// "key":123 형태의 정수 값 추출
static bool JsonInt(const std::string& j, const std::string& key, long long& out)
{
    // 키 위치
    size_t p = j.find("\"" + key + "\"");
    if (p == std::string::npos)
    {
        return false;
    }
    // 콜론 뒤 숫자
    size_t c = j.find(':', p);
    if (c == std::string::npos)
    {
        return false;
    }
    try
    {
        out = std::stoll(j.substr(c + 1));
        return true;
    }
    catch (...)
    {
        return false;
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    // ---- 서버 주소: 환경 변수 우선, 기본 localhost ----
    std::string server = "127.0.0.1:8080";
    if (const char* env = std::getenv("LOOKUP_SERVER"))
    {
        server = env;
    }
    size_t colon = server.rfind(':');
    std::string host = server.substr(0, colon);
    std::string port = server.substr(colon + 1);
    std::cerr << "[daemon] 서버: " << server << "\n";

    // ---- 컨텍스트 + 워밍업 (NTT 테이블 사전 생성으로 첫 질의 지연 제거) ----
    CryptoContext<DCRTPoly> cc = MakeContext();
    {
        KeyPair<DCRTPoly> warm = cc->KeyGen();
        Ciphertext<DCRTPoly> w = EncryptQuery(cc, warm.publicKey, 1);
        (void)w;
    }
    std::cerr << "[daemon] 워밍업 완료\n";

    // ---- 세션 캐시: 정규화 도메인 -> 판정 ----
    std::map<std::string, bool> cache;

    // ---- 메시지 루프 ----
    std::string msg;
    while (ReadMessage(msg))
    {
        // id 추출 (없으면 0)
        long long id = 0;
        JsonInt(msg, "id", id);

        // 도메인 추출
        std::string raw;
        if (!JsonString(msg, "domain", raw))
        {
            WriteMessage("{\"id\":" + std::to_string(id) + ",\"error\":\"no domain\"}");
            continue;
        }

        // 정규화
        std::string domain = NormalizeHostname(raw);
        if (domain.empty() || domain.find('.') == std::string::npos)
        {
            WriteMessage("{\"id\":" + std::to_string(id) + ",\"error\":\"bad domain\"}");
            continue;
        }

        // 캐시 조회
        auto it = cache.find(domain);
        if (it != cache.end())
        {
            WriteMessage("{\"id\":" + std::to_string(id) +
                         ",\"domain\":\"" + domain + "\"" +
                         ",\"listed\":" + (it->second ? "true" : "false") +
                         ",\"cached\":true,\"ms\":0}");
            continue;
        }

        // ---- 실제 질의 ----
        auto t0 = std::chrono::steady_clock::now();
        try
        {
            // (버킷, 값) 유도
            DomainKey dk = DeriveKey(domain);
            // 요청별 새 키
            KeyPair<DCRTPoly> keys = cc->KeyGen();
            // 암호화 + 직렬화
            Ciphertext<DCRTPoly> query = EncryptQuery(cc, keys.publicKey, dk.value);
            std::string payload = ToBytes(query);
            // 전송
            std::string req = "POST /query HTTP/1.1\r\nHost: " + host + "\r\n"
                              "X-Bucket: " + std::to_string(dk.bucket) + "\r\n"
                              "Content-Type: application/octet-stream\r\n"
                              "Content-Length: " + std::to_string(payload.size()) + "\r\n"
                              "Connection: close\r\n\r\n" + payload;
            std::string replyBytes;
            if (!HttpRequest(host, port, req, replyBytes))
            {
                // 서버 불가 — fail-open (차단하지 않음), 캐시에도 저장하지 않음
                WriteMessage("{\"id\":" + std::to_string(id) + ",\"error\":\"server unreachable\"}");
                continue;
            }
            // 복호화 판정
            Ciphertext<DCRTPoly> reply;
            FromBytes(reply, replyBytes);
            bool listed = DecryptAndCheck(cc, keys.secretKey, { reply });
            auto t1 = std::chrono::steady_clock::now();
            long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
            // 캐시 저장 + 응답
            cache[domain] = listed;
            WriteMessage("{\"id\":" + std::to_string(id) +
                         ",\"domain\":\"" + domain + "\"" +
                         ",\"listed\":" + (listed ? "true" : "false") +
                         ",\"cached\":false,\"ms\":" + std::to_string(ms) + "}");
        }
        catch (const std::exception& e)
        {
            // 요청 단위 오류 — fail-open
            WriteMessage("{\"id\":" + std::to_string(id) + ",\"error\":\"exception\"}");
            std::cerr << "[daemon] 오류: " << e.what() << "\n";
        }
    }

    std::cerr << "[daemon] 종료 (stdin EOF)\n";
    return 0;
}
