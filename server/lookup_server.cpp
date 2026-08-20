// ============================================================================
// lookup_server.cpp — rev.6 서버 데몬
//
// 하는 일:
//   - feed_hv.csv (hostname,hash64,value) 로드 -> k=6 버킷 64개 구축
//   - 최소 HTTP 서버:
//       GET  /params : 프로토콜 파라미터 공지 (t, ring, depth, group, shards, k, count, version)
//       POST /query  : 헤더 X-Bucket = 버킷 번호, 본문 = 질의 암호문(BINARY)
//                      -> 해당 버킷 평가 후 응답 암호문(BINARY) 반환
//   - 갱신 스레드: 60초마다 값 파일 mtime 확인, 바뀌면 재로드 -> 이중 버퍼 교체
//
// 빌드/실행: run_p3.sh 참고.  기본 포트 8080.
//   ./lookup_server --values feed_hv.csv --port 8080
// ============================================================================

#include "lookup_common.h"

#include <atomic>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>

// POSIX 소켓
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// 값 파일 로드 (3열 CSV -> 버킷별 값 리스트)
// ---------------------------------------------------------------------------

static std::vector<std::vector<int64_t>> LoadBuckets(const std::string& path, size_t& outCount)
{
    // 파일 열기
    std::ifstream in(path);
    if (!in)
    {
        throw std::runtime_error("값 파일을 열 수 없음: " + path);
    }

    // 버킷 배열 초기화
    size_t nBuckets = static_cast<size_t>(1) << kPrefixBits;
    std::vector<std::vector<int64_t>> buckets(nBuckets);
    outCount = 0;

    // 한 줄씩: 마지막 두 콤마 필드가 hash64, value
    std::string line;
    while (std::getline(in, line))
    {
        if (line.empty())
        {
            continue;
        }
        size_t c2 = line.rfind(',');
        if (c2 == std::string::npos)
        {
            continue;
        }
        size_t c1 = line.rfind(',', c2 - 1);
        if (c1 == std::string::npos)
        {
            continue;
        }
        try
        {
            uint64_t h = std::stoull(line.substr(c1 + 1, c2 - c1 - 1));
            int64_t  v = std::stoll(line.substr(c2 + 1));
            if (v < 1 || v >= kPlainModulus)
            {
                continue;
            }
            // 버킷 배정
            size_t b = static_cast<size_t>(h >> (64 - kPrefixBits));
            buckets[b].push_back(v);
            outCount += 1;
        }
        catch (...)
        {
            continue;
        }
    }

    // 용량 검사 (초과 버킷이 있으면 기동 거부 — k 상향이 필요한 상황)
    for (size_t b = 0; b < nBuckets; ++b)
    {
        if (buckets[b].size() > BucketCapacity())
        {
            throw std::runtime_error("버킷 " + std::to_string(b) + " 적재 "
                                     + std::to_string(buckets[b].size())
                                     + " > 용량 " + std::to_string(BucketCapacity())
                                     + " — k 상향 필요");
        }
    }

    return buckets;
}

// ---------------------------------------------------------------------------
// 공유 상태: 이중 버퍼로 교체되는 서버 데이터
// ---------------------------------------------------------------------------

struct SharedState
{
    std::mutex mtx;                                        // 교체 보호
    std::shared_ptr<std::vector<ServerData>> data;         // 버킷별 서버 데이터
    std::atomic<uint64_t> version{ 0 };                    // 리스트 버전 (mtime)
    std::atomic<size_t>   count{ 0 };                      // 총 항목 수
};

// 파일 mtime 조회 (버전 값으로 사용)
static uint64_t FileMtime(const std::string& path)
{
    struct stat st{};
    if (stat(path.c_str(), &st) != 0)
    {
        return 0;
    }
    return static_cast<uint64_t>(st.st_mtime);
}

// 값 파일 -> 서버 데이터 전체 구축
static std::shared_ptr<std::vector<ServerData>> BuildAll(const CryptoContext<DCRTPoly>& cc,
                                                         const std::string& path,
                                                         size_t& outCount)
{
    // 버킷 로드
    std::vector<std::vector<int64_t>> buckets = LoadBuckets(path, outCount);
    // 버킷별 서버 데이터 구축
    auto all = std::make_shared<std::vector<ServerData>>(buckets.size());
    for (size_t b = 0; b < buckets.size(); ++b)
    {
        (*all)[b] = BuildServerData(cc, buckets[b]);
    }
    return all;
}

// ---------------------------------------------------------------------------
// 최소 HTTP 처리
// ---------------------------------------------------------------------------

// 소켓에서 요청 전체(헤더 + Content-Length 본문)를 읽는다
static bool ReadRequest(int fd, std::string& headers, std::string& body)
{
    std::string buf;
    char tmp[4096];
    // 헤더 끝(\r\n\r\n)까지 읽기
    while (buf.find("\r\n\r\n") == std::string::npos)
    {
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0)
        {
            return false;
        }
        buf.append(tmp, static_cast<size_t>(n));
        // 비정상적으로 큰 헤더 방어
        if (buf.size() > 1 << 20)
        {
            return false;
        }
    }
    // 헤더/본문 분리
    size_t hEnd = buf.find("\r\n\r\n");
    headers = buf.substr(0, hEnd + 4);
    body = buf.substr(hEnd + 4);
    // Content-Length 파싱 (없으면 본문 없음)
    size_t need = 0;
    {
        std::string key = "Content-Length:";
        size_t p = headers.find(key);
        if (p != std::string::npos)
        {
            need = static_cast<size_t>(std::stoul(headers.substr(p + key.size())));
        }
    }
    // 본문 나머지 읽기
    while (body.size() < need)
    {
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0)
        {
            return false;
        }
        body.append(tmp, static_cast<size_t>(n));
    }
    return true;
}

// 응답 전송
static void SendResponse(int fd, const std::string& status, const std::string& contentType,
                         const std::string& body)
{
    // 헤더 구성
    std::string head = "HTTP/1.1 " + status + "\r\n"
                       "Content-Type: " + contentType + "\r\n"
                       "Content-Length: " + std::to_string(body.size()) + "\r\n"
                       "Connection: close\r\n\r\n";
    // 헤더 + 본문 전송
    std::string all = head + body;
    size_t sent = 0;
    while (sent < all.size())
    {
        ssize_t n = send(fd, all.data() + sent, all.size() - sent, 0);
        if (n <= 0)
        {
            return;
        }
        sent += static_cast<size_t>(n);
    }
}

// 헤더에서 특정 키의 값 추출 (없으면 빈 문자열)
static std::string HeaderValue(const std::string& headers, const std::string& key)
{
    size_t p = headers.find(key + ":");
    if (p == std::string::npos)
    {
        return "";
    }
    size_t start = p + key.size() + 1;
    size_t end = headers.find("\r\n", start);
    std::string v = headers.substr(start, end - start);
    // 앞 공백 제거
    while (!v.empty() && v.front() == ' ')
    {
        v.erase(v.begin());
    }
    return v;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char** argv)
{
    // ---- 인자 ----
    std::string valuesPath = "feed_hv.csv";
    int port = 8080;
    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--values" && i + 1 < argc)
        {
            valuesPath = argv[++i];
        }
        else if (a == "--port" && i + 1 < argc)
        {
            port = std::stoi(argv[++i]);
        }
    }

    // ---- 컨텍스트 + 초기 서버 데이터 ----
    CryptoContext<DCRTPoly> cc = MakeContext();
    SharedState state;
    {
        size_t count = 0;
        state.data = BuildAll(cc, valuesPath, count);
        state.count = count;
        state.version = FileMtime(valuesPath);
        std::cout << "리스트 로드: " << count << "건, 버킷 " << ((size_t)1 << kPrefixBits)
                  << "개, 버전 " << state.version << "\n";
    }

    // ---- 갱신 스레드: mtime 변화 감지 -> 재구축 -> 교체 ----
    std::thread updater([&]()
    {
        while (true)
        {
            // 60초 주기 점검
            std::this_thread::sleep_for(std::chrono::seconds(60));
            uint64_t m = FileMtime(valuesPath);
            if (m == 0 || m == state.version)
            {
                continue;
            }
            try
            {
                // 옆 버퍼에 새로 구축
                size_t count = 0;
                auto next = BuildAll(cc, valuesPath, count);
                // 원자적 교체
                {
                    std::lock_guard<std::mutex> lk(state.mtx);
                    state.data = next;
                }
                state.count = count;
                state.version = m;
                std::cout << "[갱신] " << count << "건으로 교체 (버전 " << m << ")\n";
            }
            catch (const std::exception& e)
            {
                // 갱신 실패는 기존 데이터 유지 (가용성 우선)
                std::cerr << "[갱신 실패] " << e.what() << "\n";
            }
        }
    });
    updater.detach();

    // ---- 마스크용 난수기 (요청 처리 루프 전용) ----
    std::random_device rd;
    std::mt19937_64 rng(rd());

    // ---- 소켓 준비 ----
    int listenFd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (bind(listenFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        std::cerr << "bind 실패 (포트 " << port << ")\n";
        return 1;
    }
    listen(listenFd, 16);
    std::cout << "서버 대기 중: 포트 " << port << " (k=" << kPrefixBits
              << ", 링 " << kRingDim << ", 그룹 " << kGroup << ")\n";

    // ---- 요청 처리 루프 (순차 처리 — 평가 4ms 수준이라 데모에 충분) ----
    while (true)
    {
        // 연결 수락
        int fd = accept(listenFd, nullptr, nullptr);
        if (fd < 0)
        {
            continue;
        }
        // 요청 읽기
        std::string headers;
        std::string body;
        if (!ReadRequest(fd, headers, body))
        {
            close(fd);
            continue;
        }

        try
        {
            if (headers.rfind("GET /params", 0) == 0)
            {
                // 프로토콜 파라미터 공지
                std::string txt =
                    "t=" + std::to_string(kPlainModulus) +
                    ";ring=" + std::to_string(kRingDim) +
                    ";depth=" + std::to_string(kDepth) +
                    ";group=" + std::to_string(kGroup) +
                    ";shards=" + std::to_string(kShards) +
                    ";k=" + std::to_string(kPrefixBits) +
                    ";count=" + std::to_string(state.count.load()) +
                    ";version=" + std::to_string(state.version.load()) + "\n";
                SendResponse(fd, "200 OK", "text/plain", txt);
            }
            else if (headers.rfind("POST /query", 0) == 0)
            {
                // 버킷 번호 파싱
                size_t bucket = static_cast<size_t>(std::stoul(HeaderValue(headers, "X-Bucket")));
                size_t nBuckets = static_cast<size_t>(1) << kPrefixBits;
                if (bucket >= nBuckets)
                {
                    SendResponse(fd, "400 Bad Request", "text/plain", "bad bucket\n");
                    close(fd);
                    continue;
                }
                // 질의 암호문 역직렬화
                Ciphertext<DCRTPoly> query;
                FromBytes(query, body);
                // 현재 버퍼의 해당 버킷으로 평가 (교체와 경합하지 않도록 포인터 복사)
                std::shared_ptr<std::vector<ServerData>> data;
                {
                    std::lock_guard<std::mutex> lk(state.mtx);
                    data = state.data;
                }
                std::vector<Ciphertext<DCRTPoly>> replies = ServerEvaluate(cc, (*data)[bucket], query, rng);
                // 응답 직렬화 (샤드 1 고정 — 암호문 하나)
                SendResponse(fd, "200 OK", "application/octet-stream", ToBytes(replies[0]));
            }
            else
            {
                // 그 외 경로
                SendResponse(fd, "404 Not Found", "text/plain", "not found\n");
            }
        }
        catch (const std::exception& e)
        {
            // 요청 단위 오류는 500 으로 응답하고 서버는 계속
            SendResponse(fd, "500 Internal Server Error", "text/plain",
                         std::string(e.what()) + "\n");
        }

        close(fd);
    }

    return 0;
}
