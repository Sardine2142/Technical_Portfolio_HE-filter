// ============================================================================
// lookup_common.h — rev.6 공통 로직 (서버/클라이언트 공유)
//
// 담는 것:
//   - 고정 파라미터: t, base 구성(링 8192 / 그룹 2 / 깊이 1), 접두사 k = 6
//   - SHA-256 (외부 의존성 제거용 자체 구현)
//   - 도메인 정규화 + 해시 -> (버킷, 값) 유도  [fetch_feed_v3.py 와 동일 규칙]
//   - 프로토콜 단계: 질의 암호화 / 버킷 평가 / 복호화 판정
//   - OpenFHE 직렬화 <-> 문자열 헬퍼
//
// 규칙의 단일 출처: 정규화·해시·값 유도는 이 파일과 fetch_feed_v3.py 두 곳에
// 존재하므로, 수정 시 반드시 양쪽을 함께 고칠 것.
// ============================================================================

#pragma once

#include "openfhe.h"

// 직렬화에 필요한 헤더들
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace lbcrypto;

// ---------------------------------------------------------------------------
// 고정 파라미터 (배포 지점: k=6 + base)
// ---------------------------------------------------------------------------

// 평문 모듈러스 (수집기와 일치)
static const int64_t kPlainModulus = 998244353;

// 접두사 비트 수 (= 누설 비트; 서버가 /params 로 공지, 클라이언트는 검증)
static const uint32_t kPrefixBits = 6;

// base 구성
static const uint32_t kRingDim = 8192;   // 링 차원
static const uint32_t kDepth   = 1;      // 곱셈 깊이
static const uint32_t kGroup   = 2;      // 그룹 크기
static const uint32_t kShards  = 1;      // 샤드 수

// 버킷 하나의 최대 수용량
inline size_t BucketCapacity()
{
    return static_cast<size_t>(kRingDim) * kGroup * kShards;
}

// ---------------------------------------------------------------------------
// 컨텍스트 생성 (서버/클라이언트가 동일 파라미터로 각자 생성)
// ---------------------------------------------------------------------------

inline CryptoContext<DCRTPoly> MakeContext()
{
    // BFV 파라미터 구성
    CCParams<CryptoContextBFVRNS> params;
    params.SetPlaintextModulus(kPlainModulus);
    params.SetMultiplicativeDepth(kDepth);
    params.SetRingDim(kRingDim);
    // 컨텍스트 생성 + 기능 활성화
    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    return cc;
}

// ---------------------------------------------------------------------------
// SHA-256 (컴팩트 자체 구현 — 외부 라이브러리 의존 제거)
// ---------------------------------------------------------------------------

class Sha256
{
public:
    // 문자열의 SHA-256 다이제스트(32바이트)를 반환
    static std::array<uint8_t, 32> Digest(const std::string& data)
    {
        // 해시 상태 초기값
        uint32_t h[8] =
        {
            0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
        };

        // 패딩: 0x80, 0 채움, 마지막 8바이트에 비트 길이(빅엔디언)
        std::vector<uint8_t> msg(data.begin(), data.end());
        uint64_t bitLen = static_cast<uint64_t>(msg.size()) * 8;
        msg.push_back(0x80);
        while (msg.size() % 64 != 56)
        {
            msg.push_back(0x00);
        }
        for (int i = 7; i >= 0; --i)
        {
            msg.push_back(static_cast<uint8_t>((bitLen >> (8 * i)) & 0xff));
        }

        // 64바이트 블록 단위 처리
        for (size_t off = 0; off < msg.size(); off += 64)
        {
            ProcessBlock(&msg[off], h);
        }

        // 상태를 빅엔디언 바이트열로 직렬화
        std::array<uint8_t, 32> out{};
        for (int i = 0; i < 8; ++i)
        {
            out[4 * i + 0] = static_cast<uint8_t>((h[i] >> 24) & 0xff);
            out[4 * i + 1] = static_cast<uint8_t>((h[i] >> 16) & 0xff);
            out[4 * i + 2] = static_cast<uint8_t>((h[i] >> 8) & 0xff);
            out[4 * i + 3] = static_cast<uint8_t>(h[i] & 0xff);
        }
        return out;
    }

private:
    // 우측 순환 시프트
    static uint32_t Rotr(uint32_t x, uint32_t n)
    {
        return (x >> n) | (x << (32 - n));
    }

    // 블록 하나 압축
    static void ProcessBlock(const uint8_t* p, uint32_t* h)
    {
        // 라운드 상수
        static const uint32_t K[64] =
        {
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
            0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
            0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
            0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
            0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
            0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
            0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
            0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
            0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
            0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
            0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
            0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
            0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
            0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
            0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
            0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
        };

        // 메시지 스케줄 확장
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
        {
            w[i] = (static_cast<uint32_t>(p[4 * i]) << 24)
                 | (static_cast<uint32_t>(p[4 * i + 1]) << 16)
                 | (static_cast<uint32_t>(p[4 * i + 2]) << 8)
                 | (static_cast<uint32_t>(p[4 * i + 3]));
        }
        for (int i = 16; i < 64; ++i)
        {
            uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        // 작업 변수
        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t hh = h[7];

        // 64 라운드 압축
        for (int i = 0; i < 64; ++i)
        {
            uint32_t S1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        // 상태 갱신
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }
};

// ---------------------------------------------------------------------------
// 도메인 정규화 + (버킷, 값) 유도  [fetch_feed_v3.py 와 동일 규칙]
// ---------------------------------------------------------------------------

// 소문자화 + 말단 점 제거 (스킴/경로가 붙어 있으면 호스트부만 추출)
inline std::string NormalizeHostname(const std::string& raw)
{
    std::string s = raw;
    // 앞뒤 공백 제거
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
    {
        s.erase(s.begin());
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
    {
        s.pop_back();
    }
    // 스킴 제거
    size_t pos = s.find("://");
    if (pos != std::string::npos)
    {
        s = s.substr(pos + 3);
    }
    // 경로/포트 제거
    pos = s.find_first_of("/:?#");
    if (pos != std::string::npos)
    {
        s = s.substr(0, pos);
    }
    // 소문자화
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    // 말단 점 제거
    while (!s.empty() && s.back() == '.')
    {
        s.pop_back();
    }
    return s;
}

// 해시에서 (버킷 번호, 대조 값) 유도
struct DomainKey
{
    uint64_t hash64;   // SHA-256 상위 64비트
    size_t   bucket;   // 상위 k 비트
    int64_t  value;    // [1, t) 대조 값
};

inline DomainKey DeriveKey(const std::string& host)
{
    DomainKey k{};
    // SHA-256 계산
    std::array<uint8_t, 32> d = Sha256::Digest(host);
    // 상위 64비트 (빅엔디언)
    k.hash64 = 0;
    for (int i = 0; i < 8; ++i)
    {
        k.hash64 = (k.hash64 << 8) | d[i];
    }
    // 버킷 = 상위 k 비트
    k.bucket = static_cast<size_t>(k.hash64 >> (64 - kPrefixBits));
    // 값 = 전체 다이제스트를 mod (t-1) 로 접고 +1 (파이썬의 int.from_bytes % (t-1) + 1 과 동일)
    uint64_t r = 0;
    for (int i = 0; i < 32; ++i)
    {
        r = (r * 256 + d[i]) % static_cast<uint64_t>(kPlainModulus - 1);
    }
    k.value = static_cast<int64_t>(r) + 1;
    return k;
}

// ---------------------------------------------------------------------------
// 서버 측 자료구조 + 프로토콜 단계 (rev.5 와 동일 로직)
// ---------------------------------------------------------------------------

struct ServerData
{
    // roots[shard][pos] = 그룹 내 pos 번째 원소들을 슬롯 순서로 담은 평문
    std::vector<std::vector<Plaintext>> roots;
};

// 버킷 리스트 하나를 샤드/그룹/슬롯 구조로 배치
inline ServerData BuildServerData(const CryptoContext<DCRTPoly>& cc,
                                  const std::vector<int64_t>& list)
{
    ServerData sd;
    // 슬롯 수 = 링 차원
    size_t slots = kRingDim;
    // 샤드 하나가 담는 용량
    size_t perShard = slots * kGroup;
    // 샤드별로 처리
    for (uint32_t s = 0; s < kShards; ++s)
    {
        size_t lo = static_cast<size_t>(s) * perShard;
        size_t hi = std::min(lo + perShard, list.size());
        // pos 별 슬롯 벡터를 0(패딩)으로 초기화
        std::vector<std::vector<int64_t>> vecs(kGroup, std::vector<int64_t>(slots, 0));
        // (슬롯, 그룹 내 위치) 좌표에 배치
        for (size_t i = lo; i < hi; ++i)
        {
            size_t local = i - lo;
            size_t slot  = local / kGroup;
            size_t pos   = local % kGroup;
            vecs[pos][slot] = list[i];
        }
        // 배칭 평문으로 인코딩
        std::vector<Plaintext> shardRoots;
        shardRoots.reserve(kGroup);
        for (uint32_t p = 0; p < kGroup; ++p)
        {
            shardRoots.push_back(cc->MakePackedPlaintext(vecs[p]));
        }
        sd.roots.push_back(std::move(shardRoots));
    }
    return sd;
}

// 클라이언트: 값 하나를 전 슬롯에 복제해 암호화
inline Ciphertext<DCRTPoly> EncryptQuery(const CryptoContext<DCRTPoly>& cc,
                                         const PublicKey<DCRTPoly>& pk,
                                         int64_t value)
{
    // (x, x, ..., x) 벡터 인코딩 후 암호화
    std::vector<int64_t> rep(kRingDim, value);
    Plaintext pt = cc->MakePackedPlaintext(rep);
    return cc->Encrypt(pk, pt);
}

// 서버: 해당 버킷의 서버 데이터에 대해 평가 (마스크 포함)
inline std::vector<Ciphertext<DCRTPoly>> ServerEvaluate(const CryptoContext<DCRTPoly>& cc,
                                                        const ServerData& sd,
                                                        const Ciphertext<DCRTPoly>& query,
                                                        std::mt19937_64& rng)
{
    // 마스크 값 분포: [1, t)
    std::uniform_int_distribution<int64_t> dist(1, kPlainModulus - 1);
    std::vector<Ciphertext<DCRTPoly>> replies;
    replies.reserve(kShards);
    // 샤드별로 독립 평가
    for (uint32_t s = 0; s < kShards; ++s)
    {
        // 인수: f[p] = 질의 - roots[p]  (EvalSub 는 비-const Plaintext& — 지역 복사)
        std::vector<Ciphertext<DCRTPoly>> f;
        f.reserve(kGroup);
        for (uint32_t p = 0; p < kGroup; ++p)
        {
            Plaintext root = sd.roots[s][p];
            f.push_back(cc->EvalSub(query, root));
        }
        // 요청별 무작위 마스크
        std::vector<int64_t> maskVec(kRingDim);
        for (size_t i = 0; i < maskVec.size(); ++i)
        {
            maskVec[i] = dist(rng);
        }
        Plaintext maskPt = cc->MakePackedPlaintext(maskVec);
        // 마스크 선적용 후 무재선형화 곱 (그룹 2 고정)
        Ciphertext<DCRTPoly> fm = cc->EvalMult(f[0], maskPt);
        replies.push_back(cc->EvalMultNoRelin(fm, f[1]));
    }
    return replies;
}

// 클라이언트: 응답 복호화 -> "0 슬롯 존재" 판정
inline bool DecryptAndCheck(const CryptoContext<DCRTPoly>& cc,
                            const PrivateKey<DCRTPoly>& sk,
                            const std::vector<Ciphertext<DCRTPoly>>& replies)
{
    for (const auto& r : replies)
    {
        // 복호화 후 슬롯 검사
        Plaintext pt;
        cc->Decrypt(sk, r, &pt);
        pt->SetLength(kRingDim);
        const std::vector<int64_t>& vals = pt->GetPackedValue();
        for (int64_t v : vals)
        {
            if (v == 0)
            {
                return true;
            }
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// 직렬화 헬퍼 (BINARY <-> std::string)
// ---------------------------------------------------------------------------

template <typename T>
inline std::string ToBytes(const T& obj)
{
    // 메모리 스트림에 직렬화
    std::stringstream ss;
    Serial::Serialize(obj, ss, SerType::BINARY);
    return ss.str();
}

template <typename T>
inline void FromBytes(T& obj, const std::string& bytes)
{
    // 메모리 스트림에서 역직렬화
    std::stringstream ss(bytes);
    Serial::Deserialize(obj, ss, SerType::BINARY);
}
