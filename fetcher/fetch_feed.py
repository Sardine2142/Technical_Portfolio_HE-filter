#!/usr/bin/env python3
# ============================================================================
# fetch_feed_v4.py — 운영형 수집기
#
# v3 대비 변경 (출력 형식은 v3 와 완전 동일 -> 서버 rev.6.1 무수정):
#   1) age-out    : 상태 파일(feed_state.json)에 도메인별 최종 목격일을 기록.
#                   이번 수집에 없어도 유예 기간(기본 30일) 내면 목록에 유지,
#                   넘기면 제거. 피드 일시 장애로 항목이 대량 증발하는 것을 막는다.
#   2) 안전 필터  : Tranco 상위 목록(tranco_top10k.json)과 "정확 일치"하는
#                   호스트는 목록에 넣지 않고 filtered_out.txt 에 기록만 한다.
#                   (피드 오염으로 유명 도메인이 차단되는 사고 방지)
#                   * 정확 일치만 보는 이유: 등록 도메인 기준으로 거르면
#                     공유 호스팅(blogspot 등) 위의 실제 피싱까지 통째로
#                     빠지기 때문. 필터의 목적은 유명 도메인 "그 자체"의
#                     오염 유입 차단이다.
#   3) 원자적 교체: CSV / 상태 / 제외 기록 모두 임시 파일에 쓴 뒤 os.replace.
#                   (서버의 60초 mtime 감시자가 쓰기 도중 파일을 읽는 것 방지)
#   4) --infile   : 의미 변경 — 4개 공개 피드에 "추가"되는 로컬 소스 (C-TAS
#                   CSV 투입용, 기본 비활성). 네트워크 없이 로컬만 쓰는 기존
#                   용법은 --no-network 로 분리.
#
# 사용법:
#   python3 fetch_feed_v4.py --out feed_hv.csv                  # 통상 운영
#   python3 fetch_feed_v4.py --out feed_hv.csv --infile ctas.csv  # C-TAS 추가
#   python3 fetch_feed_v4.py --no-network --infile a.txt        # 오프라인 시험
#   python3 fetch_feed_v4.py --grace 14                         # 유예 14일
# ============================================================================

import argparse            # 명령행 인자 처리
import hashlib             # SHA-256
import json                # 상태 파일 / Tranco 파일
import os                  # 원자적 교체 (os.replace)
import sys                 # 종료 코드
import time                # 소요 시간 측정
from datetime import date, timedelta   # 날짜 계산 (유예 판정)
import urllib.request      # 피드 다운로드
from urllib.parse import urlparse      # URL 에서 호스트 추출

# 평문 모듈러스 (C++ 쪽 kPlainModulus 와 반드시 일치해야 함)
PLAIN_MODULUS = 998244353

# 기본 소스 목록: (이름, URL) — 인증 없는 공개 피드 (v3 와 동일)
SOURCES = [
    ("openphish",
     "https://openphish.com/feed.txt"),
    ("phishing.army",
     "https://phishing.army/download/phishing_army_blocklist_extended.txt"),
    ("urlhaus-hostfile",
     "https://urlhaus.abuse.ch/downloads/hostfile/"),
    ("phishing.database",
     "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"),
]


# ----------------------------------------------------------------------------
# 정규화 (v3 와 동일 + 쉼표 구분 줄 지원)
# ----------------------------------------------------------------------------
def normalize_hostname(raw_line):
    """피드의 한 줄을 정규화된 호스트명으로 변환. 실패하면 None."""
    # 앞뒤 공백 제거
    line = raw_line.strip()
    # 빈 줄과 주석은 건너뜀
    if not line or line.startswith("#") or line.startswith("!"):
        return None
    # 쉼표 구분(CSV) 줄 지원: 각 칸을 앞에서부터 시도해 처음 성공하는 것을 쓴다
    # (C-TAS 내보내기 CSV 처럼 도메인이 어느 칸에 있는지 모르는 경우 대비)
    if "," in line and "://" not in line:
        for token in line.split(","):
            host = normalize_hostname(token)
            if host is not None:
                return host
        return None
    # hosts 형식 지원: 공백으로 나뉘어 있으면 마지막 토큰이 도메인
    if " " in line or "\t" in line:
        line = line.split()[-1]
    # 스킴이 없으면 urlparse 가 호스트를 못 뽑으므로 보정
    if "://" not in line:
        line = "http://" + line
    # URL 파싱으로 호스트명 추출
    host = urlparse(line).hostname
    if not host:
        return None
    # 소문자화 + 말단 점 제거
    host = host.lower().rstrip(".")
    # 문자 집합 검사: 호스트명에 올 수 없는 문자(%20 등 URL 인코딩 잔재)가
    # 있으면 피드 오염으로 보고 버린다 (퓨니코드 xn-- 은 하이픈이라 통과)
    if any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in host):
        return None
    # hosts 파일의 자기 참조 항목 제외
    if host in ("localhost", "localhost.localdomain", "local", "broadcasthost"):
        return None
    # 최소 형식 검사
    if "." not in host:
        return None
    return host


# ----------------------------------------------------------------------------
# 해시 변환 (v3 와 동일)
# ----------------------------------------------------------------------------
def hostname_to_hash_and_value(host):
    """SHA-256(호스트명) -> (상위 64비트, [1,t) 값) 쌍."""
    # 해시 계산
    digest = hashlib.sha256(host.encode("utf-8")).digest()
    # 상위 64비트: 버킷 유도용 (C++ 에서 k 에 따라 시프트)
    hash64 = int.from_bytes(digest[:8], "big")
    # 전체 해시를 [1, t) 로 접음: 대조용 값 (0 은 패딩 예약)
    number = int.from_bytes(digest, "big")
    value = (number % (PLAIN_MODULUS - 1)) + 1
    return hash64, value


# ----------------------------------------------------------------------------
# 다운로드 (v3 와 동일)
# ----------------------------------------------------------------------------
def fetch_source(name, url):
    """소스 하나를 다운로드해 (본문, 소요 초) 반환. 실패 시 (None, 소요 초)."""
    t0 = time.monotonic()
    try:
        # User-Agent 없으면 차단하는 피드가 있어 지정
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        return raw, time.monotonic() - t0
    except Exception as e:
        # 실패는 보고만 하고 진행 (상태 파일 유예가 증발을 막아준다)
        print(f"[실패] {name}: {e}")
        return None, time.monotonic() - t0


# ----------------------------------------------------------------------------
# 원자적 쓰기: 임시 파일에 쓴 뒤 목적 경로로 교체한다
# ----------------------------------------------------------------------------
def atomic_write_text(path, text):
    """text 를 path 에 원자적으로 기록한다 (쓰다 만 파일이 노출되지 않음)."""
    # 같은 디렉터리에 임시 이름으로 쓴다 (os.replace 는 같은 파일시스템이어야 원자적)
    tmp_path = path + ".tmp"
    # 임시 파일에 전체 내용을 쓴다
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(text)
    # 목적 경로로 원자적으로 바꿔치기한다
    os.replace(tmp_path, path)


# ----------------------------------------------------------------------------
# 상태 파일 입출력
# ----------------------------------------------------------------------------
def load_state(path):
    """상태 파일을 읽는다. 없거나 깨졌으면 빈 상태로 시작한다.
    형식: { "도메인": "YYYY-MM-DD(최종 목격일)", ... }"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # 형식이 사전이 아니면 무시한다
        if not isinstance(data, dict):
            return {}
        return data
    except FileNotFoundError:
        # 첫 실행: 상태 없음
        return {}
    except Exception as e:
        # 깨진 상태 파일은 경고 후 새로 시작한다 (수집 자체는 막지 않는다)
        print(f"[경고] 상태 파일 해석 실패({e}) — 새 상태로 시작")
        return {}


# ----------------------------------------------------------------------------
# Tranco 목록 적재
# ----------------------------------------------------------------------------
def load_tranco(path):
    """tranco_top10k.json 의 domains 배열을 집합으로 읽는다.
    없으면 빈 집합 + 경고 (필터 없이 진행 = fail-open)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # domains 배열을 집합으로 만든다
        return set(data.get("domains", []))
    except FileNotFoundError:
        print(f"[경고] Tranco 파일 없음({path}) — 안전 필터 없이 진행")
        return set()
    except Exception as e:
        print(f"[경고] Tranco 파일 해석 실패({e}) — 안전 필터 없이 진행")
        return set()


def main():
    # ---- 인자 해석 ----
    parser = argparse.ArgumentParser()
    # 출력 CSV 경로 (서버가 읽는 파일)
    parser.add_argument("--out", default="feed_hv.csv", help="출력 CSV 경로")
    # 추가 로컬 소스 (C-TAS CSV 등) — 공개 피드에 "추가"된다
    parser.add_argument("--infile", action="append", default=[],
                        help="추가 로컬 소스 파일 (여러 번 지정 가능; 공개 피드에 추가됨)")
    # 네트워크를 쓰지 않는 시험 모드 (v3 의 --infile 단독 용법을 대체)
    parser.add_argument("--no-network", action="store_true",
                        help="공개 피드를 받지 않음 (--infile 만 사용하는 시험용)")
    # 유예 기간 (일)
    parser.add_argument("--grace", type=int, default=30,
                        help="피드에서 사라진 항목의 유지 일수 (기본 30)")
    # 상태 파일 경로
    parser.add_argument("--state", default="feed_state.json",
                        help="도메인별 최종 목격일 상태 파일 경로")
    # Tranco 안전 필터 파일 경로
    parser.add_argument("--tranco", default="tranco_top10k.json",
                        help="안전 필터용 Tranco JSON 경로 (make_tranco_subset.py 산출물)")
    # 제외 기록 파일 경로
    parser.add_argument("--filtered-log", default="filtered_out.txt",
                        help="안전 필터로 제외된 항목의 기록 파일")
    args = parser.parse_args()

    # ---- 부속 데이터 적재 ----
    # 오늘 날짜 (목격일 기록용)
    today = date.today()
    # 유예 한계일: 이 날짜보다 오래된 최종 목격일은 제거된다
    cutoff = today - timedelta(days=args.grace)
    # 상태 파일 적재
    state = load_state(args.state)
    # Tranco 안전 필터 집합 적재
    tranco = load_tranco(args.tranco)

    # ---- 소스 확보 ----
    payloads = []
    # 공개 피드 다운로드 (--no-network 가 아니면)
    if not args.no_network:
        for name, url in SOURCES:
            raw, sec = fetch_source(name, url)
            if raw is not None:
                payloads.append((name, raw, sec))
    # 추가 로컬 소스 (C-TAS 등)
    for path in args.infile:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            payloads.append((path, f.read(), 0.0))

    # 소스가 하나도 없으면 중단한다 (상태만으로 출력을 다시 쓰는 것은 의미가 없다)
    if not payloads:
        print("받은 소스가 없음 — 네트워크 상태를 점검하거나 --infile 로 지정")
        return 1

    # ---- 소스 순회: 정규화 + 합집합 + 소스별 기여 집계 (v3 와 동일한 표) ----
    seen = set()
    print(f"\n{'소스':24s} {'줄 수':>9s} {'유효 호스트':>10s} {'신규 기여':>9s} {'다운로드':>9s}")
    for name, raw, sec in payloads:
        lines = raw.splitlines()
        valid = 0
        contributed = 0
        for line in lines:
            host = normalize_hostname(line)
            if host is None:
                continue
            valid += 1
            if host in seen:
                continue
            seen.add(host)
            contributed += 1
        print(f"{name:24s} {len(lines):>9d} {valid:>10d} {contributed:>9d} {sec:>8.1f}s")

    # ---- 안전 필터: Tranco 정확 일치 항목을 제외하고 기록한다 ----
    filtered = sorted(h for h in seen if h in tranco)
    # 제외 후 이번 수집분
    current = seen - set(filtered)
    # 제외 기록을 원자적으로 쓴다 (날짜 포함, 매 실행 덮어씀 = 최신 실행의 스냅샷)
    filtered_lines = [f"# {today.isoformat()} 실행에서 제외된 항목 (Tranco 정확 일치)"]
    for host in filtered:
        filtered_lines.append(host)
    atomic_write_text(args.filtered_log, "\n".join(filtered_lines) + "\n")

    # ---- 상태 갱신: 이번 목격분 기록 + 유예 초과분 제거 ----
    # 이번에 본 도메인의 최종 목격일을 오늘로 갱신한다
    for host in current:
        state[host] = today.isoformat()
    # 유예 판정: 최종 목격일이 한계일 이후인 것만 남긴다
    kept_state = {}
    aged_out = 0
    for host, last_seen_str in state.items():
        # 날짜 문자열을 해석한다 (깨진 항목은 버린다)
        try:
            last_seen = date.fromisoformat(last_seen_str)
        except Exception:
            continue
        # 유예 이내면 유지한다
        if last_seen >= cutoff:
            kept_state[host] = last_seen_str
        else:
            aged_out += 1
    state = kept_state

    # 유예로 살아남은 (이번 수집에는 없던) 항목 수를 센다
    grace_kept = len(state) - len(current)

    # ---- 최종 목록 = 상태의 전체 키 (이번 목격 + 유예 유지) ----
    hosts = sorted(state.keys())

    # ---- 해시 -> (hash64, 값) 변환 + 값 충돌 집계 (v3 와 동일) ----
    t2 = time.monotonic()
    value_seen = set()
    collisions = 0
    out_lines = []
    for host in hosts:
        hash64, value = hostname_to_hash_and_value(host)
        if value in value_seen:
            collisions += 1
        value_seen.add(value)
        out_lines.append(f"{host},{hash64},{value}")
    hash_sec = time.monotonic() - t2

    # ---- 출력: CSV 와 상태를 모두 원자적으로 교체한다 ----
    # CSV 먼저 (서버가 읽는 파일)
    atomic_write_text(args.out, "\n".join(out_lines) + "\n")
    # 상태 파일 (다음 실행의 기준)
    atomic_write_text(args.state, json.dumps(state, ensure_ascii=False))

    # ---- 종합 보고 ----
    n = len(hosts)
    print(f"\n이번 수집 고유 도메인 : {len(current)} (필터 제외 {len(filtered)} 건)")
    print(f"유예로 유지          : {grace_kept} (유예 {args.grace}일)")
    print(f"유예 초과 제거       : {aged_out}")
    print(f"최종 목록            : {n}")
    print(f"값 충돌              : {collisions} 건 (이론 기대 ≈ {n * n / (2 * PLAIN_MODULUS):.1f} 건)")
    print(f"해시 변환            : {hash_sec:.2f} s")
    print(f"출력                 : {args.out} / 상태: {args.state} / 제외 기록: {args.filtered_log}")

    # ---- k 별 버킷 평균 적재 미리보기 (v3 와 동일) ----
    print("\nk 별 버킷당 평균 적재 (참고):")
    for k in (4, 5, 6, 8):
        mean = n / (1 << k)
        print(f"  k={k}: 버킷 {1 << k:>3d}개, 평균 {mean:,.0f}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
