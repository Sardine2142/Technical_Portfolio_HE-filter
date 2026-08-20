#!/usr/bin/env python3
# ============================================================================
# make_tranco_subset.py
# Tranco 상위 목록 -> 확장 동봉용 tranco_top10k.json 생성기
#
# 용도:
#   1) 휴리스틱 모듈(heuristics.js)의 데이터 파일 생성   <- 이 스크립트의 산출물
#   2) fetcher v4 의 안전 필터도 같은 원본을 쓰게 된다   (이중 용도)
#
# 실행 (WSL):
#   python3 make_tranco_subset.py                       # 내려받기 + 상위 10000
#   python3 make_tranco_subset.py --top 5000            # 개수 조정
#   python3 make_tranco_subset.py --infile top-1m.csv   # 이미 받아둔 CSV 사용
#
# 산출물: tranco_top10k.json
#   { "generated": "...", "count": N,
#     "domains": ["google.com", ...],   # 등록 도메인 전체 (알려진 정상 판정)
#     "slds":    ["google", ...],       # 고유 SLD (편집거리 검사)
#     "brands":  ["google", ...] }      # 상위 100 의 SLD (서브도메인 위장 검사)
# ============================================================================

import argparse          # 명령행 인자 처리
import io                # 메모리 내 압축 해제
import json              # 산출물 직렬화
import sys               # 종료 코드
import time              # 생성 시각 기록
import urllib.request    # 목록 다운로드
import zipfile           # zip 해제

# Tranco 최신 목록의 고정 주소 (일일 갱신, zip 안에 top-1m.csv 하나)
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

# 다중부 공용 접미사 최소 목록 — heuristics.js 의 MULTI_SUFFIX 와 반드시 동일하게 유지
MULTI_SUFFIX = {
    "co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr", "pe.kr", "re.kr", "hs.kr", "ms.kr", "es.kr",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "com.au", "net.au", "org.au",
    "com.cn", "net.cn", "org.cn",
    "com.tw", "com.hk", "com.sg",
    "com.br", "com.mx", "com.ar",
    "co.in", "co.nz", "co.za",
}


def sld_of(domain):
    """등록 도메인 문자열에서 SLD(첫 유효 라벨)를 뽑는다.
    Tranco 목록의 항목은 이미 등록 도메인 형태이므로 첫 라벨이 곧 SLD 다."""
    # 점으로 나눈다
    labels = domain.split(".")
    # 첫 라벨을 돌려준다
    return labels[0]


def main():
    # ---- 인자 정의 ----
    parser = argparse.ArgumentParser(description="Tranco 상위 목록 -> 확장 동봉 JSON")
    # 상위 몇 개를 쓸 것인가 (기본 10000)
    parser.add_argument("--top", type=int, default=10000, help="사용할 상위 도메인 수 (기본 10000)")
    # 브랜드 라벨로 삼을 상위 개수 (기본 100)
    parser.add_argument("--brands", type=int, default=100, help="브랜드 라벨로 삼을 상위 수 (기본 100)")
    # 이미 받아둔 CSV 를 쓸 경우의 경로
    parser.add_argument("--infile", type=str, default=None, help="로컬 top-1m.csv 경로 (지정 시 다운로드 생략)")
    # 산출 파일 경로
    parser.add_argument("--out", type=str, default="tranco_top10k.json", help="산출 JSON 경로")
    args = parser.parse_args()

    # ---- 1) 원본 확보 ----
    if args.infile is not None:
        # 로컬 파일을 그대로 읽는다
        print(f"로컬 파일 사용: {args.infile}")
        with open(args.infile, "r", encoding="utf-8") as f:
            csv_text = f.read()
    else:
        # 다운로드한다
        print(f"다운로드: {TRANCO_URL}")
        t0 = time.monotonic()
        with urllib.request.urlopen(TRANCO_URL, timeout=120) as resp:
            zip_bytes = resp.read()
        print(f"받음: {len(zip_bytes) / 1e6:.1f} MB ({time.monotonic() - t0:.1f} s)")
        # 메모리에서 zip 을 연다
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            # zip 안의 첫 파일(top-1m.csv)을 읽는다
            inner_name = zf.namelist()[0]
            csv_text = zf.read(inner_name).decode("utf-8")

    # ---- 2) 상위 N 개 추출 ----
    # CSV 형식: "순위,도메인" 한 줄씩
    domains = []
    for line in csv_text.splitlines():
        # 빈 줄은 건너뛴다
        if line.strip() == "":
            continue
        # 쉼표로 나눈다
        parts = line.split(",")
        # 형식이 맞지 않으면 건너뛴다
        if len(parts) < 2:
            continue
        # 도메인 부분을 소문자로 정리해 담는다
        domains.append(parts[1].strip().lower())
        # 필요한 개수를 채우면 멈춘다
        if len(domains) >= args.top:
            break

    # 실제 확보 개수를 알린다
    print(f"상위 도메인 확보: {len(domains)} 개")

    # ---- 3) SLD 집합 구성 ----
    # 편집거리 검사용 고유 SLD (짧은 것은 heuristics.js 쪽에서 걸러지지만 여기서도 3자 이하 제외)
    slds = []
    seen = set()
    for domain in domains:
        # SLD 를 뽑는다
        sld = sld_of(domain)
        # 3자 이하는 우연 일치가 많아 데이터에서부터 제외한다
        if len(sld) <= 3:
            continue
        # 처음 보는 것만 담는다 (순위 순서 유지)
        if sld not in seen:
            seen.add(sld)
            slds.append(sld)

    # ---- 4) 브랜드 라벨 구성 (상위 --brands 개의 SLD) ----
    brands = []
    brand_seen = set()
    for domain in domains[: args.brands]:
        # SLD 를 뽑는다
        sld = sld_of(domain)
        # 3자 이하 제외, 중복 제외
        if len(sld) <= 3:
            continue
        if sld not in brand_seen:
            brand_seen.add(sld)
            brands.append(sld)

    # ---- 5) JSON 산출 ----
    output = {
        # 생성 시각 (문서/재현용)
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        # 도메인 수
        "count": len(domains),
        # 등록 도메인 전체
        "domains": domains,
        # 고유 SLD
        "slds": slds,
        # 브랜드 라벨
        "brands": brands,
    }
    # 파일로 쓴다 (ensure_ascii=False 로 원문 유지, 들여쓰기 없음 = 크기 절약)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False)

    # 크기를 보고한다
    import os
    size_kb = os.path.getsize(args.out) / 1024
    print(f"산출: {args.out} ({size_kb:.0f} KB, slds {len(slds)}, brands {len(brands)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
