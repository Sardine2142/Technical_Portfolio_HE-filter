// ============================================================================
// heuristics.js
// 로컬 휴리스틱 모듈 (rev.2)
//
// rev.1 -> rev.2 변경:
//   검사 2e 추가 — 서브도메인 구간에 유명 도메인 "전체"(TLD 포함)가 통째로
//   들어간 위장을 잡는다. (예: naver.com.evil-site.com, login.naver.com.evil.xyz)
//   rev.1 의 브랜드 라벨 검사(2d)는 Tranco 상위 100 의 단일 라벨만 봐서
//   naver 처럼 전 세계 100위 밖의 이름을 놓쳤다. 2e 는 상위 1만 도메인
//   전체 집합을 쓰되 TLD 까지 일치해야 하므로 오탐 여지가 거의 없다.
//
// 위치: 확장 루트 (background.js 옆)
// 로드: background.js 맨 위에서 importScripts('heuristics.js')
//
// 원칙: 클라이언트가 이미 가진 평문 URL만 검사한다. 서버로는 아무것도
//       보내지 않으므로 프라이버시 비용이 0이다.
//
// 판정 등급: 목록 일치(확정 차단)와 달리 여기서는 'caution'(주의)만 낸다.
// ============================================================================

// 전역 이름 HEUR 하나만 노출한다 (서비스 워커 전역 오염 최소화)
const HEUR = (() => {

  // --------------------------------------------------------------------------
  // 등록 도메인(eTLD+1) 추출용 최소 다중부 접미사 목록
  // 완전한 Public Suffix List 대신, 실사용 빈도가 높은 것만 담는다.
  // make_tranco_subset.py 의 MULTI_SUFFIX 와 반드시 동일하게 유지할 것.
  // --------------------------------------------------------------------------
  const MULTI_SUFFIX = new Set([
    // 한국
    'co.kr', 'or.kr', 'go.kr', 'ac.kr', 'ne.kr', 'pe.kr', 're.kr', 'hs.kr', 'ms.kr', 'es.kr',
    // 일본
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
    // 영국
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk',
    // 기타 빈도 상위
    'com.au', 'net.au', 'org.au',
    'com.cn', 'net.cn', 'org.cn',
    'com.tw', 'com.hk', 'com.sg',
    'com.br', 'com.mx', 'com.ar',
    'co.in', 'co.nz', 'co.za',
  ]);

  // --------------------------------------------------------------------------
  // Tranco 데이터 보관소 (init()에서 채워진다)
  // --------------------------------------------------------------------------
  let trancoDomains = new Set();   // 등록 도메인 전체 집합 (예: "naver.com") — 알려진 정상 판정 + 검사 2e
  let sldsByLength  = new Map();   // 길이 -> [SLD...] 버킷 — 편집거리 검사 가속용
  let brandLabels   = new Set();   // 상위 브랜드 SLD (예: "google") — 단일 라벨 위장 검사용

  // 휴리스틱 경고 후 "계속 진행"된 호스트 (rev.2 에서는 미사용 — 우회는
  // background.js 가 chrome.storage.session 으로 관리한다. 호환을 위해 남겨둠)
  let bypassedHosts = new Set();

  // init() 완료를 기다리기 위한 약속 객체 (리스너에서 await ready 로 사용)
  let readyResolve = null;
  const ready = new Promise((resolve) => { readyResolve = resolve; });

  // --------------------------------------------------------------------------
  // init: 확장에 동봉된 tranco_top10k.json 을 읽어 자료구조를 만든다.
  //       background.js 기동 시 한 번 호출한다.
  // --------------------------------------------------------------------------
  async function init() {
    try {
      // 확장 내부 정적 파일의 URL 을 얻는다
      const url = chrome.runtime.getURL('tranco_top10k.json');
      // 파일을 읽는다 (확장 내부 fetch 는 네트워크가 아니라 패키지 읽기다)
      const response = await fetch(url);
      // JSON 으로 해석한다 ({ domains: [...], slds: [...], brands: [...] })
      const data = await response.json();

      // 등록 도메인 전체를 집합으로 만든다
      trancoDomains = new Set(data.domains);

      // SLD 를 길이별 버킷에 나눠 담는다 (편집거리 1 은 길이 차 1 이내에서만 성립)
      sldsByLength = new Map();
      for (const sld of data.slds) {
        // 이 SLD 의 길이를 구한다
        const len = sld.length;
        // 해당 길이 버킷이 없으면 새로 만든다
        if (!sldsByLength.has(len)) {
          sldsByLength.set(len, []);
        }
        // 버킷에 넣는다
        sldsByLength.get(len).push(sld);
      }

      // 브랜드 라벨 집합을 만든다 (상위 100 도메인의 SLD)
      brandLabels = new Set(data.brands);

      // 준비 완료를 알린다
      readyResolve();
      // 로딩 결과를 콘솔에 남긴다 (서비스 워커 검사 창에서 확인용)
      console.log('[HEUR] loaded:', trancoDomains.size, 'domains,', data.slds.length, 'slds,', brandLabels.size, 'brands');
    } catch (e) {
      // 데이터 로드 실패 시에도 확장 본체는 살아야 한다 -> 휴리스틱만 무력화 (fail-open)
      console.error('[HEUR] init failed, heuristics disabled:', e);
      readyResolve();
    }
  }

  // --------------------------------------------------------------------------
  // registeredDomain: 호스트명에서 등록 도메인(eTLD+1)을 뽑는다.
  //   "login.naver.com"        -> "naver.com"
  //   "a.b.example.co.kr"      -> "example.co.kr"
  // --------------------------------------------------------------------------
  function registeredDomain(hostname) {
    // 점으로 라벨을 나눈다
    const labels = hostname.split('.');
    // 라벨이 2개 이하면 그 자체가 등록 도메인이다
    if (labels.length <= 2) {
      return hostname;
    }
    // 마지막 2개 라벨을 이어 붙여 다중부 접미사인지 본다 (예: "co.kr")
    const lastTwo = labels.slice(-2).join('.');
    // 다중부 접미사면 마지막 3개 라벨이 등록 도메인이다
    if (MULTI_SUFFIX.has(lastTwo) && labels.length >= 3) {
      return labels.slice(-3).join('.');
    }
    // 아니면 마지막 2개 라벨이 등록 도메인이다
    return lastTwo;
  }

  // --------------------------------------------------------------------------
  // isIpLiteral: 호스트명이 IP 주소 그 자체인지 판정한다.
  // --------------------------------------------------------------------------
  function isIpLiteral(hostname) {
    // IPv4: 숫자.숫자.숫자.숫자 (각 0~255 범위 검증까지는 하지 않는다 — 형태만 본다)
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      return true;
    }
    // IPv6: URL 파서가 "[::1]" 처럼 대괄호를 남긴다
    if (hostname.startsWith('[') && hostname.endsWith(']')) {
      return true;
    }
    // 둘 다 아니면 IP 리터럴이 아니다
    return false;
  }

  // --------------------------------------------------------------------------
  // editDistanceIsOne: 두 문자열의 편집거리가 정확히 1인지 판정한다.
  //   (삽입 1 / 삭제 1 / 치환 1 중 하나. 동일 문자열이면 false)
  //   전체 DP 없이 O(n) 으로 판정한다.
  // --------------------------------------------------------------------------
  function editDistanceIsOne(a, b) {
    // 길이 차가 2 이상이면 거리 1이 불가능하다
    const lenA = a.length;
    const lenB = b.length;
    if (Math.abs(lenA - lenB) > 1) {
      return false;
    }
    // 같은 길이: 다른 문자가 정확히 1곳이면 치환 1
    if (lenA === lenB) {
      // 다른 문자 개수를 센다
      let diff = 0;
      for (let i = 0; i < lenA; i++) {
        if (a[i] !== b[i]) {
          diff++;
          // 2곳 이상 다르면 즉시 탈락
          if (diff > 1) {
            return false;
          }
        }
      }
      // 정확히 1곳 달라야 한다 (0곳 = 동일 문자열)
      return diff === 1;
    }
    // 길이 차 1: 긴 쪽에서 문자 하나를 지워 짧은 쪽이 되는지 본다
    // long 을 긴 쪽, short 를 짧은 쪽으로 둔다
    const long  = lenA > lenB ? a : b;
    const short = lenA > lenB ? b : a;
    // 두 포인터로 앞에서부터 비교한다
    let i = 0;   // long 인덱스
    let j = 0;   // short 인덱스
    let skipped = false;   // 삭제를 이미 한 번 썼는가
    while (i < long.length && j < short.length) {
      if (long[i] === short[j]) {
        // 같으면 둘 다 전진
        i++;
        j++;
      } else if (!skipped) {
        // 다르면 long 쪽 문자 하나를 건너뛴다 (= 삭제 1회 사용)
        skipped = true;
        i++;
      } else {
        // 삭제를 이미 썼는데 또 다르면 거리 2 이상
        return false;
      }
    }
    // 끝까지 왔으면 거리 1 이다 (남은 마지막 문자 하나는 삭제로 흡수된다)
    return true;
  }

  // --------------------------------------------------------------------------
  // analyze: URL 문자열 하나를 받아 판정을 돌려준다.
  //   반환: { verdict: 'clean' | 'caution', reasons: [문자열...] }
  // --------------------------------------------------------------------------
  function analyze(urlString) {
    // 발견한 사유를 모을 배열
    const reasons = [];

    // URL 을 해석한다 (실패하면 판단하지 않는다)
    let url;
    try {
      url = new URL(urlString);
    } catch (e) {
      return { verdict: 'clean', reasons: [] };
    }

    // http/https 외의 스킴(chrome://, about: 등)은 대상이 아니다
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return { verdict: 'clean', reasons: [] };
    }

    // 호스트명을 소문자로 정규화하고 말미의 점을 제거한다
    const hostname = url.hostname.toLowerCase().replace(/\.$/, '');

    // ---- 검사 2a: 주소에 사용자정보(@ 앞부분)가 박혀 있는가 ----
    // 정상 사이트 링크에는 쓰이지 않고, 주소 위장에 흔히 쓰인다
    if (url.username !== '' || url.password !== '') {
      reasons.push('주소에 사용자정보(@) 구간이 포함되어 있습니다 — 실제 접속지를 가리는 수법에 쓰입니다');
    }

    // ---- 검사 2b: 호스트가 IP 주소 그 자체인가 ----
    if (isIpLiteral(hostname)) {
      reasons.push('도메인 이름 없이 IP 주소로 직접 접속합니다 — 정상 서비스에서는 드문 형태입니다');
      // IP 리터럴이면 이후의 도메인 문자열 검사는 의미가 없다
      return { verdict: 'caution', reasons: reasons };
    }

    // 등록 도메인(eTLD+1)을 뽑는다
    const regDomain = registeredDomain(hostname);

    // ---- 알려진 정상 지름길 ----
    // 등록 도메인이 Tranco 상위 목록에 있으면 이후 검사를 생략한다.
    // (구조 검사에서 이미 사유가 나왔다면 그것은 유지한 채 판정한다)
    if (trancoDomains.has(regDomain)) {
      if (reasons.length > 0) {
        return { verdict: 'caution', reasons: reasons };
      }
      return { verdict: 'clean', reasons: [] };
    }

    // 라벨 배열을 만든다
    const labels = hostname.split('.');
    // 등록 도메인이 차지하는 라벨 수를 구한다
    const regLabelCount = regDomain.split('.').length;
    // 서브도메인 라벨만 잘라낸다 (등록 도메인 앞부분)
    const subLabels = labels.slice(0, labels.length - regLabelCount);

    // ---- 검사 1: 퓨니코드(xn--) 라벨 ----
    // 국제화 도메인 자체는 합법이지만, 유사 문자 위장(호모글리프)의 통로다.
    // 여기서는 확정이 아니라 '주의' 등급이므로 존재 자체를 사유로 올린다.
    for (const label of labels) {
      if (label.startsWith('xn--')) {
        reasons.push('국제화 문자(퓨니코드) 도메인입니다 — 유사 문자로 유명 사이트를 흉내내는 수법에 쓰일 수 있습니다');
        break;
      }
    }

    // ---- 검사 2c: 서브도메인 깊이 ----
    // 등록 도메인 앞에 3단 이상 붙는 구조는 위장 주소에서 흔하다
    if (subLabels.length >= 3) {
      reasons.push('서브도메인이 비정상적으로 깊습니다 (' + hostname + ')');
    }

    // ---- 검사 2e (rev.2 신규): 유명 도메인 전체가 서브도메인 구간에 통째로 있는가 ----
    // "naver.com.evil-site.com", "login.naver.com.evil.xyz" 형태를 잡는다.
    // 서브도메인 라벨들의 연속 구간(길이 2 이상)을 이어 붙여
    // Tranco 상위 1만 도메인 집합과 대조한다. TLD 까지 일치해야 하므로
    // 단일 라벨 검사(2d)보다 훨씬 오탐이 적다.
    // 서브도메인 라벨 수는 실제로 몇 개 안 되므로 이중 반복의 비용은 무시 가능하다.
    let embedded = null;
    // 구간 시작 위치를 순회한다
    for (let start = 0; start < subLabels.length && embedded === null; start++) {
      // 구간 끝 위치를 순회한다 (최소 2개 라벨 = 도메인 형태)
      for (let end = start + 2; end <= subLabels.length; end++) {
        // 구간을 점으로 이어 도메인 형태 문자열을 만든다
        const candidate = subLabels.slice(start, end).join('.');
        // Tranco 도메인 집합에 있으면 위장 확정 후보
        if (trancoDomains.has(candidate)) {
          embedded = candidate;
          break;
        }
      }
    }
    // 발견되면 사유로 올린다
    if (embedded !== null) {
      reasons.push('유명 도메인 "' + embedded + '" 이(가) 주소 앞부분에 들어 있지만 실제 사이트는 ' + regDomain + ' 입니다');
    }

    // ---- 검사 2d: 브랜드 라벨 서브도메인 위장 (상위 100 한정) ----
    // 2e 가 이미 잡았다면 같은 취지의 사유를 중복으로 올리지 않는다
    if (embedded === null) {
      for (const label of subLabels) {
        if (brandLabels.has(label)) {
          reasons.push('유명 서비스 이름("' + label + '")이 서브도메인에 있지만 실제 사이트는 ' + regDomain + ' 입니다');
          break;
        }
      }
    }

    // ---- 검사 3: 타이포스쿼팅 (편집거리 1) ----
    // 등록 도메인의 첫 라벨(SLD)을 Tranco 상위 SLD 와 비교한다
    const sld = regDomain.split('.')[0];
    // 4자 미만 SLD 는 우연 일치가 많아 제외한다 (오탐 억제)
    if (sld.length >= 4) {
      // 길이 차 1 이내의 버킷만 후보로 삼는다
      const candidateLengths = [sld.length - 1, sld.length, sld.length + 1];
      // 발견 시 저장할 변수
      let matched = null;
      // 각 길이 버킷을 순회한다
      for (const len of candidateLengths) {
        // 해당 길이 버킷을 꺼낸다 (없으면 빈 배열)
        const bucket = sldsByLength.get(len) || [];
        // 버킷 안의 각 SLD 와 편집거리를 판정한다
        for (const candidate of bucket) {
          if (editDistanceIsOne(sld, candidate)) {
            matched = candidate;
            break;
          }
        }
        // 찾았으면 더 볼 필요 없다
        if (matched !== null) {
          break;
        }
      }
      // 일치가 있으면 사유로 올린다
      if (matched !== null) {
        reasons.push('유명 도메인 "' + matched + '" 과(와) 한 글자 차이입니다 — 오타 유도 위장 가능성이 있습니다');
      }
    }

    // ---- 종합 판정 ----
    if (reasons.length > 0) {
      return { verdict: 'caution', reasons: reasons };
    }
    return { verdict: 'clean', reasons: [] };
  }

  // --------------------------------------------------------------------------
  // 우회 관리 (rev.2 에서는 미사용 — background.js 가 storage.session 으로 관리.
  // 인터페이스 호환을 위해 남겨둔다)
  // --------------------------------------------------------------------------
  // 호스트를 우회 목록에 넣는다
  function addBypass(hostname) {
    bypassedHosts.add(hostname.toLowerCase());
  }
  // 호스트가 우회 목록에 있는지 본다
  function isBypassed(hostname) {
    return bypassedHosts.has(hostname.toLowerCase());
  }

  // 외부로 내보낼 함수들
  return {
    init: init,             // 기동 시 1회 호출
    ready: ready,           // init 완료 대기용 약속 객체
    analyze: analyze,       // URL 판정
    addBypass: addBypass,   // (미사용) 계속 진행 등록
    isBypassed: isBypassed, // (미사용) 계속 진행 여부 조회
  };
})();
