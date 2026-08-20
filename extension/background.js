// ============================================================================
// background.js — 2계층 판정
//
//   계층 1 (접속 전, 로컬):   onBeforeNavigate 에서 휴리스틱 검사
//                              -> 주의(caution.html, 노란색)
//   계층 2 (접속 직후, 서버): onCommitted 에서 데몬 경유 목록 조회
//                              -> 차단(warning.html, 붉은색)
//
// 구조:
//   - connectNative 로 데몬과 지속 연결 (sendNativeMessage 는 매번 프로세스를
//     새로 띄워 워밍업이 반복되므로 사용하지 않음)
//   - 요청마다 id 를 붙여 응답을 대기 목록과 짝지음
//   - 오류/서버 불가 응답은 차단하지 않음 (fail-open)
//   - 우회 플래그는 두 계층 모두 chrome.storage.session 사용
//       목록 우회:     "override:" + domain        (기존 그대로)
//       휴리스틱 우회: "heur-override:" + domain   (새로 추가)
//     키가 달라서 휴리스틱을 우회해도 목록 검사는 그대로 수행된다.
// ============================================================================

// 로컬 휴리스틱 모듈을 불러온다 (전역 이름 HEUR 가 생긴다)
importScripts("heuristics.js");

// Tranco 데이터 로드를 시작한다 (완료 대기는 리스너에서 HEUR.ready 로 한다)
HEUR.init();

// 네이티브 호스트 이름 (설치 스크립트의 매니페스트 name 과 일치해야 함)
const HOST_NAME = "com.hexlab.lookup";

// 지속 포트와 대기 목록
let port = null;
const pending = new Map();   // id -> { tabId, url, domain }
let nextId = 1;

// 포트 확보 (없으면 연결)
function getPort() {
  if (port) {
    return port;
  }
  port = chrome.runtime.connectNative(HOST_NAME);
  // 데몬 응답 처리
  port.onMessage.addListener(onVerdict);
  // 연결 끊김: 다음 질의에서 재연결
  port.onDisconnect.addListener(() => {
    console.warn("daemon disconnected:", chrome.runtime.lastError?.message);
    port = null;
    pending.clear();
  });
  return port;
}

// 데몬 판정 수신 (계층 2 의 결과)
function onVerdict(msg) {
  // 짝 찾기
  const req = pending.get(msg.id);
  if (!req) {
    return;
  }
  pending.delete(msg.id);
  // 오류는 차단하지 않음 (fail-open)
  if (msg.error) {
    console.warn("lookup error:", msg.error, req.domain);
    return;
  }
  // 위험 판정 -> 경고 페이지로 이동
  if (msg.listed) {
    const w = chrome.runtime.getURL("warning.html")
      + "?domain=" + encodeURIComponent(req.domain)
      + "&orig=" + encodeURIComponent(req.url);
    chrome.tabs.update(req.tabId, { url: w });
  }
}

// ============================================================================
// 계층 1: 휴리스틱 (접속 확정 전 시점, 서버 왕복 없음)
// ============================================================================
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // 최상위 프레임만 본다 (iframe 은 대상이 아니다)
  if (details.frameId !== 0) {
    return;
  }

  // 확장 자신의 페이지(warning/caution)로의 이동은 검사하지 않는다
  if (details.url.startsWith(chrome.runtime.getURL(""))) {
    return;
  }

  // 주소를 해석한다 (실패하면 검사하지 않는다)
  let u;
  try {
    u = new URL(details.url);
  } catch {
    return;
  }
  // http/https 외 스킴(chrome://, about: 등)은 대상이 아니다
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return;
  }
  // 호스트명을 소문자로 정규화한다
  const domain = u.hostname.toLowerCase();

  // 휴리스틱 "계속 진행" 우회 플래그 확인 (세션 저장소)
  const key = "heur-override:" + domain;
  const flags = await chrome.storage.session.get(key);
  if (flags[key]) {
    return;
  }

  // Tranco 데이터 로드가 끝날 때까지 기다린다 (기동 직후 경합 방지)
  await HEUR.ready;

  // 휴리스틱 판정을 수행한다
  const result = HEUR.analyze(details.url);

  // 주의 판정이면 주의 페이지로 탭을 돌린다
  if (result.verdict === "caution") {
    // 주의 페이지 주소를 만든다 (원래 주소와 사유를 질의 인자로 넘긴다)
    const c = chrome.runtime.getURL("caution.html")
      + "?url=" + encodeURIComponent(details.url)
      + "&reasons=" + encodeURIComponent(JSON.stringify(result.reasons));
    // 탭을 주의 페이지로 바꾼다
    chrome.tabs.update(details.tabId, { url: c });
  }
});

// ============================================================================
// 계층 2: 목록 조회 (기존 흐름 그대로)
// ============================================================================
chrome.webNavigation.onCommitted.addListener(async (details) => {
  // 메인 프레임만
  if (details.frameId !== 0) {
    return;
  }
  // http/https 만
  let u;
  try {
    u = new URL(details.url);
  } catch {
    return;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return;
  }
  const domain = u.hostname.toLowerCase();

  // "그래도 방문" 우회 플래그 확인 (세션 저장소)
  const key = "override:" + domain;
  const flags = await chrome.storage.session.get(key);
  if (flags[key]) {
    return;
  }

  // 데몬에 질의 (데몬이 자체 캐시를 가지므로 여기서는 중복 억제 불필요)
  const id = nextId++;
  pending.set(id, { tabId: details.tabId, url: details.url, domain: domain });
  try {
    getPort().postMessage({ id: id, domain: domain });
  } catch (e) {
    console.warn("postMessage failed:", e);
    port = null;
    pending.delete(id);
  }
});
