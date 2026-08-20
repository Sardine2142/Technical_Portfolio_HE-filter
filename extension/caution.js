// ============================================================================
// caution.js (rev.2) — 주의 페이지: 사유 표시 + 뒤로가기 / 계속 진행
//
// rev.1 대비 변경: 우회 등록을 백그라운드 메시지 대신 chrome.storage.session
// 직접 기록으로 바꿈 (warning.js 와 같은 방식으로 통일).
//   - 메시지 배관 불필요
//   - 서비스 워커가 잠들어도 우회가 브라우저 세션 동안 유지됨
// ============================================================================

// 현재 페이지의 질의 인자를 해석한다
const params = new URLSearchParams(window.location.search);

// 원래 이동하려던 주소를 꺼낸다 (없으면 빈 문자열)
const targetUrl = params.get("url") || "";

// 사유 배열을 꺼내 해석한다 (실패하면 빈 배열)
let reasons = [];
try {
  reasons = JSON.parse(params.get("reasons") || "[]");
} catch (e) {
  reasons = [];
}

// ---- 화면 채우기 ----

// 대상 주소 상자에 주소를 표시한다 (textContent 이므로 스크립트 주입 위험 없음)
document.getElementById("target-url").textContent = targetUrl;

// 사유 목록 요소를 가져온다
const listElement = document.getElementById("reason-list");
// 각 사유를 목록 항목으로 추가한다
for (const reason of reasons) {
  // 항목 요소를 만든다
  const item = document.createElement("li");
  // 사유 문구를 넣는다
  item.textContent = reason;
  // 목록에 붙인다
  listElement.appendChild(item);
}

// ---- 버튼 동작 ----

// 뒤로가기: 직전 페이지로 돌아간다
document.getElementById("btn-back").addEventListener("click", () => {
  // 이 주의 페이지 이전의 기록이 있는지 본다
  if (window.history.length > 1) {
    // 한 칸 뒤로 간다 (onBeforeNavigate 시점 전환이라 목적지는 기록에 남지 않음)
    window.history.back();
  } else {
    // 돌아갈 곳이 없으면 빈 탭으로 바꾼다
    window.location.href = "about:blank";
  }
});

// 계속 진행: 세션 저장소에 우회 플래그를 세우고 원래 주소로 이동한다
document.getElementById("btn-proceed").addEventListener("click", async () => {
  // 대상 주소가 없으면 아무것도 하지 않는다
  if (targetUrl === "") {
    return;
  }
  // 대상 주소에서 호스트명을 뽑는다 (실패하면 이동만 한다)
  let domain = "";
  try {
    domain = new URL(targetUrl).hostname.toLowerCase();
  } catch (e) {
    domain = "";
  }
  // 우회 플래그를 기록한다 (background.js 의 "heur-override:" 키와 일치)
  if (domain !== "") {
    await chrome.storage.session.set({ ["heur-override:" + domain]: true });
  }
  // 기록이 끝난 뒤 이동해야 다시 붙잡히지 않는다
  window.location.href = targetUrl;
});
