// ============================================================================
// warning.js — 경고 페이지: 도메인 표시 + 돌아가기 / 우회 방문
// ============================================================================

// 쿼리 파라미터에서 도메인과 원래 목적지 복원
const params = new URLSearchParams(location.search);
const domain = params.get("domain") || "";
const orig = params.get("orig") || "";

// 도메인 표시
document.getElementById("domain").textContent = domain;

// 돌아가기: 이전 페이지로
document.getElementById("back").addEventListener("click", () => {
  history.back();
});

// 우회 방문: 세션 한정 우회 플래그를 세우고 원래 목적지로 이동
document.getElementById("go").addEventListener("click", async () => {
  await chrome.storage.session.set({ ["override:" + domain]: true });
  location.href = orig;
});
