// 피지컬 AI 실습 v2 — 앱으로 설치하기 위한 서비스 워커
// 화면(HTML)은 늘 인터넷에서 새로 받아 고친 내용이 바로 반영되고, 인터넷이 끊겼을 때만 마지막으로 받은 화면을 보여 줌.
// 그 밖의 요청(VLM·학습 모델·글꼴·hex)은 건드리지 않음.
const CACHE = "pai2-shell-1";
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET" || req.mode !== "navigate") return;
  e.respondWith(
    fetch(req)
      .then((res) => {
        if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put("./", copy)); }
        return res;
      })
      .catch(() => caches.match("./").then((r) => r || Response.error()))
  );
});
