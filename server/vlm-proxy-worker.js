// 피지컬 AI 실습 — VLM 중계 서버 (Cloudflare Worker)
//
// 두 가지 방식을 함께 받는다.
//  1) 반(class): 선생님이 웹앱 선생님 화면에서 자기 Anthropic API 키로 '반'을 만들면,
//     학생은 반 ID·비밀번호로 VLM을 쓴다. 키는 암호화해 D1에 맡기고 학생 화면에는 보내지 않는다.
//     기간이 지나거나 선생님이 '반 닫기'를 누르면 키를 지운다.
//  2) 연수 코드(예전 방식, v1 웹앱): x-class-code가 CLASS_CODE와 같으면 이 서버의 ANTHROPIC_API_KEY로 부른다.
//
// Cloudflare 설정 (Workers → pai-vlm → 설정)
//  - 바인딩 → D1 데이터베이스, 변수 이름 DB          (반 방식에 필요. 표는 처음 요청 때 저절로 만듦)
//  - 변수 및 비밀 → 비밀(Secret) KEY_SECRET           (반 방식에 필요. 키 암호화용 긴 글자. 바꾸면 이미 만든 반의 키를 못 읽음)
//  - ALLOWED_ORIGIN = https://yhlee1627.github.io     (여러 곳이면 쉼표로)
//  - (예전 방식) ANTHROPIC_API_KEY(Secret), CLASS_CODE
//  - (선택) MODEL — 비우면 claude-haiku-5-5

const DEFAULT_MODEL = "claude-haiku-5-5";
const ANTHROPIC_URL = "https://api.anthropic.com/v1/messages";
const ID_CHARS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // 헷갈리는 0·O·1·I·L 뺌
const DAY = 86400000;
const LIM = {
  daysMax: 30, callsMin: 10, callsMax: 5000,
  // 비밀번호를 1시간에 반마다 100번, 한 곳(IP)에서 300번 틀리면 잠깐 막음.
  // 학교는 학생 컴퓨터가 모두 같은 IP로 나가서, 너무 낮으면 오타 몇 번에 반 전체가 막힘
  failClass: 100, failIp: 300, failWindow: 3600000,
  createPerIp: 20,                                // 한 곳에서 하루에 만들 수 있는 반
  promptMax: 1500, imageMax: 1500000, tokensMax: 400
};

// ---------- 공통 ----------
function allowedOrigins(env) {
  return String(env.ALLOWED_ORIGIN || "").split(",").map((s) => s.trim().replace(/\/+$/, "")).filter(Boolean);
}
function corsHeaders(env, origin) {
  const list = allowedOrigins(env);
  const ok = origin && (list.length === 0 || list.includes(origin));
  return {
    "access-control-allow-origin": ok ? origin : (list[0] || "*"),
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "content-type, x-class-code, x-class-id, x-class-pw, x-admin-token",
    "access-control-max-age": "86400",
    "vary": "origin"
  };
}
function json(env, origin, status, data) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", ...corsHeaders(env, origin) } });
}
const fail = (env, origin, status, code, error, extra) => json(env, origin, status, Object.assign({ error, code }, extra || {}));

const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (buf) => { let s = ""; const a = new Uint8Array(buf); for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (buf) => b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const randBytes = (n) => crypto.getRandomValues(new Uint8Array(n));
async function sha256hex(s) {
  const h = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function sameText(a, b) {        // 길이가 같은 두 글자를 처음부터 끝까지 비교(시간 차이로 짐작하지 못하게)
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function aesKey(env) {
  const raw = await crypto.subtle.digest("SHA-256", enc.encode("pai-vlm|" + env.KEY_SECRET));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function sealKey(env, text) {
  const iv = randBytes(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(env), enc.encode(text));
  return "v1." + b64(iv) + "." + b64(ct);
}
async function openKey(env, sealed) {
  const [v, iv, ct] = String(sealed).split(".");
  if (v !== "v1") throw new Error("bad seal");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, await aesKey(env), unb64(ct));
  return dec.decode(pt);
}
function newClassId() {
  const r = randBytes(4); let s = "";
  for (let i = 0; i < 4; i++) s += ID_CHARS[r[i] % ID_CHARS.length];
  return "PAI-" + s;
}
function newPw() {
  const r = new Uint32Array(1); crypto.getRandomValues(r);
  return String(r[0] % 10000).padStart(4, "0");
}
function normId(s) {
  s = String(s || "").toUpperCase().replace(/\s+/g, "").replace(/^PAI-?/, "");
  return /^[A-Z0-9]{4}$/.test(s) ? "PAI-" + s : "";
}
const clientIp = (req) => req.headers.get("cf-connecting-ip") || "local";

// ---------- D1 ----------
let schemaReady = false;
async function ensureSchema(env) {
  if (schemaReady) return;
  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS classes (
      id TEXT PRIMARY KEY, name TEXT, key_enc TEXT NOT NULL, key_hint TEXT,
      pw_salt TEXT NOT NULL, pw_hash TEXT NOT NULL, admin_hash TEXT NOT NULL,
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      max_calls INTEGER NOT NULL, calls INTEGER NOT NULL DEFAULT 0)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS fails (k TEXT PRIMARY KEY, n INTEGER NOT NULL, since INTEGER NOT NULL)`)
  ]);
  schemaReady = true;
}
async function cleanup(env) {
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM classes WHERE expires_at < ?").bind(now),
    env.DB.prepare("DELETE FROM fails WHERE since < ?").bind(now - DAY)
  ]);
}
async function blocked(env, keys) {   // [[key, limit, window]]
  const now = Date.now();
  for (const [k, limit, win] of keys) {
    const r = await env.DB.prepare("SELECT n, since FROM fails WHERE k = ?").bind(k).first();
    if (r && r.n >= limit && now - r.since < win) return true;
  }
  return false;
}
async function bump(env, keys) {      // 틀린 횟수(또는 만든 횟수) 하나 늘림. 창이 지나면 1부터
  const now = Date.now();
  await env.DB.batch(keys.map(([k, , win]) => env.DB.prepare(
    `INSERT INTO fails (k, n, since) VALUES (?1, 1, ?2)
     ON CONFLICT(k) DO UPDATE SET n = CASE WHEN ?2 - since > ?3 THEN 1 ELSE n + 1 END,
                                  since = CASE WHEN ?2 - since > ?3 THEN ?2 ELSE since END`).bind(k, now, win)));
}
async function getClass(env, id) {
  const row = await env.DB.prepare("SELECT * FROM classes WHERE id = ?").bind(id).first();
  if (!row) return null;
  if (row.expires_at < Date.now()) { await env.DB.prepare("DELETE FROM classes WHERE id = ?").bind(id).run(); return null; }
  return row;
}
const pwOk = async (row, pw) => sameText(await sha256hex(row.pw_salt + ":" + String(pw || "")), row.pw_hash);
const adminOk = async (row, token) => !!token && sameText(await sha256hex("admin:" + token), row.admin_hash);
const publicInfo = (row) => ({
  classId: row.id, name: row.name || "", expiresAt: row.expires_at, maxCalls: row.max_calls, calls: row.calls, keyHint: row.key_hint || ""
});

// ---------- Anthropic ----------
async function callAnthropic(env, key, { image, prompt, maxTokens }) {
  const content = [];
  if (image) content.push({ type: "image", source: { type: "base64", media_type: "image/jpeg", data: image } });
  content.push({ type: "text", text: prompt });
  const r = await fetch(env.ANTHROPIC_URL || ANTHROPIC_URL, {
    method: "POST",
    headers: { "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify({
      model: env.MODEL || DEFAULT_MODEL,
      max_tokens: maxTokens,
      thinking: { type: "disabled" },   // Haiku 5.5는 기본으로 생각부터 해서 짧은 답 제한을 다 씀 → 생각 끄기
      output_config: { effort: "low" },
      messages: [{ role: "user", content }]
    })
  });
  let data = {};
  try { data = await r.json(); } catch (e) {}
  if (!r.ok) {
    const m = (data.error && data.error.message) || "";
    const err = new Error(m || "API 오류 " + r.status);
    err.status = r.status;
    err.code = r.status === 401 ? "key_invalid" : /credit balance/i.test(m) ? "credit" : r.status === 403 ? "key_forbidden"
      : r.status === 429 ? "busy" : r.status === 404 ? "model" : r.status >= 500 ? "upstream" : "api";
    throw err;
  }
  const text = (data.content || []).filter((c) => c.type === "text").map((c) => c.text).join("");
  return { text, stop: data.stop_reason || "" };
}
const API_KO = {
  key_invalid: "선생님의 API 키를 더 이상 쓸 수 없어요 (키가 삭제되었거나 틀림)",
  credit: "선생님 API 계정의 크레딧이 부족해요",
  key_forbidden: "이 API 키로는 쓸 수 없어요",
  busy: "요청이 너무 많아요. 잠시 뒤 다시 해 보세요",
  model: "모델 이름을 찾을 수 없어요 (서버의 MODEL 설정 확인)",
  upstream: "Anthropic 서버가 바빠요. 잠시 뒤 다시 해 보세요",
  api: "API 오류"
};
function readVlmBody(body) {
  const image = typeof body.image === "string" ? body.image : "";
  const prompt = typeof body.prompt === "string" ? body.prompt : "";
  if (!image || image.length > LIM.imageMax) return { error: "사진이 없거나 너무 커요" };
  if (!prompt || prompt.length > LIM.promptMax) return { error: `질문이 없거나 너무 길어요 (최대 ${LIM.promptMax}자)` };
  let maxTokens = Math.round(Number(body.maxTokens) || 20);
  maxTokens = Math.max(1, Math.min(LIM.tokensMax, maxTokens));
  return { image, prompt, maxTokens };
}

// ---------- 처리 ----------
async function handleVlm(req, env, origin, body) {
  const v = readVlmBody(body);
  if (v.error) return fail(env, origin, 400, "bad_request", v.error);

  const classIdRaw = req.headers.get("x-class-id");
  if (classIdRaw) {
    if (!env.DB || !env.KEY_SECRET) return fail(env, origin, 500, "not_ready", "서버에 반 기능이 아직 설정되지 않았어요 (D1·KEY_SECRET)");
    await ensureSchema(env);
    const id = normId(classIdRaw), ip = clientIp(req);
    const keys = [["c:" + id, LIM.failClass, LIM.failWindow], ["ip:" + ip, LIM.failIp, LIM.failWindow]];
    if (await blocked(env, keys)) return fail(env, origin, 429, "locked", "비밀번호를 여러 번 틀려 잠시 막혔어요. 1시간 뒤 다시 해 보세요");
    const row = id && await getClass(env, id);
    if (!row) return fail(env, origin, 404, "class_gone", "반을 찾을 수 없어요 (기간이 끝났거나 닫힌 반이에요)");
    if (!(await pwOk(row, req.headers.get("x-class-pw")))) { await bump(env, keys); return fail(env, origin, 401, "bad_pw", "반 비밀번호가 맞지 않아요"); }
    const up = await env.DB.prepare("UPDATE classes SET calls = calls + 1 WHERE id = ? AND calls < max_calls").bind(id).run();
    if (!up.meta || !up.meta.changes) return fail(env, origin, 429, "limit", `이 반의 호출 한도(${row.max_calls}회)를 다 썼어요. 선생님께 알려 주세요`);
    let key;
    try { key = await openKey(env, row.key_enc); }
    catch (e) { return fail(env, origin, 500, "seal", "서버가 선생님 키를 읽지 못했어요 (KEY_SECRET이 바뀌었으면 반을 새로 만들어 주세요)"); }
    try {
      return json(env, origin, 200, await callAnthropic(env, key, v));
    } catch (e) {
      await env.DB.prepare("UPDATE classes SET calls = MAX(0, calls - 1) WHERE id = ?").bind(id).run();   // 실패한 호출은 세지 않음
      return fail(env, origin, e.status === 429 ? 429 : 502, e.code, API_KO[e.code] || e.message);
    }
  }

  // 예전 방식 (연수 코드)
  const code = req.headers.get("x-class-code");
  if (code != null) {
    if (!env.ANTHROPIC_API_KEY || !env.CLASS_CODE) return fail(env, origin, 500, "not_ready", "서버에 연수 코드 방식이 설정되지 않았어요");
    if (!sameText(String(code), String(env.CLASS_CODE))) return fail(env, origin, 401, "bad_code", "연수 코드가 맞지 않아요");
    try { return json(env, origin, 200, await callAnthropic(env, env.ANTHROPIC_API_KEY, v)); }
    catch (e) { return fail(env, origin, e.status === 429 ? 429 : 502, e.code, (API_KO[e.code] || e.message).replace("선생님의 ", "서버의 ").replace("선생님 ", "서버 ")); }
  }
  return fail(env, origin, 401, "need_class", "반 ID와 비밀번호를 넣어 주세요");
}

async function handleClass(req, env, origin, path, body) {
  if (!env.DB || !env.KEY_SECRET) return fail(env, origin, 500, "not_ready", "서버에 반 기능이 아직 설정되지 않았어요 (D1·KEY_SECRET)");
  await ensureSchema(env);
  const ip = clientIp(req);

  if (path === "/class/create") {
    const apiKey = String(body.apiKey || "").trim().replace(/\s+/g, "");
    if (!/^sk-ant-[A-Za-z0-9_\-]{20,}$/.test(apiKey)) return fail(env, origin, 400, "bad_key", "Anthropic API 키(sk-ant-로 시작)를 넣어 주세요");
    const lim = [["create:" + ip, LIM.createPerIp, DAY]];
    if (await blocked(env, lim)) return fail(env, origin, 429, "too_many", "오늘 이곳에서 만들 수 있는 반을 다 만들었어요. 내일 다시 해 보세요");
    const days = Math.max(1, Math.min(LIM.daysMax, Math.round(Number(body.days) || 7)));
    const maxCalls = Math.max(LIM.callsMin, Math.min(LIM.callsMax, Math.round(Number(body.maxCalls) || 1000)));
    const name = String(body.name || "").replace(/[\r\n\t]+/g, " ").trim().slice(0, 40);
    try { await callAnthropic(env, apiKey, { prompt: "OK라고만 답해.", maxTokens: 5 }); }   // 키 시험 (아주 짧은 글 한 번)
    catch (e) { return fail(env, origin, e.status === 429 ? 429 : 400, e.code, (API_KO[e.code] || e.message).replace("선생님의 API 키를 더 이상 쓸 수 없어요 (키가 삭제되었거나 틀림)", "API 키가 맞지 않아요")); }
    await cleanup(env);
    let id = "";
    for (let i = 0; i < 8 && !id; i++) { const c = newClassId(); if (!(await env.DB.prepare("SELECT 1 FROM classes WHERE id = ?").bind(c).first())) id = c; }
    if (!id) return fail(env, origin, 500, "id", "반 ID를 만들지 못했어요. 다시 눌러 주세요");
    const pw = newPw(), salt = b64url(randBytes(9)), adminToken = b64url(randBytes(24)), now = Date.now();
    await env.DB.prepare(`INSERT INTO classes (id, name, key_enc, key_hint, pw_salt, pw_hash, admin_hash, created_at, expires_at, max_calls, calls)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`).bind(
      id, name, await sealKey(env, apiKey), "…" + apiKey.slice(-4), salt, await sha256hex(salt + ":" + pw),
      await sha256hex("admin:" + adminToken), now, now + days * DAY, maxCalls).run();
    await bump(env, lim);
    return json(env, origin, 200, { ok: true, classId: id, pw, adminToken, name, expiresAt: now + days * DAY, maxCalls, calls: 0, keyHint: "…" + apiKey.slice(-4) });
  }

  const id = normId(body.classId);
  if (path === "/class/join") {
    const keys = [["c:" + id, LIM.failClass, LIM.failWindow], ["ip:" + ip, LIM.failIp, LIM.failWindow]];
    if (await blocked(env, keys)) return fail(env, origin, 429, "locked", "비밀번호를 여러 번 틀려 잠시 막혔어요. 1시간 뒤 다시 해 보세요");
    const row = id && await getClass(env, id);
    if (!row) { await bump(env, [["ip:" + ip, LIM.failIp, LIM.failWindow]]); return fail(env, origin, 404, "class_gone", "그런 반이 없어요 (반 ID를 확인하세요. 기간이 끝난 반일 수도 있어요)"); }
    if (!(await pwOk(row, body.pw))) { await bump(env, keys); return fail(env, origin, 401, "bad_pw", "반 비밀번호가 맞지 않아요"); }
    const info = publicInfo(row);
    return json(env, origin, 200, { ok: true, classId: info.classId, name: info.name, expiresAt: info.expiresAt });
  }

  // 아래는 반을 만든 선생님(관리 토큰)만
  const row = id && await getClass(env, id);
  if (!row) return fail(env, origin, 404, "class_gone", "반이 없어요 (기간이 끝났거나 이미 닫힌 반이에요)");
  if (!(await adminOk(row, req.headers.get("x-admin-token")))) return fail(env, origin, 403, "not_admin", "이 반을 만든 컴퓨터에서만 할 수 있어요");

  if (path === "/class/status") return json(env, origin, 200, Object.assign({ ok: true }, publicInfo(row)));

  if (path === "/class/update") {
    const out = {};
    if (body.newPw) {
      const pw = newPw(), salt = b64url(randBytes(9));
      await env.DB.prepare("UPDATE classes SET pw_salt = ?, pw_hash = ? WHERE id = ?").bind(salt, await sha256hex(salt + ":" + pw), id).run();
      out.pw = pw;
    }
    if (body.days != null) {
      const days = Math.max(1, Math.min(LIM.daysMax, Math.round(Number(body.days) || 7)));
      await env.DB.prepare("UPDATE classes SET expires_at = ? WHERE id = ?").bind(Date.now() + days * DAY, id).run();
    }
    if (body.maxCalls != null) {
      const m = Math.max(LIM.callsMin, Math.min(LIM.callsMax, Math.round(Number(body.maxCalls) || 1000)));
      await env.DB.prepare("UPDATE classes SET max_calls = ? WHERE id = ?").bind(m, id).run();
    }
    const now = await getClass(env, id);
    return json(env, origin, 200, Object.assign({ ok: true }, publicInfo(now), out));
  }

  if (path === "/class/close") {
    await env.DB.prepare("DELETE FROM classes WHERE id = ?").bind(id).run();
    return json(env, origin, 200, { ok: true, closed: id });
  }
  return fail(env, origin, 404, "not_found", "없는 주소예요");
}

export default {
  async fetch(req, env) {
    const origin = (req.headers.get("origin") || "").replace(/\/+$/, "");
    const list = allowedOrigins(env);
    if (origin && list.length && !list.includes(origin)) return new Response("forbidden origin", { status: 403 });
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(env, origin) });
    if (req.method !== "POST") return json(env, origin, 200, { ok: true, service: "pai-vlm", classes: !!(env.DB && env.KEY_SECRET) });
    let body = {};
    try { body = await req.json(); } catch (e) { return fail(env, origin, 400, "bad_json", "요청 형식이 맞지 않아요"); }
    const path = new URL(req.url).pathname.replace(/\/+$/, "") || "/";
    try {
      if (path === "/") return await handleVlm(req, env, origin, body || {});
      if (path.startsWith("/class/")) return await handleClass(req, env, origin, path, body || {});
      return fail(env, origin, 404, "not_found", "없는 주소예요");
    } catch (e) {
      return fail(env, origin, 500, "server", "서버 오류: " + (e && e.message || e));
    }
  }
};
