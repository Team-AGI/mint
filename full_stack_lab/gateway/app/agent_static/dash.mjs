const DAY = 86400000;
const KST = new Intl.DateTimeFormat("en-GB", { timeZone: "Asia/Seoul", year: "numeric", month: "2-digit", day: "2-digit",
  hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" });

function kst(value) {
  const date = new Date(value);
  if (!value || Number.isNaN(date.getTime())) return null;
  const o = Object.fromEntries(KST.formatToParts(date).map((p) => [p.type, p.value]));
  return { y: o.year, mo: o.month, d: o.day, h: o.hour, mi: o.minute, s: o.second };
}

export function koStamp(value, { seconds = false, year = false, full = false, now = Date.now() } = {}) {
  const p = kst(value);
  if (!p) return "—";
  const hm = `${p.h}:${p.mi}${seconds ? `:${p.s}` : ""}`;
  const today = kst(now);
  if (full) return `${p.y}.${p.mo}.${p.d} ${hm}`;
  if (today && today.y === p.y && today.mo === p.mo && today.d === p.d) return hm;
  return `${year ? `${p.y}.` : ""}${p.mo}.${p.d} ${hm}`;
}

export function koClock(date = new Date()) {
  const p = kst(date);
  return p ? `${p.h}:${p.mi}:${p.s}` : "";
}

export function koInput(value) {
  const p = kst(value);
  return p ? `${p.y}.${p.mo}.${p.d} ${p.h}:${p.mi}` : "";
}

export function parseKoStamp(text) {
  const m = /^(\d{4})[.\-/]\s*(\d{1,2})[.\-/]\s*(\d{1,2})[ T]+(\d{1,2}):(\d{2})$/.exec(String(text || "").trim());
  if (!m) return null;
  const [y, mo, d, h, mi] = m.slice(1).map(Number);
  const date = new Date(Date.UTC(y, mo - 1, d, h - 9, mi));
  const two = (n) => String(n).padStart(2, "0");
  return koInput(date) === `${y}.${two(mo)}.${two(d)} ${two(h)}:${two(mi)}` ? date : null;
}

export function koPeriod(since, until) {
  const a = kst(since), b = kst(until);
  if (!a) return b ? `~ ${b.y}.${b.mo}.${b.d} ${b.h}:${b.mi} KST` : "전체 기간";
  const from = `${a.y}.${a.mo}.${a.d} ${a.h}:${a.mi}`;
  const to = !b ? "현재" : b.y === a.y ? `${b.mo}.${b.d} ${b.h}:${b.mi}` : `${b.y}.${b.mo}.${b.d} ${b.h}:${b.mi}`;
  return `${from} – ${to} KST`;
}

export const BASELINE = { "24h": "직전 24시간", "7d": "직전 7일", "30d": "직전 30일" };
export const baseline = (key) => BASELINE[key] || "직전 같은 기간";

export function remaining(value, now = Date.now()) {
  const at = Date.parse(value);
  if (!Number.isFinite(at)) return null;
  const days = Math.ceil((at - now) / DAY);
  const p = kst(at);
  return { days, date: `${Number(p.mo)}월 ${Number(p.d)}일`, soon: days <= 14 };
}

export const NEXT_EXECUTION = { "실행됨": ["allow", "실행됨"], "실행 안 함": ["outline", "실행 안 됨"], "실행 안 됨": ["outline", "실행 안 됨"],
  "실행 미확인": ["alert", "미확인"], "미확인": ["alert", "미확인"] };

export function executionView(row) {
  if (row.decision === "Approval" && !(row.outcome_axes?.execution === "실행됨")) return { tone: "approval", label: "승인 대기", unknown: false };
  const raw = row.outcome_axes?.execution;
  const [tone, label] = NEXT_EXECUTION[raw] || ["outline", raw || "—"];
  return { tone, label, unknown: label === "미확인" };
}

export function nextStep(row, reason = "") {
  const consent = row.policy_id === "P-CONSENT-001";
  if (consent) return { text: "이용 동의 필요", kind: "consent", href: `#/my?${new URLSearchParams({ t: "consent", server: row.server, tool: row.tool })}`, label: "동의 검토" };
  if (row.decision === "Approval") return { text: "관리자 승인 대기", kind: "detail", label: "요청 보기" };
  if (row.decision === "Block") return { text: reason || "사유 미확인", kind: "detail", label: "상세" };
  if (executionView(row).unknown) return { text: "실행 여부 확인 대기", kind: "detail", label: "상세" };
  return { text: "", kind: "none", label: "" };
}

export function consentState(server, rows) {
  const reviewed = (server.tools || []).filter((tool) => tool.scope_reviewed);
  const needed = reviewed.filter((tool) => tool.consent === true);
  const mine = rows.filter((row) => row.server_id === server.server_id);
  if (mine.some((row) => row.status === "PENDING")) return "pending";
  if (mine.some((row) => row.status === "GRANTED")) return "granted";
  if (mine.some((row) => row.status === "DENIED")) return "denied";
  if (mine.length) return "revoked";
  if (!reviewed.length || (server.tools || []).some((tool) => tool.consent === undefined)) return "unknown";
  return needed.length ? "before" : "none";
}

export function hostRows(rows, agents) {
  const hosts = new Map((agents || []).map((a) => [a.endpoint_id, [a.hostname, a.owner_name].filter(Boolean).join(" · ")]));
  const merged = new Map();
  let unlinked = 0;
  for (const row of rows || []) {
    if (row.other || !row.key) continue;
    const host = hosts.get(row.key);
    if (!host) { unlinked += Number(row.total) || 0; continue; }
    merged.set(host, { name: host, value: (merged.get(host)?.value || 0) + (Number(row.total) || 0), key: row.key });
  }
  const list = [...merged.values()].sort((a, b) => b.value - a.value);
  if (unlinked) list.push({ name: "미연결 세션", value: unlinked, key: "" });
  return list;
}

export function mixParts(totals, keys) {
  const sum = keys.reduce((s, k) => s + (totals[k] || 0), 0);
  return keys.map((key) => ({ key, value: totals[key] || 0, pct: sum ? (totals[key] || 0) / sum * 100 : 0 }));
}

export function alertShort(kind, reason) {
  if (kind === "unapproved-endpoint-mcp") return "승인 목록에 없음";
  return reason;
}

export function purposePhrase(text, max = 24) {
  const one = String(text || "").split(/[.\n]/)[0].trim().replace(/\s*(을|를)?\s*(위해|위한|위하여)?\s*(사용|이용|활용)(합니다|한다|함)$/, "").trim();
  return one.length > max ? `${one.slice(0, max - 1)}…` : one || "—";
}

export function reportView(device, now = Date.now()) {
  if (!device) return { state: "", at: null, delayed: false };
  const at = device.last_seen_at || device.heartbeat_at || null;
  const age = at ? now - Date.parse(at) : Infinity;
  return { state: device.managed_state || "", at, delayed: !(age <= 15 * 60000) };
}
