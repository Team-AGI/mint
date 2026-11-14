import { lang, t, clockText, dateTimeText } from "./i18n.mjs";
import { mergeRows, harnessLabel, DECISIONS, EVIDENCE,
  statusView, dedupeItems, connectorControl, pipelineOf, resourceValues, observationRows, listenerCoverage,
  msText, pctText, LATENCY_STAGE, timingRows, privacyText,
  originLabel, denialClass, provenanceView, countView, pager, denialCount } from "./console-state.mjs";
import { scanSummary, intakeCards, intakeStages, riskMix, shadowGroups, shadowPcs, seriesRows, impactRows, serverCards, serverOrder, daysLeft, blockRate, terminationCards, stageCounts, gradeCounts, caseDone, caseDue, reportState, endpointCards, endpointRows, filterEndpoints, userCards, topBlocked, peopleStats, userRows } from "./screens.mjs";
import * as charts from "./charts.mjs";
import { inboxRoute, inboxActions, loadInbox, alertCallsHref, waitText, reviewHref, KIND_LABEL } from "./inbox.mjs";
import { myRoute } from "./my.mjs";
import { purposePhrase, koStamp, koInput, koClock, koPeriod, parseKoStamp, baseline, remaining, executionView, nextStep, hostRows, mixParts, alertShort } from "./dash.mjs";

const TOKEN_KEY = "mcp-console-token";
const THEME_KEY = "mcp-console-theme";
const NAV_KEY = "mcp-console-nav-v4";
const ADMIN_IDLE_MS = 30 * 60 * 1000;
const ADMIN_MAX_MS = 8 * 60 * 60 * 1000;
const SESSION_WARNING_MS = 2 * 60 * 1000;
const token = localStorage.getItem(TOKEN_KEY);
if (!token) location.replace("/login");

function tokenTimes(value) {
  try {
    const encoded = value.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const payload = JSON.parse(atob(encoded.padEnd(Math.ceil(encoded.length / 4) * 4, "=")));
    return { issuedAt: Number(payload.iat) * 1000, expiresAt: Number(payload.exp) * 1000,
      identityBinding: payload.identity_binding || "" };
  } catch { return { issuedAt: 0, expiresAt: 0 }; }
}

const $ = (selector, root = document) => root.querySelector(selector);

class Raw { constructor(s) { this.s = s; } toString() { return this.s; } }
const raw = (s) => new Raw(String(s));
const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (v) => String(v).replace(/[&<>"']/g, (c) => ESC[c]);
const part = (v) => (v instanceof Raw ? v.s : Array.isArray(v) ? v.map(part).join("")
  : v === null || v === undefined || v === false ? "" : esc(v));
function html(strings, ...values) {
  let out = strings[0];
  values.forEach((value, i) => { out += part(value) + strings[i + 1]; });
  return new Raw(out);
}
const short = (text, n = 120) => { const s = String(text ?? ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; };

const entityRef = (value, n = 24) => html`<span class="entity-ref mono" title="${value || ""}">${short(value || "—", n)}</span>`;
const listToolbar = (id, placeholder, value = "") => html`<label class="list-search"><input type="search" data-list-search="${id}" placeholder="${placeholder}" aria-label="${placeholder}" maxlength="120" value="${value}" /><span class="result-count" data-list-count="${id}" role="status"></span></label>`;

function detailText(detail) {
  if (!detail) return "";
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d) => d.msg || JSON.stringify(d)).join(" · ");
  return JSON.stringify(detail);
}

async function api(path, { method = "GET", body, signal } = {}) {
  const response = await fetch(path, {
    method,
    headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "content-type": "application/json" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  });
  const accountStatus = response.headers.get("x-account-status");
  if (response.status === 401 || accountStatus) {
    localStorage.removeItem(TOKEN_KEY);
    location.replace(`/login?${accountStatus ? "account=" + encodeURIComponent(accountStatus) : "session=authentication"}`);
    throw new Error("로그인 만료");
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(typeof data.detail === "string" ? data.detail : "요청 실패");
    error.status = response.status;
    error.detail = data.detail;
    throw error;
  }
  return data;
}
const gw = (path, options) => api(`/gw/${path}`, options);

const DECISION = {
  Allow: ["allow", "허용"], Alert: ["alert", "경보"], Restrict: ["restrict", "제한 실행"],
  Approval: ["approval", "승인 대기"], Block: ["block", "차단"],
};
const ARTIFACT_KIND = { sbom: "SBOM", trivy: "Trivy", semgrep: "Semgrep", gitleaks: "Gitleaks", "exit-terms": "종료 조건" };
const NONE = html`<span class="muted">—</span>`;
const SERVER_STATUS = { READY: "정상", DRIFT: "계약 변경", PENDING: "확인 대기", DISABLED: "사용 중지", ERROR: "연결 오류" };
const serverNeedsAttention = (s) => ["ERROR", "DRIFT", "PENDING"].includes(s.status);
const LIFECYCLE = { OPERATING: "운영", TERMINATING: "종료 중", RETIRED: "폐기" };
const GRADE = { T1: "완전 종료", T2: "부분 종료", T3: "종료 확인 불가" };
const CASE_STATUS = { OPEN: "진행", REVOKING: "회수 중", ASSESSED: "판정됨", CLOSED: "종결", REOPENED: "재개됨" };
const TARGET_KIND = {
  "gateway-route": "게이트웨이 경로", "gateway-access": "사용자 접근", "client-token": "클라이언트 토큰",
  "refresh-token": "갱신 토큰", "dynamic-registration": "동적 클라이언트 등록", session: "MCP 세션",
  "server-held-credential": "서버 보유 자격", "endpoint-config": "엔드포인트 MCP 설정", "api-key": "API 키",
  webhook: "웹훅", "cached-artifact": "캐시 산출물",
};
const HOLDER = { org: "조직", provider: "제공자", endpoint: "엔드포인트" };
const DISCOVERED = {
  "gateway-ledger": "게이트웨이 기록", "endpoint-agent": "엔드포인트 보고", "provider-disclosure": "제공자 고지",
  "operator-manual": "수동 등록", "liveness-probe": "도달 확인",
};
const VERIFICATION = {
  "gateway-probe": "게이트웨이 차단 확인", "endpoint-report": "엔드포인트 보고", "gitea-token": "조직 직접 확인",
  "provider-attestation": "제공자 증명", stateless: "만료 시각", "credential-store": "조직 보관소 확인",
};
const PROVIDER_SIDE = { rejected: "거부 확인", accepted: "수락함", unverified: "미확인" };
const TARGET_STATUS = { OUTSTANDING: ["alert", "미회수"], REVOKED: ["allow", "회수됨"], EXPIRED: ["allow", "만료"], UNVERIFIABLE: ["block", "확인 불가"] };
const COLLECTOR = {
  "config-file": "설정 파일", "proc-socket": "로컬 소켓", "windows-netstat": "로컬 소켓", lsof: "로컬 소켓",
  "network-probe": "네트워크 탐색", "process-table": "프로세스 표", "journal-apparmor": "운영체제 로그 · 실행",
  "journal-nft": "운영체제 로그 · 네트워크", "windows-event-log": "Windows 이벤트 로그", gateway: "게이트웨이",
};
const TRANSFORM = {
  command_sha256: "명령 해시화", url_sha256: "주소 해시화", drop_env_headers: "환경변수·헤더 제외", truncate: "길이 제한",
  path_to_basename: "파일명만 유지", journal_field_allowlist: "허용 필드만 추출", drop_raw_message: "원문 제외",
  event_xml_allowlist: "허용 필드만 추출",
};
const transformLabel = (step) => (step.startsWith("server:") ? "서버 · " : "") + (TRANSFORM[step.replace(/^server:/, "")] || step);
const RECORD_KIND = { config: "MCP 설정", listener: "수신기", "os-event": "엔드포인트 차단", decision: "게이트웨이 판정", "dispatch-intent": "전송 의도", "server-egress": "서버 외부 통신" };
const ENDPOINT_CLASS = { registered: ["allow", "등록 서버"], shadow: ["block", "미등록 MCP"], "retired-residue": ["alert", "폐기 잔존"] };
const CONTROL_STATE = {
  gateway_enforced: ["allow", "게이트웨이 통제"], endpoint_enforced: ["allow", "엔드포인트 통제"],
  vendor_enforced: ["brand", "벤더 통제"], observed_only: ["alert", "관찰만"],
  unknown_not_enrolled: ["outline", "엔드포인트 미등록"], bypass_possible: ["block", "조직 통제 의존"],
};
const INTEGRATION_CLASS = {
  gateway_mcp: "게이트웨이 MCP", gateway_backend_connector: "게이트웨이 연동 SaaS", vendor_native_connector: "벤더 커넥터",
  local_plugin_or_stdio: "로컬 MCP", shadow_or_unknown: "미등록 MCP",
};
const APPROVAL_STATE = {
  approved: "승인", pending: "미승인", unapproved: "미승인", expired: "기한 만료", denied: "거부", default: "기본 승인",
  drift: "계약 변경", disabled: "사용 중지", error: "연결 오류", blocked_supply_chain: "공급망 차단",
};
const PLATFORM = { linux: "Linux", windows: "Windows", wsl: "WSL", macos: "macOS", other: "기타", unknown: "기타" };
const RESPONSE = {
  returned: ["allow", "응답 반환"], masked: ["restrict", "마스킹 반환"], withheld: ["block", "응답 보류"],
  unknown: ["alert", "결과 미확인"], not_executed: ["outline", "실행 안 함"],
};
const controlChip = (s) => chip(...(CONTROL_STATE[s] || ["", s]));
const TONE_DECISION = { allow: "Allow", restrict: "Restrict", alert: "Alert", approval: "Approval", block: "Block", outline: "" };
const responseChip = (s) => chip(...(RESPONSE[s] || ["", s]));
const stateLabel = (s) => (CONTROL_STATE[s] || [, s])[1];
const approvalLabel = (s) => (s ? APPROVAL_STATE[String(s).toLowerCase()] || s : "—");

function statusPair(item) {
  if (item.class === "vendor_native_connector" && item.state === "observed_only" && ["default", "approved"].includes(item.approval?.state)) {
    return html`<span class="pair">${chip("outline", item.approval.state === "default" ? "기본 승인" : "승인")}<span class="ev">벤더 경유</span></span>`;
  }
  const v = statusView(item);
  return html`<span class="pair">${chip(v.tone, stateLabel(v.state))}<span class="ev ${v.stale ? "stale" : ""}">${v.evLabel}</span></span>`;
}
function flow3(r) {
  const label = r.executed ? "실행됨" : r.attempted ? "실행 미확인" : "실행 안 함";
  const notSent = r.event_kind === "mcp-connection" ? chip("block", "연결 거부")
    : r.decision === "Block" ? chip("block", "차단")
      : r.decision === "Approval" ? chip("approval", "승인 대기")
        : chip("outline", "전송 안 함");
  return html`<span class="flow3">${label}</span>${r.executed || r.attempted ? responseChip(r.response) : notSent}`;
}
const UPSTREAM = { executed: ["allow", "실행됨"], unknown: ["alert", "실행 미확인"], not_sent: ["outline", "실행 안 함"] };
function pipeline(r, device) {
  const [, gate, endpoint, upstream, response] = pipelineOf(r);
  const stage = (n, title, body, cls = "") => html`<li class="${cls}"><span class="step-no" aria-hidden="true">${n}</span><b>${title}</b><div class="stage-body">${body}</div></li>`;
  return html`<ol class="pipe" aria-label="호출 경로">
    ${stage(1, "요청", html`<span>${r.harness ? harnessLabel(r.harness) : r.agent || "—"}</span>
      <span class="v">엔드포인트 <code>${r.workstation || "—"}</code></span>`)}
    ${stage(2, "게이트웨이", html`${decisionChip(r.decision)}
      ${gate.state === "refused-connection" ? html`<span class="v">연결 거부</span>` : ""}`, r.decision === "Block" ? "stop" : "")}
    ${stage(3, "엔드포인트", endpoint.state === "bound" ? html`${chip("brand", "인증된 엔드포인트")}${device ? statusPair(device) : ""}`
      : chip("outline", "인증 없음"), endpoint.state === "bound" ? "" : "off")}
    ${stage(4, "도구 실행", chip(...UPSTREAM[upstream.state]), upstream.state === "not_sent" ? "off" : "")}
    ${stage(5, "응답", responseChip(response.state), response.state === "withheld" ? "stop" : "")}
    </ol>`;
}

let planesCache = { at: 0, data: null };
async function planes() {
  if (!viewer.admin) return null;
  if (!planesCache.data || Date.now() - planesCache.at > 15000) planesCache = { at: Date.now(), data: await api("/api/integrations") };
  return planesCache.data;
}
const ACTION = { r: "읽기", w: "쓰기", x: "외부 전송·실행" };
const DATA_CLASS = { public: "공개", nonimportant: "내부", important: "중요" };
const ROLE = { admin: "관리자", employee: "직원", partner: "협력사" };
const PLATFORM_KIT = { linux: "Linux", macos: "macOS", windows: "Windows" };
const KIT_FILE = { linux: "mcp-managed-setup-linux", macos: "mcp-connect-macos.command", windows: "mcp-managed-setup-windows.exe" };
function preferredKitPlatform() {
  return "windows";
}
function kitSteps(os, kit = {}) {
  const run = os === "linux" ? html`<li>터미널에서 실행<code>f="$(ls -t ~/Downloads/${KIT_FILE.linux}* | head -1)" && chmod +x "$f" && "$f"</code><span class="sub">관리자 암호 1회</span></li>`
    : os === "macos" ? html`<li>터미널에서 실행<code>/bin/bash "$HOME/Downloads/${KIT_FILE.macos}"</code><span class="sub">관리자 암호 1회 · 연결 파일 유효 시간 5분</span></li>`
    : html`<li>받은 .exe 파일 실행<span class="sub">관리자 권한 확인 1회 · 지금 계정 그대로</span></li>`;
  const ready = kit.auto_activate === false ? "관리자 활성화 뒤 사용" : "설치가 끝나면 바로 사용";
  return html`<ol class="kit-steps"><li>설치 파일 받기</li>${run}<li>${ready}</li></ol>
    ${os === "linux" ? kv([["제거", html`<code>sudo ~/mcp-managed-kit/install.sh --remove</code>`]]) : ""}`;
}
function kitView(kit, os) {
  const platforms = [...(kit.platforms || [])].sort((a, b) => Number(b === preferredKitPlatform()) - Number(a === preferredKitPlatform()));
  return html`<div class="row-actions">${chip(kit.servers ? "allow" : "outline", kit.servers ? `MCP 서버 ${kit.servers.split(",").length}개` : "사용 가능한 서버 없음")}</div>
    <div class="row-actions" role="group">${platforms.map((name) => html`<button class="btn sm ${name === os ? "primary" : ""}" type="button" aria-pressed="${String(name === os)}" data-act="pc-kit-os" data-os="${name}">${PLATFORM_KIT[name] || "—"}</button>`)}</div>
    ${platforms.includes(os) ? html`${kitSteps(os, kit)}${os === "macos" ? "" : html`<label class="check"><input type="checkbox" name="kit-isolated"> 고급: 격리 계정<span class="sub">관리자 활성화</span></label>`}
      <div class="row-actions kit-download-actions"><button class="btn primary" type="button" data-act="pc-kit-download" data-os="${os}">설치 파일 받기</button></div>` : ""}`;
}
const EXIT_TERMS = {
  provider_credential_disclosure: "보유 자격 고지",
  revocation_evidence: "폐기 기록 제출",
  audit_access_retained: "종료 후 감사 접근",
};
const CRITERIA = { C1: "모집단", C2: "수행 권한", C3: "연속성", C4: "증거 접근" };
const APPROVAL_STATUS = {
  REVOKED: ["block", "승인 번복"],
  APPROVED: ["allow", "승인"], EXECUTED: ["allow", "실행됨"], REJECTED: ["block", "거부"], EXPIRED: ["outline", "만료"],
  NOT_EXECUTED: ["alert", "실행 안 됨"], UNCONFIRMED: ["alert", "실행 미확인"],
};
const REVIEW_KIND = {
  "user-consent": "사용자 동의", "intake-approve": "운영자 승인", "contract-review": "계약 검토", "risk-accept": "위험 수용",
  "risk-lapse": "위험 수용 만료", "intake-reject": "거부", "intake-hold": "보류", "provenance-mismatch": "보류",
  "server-register": "게이트웨이 등록", "tool-scope-review": "범위 심사", "residency-review": "처리 위치 검토", "intake-cosign": "1차 승인", "risk-input": "영향평가 입력",
  "tool-sunset": "자동 비활성", "tool-sunset-extension": "이용 기간 연장", "tool-sunset-review": "도구 재심사",
  "tool-sunset-check": "이용 상태 확인", "tool-approval-extension": "승인 기간 연장",
  "auto-suspend-count-failed": "자동 중지 집계 실패",
  "intake-one-click": "도입 승인",
  "mcp-source-download": "소스 다운로드",
  "local-source-download": "승인 소스 수신",
  "runtime-start": "실행 요청", "runtime-stop": "실행 중지 요청", "runtime-built": "이미지 빌드", "runtime-active": "실행 시작",
  "runtime-rollback": "실행 판본 되돌리기", "runtime-rollback-queued": "실행 판본 전환", "runtime-rollback-refused": "실행 판본 전환 거부", "runtime-rollback-request-refused": "실행 판본 되돌리기 요청 거부",
  "runtime-failed": "실행 실패", "runtime-stopped": "실행 중지", "runtime-egress": "외부 통신", "runtime-image-scan": "이미지 검사",
  "solo-mode": "단독 운영 모드", "ledger-retention": "보존 기간 변경", "audit-annotate": "감사 주석",
  "server-deregister": "게이트웨이 등록 해제", "contract-reapprove": "계약 재승인", "addon-result": "외부 게이트웨이 실행 결과",
  "litellm-sync": "외부 게이트웨이 동기화",
  "automatic-suspension": "자동 중지", "automatic-suspension-resume": "자동 중지 해제",
  "user-server-suspend": "이용 중지", "user-server-resume": "이용 재개", "account-restore": "계정 복구",
  "server-audience": "사용 대상 변경", "upstream-credential-connect": "계정 연결", "upstream-credential-disconnect": "계정 연결 해제",
  "call-request": "중대 영향 요청", "call-explanation-view": "중대 영향 설명 열람", "call-approve": "중대 영향 승인",
  "call-reject": "중대 영향 거부", "call-revoke": "중대 영향 번복",
  "incident-created": "사고 기록 생성", "incident-supplement": "사고 범위 보완", "incident-report": "사고 보고 제출",
  "disposal-reconciled": "폐기 상태 복원", "disposal-integrity-failure": "폐기 목록 확인 실패",
};

const REVIEW_OUTCOME = { approved: ["allow", "승인"], rejected: ["block", "거부"], refused: ["block", "본인 승인 차단"], held: ["alert", "보류"], recorded: ["outline", "기록됨"], failed: ["block", "확인 실패"], verified: ["outline", "동기화 완료"] };
const SCAN_STATE = { DONE: ["allow", "완료"], FAILED: ["block", "실패"] };
const UNSUPPORTED_POLICY = new Set(["PAC-05-DELEGATION-UNSUPPORTED"]);
const INTAKE_STATUS = {
  HOLD: ["outline", "검토 대기"], REMOTE_REVIEWED: ["approval", "계약 검토 완료"], VALIDATION_QUEUED: ["approval", "검증 대기"], VALIDATING: ["approval", "검증 중"],
  VALIDATED: ["restrict", "검증 완료"], APPROVED: ["allow", "승인"], REJECTED: ["block", "거부"], FAILED: ["alert", "검증 실패"],
};

const chip = (tone, label) => html`<span class="chip ${tone}">${label}</span>`;
const sameSite = (u) => { try { const x = new URL(u, location.href); return x.hostname === location.hostname ? x.pathname + x.search + x.hash : u; } catch { return u; } };
const decisionChip = (d) => chip(...(DECISION[d] || ["", d]));
const gradeChip = (g, prefix = "") => (g ? chip(g, `${prefix}${GRADE[g]}`) : chip("outline", "미판정"));
const REL_STATUS = { ACTIVE: ["outline", "이용 중"], TERMINATED: ["block", "종료"], TERMINATING: ["alert", "종료 중"], SUSPENDED: ["alert", "중지"] };
const bool = (v, label) => (v ? chip("allow", label) : chip("block", label));
const pad = (n) => String(n).padStart(2, "0");
const MONTH = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const dayLabel = (d) => (lang() === "en" ? `${MONTH[d.getMonth()]} ${d.getDate()}` : `${pad(d.getMonth() + 1)}-${pad(d.getDate())}`);
function when(value, { seconds = false, year = false } = {}) {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  const hm = `${pad(d.getHours())}:${pad(d.getMinutes())}${seconds ? `:${pad(d.getSeconds())}` : ""}`;
  if (lang() !== "en") {
    const day = `${pad(d.getMonth() + 1)}.${pad(d.getDate())}`;
    if (year) return `${d.getFullYear()}.${day} ${hm}`;
    return d.toDateString() === new Date().toDateString() ? hm : `${day} ${hm}`;
  }
  return d.toDateString() === new Date().toDateString() && !year ? hm : `${year ? `${d.getFullYear()} ` : ""}${dayLabel(d)} ${hm}`;
}
function dateTimeInput(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}
function ago(value) {
  if (!value) return "—";
  const s = Math.round((Date.now() - new Date(value).getTime()) / 1000);
  if (s < 60) return "방금";
  if (s < 3600) return `${Math.floor(s / 60)}분 전`;
  if (s < 86400) return `${Math.floor(s / 3600)}시간 전`;
  return `${Math.floor(s / 86400)}일 전`;
}
const json = (v) => html`<pre class="json">${JSON.stringify(v, null, 2)}</pre>`;
const kv = (pairs) => html`<dl class="kv">${pairs.filter(([, v]) => v !== undefined && v !== null && v !== "")
  .map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}</dl>`;
const empty = (text, { filtered = false, failed = false } = {}) => html`<p class="empty" role="${failed ? "alert" : "status"}">${failed ? "조회 실패" : filtered ? "조건에 맞는 결과 없음" : text}</p>`;
const OUTCOME_TONE = [["차단", "Block"], ["승인", "Approval"], ["경보", "Alert"], ["제한", "Restrict"], ["허용", "Allow"]];
const outcomeDecision = (text) => (OUTCOME_TONE.find(([word]) => String(text || "").includes(word)) || [])[1];

const ICON = {
  consent: '<path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>',
  pause: '<rect width="4" height="16" x="6" y="4" rx="1" fill="currentColor" stroke="none"/><rect width="4" height="16" x="14" y="4" rx="1" fill="currentColor" stroke="none"/>',
  play: '<path d="m7 4 13 8-13 8Z" fill="currentColor" stroke="none"/>',
  refresh: '<path d="M20 11a8.1 8.1 0 0 0-15.5-2M4 4v5h5"/><path d="M4 13a8.1 8.1 0 0 0 15.5 2M20 20v-5h-5"/>',
  overview: '<rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/>',
  activity: '<path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/>',
  audit: '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="m9 15 2 2 4-4"/>',
  approvals: '<rect width="8" height="4" x="8" y="2" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="m9 14 2 2 4-4"/>',
  servers: '<rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6 6h.01M6 18h.01"/>',
  coverage: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>',
  people: '<path d="M18 5a2 2 0 0 1 2 2v8.5a2 2 0 0 0 .2.9l1.1 2.1a1 1 0 0 1-.9 1.5H3.6a1 1 0 0 1-.9-1.5l1.1-2.1a2 2 0 0 0 .2-.9V7a2 2 0 0 1 2-2z"/><path d="M20 16H4"/>',
  intake: '<path d="M16 16h6M19 13v6"/><path d="M21 10V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l2-1.14"/><path d="M3.3 7 12 12l8.7-5M12 22V12"/>',
  termination: '<path d="m19 5 3-3M2 22l3-3"/><path d="M6.3 20.3a2.4 2.4 0 0 0 3.4 0L12 18l-6-6-2.3 2.3a2.4 2.4 0 0 0 0 3.4Z"/><path d="M7.5 13.5 10 11M10.5 16.5 13 14"/><path d="m12 6 6 6 2.3-2.3a2.4 2.4 0 0 0 0-3.4l-2.6-2.6a2.4 2.4 0 0 0-3.4 0Z"/>',
  git: '<line x1="6" x2="6" y1="3" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/>',
  plug: '<path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z"/>',
  policy: '<path d="m16 16 3-8 3 8c-.9.7-1.9 1-3 1s-2.1-.3-3-1Z"/><path d="m2 16 3-8 3 8c-.9.7-1.9 1-3 1s-2.1-.3-3-1Z"/><path d="M7 21h10M12 3v18M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2"/>',
};
ICON.endpoints = ICON.people;
ICON.security = ICON.coverage;
ICON.inbox = ICON.approvals;
ICON.connections = ICON.coverage;
ICON.my = ICON.consent;
const icon = (name) => raw(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON[name] || ""}</svg>`);

let toastTimer;
function toast(message, bad = false) {
  const el = $("#toast");
  el.innerHTML = String(kv([["상태", bad ? "요청 실패" : "완료"], [bad ? "사유" : "결과", message]]));
  el.setAttribute("role", bad ? "alert" : "status");
  el.className = bad ? "toast bad" : "toast";
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, bad ? 8000 : 4000);
}

let drawerReturn = null;
let detailSeq = 0;
function setDrawer(open) {
  const drawer = $("#drawer");
  drawer.classList.toggle("open", open);
  drawer.setAttribute("aria-hidden", String(!open));
  drawer.inert = !open;
  if (open && !drawer.open) drawer.showModal();
  if (!open && drawer.open) drawer.close();
}
function openDrawer(title, body, tabs = null) {
  detailSeq += 1;
  if (!$("#drawer").classList.contains("open")) drawerReturn = document.activeElement;
  $("#drawer-title").textContent = title;
  $("#drawer-body").innerHTML = String(tabs ? html`${body}${tabBar(tabs, tabs.some((t) => t.key === current.query?.get("dt")) ? current.query.get("dt") : tabs[0].key, "d")}${tabs.map((t) => tabPanel(t.key, tabs.some((t) => t.key === current.query?.get("dt")) ? current.query.get("dt") : tabs[0].key, t.body, "d"))}` : body);
  setDrawer(true);
  $("#drawer-body").scrollTop = 0;
}
function routeHash(q = current.query) {
  return `#/${current.page}${current.arg ? `/${encodeURIComponent(current.arg)}` : ""}${q.size ? `?${q}` : ""}`;
}
function rememberDetail(id, kind = "decision") {
  const q = new URLSearchParams(current.query);
  const opened = q.has("d") || q.has("record_id") || q.has("detail_id");
  const previous = routeHash(q);
  q.delete("d"); q.delete("record_kind"); q.delete("record_id"); q.delete("detail_kind"); q.delete("detail_id");
  if (id) {
    if (kind === "decision") q.set("d", id);
    else if (["config", "listener", "os-event"].includes(kind)) { q.set("record_kind", kind); q.set("record_id", id); }
    else { q.set("detail_kind", kind); q.set("detail_id", id); }
  } else q.delete("dt");
  if (id && ((kind === "decision" && current.query.get("d") !== String(id)) ||
      (!["decision", "config", "listener", "os-event"].includes(kind) && current.query.get("detail_id") !== String(id)) ||
      (["config", "listener", "os-event"].includes(kind) && current.query.get("record_id") !== String(id)))) q.delete("dt");
  if (q.toString() === current.query.toString()) return;
  if (id && !opened) history.pushState({ ...history.state, detailEntry: previous }, "", routeHash(q));
  else history.replaceState(history.state, "", routeHash(q));
  current.query = q;
}

function closeDrawer() {
  if (history.state?.detailEntry && (current.query?.has("d") || current.query?.has("record_id") || current.query?.has("detail_id") || current.arg)) history.back();
  else if (/^#\/servers\/./.test(location.hash)) history.replaceState(null, "", "#/servers");
  else if (current.query?.has?.("d") || current.query?.has?.("record_id") || current.query?.has?.("detail_id")) rememberDetail(null);
  const wasOpen = $("#drawer").classList.contains("open");
  setDrawer(false);
  if (wasOpen && drawerReturn?.isConnected) drawerReturn.focus();
  drawerReturn = null;
}
function ask({ title, body = "", fields = "", confirm = "확인", danger = false, disabled = false, reject = false }) {
  const dialog = $("#dialog");
  const form = $("#dialog-form");
  form.innerHTML = String(html`<h3 id="dialog-title">${title}</h3>${body ? html`<p>${body}</p>` : ""}${fields}
    <div class="row"><button class="btn ${danger ? "danger solid" : "primary"}" value="ok" ${disabled ? raw("disabled") : ""}>${confirm}</button>
    ${reject ? html`<button class="btn danger" value="reject" formnovalidate>거부</button>` : ""}
    <button class="btn" value="cancel" formnovalidate>취소</button></div>`);
  dialog.returnValue = "";
  dialog.showModal();
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => {
      if (!["ok", "reject", "load"].includes(dialog.returnValue)) { resolve(null); return; }
      const data = new FormData(form); data.set("dialog_action", dialog.returnValue); resolve(data);
    }, { once: true });
  });
}

function tabBar(tabs, active, scope = "p") {
  return html`<div class="tabs" role="tablist">${tabs.map((t) => html`<button class="tab" role="tab" type="button"
    id="${scope}-tab-${t.key}" aria-controls="${scope}-panel-${t.key}" aria-selected="${String(t.key === active)}"
    tabindex="${t.key === active ? 0 : -1}" data-act="tab" data-tab="${t.key}">${t.label}${t.n !== undefined && t.n !== null
      ? html`<span class="n ${t.hot ? "hot" : ""}">${t.n}</span>` : ""}</button>`)}</div>`;
}
function tabPanel(key, active, body, scope = "p") {
  return html`<section class="tabpanel" role="tabpanel" id="${scope}-panel-${key}" aria-labelledby="${scope}-tab-${key}"
    data-panel="${key}" ${key === active ? "" : raw("hidden")}>${body}</section>`;
}
function page({ head, kpis = "", tabs, active }) {
  const current = tabs.some((t) => t.key === active) ? active : tabs[0].key;
  return tabs.length < 2 ? html`${head}${kpis}${tabs[0].body}`
    : html`${head}${kpis}${tabBar(tabs, current)}${tabs.map((t) => tabPanel(t.key, current, t.body))}`;
}
const head = (title, { status = "", actions = "", back = "" } = {}) => html`<div class="page-head">
  ${back}<div class="heading"><h1>${title}</h1>${status ? html`<div class="status">${status}</div>` : ""}</div>
  ${actions ? html`<div class="actions">${actions}</div>` : ""}</div>`;
const kpiStrip = (items, variant = "compact") => html`<div class="kpis kpis-${items.length} ${variant}">${items.map(([label, value, tone = "", href = ""]) => [label, value,
  value == null || value === "—" || value === 0 || value === "0" ? "" : tone, href]).map(([label, value, tone, href]) => href
  ? html`<a class="kpi ${tone}" href="${href}"><div class="label">${label}</div><div class="value">${value ?? "—"}</div></a>`
  : html`<div class="kpi ${tone}"><div class="label">${label}</div><div class="value">${value ?? "—"}</div></div>`)}</div>`;
const rowMenu = (items, label = "관리") => html`<details class="row-menu"><summary class="btn sm">${label}</summary><div class="menu" role="menu">${items}</div></details>`;
const panel = (title, body, { sub = "", status = "", tools = "", flush = false, end = "" } = {}) => html`<section class="panel">
  <header><h2>${title}</h2>${status}${sub ? html`<span class="sub">${sub}</span>` : ""}${end ? html`<div class="tools-end">${end}</div>` : ""}</header>
  ${tools ? html`<div class="tools">${tools}</div>` : ""}
  <div class="body ${flush ? "flush" : ""}">${body}</div></section>`;
const chartBox = (id, label, size = "") => html`<div class="chart ${size}" id="${id}" role="img" aria-label="${label}"></div>`;

const PAGES = [
  { id: "overview", label: "대시보드", group: "운영" },
  { id: "inbox", label: "처리함", group: "운영", badge: "inbox" },
  { id: "activity", label: "호출·감사", group: "운영" },
  { id: "intake", label: "도입 심사", group: "MCP 수명주기", badge: "intake" },
  { id: "servers", label: "MCP 서버", group: "MCP 수명주기" },
  { id: "connections", label: "연결 통제", group: "MCP 수명주기", badge: "coverage" },
  { id: "termination", label: "종료·폐기", group: "MCP 수명주기", badge: "termination" },
  { id: "people", label: "사용자", group: "사람·기기" },
  { id: "endpoints", label: "엔드포인트", group: "사람·기기" },
  { id: "policy", label: "정책", group: "정책" },
];
const STAFF_PAGES = [
  { id: "my", label: "내 MCP", group: "내 이용", badge: "consent" },
  { id: "activity", label: "내 호출", group: "내 이용" },
];
let viewer = null;
let routeSeq = 0;
let current = { page: "", arg: "", query: new URLSearchParams() };
const badges = { inbox: 0, intake: 0, termination: 0, coverage: 0, consent: 0 };

function userMenu() {
  const items = [
    viewer.admin && viewer.pages.includes("my") && html`<a href="#/my" data-i18n-ctx="nav">${icon("my")}<span>내 MCP</span>${badges.consent ? html`<span class="count">${badges.consent}</span>` : ""}</a>`,
    viewer.kit && html`<a href="#" data-i18n-ctx="nav" data-act="pc-kit">${icon("plug")}<span>PC 연결 설정</span></a>`,
    viewer.git_url && html`<a href="${sameSite(viewer.git_url)}" data-i18n-ctx="nav" target="_blank" rel="noopener">${icon("git")}<span>승인된 MCP 저장소</span><span class="ext" aria-hidden="true">↗</span></a>`,
  ].filter(Boolean);
  if (!items.length) return html`${viewer.name} · ${viewer.role_label}`;
  return html`<details class="row-menu user-menu"><summary class="btn ghost">${viewer.name} · ${viewer.role_label}</summary>
    <div class="menu" role="menu">${items}</div></details>`;
}

function renderNav(active) {
  const groups = new Map();
  for (const p of (viewer.admin ? PAGES : STAFF_PAGES).filter((x) => viewer.pages.includes(x.id))) {
    if (!groups.has(p.group)) groups.set(p.group, []);
    groups.get(p.group).push({ ...p, count: badges[p.badge] });
  }
  $("#nav").innerHTML = String(html`${[...groups].map(([group, pages]) => html`<div class="group" data-i18n-ctx="group">${group}</div>${pages.map((p) => html`
    <a href="#/${p.id}" data-i18n-ctx="nav" title="${p.label}" aria-label="${p.label}" ${active === p.id ? raw('aria-current="page"') : ""}>${icon(p.id)}<span>${p.label}</span>
      ${p.count ? html`<span class="count">${p.count}</span>` : ""}</a>`)}`)}`);
  const identity = $("#app-identity");
  if (identity) identity.innerHTML = String(userMenu());
}

function setNavCollapsed(closed) {
  document.documentElement.classList.toggle("nav-collapsed", closed);
  const button = document.querySelector('[data-act="sidebar"]');
  button.setAttribute("aria-expanded", String(!closed));
  button.setAttribute("aria-label", closed ? "메뉴 펼치기" : "메뉴 접기");
  button.title = closed ? "메뉴 펼치기" : "메뉴 접기";
}

function parseHash() {
  const [path, query = ""] = location.hash.replace(/^#\/?/, "").split("?");
  const [page = "", arg = ""] = path.split("/").map(decodeURIComponent);
  return { page, arg, query: new URLSearchParams(query) };
}

function canonicalRoute(at) {
  const t = at.query.get("t");
  const go = (page, tab, extra = {}) => {
    const query = new URLSearchParams(at.query);
    query.delete("t");
    query.delete("approval_view");
    if (tab) query.set("t", tab);
    for (const [key, value] of Object.entries(extra)) query.set(key, value);
    return { page, arg: "", query };
  };
  if (at.page === "consent") return go("my", "consent");
  if (at.page === "intake" && !viewer.admin) return go("my", { approved: "available", list: "mine", new: "new" }[t] || "available");
  if (!viewer.admin) return at;
  if (at.page === "security") return go("activity", { integration: "audit", incidents: "incidents" }[t] || "alerts");
  if (at.page === "overview" && t === "approvals") return go("inbox", "", at.query.get("approval_view") === "history" ? { view: "history" } : {});
  if ((at.page === "overview" && t === "unsent") || (at.page === "activity" && t === "unsent")) return go("inbox", "", { f: "execution" });
  if ((at.page === "activity" && t === "approval-history") || (at.page === "approvals" && t === "history")) return go("inbox", "", { view: "history" });
  if (at.page === "approvals") return t === "consent" ? go("my", "consent") : t === "unsent" ? go("inbox", "", { f: "execution" }) : go("inbox");
  const destinations = {
    overview: at.query.get("t") === "traffic" ? ["activity", "live"] : ["connections", "items"],
    audit: at.query.get("t") === "incidents" ? ["activity", "incidents"]
      : at.query.get("t") === "siem" ? ["activity", "audit"] : ["activity", "live"],
    activity: at.query.get("t") === "siem" ? ["activity", "audit"] : ["activity", "live"],
    people: ["endpoints", at.query.get("t")],
    coverage: [at.query.get("t") === "devices" ? "endpoints" : "connections", at.query.get("t") || "items"],
    servers: at.query.get("t") === "contract" ? ["servers", "servers"] : ["connections", "shadow"],
    "sbom-impact": ["servers", "supply"],
    intake: ["servers", "supply"],
    policy: ["servers", "tools"],
  };
  const moved = (page, tab) => ({ page, arg: at.arg, query: new URLSearchParams([...at.query].map(([k, v]) => [k, k === "t" && tab ? tab : v])) });
  if (at.page === "servers" && ["items", "vendor"].includes(at.query.get("t"))) return moved("connections");
  if (at.page === "servers" && at.query.get("t") === "capabilities") return moved("servers", "tools");
  if (at.page === "servers" && at.query.get("impact") === "1" && at.query.get("t") !== "supply") return moved("servers", "supply");
  if (at.page === "endpoints" && at.query.get("t") === "shadow") return moved("connections");
  if (at.page === "activity" && !["events", "siem"].includes(at.query.get("t"))) return at;
  if (at.page === "overview" && !["planes", "traffic"].includes(at.query.get("t"))) return at;
  if (at.page === "policy" && at.query.get("t") !== "capabilities") return at;
  if (at.page === "people" && !["devices", "managed"].includes(at.query.get("t"))) return at;
  if (at.page === "servers" && !["shadow", "contract"].includes(at.query.get("t"))) return at;
  if (at.page === "intake" && at.query.get("t") !== "impact") return at;
  if (!Object.hasOwn(destinations, at.page)) return at;
  const target = destinations[at.page];
  const query = new URLSearchParams(at.query);
  query.set("t", target[1]);
  if (at.page === "sbom-impact" || (at.page === "intake" && at.query.get("t") === "impact")) query.set("impact", "1");
  if ((at.page === "audit" && target[1] === "live") || (at.page === "activity" && at.query.get("t") === "events")) {
    if (!query.has("since")) query.set("since", "");
    if (!query.has("event_kind")) query.set("event_kind", "");
  }
  if (at.page === "overview" && at.query.get("t") === "traffic") {
    if (!query.has("since")) query.set("since", new Date(Date.now() - 86400000).toISOString());
    if (!query.has("event_kind")) query.set("event_kind", "tools/call");
  }
  return { page: target[0], arg: at.page === "overview" ? "" : at.arg, query };
}

async function route() {
  detailSeq += 1;
  if (matchMedia("(max-width: 900px)").matches) setNavCollapsed(true);
  stopLive();
  stopSystemMetrics();
  stopIntake();
  stopDashboardRefresh();
  setDrawer(false);
  charts.disposeAll();
  const requested = parseHash();
  const at = canonicalRoute(requested);
  if (at !== requested) history.replaceState(null, "", `#/${at.page}${at.arg ? `/${encodeURIComponent(at.arg)}` : ""}?${at.query}`);
  const id = viewer.pages.includes(at.page) ? at.page : viewer.pages[0];
  if (id !== at.page) { history.replaceState(null, "", `#/${id}`); return route(); }
  current = at;
  renderNav(id);
  const seq = ++routeSeq;
  const view = $("#view");
  if (view.dataset.page !== id) view.innerHTML = '<p class="skeleton">불러오는 중…</p>';
  view.dataset.page = id;
  const moved = view.dataset.at !== `${id}/${at.arg}`;
  if (moved && ["servers", "endpoints", "connections"].includes(id)) resetCoveragePaging();
  view.dataset.at = `${id}/${at.arg}`;
  try {
    const out = await ROUTES[id](at.arg, at.query.get("t") || "", at.query);
    if (seq !== routeSeq) return;
    view.innerHTML = String(out.html ?? out) + String(out.dock ?? "");
    if (id === "intake") intakeRendered = String(out.html);
    charts.register(out.charts);
    charts.mountVisible(view);
    const h1 = $("h1", view);
    if (h1) {
      document.title = `${t(h1.textContent.trim())} · MINT`;
      if (moved) { h1.tabIndex = -1; h1.focus(); }
    }
    out.after?.();
    if (at.query.get("d") && /^\d+$/.test(at.query.get("d"))) await showDecision(at.query.get("d"));
    else if (["config", "listener", "os-event"].includes(at.query.get("record_kind")) && /^\d+$/.test(at.query.get("record_id") || ""))
      await ACTIONS["endpoint-record"]({ dataset: { kind: at.query.get("record_kind"), id: at.query.get("record_id") } });
    else if (["approval", "relationship", "intake-report", "audit-event", "alert-detail", "incident-evidence", "integration", "policy", "organization-policy", "connector", "target", "endpoint-device"].includes(at.query.get("detail_kind")) && at.query.get("detail_id"))
      await ACTIONS[at.query.get("detail_kind")]({ dataset: { id: at.query.get("detail_id"), key: at.query.get("detail_id") } });
  } catch (error) {
    if (seq === routeSeq) view.innerHTML = String(empty("", { failed: true }));
  }
}
const reload = () => current.page === "intake" && !current.arg && parseHash().page === "intake"
  && parseHash().query.get("t") !== "new" ? refreshIntake() : route();

function rememberTab(key) {
  const q = new URLSearchParams(current.query);
  q.set("t", key);
  current.query = q;
  history.replaceState(history.state, "", routeHash(q));
}

const ALERT_KIND = { "unapproved-endpoint-mcp": "미등록 MCP 사용", "endpoint-quarantined": "엔드포인트 격리", "unapproved-connection": "미승인 연결", "call-burst": "호출 급증",
  "new-tool": "새 도구", "incident-deadline": "사고 보고 기한", "policy-self-test-failed": "정책 점검 실패" };
const ALERT_SEEN_KEY = "mcp-console-alerts-seen";
const alertsSeen = () => { try { const ranges = JSON.parse(localStorage.getItem(`${ALERT_SEEN_KEY}-${viewer.user_id}`) || "[]"); return Array.isArray(ranges) ? ranges.filter((p) => Array.isArray(p) && p.length === 2 && p.every(Number.isSafeInteger) && p[0] <= p[1]) : []; } catch { return []; } };
function markAlertsSeen(alerts) {
  const ranges = [...alertsSeen(), ...alerts.map((a) => [Number(a.id), Number(a.id)])].sort((a,b) => a[0]-b[0]);
  const merged = [];
  for (const pair of ranges) {
    const last = merged.at(-1);
    if (last && pair[0] <= last[1] + 1) last[1] = Math.max(last[1], pair[1]);
    else merged.push([...pair]);
  }
  try { localStorage.setItem(`${ALERT_SEEN_KEY}-${viewer.user_id}`, JSON.stringify(merged)); } catch { }
  refreshAlertBell();
}
function showAlertCount(n) {
  const count = $("#alert-count");
  count.hidden = !n;
  count.textContent = n > 99 ? "99+" : String(n);
  $("#alert-bell").setAttribute("aria-label", n ? `읽지 않음 ${n}건` : "읽지 않음");
}
async function refreshAlertBell() {
  if (!viewer.admin) return;
  $("#alert-bell").hidden = false;
  try {
    const data = await gw(`audit/alerts?limit=1&read_ranges=${encodeURIComponent(alertsSeen().map(([a,b]) => a === b ? String(a) : `${a}-${b}`).join(","))}`);
    showAlertCount(data.unread_count ?? 0);
  } catch {  }
}
function shadowLink(endpoint, kind, id) {
  const q = new URLSearchParams({ t: "shadow" });
  if (endpoint) q.set("endpoint", endpoint);
  if (["config", "listener", "os-event"].includes(kind) && /^\d+$/.test(String(id || ""))) {
    q.set("record_kind", kind); q.set("record_id", id);
  }
  return `#/connections?${q}`;
}
const alertTarget = (a) => {
  const e = a.evidence || {};
  const person = a.owner_name || e.owner_name;
  const target = [...new Set([a.hostname || e.hostname, person].filter(Boolean))].join(" · ") || "—";
  if ((e.policy_id || "").startsWith("MCP-SHADOW-") || a.kind === "unapproved-endpoint-mcp") return [target, shadowLink(e.endpoint_id, e.record_kind, e.record_id)];
  if (a.kind === "endpoint-quarantined") return [target, `#/endpoints?t=devices&endpoint=${encodeURIComponent(e.endpoint_id || "")}`];
  if (a.kind === "incident-deadline") return [`${e.jurisdiction || ""} ${e.stage || ""}`.trim() || "—", "#/activity?t=incidents"];
  if (e.server_id) return [a.server_name || e.server_id, `#/servers/${encodeURIComponent(e.server_id)}`];
  return ["—", ""];
};
const alertReason = (a) => alertShort(a.kind, alertDetail(a));
const alertDetail = (a) => {
  const e = a.evidence || {};
  if (e.reason) return e.reason;
  if (a.kind === "unapproved-endpoint-mcp") return [e.channel, e.place].filter(Boolean).join(" · ");
  if (a.kind === "endpoint-quarantined") return [...(e.files || []).map((f) => `${f} 변경`), ...(e.checks || []).map((c) => `${CHECK_LABEL[c] || "점검"} 실패`)].join(" · ");
  if (a.kind === "new-tool") return (e.added || []).join(", ");
  return e.policy_id ? policyLabel(e.policy_id) : "";
};

async function refreshBadges() {
  try {
    badges.consent = new Set((await api("/api/consents")).consents.filter((c) => c.status === "PENDING").map((c) => c.server_id)).size;
  } catch {  }
  if (!viewer.pages.includes("overview")) return renderNav($("#view").dataset.page);
  try {
    const [o, conn, queue] = await Promise.all([gw("overview"), api("/api/connectors?summary=1"), loadInbox(inboxContext()).catch(() => null)]);
    badges.inbox = queue ? queue.items.length : o.pending_approvals;
    badges.intake = o.intake_actions || 0;
    badges.termination = o.termination?.overdue || 0;
    badges.coverage = conn.summary.pending + conn.summary.expired;
    renderNav($("#view").dataset.page);
  } catch {  }
}

const modeChip = (mode) => chip(mode === "enforce" ? "allow" : "alert", mode === "enforce" ? "집행 모드" : "관찰 모드");
const HEALTH_LABEL = { gateway: "게이트웨이", postgresql: "데이터베이스", opa: "정책 엔진",
  presidio_analyzer: "개인정보 분석기", presidio_anonymizer: "개인정보 익명화기" };
function componentHealth(health) {
  if (!health?.components) return chip("alert", "구성 요소 확인 불가");
  const issues = Object.entries(HEALTH_LABEL).filter(([key]) => health.components[key] !== true).map(([, label]) => label);
  if (health.policy?.matches === false) issues.push("정책 설정");
  if (health.status !== "ok" && !issues.length && health.components.jaeger !== false) issues.push("상태 상세 확인");
  const tracingIssue = health.components.jaeger === false;
  return html`${chip(issues.length ? "alert" : "allow", issues.length ? "구성 요소 확인 필요" : "구성 요소 정상")}
    ${issues.length || tracingIssue ? html`<span class="health-detail">${[...issues, ...(tracingIssue ? ["추적 수집기"] : [])].join(", ")}</span>` : ""}`;
}

const decisionReason = (r) => ({ "P-RATE-003": "중복 호출 차단", "P-CONSENT-001": "이용 동의 필요" }[r.policy_id]
  || policyLedger.find((p) => p.policy_id === r.policy_id)?.name || "사유 미확인");
function decisionRow(r) {
  return html`<tr class="clickable" tabindex="0" data-act="decision" data-id="${r.id}">
    <td class="t">${when(r.at, { seconds: true })}</td>
    <td>${decisionChip(r.decision)}${r.invalid ? chip("outline", "무효 처리") : ""}</td>
    <td class="who-cell"><b>${r.who}</b></td>
    <td><b>${r.server_name || r.server}</b><span class="sub mono">${r.tool}</span>${r.decision === "Block" ? html`<span class="sub">${decisionReason(r)}</span>` : ""}</td>
    <td>${TOOL_PATH.gateway[1]}</td><td>${r.outcome_axes?.execution || "—"}</td><td>${outcomeSummary({ task: r.outcome_axes?.task })}</td></tr>`;
}
const OUTCOME_LABELS = { route: "경로", connection: "연결", decision: "정책 판정", execution: "도구 실행", task: "업무 결과", effect: "독립 효과" };
function outcomeChips(axes) {
  const tone = (value) => ["연결 성공", "허용", "업무 성공", "실행됨"].includes(value) ? "allow"
    : ["연결 실패", "정책 거부", "통제 장애 차단", "도구 오류", "제공자 인증 실패", "제공자 접근 거부", "제공자 한도 초과"].includes(value) ? "block" : "outline";
  return html`<div class="outcome-axes">${Object.entries(OUTCOME_LABELS).map(([key, label]) => html`<div class="row-actions"><span>${label}</span>${chip(tone(axes?.[key]), axes?.[key] || "—")}</div>`)}</div>`;
}
function outcomeSummary(axes) {
  const bad = ["연결 실패", "정책 거부", "통제 장애 차단", "도구 오류", "제공자 인증 실패", "제공자 접근 거부", "제공자 한도 초과"];
  const key = Object.keys(OUTCOME_LABELS).find((k) => bad.includes(axes?.[k]));
  if (key) return html`${chip("block", axes[key])}<span class="sub">${OUTCOME_LABELS[key]}</span>`;
  const done = axes?.task || axes?.connection;
  return done ? html`${chip(["업무 성공", "연결 성공"].includes(done) ? "allow" : "outline", done)}${axes?.effect ? html`<span class="sub">${OUTCOME_LABELS.effect} ${axes.effect}</span>` : ""}` : "—";
}
const decisionTable = (rows, id = "") => html`<table class="data call-table"><thead><tr><th>시각</th><th>판정</th><th>사용자</th>
  <th>도구</th><th>경로</th><th>도구 실행</th><th>업무 결과</th></tr></thead><tbody ${id ? raw(`id="${id}"`) : ""}>${rows.map(decisionRow)}</tbody></table>`;

const VALIDITY = { 1: "1일", 30: "30일", 90: "90일", 180: "180일", 365: "1년" };
const AUDIENCE = { all: "전체 직원", requester: "신청자만", selected: "지정 직원" };
const audienceFields = (cur) => html`<label>사용 대상<select name="audience" data-audience>${Object.entries(AUDIENCE).map(([v, l]) =>
  html`<option value="${v}" ${v === cur ? raw("selected") : ""}>${l}</option>`)}</select></label>
  <label data-audience-users ${cur === "selected" ? "" : raw("hidden")}>지정 직원<input name="audience_users" maxlength="2000" placeholder="아이디, 아이디" /></label>`;
const audienceBody = (fd) => {
  const audience = String(fd.get("audience") || "all");
  return { audience, audience_users: audience === "selected" ? String(fd.get("audience_users") || "").split(",").map((v) => v.trim()).filter(Boolean) : [] };
};
const audienceText = (principals) => (principals || []).includes("*") ? AUDIENCE.all : (principals || []).join(", ") || NONE;
function validityChip(registration) {
  const until = registration?.valid_until ? new Date(registration.valid_until).getTime() : NaN;
  if (!Number.isFinite(until)) return NONE;
  const days = Math.ceil((until - Date.now()) / 86400000);
  return days <= 0 ? chip("block", "만료") : chip(days <= 14 ? "alert" : "outline", `${days}일 남음`);
}

const ROUTES = {};

let metricsTimer = null;
let metricsRequest = null;
function stopSystemMetrics() {
  clearInterval(metricsTimer);
  metricsTimer = null;
  metricsRequest?.abort();
  metricsRequest = null;
}
function metricsCards(sample, failure = false) {
  const values = resourceValues(sample);
  return html`<div class="system-values">${[
    ["CPU 부하", values.cpu], ["메모리 사용", values.memory], ["콘솔 서버 → 게이트웨이 연결 시간", values.latency],
  ].map(([label, value]) => html`<div class="system-stat"><span>${label}</span><b>${value}</b></div>`)}</div>
    <div class="system-time">${failure ? "확인 실패" : values.measuredAt
      ? `확인 ${clockText(new Date(values.measuredAt))}` : sample ? "갱신 필요" : "미측정"}</div>`;
}
function latencyCards(lat) {
  return html`<div class="system-values">${[
    ["전체 처리", lat.total, lat.calls, "게이트웨이에서 측정한 도구 호출 처리 시간입니다. 직원 PC의 통신 시간과 AI 모델 응답 시간은 포함하지 않습니다."],
    ["게이트웨이 처리", lat.gateway, lat.calls, "전체 처리 시간에서 MCP 통신 및 처리 시간을 제외한 값입니다."],
    ["MCP 통신 및 처리", lat.upstream, lat.dispatched, "도구 전송 구간이 기록된 호출의 서버 연결, 계약 재확인, 도구 처리와 세션 종료 시간을 합산합니다."],
  ].map(([label, values, n, description]) => html`<div class="system-stat"><span title="${description}">${label}</span><b>${msText(values?.p50)}</b>
    <small>중앙값</small><small title="측정값의 95%가 이 시간 이하입니다."><span>95백분위</span> ${msText(values?.p95)}</small>
    <small><span>측정 호출</span> ${n ?? "—"}</small></div>`)}</div>`;
}
function performancePanels(lat, net, serverName) {
  const p95 = html`<span title="측정값의 95%가 이 시간 이하입니다.">95백분위</span>`;
  const failed = html`<div class="note bad">조회 실패</div>`;
  const stages = lat?.stages || [], servers = lat?.servers || [], devices = net?.devices || [];
  const end = lat?.window_end || new Date().toISOString();
  const start = lat?.window_start || new Date(new Date(end).getTime() - 86400000).toISOString();
  const records = (server) => `#/activity?${new URLSearchParams({ server, since: start, until: end, event_kind: "tools/call" })}`;
  return html`<div class="stack">
    ${panel("호출 처리 성능", lat === null ? failed : lat?.calls > 0 ? latencyCards(lat) : empty("측정된 호출 없음"), {
      sub: html`<span>최근 24시간</span> <span>조회 시각</span> ${when(lat?.checked_at)}`,
      end: html`<button class="btn sm" data-act="performance-refresh">새로고침</button>` })}
    ${lat?.calls > 0 ? html`${panel("MCP 서버별 통신 및 처리", servers.length ? html`<table class="data"><thead><tr><th>MCP 서버</th><th class="num">측정 호출</th><th class="num">중앙값</th><th class="num">${p95}</th><th class="num"><span title="허용 후 MCP 처리를 완료하지 못한 건수이며 실제 실행 여부를 뜻하지 않습니다.">MCP 처리 오류</span></th></tr></thead><tbody>
        ${servers.map((r) => html`<tr class="clickable" tabindex="0" data-act="goto" data-href="${records(r.server_id)}"><td><b>${serverName[r.server_id] || r.server_id}</b></td><td class="num">${r.n}</td><td class="num">${msText(r.p50)}</td><td class="num">${msText(r.p95)}</td><td class="num ${r.failed > 0 ? "bad-text" : ""}">${r.failed ?? "—"}</td></tr>`)}</tbody></table>` : empty("MCP 통신 측정 없음"), { flush: true, sub: "95백분위 높은 순, 최대 12개" })}
      ${panel("구간별 처리 시간", stages.length ? html`<table class="data"><thead><tr><th>구간</th><th class="num">측정 호출</th><th class="num">중앙값</th><th class="num">${p95}</th></tr></thead><tbody>
      ${stages.map((r) => html`<tr><td>${LATENCY_STAGE[r.stage] || "—"}</td><td class="num">${r.n ?? "—"}</td><td class="num">${msText(r.p50)}</td><td class="num">${msText(r.p95)}</td></tr>`)}</tbody></table>` : empty("구간별 측정 없음"), { flush: true })}` : ""}
    ${panel("엔드포인트 → 게이트웨이 통신", net === null ? failed : devices.length ? html`<table class="data endpoint-communication-table"><colgroup span="1"></colgroup><colgroup span="3"></colgroup><colgroup span="2"></colgroup><colgroup span="2"></colgroup><thead>
      <tr><th scope="col" rowspan="2">엔드포인트</th><th scope="colgroup" colspan="3">연결 시간</th><th scope="colgroup" colspan="2">점검</th><th scope="colgroup" colspan="2">측정</th></tr>
      <tr><th scope="col" class="num"><span title="엔드포인트에서 게이트웨이로 연결을 맺는 시간의 중앙값입니다.">중앙값</span></th><th scope="col" class="num"><span title="연결 시간의 95백분위수(P95)로, 측정된 연결 시간의 약 95%가 이 값 이하입니다.">P95</span></th><th scope="col" class="num"><span title="연속된 연결 시간 측정값 사이 차이의 절댓값을 평균한 값입니다.">변동</span></th><th scope="col" class="num"><span title="연결 점검과 게이트웨이 상태 확인 요청의 실패 비율이며 패킷 손실률이 아닙니다.">실패율</span></th><th scope="col" class="num"><span title="연결 점검과 게이트웨이 상태 확인 요청 횟수의 합계입니다.">횟수</span></th><th scope="col">최근 시각</th><th scope="col">상태</th></tr></thead><tbody>
      ${devices.map((d) => html`<tr><td>${d.hostname ? html`<b>${d.hostname}</b><span class="sub">${entityRef(d.endpoint_id)}</span>` : entityRef(d.endpoint_id)}</td>
        <td class="num">${d.state === "fresh" ? msText(d.rtt_p50_ms) : "—"}</td><td class="num">${d.state === "fresh" ? msText(d.rtt_p95_ms) : "—"}</td><td class="num">${d.state === "fresh" ? msText(d.jitter_ms) : "—"}</td><td class="num">${d.state === "fresh" ? pctText(d.failure_pct) : "—"}</td>
        <td class="num">${d.probes ?? "—"}</td><td class="small">${when(d.measured_at)}</td><td>${d.state === "fresh" ? d.rtt_p50_ms == null ? chip("alert", "측정 실패") : html`<span title="조회 시각 기준 최근 3분 이내의 측정입니다.">${chip("outline", "최근")}</span>` : d.state === "stale" ? chip("alert", "오래됨") : chip("outline", "미측정")}</td></tr>`)}</tbody></table>` : empty("측정 대상 엔드포인트 없음"), { flush: true, sub: html`<span>조회 시각</span> ${when(net?.checked_at)}` })}
    ${panel("시스템 자원", html`<div id="system-metrics" aria-live="polite">${metricsCards(null)}</div>`)}
  </div>`;
}
function startSystemMetrics() {
  if (!$("#system-metrics")) return;
  const seq = routeSeq;
  let busy = false;
  let lastSample = null;
  let failing = false;
  const refresh = async () => {
    if (seq === routeSeq && $("#system-metrics")) $("#system-metrics").innerHTML = String(metricsCards(lastSample, failing));
    if (busy || seq !== routeSeq || document.hidden) return;
    busy = true;
    const controller = new AbortController();
    metricsRequest = controller;
    const timeout = setTimeout(() => controller.abort(), 5000);
    try {
      const sample = await api("/api/system/metrics", { signal: controller.signal });
      lastSample = sample;
      failing = false;
      if (seq === routeSeq && $("#system-metrics")) $("#system-metrics").innerHTML = String(metricsCards(sample));
    } catch {
      lastSample = null;
      failing = true;
      if (seq === routeSeq && $("#system-metrics")) $("#system-metrics").innerHTML = String(metricsCards(null, true));
    } finally {
      clearTimeout(timeout);
      if (metricsRequest === controller) metricsRequest = null;
      busy = false;
    }
  };
  refresh();
  metricsTimer = setInterval(refresh, 10000);
}

const signupPendingTotal = (data) => data.pending_total ?? data.requests.filter((r) => r.status === "pending").length;
const listPageNumber = (query, key) => Math.max(1, Math.floor(Number(query.get(key)) || 1));
function listPager(data, href) {
  const page = data.page || 1, pages = Math.max(1, Math.ceil((data.total || 0) / data.page_size));
  return pages > 1 ? html`<div class="row-actions">${page > 1 ? html`<a class="btn sm" href="${href(page - 1)}">이전</a>` : ""}<span>${page} / ${pages}</span>${page < pages ? html`<a class="btn sm" href="${href(page + 1)}">다음</a>` : ""}</div>` : "";
}
let dashboardTimer = null, dashboardRequest = null, dashboardBusy = false, dashboardGeneration = 0;
function stopDashboardRefresh() {
  clearInterval(dashboardTimer); dashboardTimer = null;
  dashboardRequest?.abort(); dashboardRequest = null;
  dashboardBusy = false; dashboardGeneration += 1;
}
function startDashboardRefresh() {
  stopDashboardRefresh();
  dashboardTimer = setInterval(() => refreshDashboard(), 30000);
}
function dashboardCanRefresh() {
  return current.page === "overview" && ["summary", "analysis"].includes(current.query.get("t") || "summary") && !document.hidden
    && !$("#drawer")?.classList.contains("open") && !$("#dialog")?.open
    && !document.activeElement?.closest?.("#dashboard-summary, #dashboard-bar");
}

const DASH_RANGES = { "24h": ["24시간", 86400000], "7d": ["7일", 604800000], "30d": ["30일", 2592000000] };
function dashboardRange(query) {
  const key = DASH_RANGES[query.get("range")] ? query.get("range") : query.get("range") === "custom" ? "custom" : "24h";
  const now = Date.now();
  let until = now, since = now - DASH_RANGES["24h"][1];
  if (key === "custom") {
    const from = Date.parse(query.get("since")), to = Date.parse(query.get("until"));
    if (Number.isFinite(to)) until = to;
    since = Number.isFinite(from) && from < until ? from : until - DASH_RANGES["24h"][1];
  } else since = now - DASH_RANGES[key][1];
  const length = until - since;
  return { key, since: new Date(since), until: new Date(until), length, previousSince: new Date(since - length), previousUntil: new Date(since) };
}
const dashboardScope = (since, until, server, extra = {}) => new URLSearchParams({ event_kind: "tools/call", since: since.toISOString(), until: until.toISOString(), ...(server ? { server } : {}), ...extra });
const dashboardHref = (page, params) => `#/${page}?${params}`;
const decisionOf = (name) => DECISIONS.find((d) => [charts.DECISION_LABEL[d], DECISION[d][1]].some((label) => name === label || name === t(label)));
const bucketLength = (data) => (data?.bucket === "day" ? 86400000 : data?.bucket === "month" ? 2678400000 : 3600000);

async function dashboardModel(query, options = {}) {
  const r = dashboardRange(query), server = query.get("server") || "";
  const range = (since, until) => dashboardScope(since, until, server);
  const soft = (promise) => promise.catch(() => null);
  const [o, pl, inventory, cur, prev, blocked, health, alerts, previousAlerts, ledger, delivery, queue] = await Promise.all([
    gw("overview", options), planes(), gw("endpoint/inventory", options),
    soft(gw(`activity/analysis?${range(r.since, r.until)}`, options)), soft(gw(`activity/analysis?${range(r.previousSince, r.previousUntil)}`, options)),
    gw(`activity?${dashboardScope(r.since, r.until, server, { decision: "Block", limit: 10 })}`, options),
    soft(gw("health", options)), soft(gw(`audit/alerts?${new URLSearchParams({ limit: 6, since: r.since.toISOString(), until: r.until.toISOString() })}`, options)),
    soft(gw(`audit/alerts?${new URLSearchParams({ limit: 1, since: r.previousSince.toISOString(), until: r.previousUntil.toISOString() })}`, options)),
    soft(gw("policy/ledger", options)), soft(gw("audit/siem", options)), soft(loadInbox(inboxContext()))]);
  return { r, server, o, pl, inventory, cur, prev, blocked, health, alerts, previousAlerts, ledger, delivery, queue };
}

function dashboardTotals(data) {
  const totals = Object.fromEntries(DECISIONS.map((d) => [d, 0]));
  for (const row of data?.series || []) if (row.decision in totals) totals[row.decision] += Number(row.n) || 0;
  return totals;
}
const count = (value) => (value == null || value === "" || !Number.isFinite(Number(value)) ? null : Number(value));
const percent = (part, whole) => (whole > 0 ? part / whole * 100 : null);
const percentText = (value) => (value == null ? "—" : value > 0 && value < 0.1 ? "<0.1%" : `${Math.round(value * 10) / 10}%`);
function deltaView(now, before, { points = false, bad = "up" } = {}) {
  if (now == null || before == null) return html`<span class="delta">—</span>`;
  if (!points && before < 5) return html`<span class="delta">이전 ${before}</span>`;
  const change = points ? now - before : (now - before) / before * 100;
  const rounded = Math.round(change * 10) / 10;
  if (Math.abs(rounded) < (points ? 0.1 : 1)) return html`<span class="delta">0${points ? "%p" : "%"}</span>`;
  const worse = bad === "up" ? rounded > 0 : bad === "down" && rounded < 0;
  return html`<span class="delta ${worse ? "bad" : ""}">${rounded > 0 ? "▲" : "▼"} ${Math.abs(rounded)}${points ? "%p" : "%"}</span>`;
}

function dashboardQueue(m) {
  const items = m.queue?.items || [];
  const bypass = dedupeItems(m.pl?.items || []).filter((i) => i.state === "bypass_possible").length;
  const checks = [["연결 통제 점검", bypass, "개", "#/servers?t=items&state=bypass_possible"],
    ["종료 처리", Number(m.o.termination?.action_required) || 0, "건", "#/termination?t=cases&attention=required"]].filter(([, n]) => n > 0);
  const dated = items.filter((item) => item.at);
  return { items, ok: Boolean(m.queue), total: items.length, oldest: dated.length ? dated[0].at : null, checks };
}

function kpiCard(label, value, foot, { href = "", tone = "", trend = "", of = null } = {}) {
  const body = html`<div class="label">${label}</div><div class="value">${value ?? "—"}${of == null ? "" : html`<small class="of">/ ${of}</small>`}</div><div class="foot">${foot}${trend ? raw(trend) : ""}</div>`;
  return href ? html`<a class="kpi ${tone}" href="${href}">${body}</a>` : html`<div class="kpi ${tone}">${body}</div>`;
}

function engineChip(deployment) {
  if (typeof deployment?.rules_match !== "boolean" || typeof deployment?.data_match !== "boolean") return chip("outline", "정책 엔진 확인 불가");
  const same = deployment.rules_match && deployment.data_match;
  return html`<span title="${`룰셋 ${deployment.rules_match ? "일치" : "불일치"} · 정책 데이터 ${deployment.data_match ? "일치" : "불일치"}`}">${chip(same ? "allow" : "alert", same ? "정책 엔진 일치" : "정책 엔진 불일치")}</span>`;
}

function dashboardCards(m) {
  const { o, r } = m, cur = m.cur, prev = m.prev;
  const total = count(cur?.total), before = count(prev?.total);
  const blockedTotal = cur ? dashboardTotals(cur).Block : null;
  const rate = total == null ? null : percent(blockedTotal, total), previousRate = before == null ? null : percent(dashboardTotals(prev).Block, before);
  const buckets = analysisSeries(cur);
  const queue = dashboardQueue(m), base = baseline(r.key);
  const stations = o.workstations ? new Set(o.workstations.filter((w) => Number(w.shadow) > 0).map((w) => w.endpoint_id)) : new Set();
  const agents = m.inventory.agents.filter((a) => a.status !== "revoked");
  const unmanaged = agents.filter((a) => a.managed_state !== "active");
  const gap = new Set([...stations, ...unmanaged.map((a) => a.endpoint_id)]);
  const attention = (o.servers || []).filter(serverNeedsAttention).length;
  const alertTotal = count(m.alerts?.total), previousAlertTotal = count(m.previousAlerts?.total);
  const logs = dashboardScope(r.since, r.until, m.server);
  const alertRange = new URLSearchParams({ t: "alerts", since: r.since.toISOString(), until: r.until.toISOString() });
  return html`<div class="kpis dash-kpis">
    ${kpiCard("호출", total, html`${deltaView(total, before, { bad: "none" })}<span class="base">${base}</span>`, { href: dashboardHref("activity", logs), trend: charts.spark(buckets.map((b) => DECISIONS.reduce((s, d) => s + b[d], 0))) })}
    ${kpiCard("차단 비율", percentText(rate), html`<span class="delta">${blockedTotal ?? "—"} / ${total ?? "—"}건</span>${deltaView(rate, previousRate, { points: true, bad: "none" })}`, { href: dashboardHref("activity", dashboardScope(r.since, r.until, m.server, { decision: "Block" })), trend: charts.spark(buckets.map((b) => b.Block)) })}
    ${kpiCard("처리할 일", queue.ok ? queue.total : null, html`<span class="delta">${queue.oldest ? `최장 대기 ${waitText(Date.now() - Date.parse(queue.oldest))}` : queue.total ? "대기 시각 없음" : "대기 없음"}</span>`, { href: "#/inbox", tone: queue.total > 0 ? "alert" : "" })}
    ${kpiCard("경보", alertTotal, html`<span class="base">기간 내 발생</span>${deltaView(alertTotal, previousAlertTotal)}`, { href: dashboardHref("activity", alertRange), tone: alertTotal > 0 ? "block" : "" })}
    ${kpiCard("미적용", gap.size, html`<span class="delta">미등록 ${stations.size} · 미적용 ${unmanaged.length}</span>`, { href: stations.size ? "#/endpoints?t=shadow" : "#/endpoints?t=devices", tone: gap.size > 0 ? "alert" : "", of: new Set([...agents.map((a) => a.endpoint_id), ...stations]).size })}
    ${kpiCard("점검 필요 서버", attention, "", { href: "#/servers?t=servers&attention=required", tone: attention > 0 ? "alert" : "", of: (o.servers || []).length })}
  </div>`;
}

function dashboardCharts(m) {
  const { r } = m, cur = m.cur || {}, prev = m.prev || {};
  const serverName = Object.fromEntries((m.o.servers || []).map((s) => [s.id, s.display_name || s.id]));
  const series = analysisSeries(cur);
  const go = (href) => { location.hash = href; };
  const logs = (extra = {}) => dashboardScope(r.since, r.until, m.server, extra);
  const around = (b) => ({ since: new Date(b.at).toISOString(), until: new Date(b.at + bucketLength(cur)).toISOString() });
  const known = (rows) => (rows || []).filter((row) => !row.other && row.key);
  const policies = known(cur.policies).slice(0, 5), people = known(cur.people).slice(0, 10);
  const hosts = hostRows(cur.endpoints, m.inventory.agents).slice(0, 10);
  const violations = (b) => (b.Block || 0) + (b.Alert || 0);
  const earlier = (b) => {
    const from = b.at - r.length, to = from + bucketLength(cur);
    return analysisSeries(prev).filter((p) => p.at >= from && p.at < to).reduce((sum, p) => sum + violations(p), 0);
  };
  return {
    "c-dash-trend": () => ({ ...charts.decisionColumns(series.map((b) => b.label), series), onClick: (p) => {
      const b = series[p.dataIndex], decision = decisionOf(p.seriesName);
      if (b) go(dashboardHref("activity", logs({ ...around(b), ...(decision ? { decision } : {}) })));
    } }),
    "c-dash-policies": () => charts.bars(policies.map((p) => ({ name: policyLabel(p.key), value: (p.Block || 0) + (p.Alert || 0), color: charts.color(p.Block >= p.Alert ? "Block" : "Alert") })),
      { labelWidth: 220, wrap: true, onClick: (p) => { const row = policies[p.dataIndex]; if (row) go(`#/policy?detail_kind=policy&detail_id=${encodeURIComponent(row.key)}`); } }),
    "c-dash-servers": () => charts.decisionColumns((cur.servers || []).map((x) => (x.other ? "기타" : serverName[x.key] || x.key)), cur.servers || [], { horizontal: true,
      onClick: (p) => { const row = (cur.servers || [])[p.dataIndex]; if (row && !row.other) go(`#/servers/${encodeURIComponent(row.key)}`); } }),
    "c-dash-violations": () => charts.lines(series.map((b) => b.label), [
      { name: "차단·경보", data: series.map(violations), color: charts.color("Block"), area: true },
      ...(prev.total ? [{ name: baseline(r.key), data: series.map(earlier), color: "#8c9bb1", dashed: true }] : [])],
    { onClick: (p) => { const b = series[p.dataIndex]; if (b) go(dashboardHref("activity", logs(around(b)))); } }),
    "c-dash-people": () => charts.bars(people.map((p) => ({ name: p.key, value: p.total })),
      { onClick: (p) => { const row = people[p.dataIndex]; if (row) go(dashboardHref("activity", logs({ person: row.key }))); } }),
    "c-dash-endpoints": () => charts.bars(hosts.map((h) => ({ name: h.name, value: h.value })),
      { labelWidth: 200, wrap: true, onClick: (p) => { const row = hosts[p.dataIndex]; if (row?.key) go(dashboardHref("activity", logs({ endpoint: row.key }))); } }),
    "c-dash-responses": () => charts.donut(Object.entries(RESPONSE).map(([k, [tone, label]]) => ({ name: label,
      value: Number((cur.responses || []).find((row) => row.response === k)?.n) || 0, color: charts.color(TONE_DECISION[tone]) })).filter((g) => g.value)),
  };
}

function mixBar(totals, href) {
  const parts = mixParts(totals, DECISIONS);
  let x = 0;
  const segments = parts.filter((p) => p.value).map((p) => { const rect = html`<rect class="mix-${p.key}" x="${x.toFixed(2)}" y="0" width="${p.pct.toFixed(2)}" height="8" />`; x += p.pct; return rect; });
  return html`<div class="mix" role="img" aria-label="판정 분포"><svg viewBox="0 0 100 8" preserveAspectRatio="none" class="mix-bar" aria-hidden="true"><rect class="mix-none" x="0" y="0" width="100" height="8" />${segments}</svg>
    <ul class="mix-legend">${parts.map((p) => html`<li class="${p.value ? "" : "is-zero"}">${href ? html`<a href="${href(p.key)}">${decisionChip(p.key)} <b>${p.value}</b></a>` : html`${decisionChip(p.key)} <b>${p.value}</b>`}</li>`)}</ul></div>`;
}

function dashboardTodo(m) {
  const queue = dashboardQueue(m), rows = queue.items.slice(0, 5);
  const wait = (item) => (item.at ? waitText(Date.now() - Date.parse(item.at)) : NONE);
  const list = queue.ok ? rows.length ? html`<table class="data compact todo-table"><thead><tr><th>대상</th><th class="num">대기</th><th></th></tr></thead><tbody>
    ${rows.map((item) => html`<tr class="clickable" tabindex="0" data-act="goto" data-href="${reviewHref(item)}"><td class="cut"><b>${item.summary}</b><span class="sub">${KIND_LABEL[item.type]} · ${String(item.who ?? "—").split(" · ")[0]}</span></td>
      <td class="num nowrap">${wait(item)}</td><td class="num"><span class="btn sm">검토</span></td></tr>`)}</tbody></table>` : empty("처리할 일 없음") : empty("", { failed: true });
  const checks = queue.checks.length ? html`<table class="data compact todo-checks"><thead><tr><th>점검 대상</th><th class="num">대상</th><th></th></tr></thead><tbody>
    ${queue.checks.map(([label, n, unit, href]) => html`<tr class="clickable" tabindex="0" data-act="goto" data-href="${href}"><td>${label}</td><td class="num">${n}${unit}</td><td class="num"><span class="btn sm">점검</span></td></tr>`)}</tbody></table>` : "";
  return panel("처리할 일", html`${list}${checks}`, { flush: true, sub: queue.ok && queue.total ? `${queue.total}건` : "",
    end: queue.total > rows.length ? html`<a class="btn sm" href="#/inbox">전체 ${queue.total}건</a>` : "" });
}

function dashboardRecent(m) {
  const rows = [...(m.blocked?.rows || [])].sort((a, b) => Date.parse(b.at) - Date.parse(a.at)).slice(0, 5);
  return panel("최근 차단", rows.length ? html`<table class="data compact recent-blocks"><thead><tr><th>시각</th><th>사용자</th><th>MCP · 도구</th><th>사유</th></tr></thead><tbody>
    ${rows.map((r) => html`<tr class="clickable" tabindex="0" data-act="decision" data-id="${r.id}"><td class="nowrap">${when(r.at, { seconds: true })}</td><td class="cut">${r.who}</td>
      <td class="cut"><b>${r.server_name || r.server}</b><span class="sub mono">${r.tool}</span></td><td class="cut">${decisionReason(r)}</td></tr>`)}</tbody></table>`
    : empty("차단된 호출 없음", { failed: !m.blocked }), { flush: true,
    end: html`<a class="btn sm" href="${dashboardHref("activity", dashboardScope(m.r.since, m.r.until, m.server, { decision: "Block" }))}">호출 기록 <span aria-hidden="true">↗</span></a>` });
}

function dashboardSummary(m) {
  const cur = m.cur || {}, total = Number(cur.total) || 0;
  const logs = (decision) => dashboardHref("activity", dashboardScope(m.r.since, m.r.until, m.server, { decision }));
  return html`${dashboardCards(m)}
    <div class="dash-grid dash-lead">
      <div class="c8">${panel("시간대별 호출", html`${chartBox("c-dash-trend", "시간대별 호출 판정 추이", "d200")}${m.cur ? mixBar(dashboardTotals(cur), logs) : ""}`, { sub: m.cur ? `${total}건` : "" })}</div>
      <div class="c4">${dashboardTodo(m)}</div>
    </div>
    <div class="dash-grid"><div class="c12">${dashboardRecent(m)}</div></div>`;
}

function dashboardAnalysis(m) {
  const box = (cls, title, id, label, size) => html`<div class="${cls}">${panel(title, chartBox(id, label, size))}</div>`;
  return html`<div class="dash-grid">
    ${box("c6", "상위 차단·경보 정책", "c-dash-policies", "상위 차단·경보 정책", "d220")}
    ${box("c6", "차단·경보 추이", "c-dash-violations", "차단·경보 추이", "d220")}
    ${box("c6", "서버별 호출", "c-dash-servers", "서버별 호출 판정", "d220")}
    ${box("c6", "응답 처리", "c-dash-responses", "응답 처리 비율", "d220")}
    ${box("c6", "사용자별 호출", "c-dash-people", "사용자별 호출", "d220")}
    ${box("c6", "엔드포인트별 호출", "c-dash-endpoints", "엔드포인트별 호출", "d220")}
  </div>`;
}

function dashboardStatus(m) {
  const d = m.delivery;
  const siem = !d ? chip("alert", "관제 확인 불가") : d.configured === false ? html`<a href="#/activity?t=audit">${chip("outline", "관제 미설정")}</a>`
    : Number(d.pending) > 0 ? chip(Number(d.retrying) > 0 ? "alert" : "outline", `관제 미전달 ${d.pending}`)
      : d.last_delivered ? chip("allow", `관제 전달 ${ago(d.last_delivered)}`) : html`<a href="#/activity?t=audit">${chip("outline", "관제 미설정")}</a>`;
  return html`${modeChip(m.o.enforcement)}${componentHealth(m.health)}${engineChip(m.ledger?.deployment)}${siem}`;
}

function dashboardBar(m) {
  const r = m.r;
  const servers = (m.o.servers || []).map((s) => [s.id, s.display_name || s.id]);
  return html`<div class="dash-bar" id="dashboard-bar" role="group" aria-label="조회 조건">
    <div class="seg" role="group" aria-label="기간">${[...Object.entries(DASH_RANGES).map(([k, [label]]) => [k, label]), ["custom", "직접"]].map(([k, label]) => html`<button class="seg-btn" type="button" data-act="dash-range" data-range="${k}" aria-pressed="${String(r.key === k)}">${label}</button>`)}</div>
    ${r.key === "custom" ? html`<input type="text" inputmode="numeric" data-dash="since" data-ko="1" placeholder="2026.11.13 18:28" value="${koInput(r.since)}" aria-label="조회 시작 시각" /><input type="text" inputmode="numeric" data-dash="until" data-ko="1" placeholder="2026.11.14 18:28" value="${koInput(r.until)}" aria-label="조회 종료 시각" />` : ""}
    <span class="muted period" id="dashboard-period">${koPeriod(r.since, r.key === "custom" ? r.until : null)}</span>
    <select data-dash="server" aria-label="서버"><option value="">모든 서버</option>${servers.map(([id, name]) => html`<option value="${id}" ${id === m.server ? raw("selected") : ""}>${name}</option>`)}</select>
    <button class="btn sm" type="button" data-act="dash-refresh">새로고침</button>
    <span class="muted updated" id="dashboard-updated">${koClock()}</span>
  </div>`;
}

function dashboardGo(patch) {
  const q = new URLSearchParams(current.query);
  for (const [key, value] of Object.entries(patch)) { if (value) q.set(key, value); else q.delete(key); }
  location.hash = `#/overview?${q}`;
}

async function refreshDashboard() {
  if (dashboardBusy || !dashboardCanRefresh()) return;
  const generation = dashboardGeneration, seq = routeSeq;
  const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 10000);
  dashboardRequest = controller; dashboardBusy = true;
  try {
    const m = await dashboardModel(current.query, { signal: controller.signal });
    if (generation !== dashboardGeneration || seq !== routeSeq || !dashboardCanRefresh()) return;
    planesCache = { at: Date.now(), data: m.pl };
    policyLedger = m.ledger?.policies || policyLedger;
    feed.rows = mergeRows([], m.blocked.rows);
    $("#dashboard-summary").innerHTML = String(dashboardSummary(m));
    const analysis = $("#dashboard-analysis");
    if (analysis) analysis.innerHTML = String(dashboardAnalysis(m));
    charts.disposeAll();
    charts.register(dashboardCharts(m));
    charts.mountVisible($("#view"));
    const status = $("#view .page-head .status");
    if (status) status.innerHTML = String(dashboardStatus(m));
    $("#dashboard-updated").textContent = koClock();
    $("#dashboard-refresh-status").innerHTML = "";
  } catch {
    controller.abort();
    if (generation === dashboardGeneration && seq === routeSeq) $("#dashboard-refresh-status").innerHTML = String(chip("alert", "갱신 실패"));
  } finally {
    clearTimeout(timeout);
    if (generation === dashboardGeneration) { dashboardBusy = false; dashboardRequest = null; }
  }
}

ROUTES.overview = async (arg, tab, query = new URLSearchParams()) => {
  const [m, lat, net] = await Promise.all([dashboardModel(query), gw("latency").catch(() => null), gw("endpoint/network-quality").catch(() => null)]);
  policyLedger = m.ledger?.policies || policyLedger;
  const serverName = Object.fromEntries((m.o.servers || []).map((server) => [server.id, server.display_name || server.id]));
  feed.rows = mergeRows([], m.blocked.rows);
  return {
    html: page({
      head: head("대시보드", { status: dashboardStatus(m) }),
      kpis: html`<div id="dashboard-refresh-status" class="dashboard-refresh-status" role="status"></div>${dashboardBar(m)}`,
      active: tab || "summary",
      tabs: [
        { key: "summary", label: "개요", body: html`<div id="dashboard-summary">${dashboardSummary(m)}</div>` },
        { key: "analysis", label: "분석", body: html`<div id="dashboard-analysis">${dashboardAnalysis(m)}</div>` },
        { key: "latency", label: "성능", body: performancePanels(lat, net, serverName) },
      ],
    }),
    charts: dashboardCharts(m),
    after: () => { startSystemMetrics(); startDashboardRefresh(); if (arg) showApproval(arg); },
  };
};

const FEED_FILTERS = ["decision", "server", "since", "until", "execution", "person", "endpoint", "policy", "event_kind", "principal", "trace_id", "before"];
let auditExportPage = null;
async function exportCallEvidence(next = false) {
  if (!viewer.admin) return;
  const key = feedQuery().toString();
  if (next && (!auditExportPage || auditExportPage.key !== key)) return;
  const q = feedQuery({ view: "calls", limit: 500 });
  if (next) q.set("before", auditExportPage.before);
  const result = await gw(`audit/export?${q}`);
  lastDocument = result;
  ACTIONS["save-json"]({ dataset: { name: "mcp-audit-evidence.json" } });
  auditExportPage = result.payload.has_more ? { key, before: result.payload.next_before } : null;
  if (current.page === "activity" && key === feedQuery().toString()) {
    const button = $("#audit-export-next");
    if (button) button.hidden = !auditExportPage;
  }
  const intact = result.payload.verification.intact;
  toast([`${result.manifest.count}건 내보냄`, result.payload.has_more ? "다음 페이지 있음" : "", intact ? "무결성 정상" : "무결성 손상"].filter(Boolean).join(" / "), !intact);
}
const FEED_PAGE_SIZE = 50;
let feedDefaultSince = "";
const defaultFeedFilters = () => {
  feedDefaultSince = new Date(Date.now() - 86400000).toISOString();
  return { ...Object.fromEntries(FEED_FILTERS.map((key) => [key, ""])), since: feedDefaultSince, event_kind: "tools/call" };
};
const feedFiltered = () => !!feed.query || Object.entries(feed.filters).some(([key, value]) => value
  && !(key === "event_kind" && value === "tools/call") && !(key === "since" && value === feedDefaultSince));
const feed = { rows: [], pending: [], cursor: 0, filters: defaultFeedFilters(), query: "",
  live: true, servers: [], lastOk: 0, failing: false, gen: 0, page: 1, pageSize: FEED_PAGE_SIZE,
  total: 0, filteredTotal: 0, highlight: [], analysis: null, analysisKey: "", analysisAt: 0 };
let liveTimer = null;
function stopLive() { clearInterval(liveTimer); liveTimer = null; feed.gen += 1; }
const feedQuery = (extra) => new URLSearchParams({ ...Object.fromEntries(Object.entries(feed.filters).filter(([, v]) => v)
  .map(([key, value]) => [key,
    ["since", "until"].includes(key) ? new Date(value).toISOString() : value])),
  ...(feed.query ? { q: feed.query } : {}), ...extra });
function analysisEndpoints(data) {
  const rows = data?.endpoints || [];
  return rows.length ? html`<table class="data"><thead><tr><th>엔드포인트</th><th class="num">호출 수</th><th>판정 분포</th><th>마지막 호출</th></tr></thead><tbody>
    ${rows.map((row) => html`<tr><td>${row.other ? "기타" : row.key ? entityRef(row.key) : chip("outline", "엔드포인트 미확인")}</td><td class="num">${row.total}</td>
      <td><div class="row-actions">${DECISIONS.filter((d) => row[d] > 0).map((d) => html`<span class="pair">${chip(...DECISION[d])}<b>${row[d]}</b></span>`)}</div></td>
      <td class="small">${when(row.last_call)}</td></tr>`)}</tbody></table>` : empty("조건에 맞는 호출 없음");
}
function renderAnalysisDetails() {
  const endpoints = $("#analysis-endpoints");
  if (endpoints) endpoints.innerHTML = String(analysisEndpoints(feed.analysis));
}

function rememberFeed() {
  const q = new URLSearchParams(current.query);
  for (const key of FEED_FILTERS) q.set(key, ["since", "until"].includes(key) && feed.filters[key]
    ? new Date(feed.filters[key]).toISOString() : feed.filters[key]);
  if (feed.filters.since === feedDefaultSince) q.delete("since");
  q.set("q", feed.query);
  q.set("page", feed.page);
  current.query = q; history.replaceState(history.state, "", routeHash(q));
}

function renderFeedStatus() {
  const status = $("#feed-status");
  if (!status) return;
  const start = feed.rows.length ? (feed.page - 1) * feed.pageSize + 1 : 0;
  const end = feed.rows.length ? start + feed.rows.length - 1 : 0;
  status.textContent = `조회 ${feed.filteredTotal}건 · ${start}–${end}`;
  const total = $("#feed-total");
  if (total) total.textContent = feed.filteredTotal === feed.total ? "" : `전체 누적 ${feed.total}건`;
  $("#feed-live-state").textContent = feed.failing ? "갱신 실패" : feed.live ? "실시간" : "일시정지";
  $("#feed-live-time").textContent = feed.lastOk ? koClock(new Date(feed.lastOk)) : "연결 중";
  $("#feed-dot").className = `dot ${feed.failing ? "bad" : feed.live ? "on" : "paused"}`;
  const note = $("#feed-empty");
  if (note) {
    note.hidden = feed.rows.length > 0;
    note.innerHTML = String(html`${empty("호출 없음", { failed: feed.failing, filtered: feedFiltered() })}
      ${!feed.failing && feedFiltered() ? html`<button class="btn sm" type="button" data-act="feed-reset">조건 초기화</button>` : ""}`);
  }
}

function analysisSeries(data) {
  const occupied = new Map();
  for (const row of data?.series || []) {
    const key = new Date(row.at).getTime();
    if (!occupied.has(key)) occupied.set(key, Object.fromEntries(DECISIONS.map((decision) => [decision, 0])));
    if (DECISIONS.includes(row.decision)) occupied.get(key)[row.decision] = Number(row.n) || 0;
  }
  const series = [];
  const times = [...occupied.keys()].sort((a, b) => a - b);
  if (times.length) {
    const cursor = new Date(times[0]), end = times[times.length - 1];
    while (cursor.getTime() <= end) {
      const at = cursor.getTime();
      const label = data.bucket === "hour" ? `${dayLabel(cursor)} ${pad(cursor.getHours())}${lang() === "en" ? ":00" : "시"}`
        : data.bucket === "day" ? `${cursor.getFullYear()}-${pad(cursor.getMonth() + 1)}-${pad(cursor.getDate())}`
          : `${cursor.getFullYear()}-${pad(cursor.getMonth() + 1)}`;
      series.push({ label, at, ...(occupied.get(at) || Object.fromEntries(DECISIONS.map((decision) => [decision, 0]))) });
      if (data.bucket === "month") cursor.setMonth(cursor.getMonth() + 1);
      else cursor.setTime(cursor.getTime() + (data.bucket === "day" ? 86400000 : 3600000));
    }
  }
  return series;
}

function feedCharts() {
  const data = feed.analysis || { series: [], hours: [], responses: [], harnesses: [], servers: [], people: [] };
  const series = analysisSeries(data);
  return {
    "c-minutes": () => charts.decisionColumns(series.map((b) => b.label), series),
    "c-calls-trend": () => charts.decisionColumns(series.map((b) => b.label), series, { onClick: (event) => {
      const bucket = series[event.dataIndex];
      if (!bucket) return;
      const step = data.bucket === "day" ? 86400000 : data.bucket === "hour" ? 3600000 : 2678400000;
      const decision = DECISIONS.find((d) => charts.DECISION_LABEL[d] === event.seriesName) || "";
      applyFeedFilters({ since: new Date(bucket.at).toISOString(), until: new Date(bucket.at + step).toISOString(), decision });
    } }),
    "c-decision-mix": () => ({ ...charts.donut(DECISIONS.map((d) => ({ name: charts.DECISION_LABEL[d], color: charts.color(d),
      value: (data.series || []).filter((row) => row.decision === d).reduce((sum, row) => sum + (Number(row.n) || 0), 0) }))),
      onClick: (event) => applyFeedFilters({ decision: DECISIONS.find((d) => charts.DECISION_LABEL[d] === event.name) || "" }) }),
    "c-by-server": () => charts.decisionColumns(data.servers.map((x) => x.key), data.servers, { horizontal: true, grouped: true }),
    ...(viewer.admin ? { "c-by-person": () => charts.decisionColumns(data.people.map((x) => x.key), data.people, { horizontal: true, grouped: true }) } : {}),
    "c-by-response": () => charts.donut(Object.entries(RESPONSE).map(([k, [tone, label]]) => ({ name: label,
      value: Number(data.responses.find((row) => row.response === k)?.n) || 0, color: charts.color(TONE_DECISION[tone]) })).filter((g) => g.value)),
    ...(viewer.admin ? {
      "c-policy-outcomes": () => charts.stacked((data.policies || []).map((p) => p.other ? "기타" : p.key ? policyLabel(p.key) : "—"),
        ["Block", "Alert"].map((d) => ({ name: DECISION[d][1], color: charts.color(d), data: (data.policies || []).map((p) => p[d] || 0) })), { horizontal: true, grouped: true }),
    } : {}),
  };
}

function applyFeedFilters(values) {
  Object.assign(feed.filters, values);
  feed.page = 1;
  rememberFeed();
  reload();
}

function renderFeed(newIds = []) {
  const body = $("#feed");
  if (!body) return;
  const focused = document.activeElement?.closest?.("#feed tr")?.dataset.id;
  body.innerHTML = String(html`${feed.rows.map(callRow)}`);
  const fresh = new Set(newIds.map(String));
  for (const row of body.querySelectorAll("tr[data-id]")) row.classList.toggle("new-call", fresh.has(row.dataset.id));
  if (focused) $(`#feed tr[data-id="${CSS.escape(focused)}"]`)?.focus();
  const pages = Math.max(1, Math.ceil(feed.filteredTotal / feed.pageSize));
  for (const pager of document.querySelectorAll("[data-feed-pager]")) pager.innerHTML = String(html`<button class="pager-button" type="button" data-act="feed-page" data-page="${feed.page - 1}" aria-label="이전 페이지" title="이전 페이지" ${feed.page <= 1 ? raw("disabled") : ""}>‹</button>
    <span>${feed.page} / ${pages}</span>
    <button class="pager-button" type="button" data-act="feed-page" data-page="${feed.page + 1}" aria-label="다음 페이지" title="다음 페이지" ${feed.page >= pages ? raw("disabled") : ""}>›</button>`);
  for (const [id, build] of Object.entries(feedCharts())) charts.redraw(id, build);
  renderFeedStatus();
}

function startLive() {
  stopLive();
  const gen = feed.gen;
  liveTimer = setInterval(async () => {
    if (document.hidden) return;
    try {
      const data = await gw(`activity?${feedQuery({ after: feed.cursor, limit: 100 })}`);
      if (gen !== feed.gen) return;
      feed.cursor = Math.max(feed.cursor, data.cursor || 0);
      feed.lastOk = Date.now();
      feed.failing = false;
      if (feed.live && feed.page === 1 && data.rows.length) {
        const existing = new Set(feed.rows.map((row) => String(row.id)));
        const fresh = data.rows.filter((row) => !existing.has(String(row.id)));
        if (fresh.length) {
          feed.rows = mergeRows(feed.rows, data.rows, feed.pageSize);
          feed.filteredTotal += fresh.length;
          if (!feed.query && !Object.values(feed.filters).some(Boolean)) feed.total += fresh.length;
          renderFeed(fresh.map((row) => row.id));
        } else renderFeedStatus();
      } else {
        feed.pending = mergeRows(feed.pending, data.rows);
        renderFeedStatus();
      }
    } catch {
      if (gen === feed.gen) { feed.failing = true; renderFeedStatus(); }
    }
  }, 5000);
}

const policyCell = (r) => (r.policy_id ? html`${policyLabel(r.policy_id)}<span class="sub mono">${r.policy_id}</span>` : "—");
const nextCell = (r) => {
  const next = nextStep(r, decisionReason(r));
  if (next.kind === "none") return html`<span class="muted">—</span>`;
  const action = next.href ? html`<a class="btn sm" href="${next.href}">${next.label}</a>` : html`<button class="btn sm" type="button" data-act="decision" data-id="${r.id}">${next.label}</button>`;
  return html`<span class="next-text">${next.text}</span>${action}`;
};
const callRow = (r) => {
  const run = executionView(r);
  return html`<tr class="clickable" tabindex="0" data-act="decision" data-id="${r.id}">
    <td class="nowrap">${when(r.at, { seconds: true })}</td><td>${decisionChip(r.decision)}${r.invalid ? chip("outline", "무효 처리") : ""}</td>
    ${viewer.admin ? html`<td class="cut">${r.who}</td>` : ""}<td><b>${r.server_name || r.server}</b><span class="sub mono">${r.tool}</span></td>
    ${viewer.admin ? html`<td title="${r.policy_id || ""}">${policyCell(r)}</td>` : html`<td>${nextCell(r)}</td>`}
    <td class="nowrap">${chip(run.tone, run.unknown ? html`<span aria-hidden="true">!</span> ${run.label}` : run.label)}${run.unknown && viewer.admin ? html`<a class="sub" href="#/inbox?f=execution">실행 확인</a>` : ""}</td><td class="chev" aria-hidden="true">›</td></tr>`;
};
const callTable = (rows, id = "") => html`<table class="data rows-32 calls"><thead><tr><th>시각</th><th>판정</th>${viewer.admin ? html`<th>사용자</th>` : ""}<th class="col-tool">MCP · 도구</th>
  <th class="${viewer.admin ? "col-policy" : "col-next"}">${viewer.admin ? "적용 정책" : "사유 · 다음 조치"}</th><th>실행</th><th></th></tr></thead><tbody ${id ? raw(`id="${id}"`) : ""}>${rows.map(callRow)}</tbody></table>`;

ROUTES.activity = async (arg, tab, query) => {
  for (const key of FEED_FILTERS) feed.filters[key] = query.get(key) || "";
  if (!query.has("since")) feed.filters.since = defaultFeedFilters().since;
  if (!query.has("event_kind")) feed.filters.event_kind = feed.filters.execution === "connection-denied" ? "mcp-connection" : "tools/call";
  feed.query = query.get("q") || "";
  feed.page = Math.max(1, Number(query.get("page")) || 1);
  const analysisKey = feedQuery({}).toString();
  const [data, analysis] = await Promise.all([
    gw(`activity?${feedQuery({ limit: FEED_PAGE_SIZE, page: feed.page })}`),
    feed.analysis && feed.analysisKey === analysisKey && Date.now() - feed.analysisAt < 30000
      ? Promise.resolve(feed.analysis) : gw(`activity/analysis?${analysisKey}`),
  ]);
  feed.rows = mergeRows([], data.rows);
  feed.pending = [];
  feed.cursor = data.cursor;
  feed.page = data.page || feed.page;
  feed.pageSize = data.page_size || FEED_PAGE_SIZE;
  feed.total = data.total || 0;
  feed.filteredTotal = data.filtered_total || 0;
  feed.analysis = analysis;
  feed.analysisKey = analysisKey;
  feed.analysisAt = Date.now();
  feed.lastOk = Date.now();
  feed.failing = false;
  if (viewer.admin && !feed.servers.length) feed.servers = (await gw("registry")).servers.map((s) => s.id);
  const alertQuery = new URLSearchParams({ limit: "200", ...(tab === "alerts" ? Object.fromEntries([...query].filter(([k, v]) => ["hours", "before"].includes(k) && v)) : {}) });
  const [toolData, ledger, siem, alertData, incidentData, retention] = viewer.admin ? await Promise.all([gw("endpoint/tool-events?limit=100").catch(() => null),
    gw("policy/ledger").catch(() => null), gw("audit/siem").catch(() => null), gw(`audit/alerts?${alertQuery}`).catch(() => null),
    gw("audit/incidents").catch(() => null), gw("audit/retention").catch(() => null)]) : [null, null, null, null, null, null];
  if (ledger) policyLedger = ledger.policies || [];
  loadedAlerts = alertData?.alerts || [];
  const servers = viewer.admin ? feed.servers : [...new Set(feed.rows.map((r) => r.server))].sort();
  const option = (value, label, cur) => html`<option value="${value}" ${value === cur ? raw("selected") : ""}>${label}</option>`;
  const f = feed.filters;
  const advancedOpen = ["event_kind", "execution", "person", "endpoint", "policy", "principal", "trace_id", "before"].some((key) => f[key] && !(key === "event_kind" && f[key] === "tools/call"));
  const span = f.since ? Date.now() - Date.parse(f.since) : null;
  const preset = !f.since && !f.until ? "0" : f.until ? "custom" : ["24", "168", "720"].find((h) => Math.abs(span - Number(h) * 3600000) < 900000) || "custom";
  const presets = [["24", "24시간"], ["168", "7일"], ["720", "30일"], ["0", "전체"]];
  const filters = html`<div class="filters filters-compact">
            <div class="seg" role="group" aria-label="기간">${presets.map(([h, label]) => html`<button class="seg-btn" type="button" data-act="feed-window" data-hours="${h}" aria-pressed="${String(preset === h)}">${label}</button>`)}<button class="seg-btn" type="button" data-act="feed-custom" aria-pressed="${String(preset === "custom")}">직접</button></div>
            <span class="muted period">${koPeriod(f.since, f.until)}</span>
            <label class="grow">검색<input data-feed-search type="search" maxlength="120" value="${feed.query}" placeholder="${viewer.admin ? "사용자, 엔드포인트, 도구, 정책" : "서버, 도구, 사유"}" aria-label="호출 검색" /></label>
            <label>판정<select data-filter="decision" aria-label="판정">${option("", "모든 판정", f.decision)}
              ${Object.entries(DECISION).map(([k, [, label]]) => option(k, label, f.decision))}</select></label>
            <label>MCP 서버<select data-filter="server" aria-label="서버">${option("", "모든 서버", f.server)}${servers.map((s) => option(s, s, f.server))}</select></label>
            <div class="feed-custom" ${preset === "custom" ? "" : raw("hidden")}>
              <label>시작<input data-filter="since" data-ko="1" type="text" inputmode="numeric" placeholder="2026.11.13 18:28" value="${koInput(f.since)}" aria-label="조회 시작 시각" /></label>
              <label>종료<input data-filter="until" data-ko="1" type="text" inputmode="numeric" placeholder="현재" value="${koInput(f.until)}" aria-label="조회 종료 시각" /></label></div>
            <details class="feed-advanced" ${advancedOpen ? raw("open") : ""}><summary>상세 필터</summary><div class="advanced-filters">
              <label>호출 유형<select data-filter="event_kind" aria-label="호출 유형">${option("tools/call", "도구 호출", f.event_kind)}${option("mcp-connection", "MCP 연결", f.event_kind)}${option("", "전체", f.event_kind)}</select></label>
              <label>실행 결과<select data-filter="execution" aria-label="실행 결과">${option("", "모든 실행 결과", f.execution)}${option("executed", "실행됨", f.execution)}${option("not-sent", "실행 안 됨", f.execution)}${option("unknown", "미확인", f.execution)}${option("withheld", "응답 보류", f.execution)}${option("connection-denied", "연결 거부", f.execution)}</select></label>
              ${viewer.admin ? html`<label>사용자<input data-filter="person" type="search" maxlength="150" placeholder="이름 또는 계정" value="${f.person}" aria-label="사용자" /></label><label>사용자 ID<input data-filter="principal" type="search" maxlength="150" value="${f.principal}" aria-label="사용자 ID" /></label>
              <label>엔드포인트<input data-filter="endpoint" type="search" maxlength="200" placeholder="엔드포인트 ID" value="${f.endpoint}" aria-label="엔드포인트" /></label>
              <label>정책<input data-filter="policy" type="search" maxlength="150" placeholder="정책 ID" value="${f.policy}" aria-label="정책" /></label>
              <label>추적 ID<input data-filter="trace_id" type="search" maxlength="128" value="${f.trace_id}" aria-label="추적 ID" /></label>` : ""}
              ${f.before ? html`<label>기록 번호 상한<input data-filter="before" type="number" min="0" step="1" value="${f.before}" aria-label="기록 번호 상한" /></label>` : ""}
            </div></details>
          </div>`;
  return {
    html: page({
      head: head(viewer.admin ? "호출·감사" : "내 호출", { status: viewer.admin ? html`<a href="#/activity?t=audit">${siemChip(siem)}</a>` : "" }),
      active: tab || "live",
      tabs: [
        { key: "live", label: viewer.admin ? "게이트웨이 호출" : "호출 기록", body: html`<section class="panel feed-panels">${filters}</section><div class="feed-toolbar">
          <span class="live"><span class="dot" id="feed-dot"></span><span id="feed-live-state"></span><span aria-hidden="true">|</span><span id="feed-live-time"></span>
            <button class="feed-live-toggle" type="button" data-act="live" aria-pressed="${String(!feed.live)}" aria-label="${feed.live ? "일시정지" : "실시간 재개"}" title="${feed.live ? "일시정지" : "실시간 재개"}">${icon(feed.live ? "pause" : "play")}</button></span>
          <span class="feed-count"><span id="feed-status"></span> <span class="muted" id="feed-total"></span></span>
        </div><details class="feed-charts"><summary><span>호출 추이·판정 분포</span>${mixBar(dashboardTotals(analysis), null)}</summary><div class="chart-pair">${panel("호출 추이", chartBox("c-calls-trend", "필터 결과의 호출 추이", "xxs"))}
          ${panel("판정 분포", chartBox("c-decision-mix", "필터 결과의 판정 분포", "xxs"))}</div></details>
        <section class="panel feed-panels"><div class="body flush"><div class="pager" data-feed-pager></div>${callTable([], "feed")}<div id="feed-empty" hidden></div><div class="pager" id="feed-pager" data-feed-pager></div></div></section>` },
        { key: "stats", label: "분석", body: html`<section class="panel feed-panels">${filters}</section><div class="feed-toolbar analysis-toolbar">
          <span class="analysis-total" id="analysis-total">전체 ${analysis.total ?? 0}건</span>
          <span class="analysis-updated">갱신 시각 <span id="analysis-updated-time">${koClock()}</span></span>
          <button class="analysis-refresh" type="button" data-act="analysis-refresh" aria-label="분석 새로고침" title="분석 새로고침">${icon("refresh")}</button>
        </div><div class="stack">
          ${panel("호출 추이", chartBox("c-minutes", "전체 호출 추이", "sm"), { sub: `${analysis.total}건` })}
          ${viewer.admin ? panel("정책별 차단 및 경보", chartBox("c-policy-outcomes", "정책별 차단 및 경보 건수", "lg")) : ""}
          ${panel("서버별 호출 판정", chartBox("c-by-server", "전체 호출의 서버별 판정"))}
          ${viewer.admin ? html`${panel("엔드포인트별 호출", html`<div id="analysis-endpoints">${analysisEndpoints(analysis)}</div>`, { flush: true })}
            ${panel("사용자별 호출 판정", chartBox("c-by-person", "전체 호출의 사용자별 판정", "lg"))}` : ""}
          ${panel("응답 처리", chartBox("c-by-response", "전체 호출의 응답 처리 비율", "sm"))}</div>` },
        ...(viewer.admin ? [endpointCallsTab(toolData),
          { key: "alerts", label: "경보", n: alertData ? freshAlertGroups(alertData.alerts) : undefined, hot: alertData ? freshAlertGroups(alertData.alerts) > 0 : false, body: alertsTab(alertData, query) },
          { key: "incidents", label: "사고 보고", body: incidentsPanel(incidentData) },
          { key: "audit", label: "감사 증빙", body: auditTab(retention) }] : []),
      ],
    }),
    charts: feedCharts(),
    after: () => { const highlighted = feed.highlight; feed.highlight = []; renderFeed(highlighted); startLive(); },
  };
};

function timingView(timings) {
  const { rows, total } = timingRows(timings);
  if (!rows.length) return empty("측정 없음");
  return html`<table class="data"><thead><tr><th>구간</th><th class="num">시간</th><th class="num">비율</th></tr></thead><tbody>
    ${rows.map((r) => html`<tr><td>${r.label}</td><td class="num">${msText(r.ms)}</td><td class="num">${r.share == null ? "—" : `${r.share}%`}</td></tr>`)}
    <tr><td><b>전체</b></td><td class="num"><b>${msText(total)}</b></td><td class="num"></td></tr></tbody></table>`;
}

const MCP_EVIDENCE_LABEL = { confirmed: "MCP 응답 확인", suspected: "MCP로 추정", unknown: "MCP 여부 미확인" };
function relatedBody(related) {
  if (!related) return empty("확인 불가");
  if (!related.records.length) return empty("연관 기록 없음");
  const evidence = (x) => (x.link_basis || []).map((key) => ({ request_id: "요청 ID", trace_id: "추적 ID",
    decision_id: "판정 ID", same_endpoint: "같은 엔드포인트", same_principal: "같은 주체", time_window: "시간 창",
    same_server: "같은 서버", dispatch_interval: "호출 실행 구간" })[key] || key).join(" · ");
  const state = { pending: "대기", resolved: "확정", uncertain: "미확인", confirmed_executed: "실행 확인", confirmed_not_executed: "미실행 확인" };
  const egressState = { connected: "연결 확인", blocked: "프록시에서 차단", connect_failed: "연결 실패" };
  const identifier = (x) => x.kind === "decision" ? `판정 ${x.id} · 추적 ID ${x.trace_id || "—"}`
    : x.kind === "dispatch-intent" ? `요청 ID ${x.request_id}` : `${x.kind === "os-event" ? "이벤트" : "기록"} ${x.id}`;
  return html`<table class="data"><thead><tr><th>시각</th><th>종류</th><th>ID</th><th>내용</th><th>상태</th><th>연관 근거</th></tr></thead><tbody>
    ${related.records.map((x) => html`<tr><td class="small nowrap">${when(x.at, { seconds: true })}</td><td>${chip("outline", RECORD_KIND[x.kind] || x.kind)}</td>
      <td class="small"><code>${identifier(x)}</code></td>
      <td class="small">${x.kind === "decision" ? html`${decisionChip(x.decision)} <code>${x.title}</code>` : html`${x.denial_class ? chip(...denialClass(x.denial_class)) : ""} ${x.title || "—"}`}</td>
      <td class="small">${x.kind === "server-egress" ? egressState[x.state] || "—" : x.kind === "dispatch-intent" ? state[x.state] || "—" : x.policy_id || "—"}</td>
      <td class="small">${evidence(x)} · ${x.link_strength === "exact" ? "정확 연결" : "보조 근거"}</td></tr>`)}
    </tbody></table><span class="small muted">±${Math.round(related.window_seconds / 60)}분</span>`;
}

function decisionAction(r) {
  if (!["Block", "Alert", "Approval"].includes(r.decision)) return "";
  const consent = /CONSENT/.test(r.policy_id || "");
  const href = consent ? `#/my?${new URLSearchParams({ t: "consent", server: r.server || r.server_id || "", tool: r.tool || r.tool_name || "" })}`
    : /SHADOW/.test(r.policy_id || "") ? shadowLink(r.device_id || r.evidence?.endpoint_id, r.evidence?.record_kind, r.evidence?.record_id) : "";
  return kv([["사유", r.reason || policyLabel(r.policy_id) || "—"],
    ["실행", r.outcome_axes?.execution || (r.executed ? "실행됨" : r.attempted ? "실행 미확인" : "실행 안 함")],
    ["조치", href ? html`<a class="btn sm" href="${href}">${consent ? "도구 이용 동의" : "미등록 MCP 보기"}</a>` : "—"]]);
}

async function showDecision(id) {
  const seq = routeSeq, detail = ++detailSeq;
  const r = feed.rows.find((row) => String(row.id) === String(id))
    || (await gw(`activity?decision_id=${encodeURIComponent(id)}&limit=1`).catch(() => ({ rows: [] }))).rows?.[0];
  if (seq !== routeSeq || detail !== detailSeq) return;
  if (!r) { toast("호출 기록을 찾을 수 없습니다.", true); return; }
  if (seq !== routeSeq || detail !== detailSeq) return;
  rememberDetail(r.id);
  const [related, device] = viewer.admin ? await Promise.all([
    gw(`endpoint/correlation?decision_id=${encodeURIComponent(r.id)}`).catch(() => null),
    r.device_id ? planes().then((p) => p?.devices.find((d) => d.endpoint_id === r.device_id)).catch(() => null) : null]) : [null, null];
  const conflictChip = (c) => chip((DECISION[c.decision] || [""])[0], `${(DECISION[c.decision] || [, c.decision])[1]} ${c.policy_id}`);
  if (seq !== routeSeq || detail !== detailSeq) return;
  openDrawer(`호출 #${r.id}`, html`${decisionAction(r)}${outcomeChips(r.outcome_axes)}<div class="drawer-summary"><span class="tool">${r.server_name || r.server} · ${r.tool}</span>
    ${decisionChip(r.decision)}${r.invalid ? chip("outline", "무효 처리") : ""}<span class="muted small">${koStamp(r.at, { seconds: true, full: true })}</span>${viewer.admin ? html`<button class="btn" data-act="audit-event" data-id="${r.id}">감사 증빙</button>` : ""}</div>`, [
    { key: "flow", label: "요약", body: pipeline(r, device) },
    { key: "call", label: "요청 정보", body: kv([
      ["사용자", r.who], ["부서", r.department],
      ["역할", ROLE[r.role] || r.role], ["엔드포인트", r.workstation], ["하네스", r.harness ? harnessLabel(r.harness) : r.agent],
      ["이벤트", r.event_kind === "mcp-connection" ? "연결 거부" : ""],
      ["MCP 서버", r.server], ["도구", html`<code>${r.tool}</code>`], ["대상", r.target ? html`<code>${r.target}</code>` : ""]]) },
    { key: "policy", label: "판정", body: html`
      <div class="decision-reason"><span>판정 사유</span><p>${r.reason || "—"}</p>${String(r.policy_id || "").startsWith("MCP-SHADOW-")
        ? html`<a href="${shadowLink(r.device_id)}">미등록 MCP 보기</a>` : ""}</div>${kv([
        ["적용 정책", policyLabel(r.policy_id)],
        ["실행 권한 위반", (r.pac_failures || []).length ? html`${r.pac_failures.map((x) => chip("block", x))}` : "없음"],
        ["함께 적용된 정책", (r.conflicts || []).length ? html`${r.conflicts.map(conflictChip)}` : "없음"],
        ["행위", r.action_ko || ACTION[r.action] || "—"], ["데이터 등급", r.data_class_ko], ["분류 근거", r.summary],
        ["개인정보", privacyText(r.privacy_types)], ["연쇄 탐지", (r.sequence_flags || []).join(", ")],
        ["무효 처리", r.invalid ? `${r.invalid.reason} · ${r.invalid.by} · ${when(r.invalid.at)}` : ""],
        ["승인 요청", r.approval_id], ["집행 모드", r.enforcement === "monitor" ? "관찰" : r.enforcement === "enforce" ? "집행" : r.enforcement],
        ["관찰 판정", r.would_decision ? (DECISION[r.would_decision]?.[1] || r.would_decision) : ""]])}` },
    { key: "execution", label: "실행 결과", body: html`${outcomeChips(r.outcome_axes)}${kv([
      ["MCP 서버 전송", r.attempted ? "시도" : "전송 안 함"],
      ["도구 실행", r.executed ? "실행됨" : r.attempted ? "실행 미확인" : "실행 안 함"],
      ["응답 처리", RESPONSE[r.response]?.[1] || r.response || "—"],
      ["응답 크기", r.response_bytes != null ? `${r.response_bytes} 바이트` : ""],
      ["응답 형식", (r.response_types || []).join(", ")],
      ["마스킹 항목", (r.masked_types || []).join(", ")],
      ["오류", r.error]])}<details><summary>추적 정보</summary>${kv([
      ["응답 해시", r.response_sha256 ? html`<code>${r.response_sha256}</code>` : ""],
      ["감사 해시", r.evidence_sha256 ? html`<code>${r.evidence_sha256}</code>` : ""],
      ["추적 ID", r.trace_id ? (viewer.admin && /^[0-9a-f]{32}$/.test(r.trace_id)
        ? html`<a href="/jaeger/trace/${r.trace_id}" target="_blank" rel="noopener"><code>${r.trace_id}</code></a>`
        : html`<code>${r.trace_id}</code>`) : ""], ["추적 문맥", r.traceparent ? html`<code>${r.traceparent}</code>` : ""],
      ["작업 ID", r.task_id]])}</details>` },
    { key: "timing", label: "처리 시간", body: timingView(r.timings) },
    ...(viewer.admin ? [{ key: "related", label: "연관 이벤트", n: related ? related.records.length : undefined, body: relatedBody(related) }] : []),
  ]);
}

let approvalRows = [];
let approvalPending = [];
let approvalHistoryRows = [];
function setApprovalLists(first, selected) {
  const firstPage = first.approvals.map((a) => ({ ...a, pending: true }));
  approvalPending = selected.approvals.map((a) => ({ ...a, pending: true }));
  approvalHistoryRows = first.history;
  approvalRows = [...approvalPending, ...firstPage, ...approvalHistoryRows];
}
function approvalHistory() {
  const history = approvalHistoryRows;
  return panel("승인 처리 이력", history.length ? html`<table class="data"><thead><tr><th>요청자</th><th>도구</th><th>결과</th><th>처리 시각</th><th>검토자</th></tr></thead><tbody>
            ${history.map((h) => html`<tr class="clickable" tabindex="0" data-act="${h.explanation ? "approval" : ""}" data-id="${h.id}"><td class="who-cell"><b>${h.display_name || h.requested_by}</b><span class="sub">${h.department || ""}</span></td>
              <td><code>${h.server_id}.${h.tool}</code></td><td>${chip(...(h.status === "APPROVED" && h.valid_until && !h.window_open ? ["outline", "승인 기간 종료"] : APPROVAL_STATUS[h.status] || ["", h.status]))}<span class="sub">${approvalWindowText(h)}</span></td>
              <td class="small nowrap">${when(h.reviewed_at || h.created_at)}</td><td class="small">${h.reviewed_by || "—"}
                ${h.window_open ? html`<button class="btn sm danger" data-act="approval-close" data-id="${h.id}">승인 종료</button>`
                  : h.explanation && h.can_revoke && ["APPROVED", "UNCONFIRMED", "EXECUTED", "NOT_EXECUTED"].includes(h.status) ? html`<button class="btn sm danger" data-act="approval-revoke" data-id="${h.id}">승인 번복</button>` : ""}</td></tr>`)}</tbody></table>` : empty("처리 이력 없음"), { flush: true, sub: "최근 50건",
      end: html`<button class="btn sm" data-act="approval-refresh">새로고침</button>` });
}

const APPROVAL_WINDOW_FIELD = () => field.select("window_minutes", "사용 기간", { 30: "30분", 10: "10분", 0: "1회" }, "30");
const approvalWindowText = (h) => h.window_open ? `${h.window_minutes ? `${when(h.valid_until)}까지` : "1회 남음"} · ${h.uses || 0}회 사용` : (h.valid_until ? `${h.uses || 0}회 사용` : "");

const IMPACT_DOMAIN = { employment: "고용·급여", credit: "신용", legal: "법적 효력", benefits: "급부", contract: "계약", service_access: "서비스 접근" };
function impactExplanation(e) {
  const types = { object: "객체", array: "목록", string: "문자", number: "숫자", boolean: "참거짓", null: "빈 값" };
  return kv([["요청 요약", e.summary], ["중대 영향", "해당"], ["영향 영역", e.impact_domains.map((d) => IMPACT_DOMAIN[d] || "—").join(" · ")],
    ["서버", e.server_id], ["도구", e.tool],
    ["인자 유형·건수", Object.entries(e.arguments).map(([k, v]) => `${types[k] || "—"} ${v}`).join(" · ")],
    ["데이터 등급", DATA_CLASS[e.data_class] || "—"], ["행위", ACTION[e.action] || "—"],
    ["정책", e.policy_id], ["선행 정책", e.basis_policy_id], ["선행 판정", DECISION[e.basis_decision]?.[1] || "—"],
    ["기존 실행 효과 복구", "미지원"]]);
}
async function showApproval(id) {
  const seq = routeSeq, detail = ++detailSeq;
  const a = approvalRows.find((row) => row.id === id);
  if (!a) return;
  const controls = a.pending ? html`<button class="btn danger" data-act="reject" data-id="${a.id}">거부</button>
    ${a.own ? chip("outline", "본인 요청") : html`<button class="btn primary" data-act="approve" data-id="${a.id}">승인</button>`}` : "";
  if (a.explanation) {
    const bundle = await gw(`approvals/${id}/evidence`);
    const kinds = { "call-request": "요청", "call-explanation-view": "설명 열람", "call-approve": "승인", "call-reject": "거부", "call-revoke": "번복" };
    if (seq !== routeSeq || detail !== detailSeq) return;
    rememberDetail(id, "approval");
    openDrawer("중대 영향 결정 증빙", html`<div class="row-actions">${controls}<button class="btn" data-act="approval-export" data-id="${id}">결정 증빙 내보내기</button></div>`, [
      { key: "explanation", label: "설명 증빙", body: impactExplanation(bundle.explanation) },
      { key: "history", label: "개입 이력", body: html`<table class="data"><thead><tr><th>결정</th><th>처리자</th><th>시각</th><th>근거</th></tr></thead><tbody>
        ${bundle.events.map((e) => html`<tr><td>${kinds[e.kind] || "검토"}</td><td>${e.actor_display_name || "—"}</td><td class="nowrap">${when(e.created_at)}</td><td>${e.reason || "—"}</td></tr>`)}</tbody></table>` },
    ]);
    return;
  }
  if (seq !== routeSeq || detail !== detailSeq) return;
  rememberDetail(id, "approval");
  openDrawer(`${a.server_id}.${a.tool}`, html`<div class="row-actions">${controls}</div>`, [
    { key: "request", label: "요청", body: kv([["요청자", `${a.display_name || a.requested_by}${a.department ? ` · ${a.department}` : ""}`],
      ["엔드포인트", a.client?.workstation], ["하네스", a.client?.harness?.name ? harnessLabel(a.client.harness.name) : a.client?.agent],
      ["요청 시각", when(a.created_at, { seconds: true })], ["만료 시각", when(a.expires_at)]]) },
    { key: "args", label: "인자", body: json(a.arguments) },
    { key: "policy", label: "정책", body: html`${a.reason ? html`<p class="note">${a.reason}</p>` : ""}${kv([
      ["정책", html`<code>${a.policy_id || "—"}</code>`], ["행위", ACTION[a.action] || a.action], ["데이터 등급", DATA_CLASS[a.data_class] || a.data_class],
      ["분류 근거", a.summary]])}` },
  ]);
}

let registry = null;
const SERVER_TABS = ["servers", "tools", "supply"];
const serverChips = (s) => html`${chip(s.status === "READY" ? "allow" : s.status === "DISABLED" ? "outline" : "alert", SERVER_STATUS[s.status] || s.status)}
  ${s.lifecycle && s.lifecycle !== "OPERATING" ? chip(s.lifecycle === "RETIRED" ? "block" : "alert", LIFECYCLE[s.lifecycle] || s.lifecycle) : ""}
  ${s.registration?.risk_review?.state === "grace" ? chip("alert", "재평가 필요") : ""}
  ${s.litellm_sync && s.litellm_sync.label !== "동기화 완료" ? chip("alert", s.litellm_sync.label) : ""}`;
ROUTES.servers = async (id, tab, query) => {
  const snapshot = planes();
  const [reg, o, pl, matrix, rels, analysis] = await Promise.all([gw("registry"), gw("overview"), snapshot, gw("policy/matrix"),
    gw("termination/relationships").catch(() => ({ relationships: [] })), gw(`activity/analysis?${sinceDay()}`).catch(() => null)]);
  registry = reg;
  termRelationships = rels.relationships;
  const counts = Object.fromEntries(o.servers.map((s) => [s.id, s]));
  const plane = Object.fromEntries((pl?.items || []).filter((i) => i.key.startsWith("gateway:")).map((i) => [i.key.slice(8), i]));
  const users = Object.fromEntries(rels.relationships.map((r) => [r.server_id, r.users]));
  const servers = reg.servers.map((s) => ({ ...s, registration: reg.registrations?.[s.id], plane: plane[s.id],
    ...(counts[s.id] ? { calls: counts[s.id].calls, blocked: counts[s.id].blocked, tools: counts[s.id].tools } : {}) }));
  const attention = query.get("attention") === "required";
  const serverRows = serverOrder(attention ? servers.filter(serverNeedsAttention) : servers, reg.registrations);
  const cards = serverCards(servers, reg.registrations);
  const busy = servers.filter((s) => Number(s.calls) > 0).sort((a, b) => b.calls - a.calls).slice(0, 8);
  const byDecision = Object.fromEntries((analysis?.servers || []).filter((x) => !x.other && x.key).map((x) => [x.key, x]));
  const dueSoon = serverOrder(servers.filter((s) => s.lifecycle !== "RETIRED"), reg.registrations).filter((s) => {
    const left = daysLeft(reg.registrations?.[s.id]?.valid_until); return serverNeedsAttention(s) || (left != null && left <= 14); }).slice(0, 5);
  const actions = (list) => (list || []).map((a) => ACTION[a] || a).join(", ");
  const resources = (g) => html`${[["경로", g.path_roots], ["읽기 전용 경로", g.readonly_path_roots],
    ["저장소", g.repositories], ["테이블", g.tables], ["명령", g.commands], ["전송 대상", g.transfer_destinations]]
    .filter(([, values]) => values?.length).map(([label, values]) => html`<span class="sub"><span>${label}</span>: <span>${values.join(", ")}</span></span>`)}`;
  const toolFilter = query.get("server") || "";
  const tools = reg.tools.filter((t) => !toolFilter || t.server_id === toolFilter);
  const option = (value, label) => html`<option value="${value}" ${value === toolFilter ? raw("selected") : ""}>${label}</option>`;
  return {
    html: page({
      head: head("MCP 서버", { actions: html`<a class="btn" href="#/intake">도입 심사</a>` }),
      kpis: html`${kpiStrip([["운영 서버", cards.operating, "", "#/servers?t=servers"], ["연결 점검 필요", cards.attention, cards.attention ? "alert" : "", "#/servers?t=servers&attention=required"],
        ["통제 미검증", html`${cards.unverified}<small class="of">/ ${cards.live}개</small>`, cards.unverified ? "alert" : ""],
        ["기한 14일 이내", cards.due, cards.due ? "alert" : ""], ["차단 발생 서버", html`${cards.blocked}<small class="of">/ ${cards.live}개</small>`, ""]])}
        <div class="chart-pair server-pair">${panel("서버별 호출 24시간", chartBox("c-server-calls", "서버별 24시간 호출 판정", "d220"))}
          ${panel("기한 임박·점검 필요", dueSoon.length ? html`<table class="data compact"><tbody>${dueSoon.map((s) => html`<tr class="clickable" tabindex="0" data-act="goto" data-href="#/servers/${encodeURIComponent(s.id)}">
            <td><b>${s.display_name}</b></td><td>${serverNeedsAttention(s) ? serverChips(s) : validityChip(s.registration)}</td><td class="num"><a class="btn sm" href="#/servers/${encodeURIComponent(s.id)}">검토</a></td></tr>`)}</tbody></table>` : empty("기한 임박·점검 필요 서버 없음"), { flush: true })}</div>`,
      active: SERVER_TABS.includes(tab) ? tab : "servers",
      tabs: [
        { key: "servers", label: "서버", n: serverRows.length, body: panel(attention ? "점검 필요" : "서버", serverRows.length ? html`<table class="data"><thead><tr><th>서버</th><th>서버 연결</th><th>운영</th><th>통제 검증</th><th>사용 기한</th><th class="num">사용자</th><th class="num">호출 24시간</th><th class="num">차단 / 호출</th><th></th></tr></thead><tbody id="server-list">
            ${serverRows.map((s) => { const rate = blockRate(s); return html`<tr class="clickable" tabindex="0" data-act="goto" data-href="#/servers/${encodeURIComponent(s.id)}">
              <td><b>${s.display_name}</b></td><td>${serverChips(s)}</td>
              <td class="small">${s.deployment === "provider" ? "제공자" : "사내"}</td>
              <td>${s.plane ? statusPair(s.plane) : NONE}</td>
              <td>${validityChip(s.registration)}</td>
              <td class="num">${users[s.id] ?? "—"}</td><td class="num">${s.calls || 0}</td>
              <td class="num">${rate == null ? "—" : html`${s.blocked || 0} / ${s.calls}<span class="sub">${rate}%</span>`}</td><td class="num muted" aria-hidden="true">›</td></tr>`; })}</tbody></table><p class="empty" role="status" data-list-empty="server-list" hidden>조건에 맞는 결과 없음</p>`
            : attention ? empty("점검할 MCP 서버 없음") : empty("등록된 MCP 서버 없음"),
            { flush: true, end: attention ? html`<a class="btn sm" href="#/servers?t=servers">전체 보기</a>` : "",
              tools: html`${listToolbar("server-list", "서버 검색")}<div class="server-list-actions"><button class="btn" type="button" data-act="catalog-refresh">정의 변경 확인</button>
                <select data-registry-export aria-label="도입 승인 등록부 내보내기"><option value="">내보내기</option><option value="csv">CSV</option><option value="json">JSON</option></select></div>` }) },
        { key: "tools", label: "도구·권한", n: reg.tools.length, body: html`<div class="stack">
          ${panel("도구", html`<table class="data"><thead><tr><th>서버</th><th>도구</th><th>행위</th><th>상태</th></tr></thead><tbody>
            ${tools.map((t) => html`<tr><td class="mono">${t.server_id}</td><td><code>${t.name}</code></td>
              <td>${chip({ r: "allow", w: "alert", x: "block" }[t.action] || "", ACTION[t.action] || t.action)}</td>
              <td>${!t.enabled ? chip("outline", "미승인") : t.contract_ok ? chip("allow", "계약 일치") : chip("alert", "계약 불일치")}</td></tr>`)}
            </tbody></table>${tools.length ? "" : empty("등록된 도구 없음")}`, { flush: true, sub: `${tools.length}개`,
            tools: html`<select data-act-change="tool-filter" aria-label="서버">${option("", "모든 서버")}${reg.servers.map((s) => option(s.id, s.id))}</select>` })}
          ${panel("접근 권한", matrix.capabilities.length + matrix.runtime_envelopes.length ? html`<table class="data"><thead><tr><th>권한</th><th>출처</th><th>사용자</th><th>서버</th><th>허용 행위</th><th>허용 자원</th><th>허용 도구</th><th>만료</th></tr></thead><tbody>
          ${matrix.capabilities.map((g) => html`<tr><td><code>${g.id}</code></td><td>개별 접근 권한</td><td>${audienceText(g.principals)}</td><td>${(g.servers || []).join(", ") || "—"}</td>
            <td>${Object.keys(g.server_actions || {}).length ? (g.servers || []).map((server) => html`<span class="sub">${server}: ${actions(g.server_actions[server] || g.actions) || "—"}</span>`) : actions(g.actions) || "—"}</td>
            <td>${String(resources(g)) ? resources(g) : "—"}</td><td>${(g.tools || []).join(", ") || "—"}</td><td class="nowrap">${when(g.valid_until)}</td></tr>`)}
          ${matrix.runtime_envelopes.map((g) => html`<tr><td><code>${g.server_id}</code></td><td>도입 승인</td><td>${audienceText(g.principals)}</td><td><code>${g.server_id}</code></td>
            <td>${actions([...new Set(Object.values(g.tools || {}).filter((a) => typeof a === "string"))]) || "—"}</td><td>—</td><td>${Object.entries(g.tools || {}).map(([tool, action]) => html`<span class="sub"><code>${tool}</code>${ACTION[action] ? ` / ${ACTION[action]}` : ""}</span>`)}</td><td>${when(g.valid_until)}</td></tr>`)}
          </tbody></table>` : empty("실행 권한 없음"), { flush: true })}</div>` },
        { key: "supply", label: "공급망", body: await supplyChainImpact(tab === "supply" ? query : new URLSearchParams(), users) },
      ],
    }),
    charts: {
      "c-server-calls": () => {
        const open = (e) => { const s = busy[e.dataIndex]; if (s) location.hash = `#/servers/${encodeURIComponent(s.id)}`; };
        return byDecision[busy[0]?.id]
          ? charts.decisionColumns(busy.map((s) => s.display_name), busy.map((s) => byDecision[s.id] || {}), { horizontal: true, onClick: open })
          : charts.stacked(busy.map((s) => s.display_name), [{ name: "차단 외", color: charts.color(""), data: busy.map((s) => s.calls - (s.blocked || 0)) },
            { name: "차단", color: charts.color("Block"), data: busy.map((s) => s.blocked || 0) }], { horizontal: true, onClick: open });
      },
    },
    after: () => { if (id) showServer(id); },
  };
};

async function showServer(id) {
  const s = registry?.servers.find((row) => row.id === id);
  if (!s) return;
  const seq = routeSeq, detail = ++detailSeq;
  const [trend, intakes] = await Promise.all([
    gw(`activity/analysis?${new URLSearchParams({ event_kind: "tools/call", server: id, since: new Date(Date.now() - 86400000).toISOString(), until: new Date().toISOString() })}`).catch(() => null),
    api("/api/mcp-requests").catch(() => ({ requests: [] }))]);
  if (seq !== routeSeq || detail !== detailSeq) return;
  const tools = registry.tools.filter((t) => t.server_id === id);
  const rels = registry.usage_relationships.filter((u) => u.server_id === id);
  const rel = termRelationships.find((r) => r.server_id === id);
  const terms = s.exit_terms || {};
  const creds = s.server_held_credentials || [];
  const registration = registry.registrations?.[id];
  const intake = (intakes.requests || []).find((r) => r.registered_server_id === id);
  const series = seriesRows(trend?.series);
  const label = (row) => { const d = new Date(row.at); return trend?.bucket === "day" ? dayLabel(d) : `${dayLabel(d)} ${pad(d.getHours())}${lang() === "en" ? ":00" : "시"}`; };
  const startable = rel && rel.lifecycle === "OPERATING" && rel.status === "ACTIVE";
  openDrawer(s.display_name, html`<div class="row-actions">${serverChips({ ...s, registration })}
      ${chip("outline", s.deployment === "provider" ? "제공자 운영" : "사내 운영")} ${validityChip(registration)}</div>
    <div class="row-actions">
      ${s.status === "DRIFT" && !registration ? html`<button class="btn sm primary" data-act="approve-contract" data-id="${s.id}">승인본 갱신</button>` : ""}
      ${s.lifecycle !== "RETIRED" ? html`<button class="btn sm" type="button" data-act="server-check" data-id="${s.id}">연결 확인</button>` : ""}
      ${registration && tools.some((t) => registration.tools?.[t.name] && !registration.tool_reviews?.[t.name]) ? html`<button class="btn sm primary" type="button" data-act="tool-scope" data-id="${s.id}">범위 심사</button>` : ""}
      ${registration?.intake_id ? html`<button class="btn sm" type="button" data-act="server-audience" data-id="${s.id}">사용 대상</button>` : ""}
      ${s.lifecycle === "OPERATING" ? (s.status === "DISABLED" ? html`<button class="btn sm" type="button" data-act="server-resume" data-id="${s.id}" data-name="${s.display_name}">재개</button>`
        : html`<button class="btn sm danger" type="button" data-act="server-suspend" data-id="${s.id}" data-name="${s.display_name}">긴급 중지</button>`) : ""}
      ${startable ? html`<button class="btn sm danger" type="button" data-act="open-termination" data-id="${rel.id}" data-name="${rel.display_name}" data-grade="${rel.readiness?.best_attainable_grade || ""}">종료·폐기</button>`
        : rel?.latest_case ? html`<a class="btn sm" href="#/termination/${rel.latest_case}">종료 처리</a>` : ""}</div>
    ${s.status_reason ? html`<p class="note ${s.status !== "READY" ? "warn" : ""}">${s.status_reason}</p>` : ""}`, [
    { key: "info", label: "개요", body: kv([["ID", html`<code>${s.id}</code>`], ["게이트웨이 경로", html`<code>/mcp/${s.id}/</code>`],
      ["패키지", html`<code>${s.source_ref || `${s.package}@${s.version}`}</code>`], ["원격 주소", html`<code>${s.endpoint}</code>`],
      ["공급자", s.supplier], ["라이선스", s.license], ["하위 시스템", downstreamText(s.downstream)],
      ...(intake?.internal_repo_url ? [["사내 저장소", html`<a href="${sameSite(intake.internal_repo_url)}" target="_blank" rel="noopener noreferrer">열기 ↗</a>`]] : []),
      ...(registration?.supplier_assurance ? assuranceRows(registration.supplier_assurance) : []),
      ...(registration?.risk_assessment ? [["위험 등급", chip(...RISK_TIER[registration.risk_assessment.tier])],
        ["처리 개인정보", RISK_CHOICES.personal_data[registration.risk_assessment.input.personal_data]],
        ["외부 전송", registration.risk_assessment.input.external_transfer ? "있음" : "없음"],
        ["실행 권한", RISK_CHOICES.permission[registration.risk_assessment.input.permission]],
        ["예상 사용자 수", `${registration.risk_assessment.input.users}명`],
        ["자율성", RISK_CHOICES.autonomy[registration.risk_assessment.input.autonomy]],
        ["승인자", (registration.risk_assessment.approvers || []).join(", ")],
        ["승인 방식", registration.risk_assessment.solo_mode === true ? "단독 운영" : registration.risk_assessment.solo_mode === false ? "일반 운영" : "—"]]
        : registration?.risk_review ? [["위험 등급", html`${chip(...RISK_TIER[registration.risk_review.tier])}<span class="sub">영향평가 입력 없음</span>`],
          ["재평가 기한", registration.risk_review.until.slice(0, 10)]] : []),
      ["사용 기한", registration ? `${when(registration.valid_until)} · ${DATA_CLASS[registration.data_class] || ""}` : ""],
      ["등록", registration ? `${registration.registered_by} · ${when(registration.registered_at)}` : ""],
      ["마지막 확인", s.last_seen_at ? `${when(s.last_seen_at)} · ${ago(s.last_seen_at)}` : ""]]) },
    { key: "tools", label: "도구·범위", n: tools.length, body: html`<div class="stack"><table class="data"><thead><tr><th>도구</th><th>행위</th><th>상태</th><th>마지막 사용</th><th>기한</th><th>이용 상태</th></tr></thead><tbody>
      ${tools.map((t) => { const [lastUse, deadline, sunsetStatus] = toolSunsetRow(id, t.name); return html`<tr><td><code>${t.name}</code></td><td>${chip({ r: "allow", w: "alert", x: "block" }[t.action] || "", ACTION[t.action] || t.action)}</td>
        <td>${!t.enabled ? (registration?.tools?.[t.name] ? chip("block", "범위 미심사") : chip("outline", "미승인")) : t.contract_ok ? chip("allow", "일치") : chip("alert", "불일치")}</td>
        <td>${lastUse}</td><td>${deadline}</td><td>${sunsetStatus}</td></tr>`; })}</tbody></table>
      ${registration ? scopeTable(registration.tools, registration.tool_reviews, registration.data_class, registration.intake_id ? s.id : null, registration.address_tools || []) : ""}</div>` },
    { key: "audience", label: "사용 대상", body: html`${kv([["대상", registration?.intake_id ? audienceText(registration.allowed_principals) : "—"]])}
      ${rels.length ? html`<h3>이용 관계</h3>${kv(rels.map((u) => [u.purpose, html`${u.organization} · ${(REL_STATUS[u.status] || [, u.status])[1]}
        <span class="sub">허용 자원 ${(u.allowed_resources || []).map(resourceName).join(", ") || "—"}</span>`]))}` : ""}` },
    { key: "trend", label: "호출 추이", body: trend ? chartBox("c-server-trend", "서버 호출 추이", "sm") : empty("", { failed: true }) },
    { key: "exit", label: "종료·폐기", body: html`<div class="stack"><div class="pill-list">${Object.entries(EXIT_TERMS).map(([k, label]) => bool(terms[k], label))}</div>
      ${creds.length ? kv([["보유 자격", html`${creds.map((c) => html`<code>${c.id}</code> `)}`]]) : ""}
      ${rel ? kv([["운영", operatorLabel(rel)], ["이용자", rel.users ?? 0], ["호출", rel.calls ?? 0],
        ...Object.entries(REVOKE_KEY).map(([k, text]) => [text, rel.readiness?.would_revoke?.[k] ?? 0]),
        ["예상 결과", rel.readiness?.best_attainable_grade ? gradeChip(rel.readiness.best_attainable_grade) : "—"]]) : empty("이용 관계 없음")}
      ${(rel?.readiness?.blockers || []).length ? html`<ul class="small">${rel.readiness.blockers.map((b) => html`<li>${b}</li>`)}</ul>` : ""}</div>` },
  ]);
  charts.register({ "c-server-trend": () => charts.decisionColumns(series.map(label), series) });
  charts.mountVisible($("#drawer-body"));
}
const resourceName = (a) => (typeof a === "string" ? a : a?.name || JSON.stringify(a));
function downstreamText(d) {
  if (!d) return "";
  if (typeof d !== "object") return String(d);
  return Object.entries(d).map(([k, v]) => `${k} ${Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : v}`).join(" · ");
}

const CONNECTOR_KIND = { connector: "claude.ai 커넥터", plugin: "플러그인", server: "직접 추가", app: "ChatGPT 앱", feature: "기본 기능" };
const CONNECTOR_STATE = { pending: ["approval", "미승인"], expired: ["block", "검토 기한 만료"], denied: ["block", "차단"],
  approved: ["outline", "승인 · 기록만"], default: ["allow", "기본 승인"] };
const FEATURE_LABEL = { web_search: "웹 검색", apps: "ChatGPT 앱 전체", plugins: "플러그인", browser_use: "브라우저 조작",
  computer_use: "컴퓨터 조작", image_generation: "이미지 생성", memories: "메모리" };
const connectorName = (g) => (g.kinds.includes("feature") ? FEATURE_LABEL[g.names[0]] || g.names[0] : g.names.join(" · "));
const connectorTarget = (g) => (g.key.split(":")[1] === "stdio" ? "stdio" : g.key.split(":").slice(2).join(":"));
const HARNESS_STATUS = [[/Connected/, "연결됨"], [/Needs authentication/, "인증 필요"], [/Failed/, "연결 실패"],
  [/Not configured/, "설정 안 됨"], [/^(enabled|on)$/, "켜짐"], [/^disabled$/, "꺼짐"], [/^absent$/, "미관측"]];
const harnessStatus = (s) => (HARNESS_STATUS.find(([re]) => re.test(s || "")) || [null, s || "켜짐"])[1];
function connectorState(g) {
  const [tone, label] = CONNECTOR_STATE[g.state] || ["", g.state];
  const days = g.due ? Math.ceil((new Date(g.due).getTime() - Date.now()) / 86400000) : null;
  return chip(tone, g.state === "pending" && days !== null ? `${label} D-${Math.max(days, 0)}` : label);
}
const connectorButtons = (g) => g.decision
  ? html`<button class="btn sm" data-act="connector-decide" data-key="${g.key}" data-decision="reset">${g.decision === "denied" ? "차단 해제" : "승인 취소"}</button>`
  : html`<button class="btn sm danger" data-act="connector-deny" data-key="${g.key}" data-name="${connectorName(g)}">차단</button>
    ${g.state === "default" ? "" : html`<button class="btn sm primary" data-act="connector-decide" data-key="${g.key}" data-decision="approved">승인</button>`}`;
const connectorControlChip = (all, key) => { const c = connectorControl(all, key); return c ? chip(c[0], c[1]) : NONE; };
const OUTSIDE = chip("outline", "게이트웨이 외부");
const harnessName = (h) => (h === "claude" ? "Claude Code" : "Codex");
const builtinRow = (b) => html`<tr><td><b>${b.label}</b></td><td>${chip("plain", harnessName(b.harness))}</td><td>${OUTSIDE}</td>
  <td class="num">${b.active_pcs ?? NONE}</td><td>${connectorState(b)}${b.state === "denied" && b.note ? html`<span class="sub">${b.note}</span>` : ""}</td>
  <td class="num nowrap">${b.state === "denied"
    ? html`<button class="btn sm" data-act="connector-decide" data-key="${b.key}" data-decision="reset">차단 해제</button>`
    : html`<button class="btn sm danger" data-act="connector-deny" data-key="${b.key}" data-name="${b.label}">차단</button>`}</td></tr>`;
const groupRow = (g, items, switchOff = false) => { const vendor = items.find((i) => i.item_key === g.key)?.vendor_control; return html`<tr class="clickable" tabindex="0" data-act="connector" data-key="${g.key}">
  <td><b>${connectorName(g)}</b><span class="sub mono">${connectorTarget(g)}</span></td>
  <td>${chip("plain", harnessName(g.harness))}</td>
  <td class="small">${g.kinds.map((k) => CONNECTOR_KIND[k] || k).join(" · ")}</td>
  <td class="num">${g.active_pcs}<span class="sub">${g.people}명</span></td>
  <td>${connectorState(g)}${switchOff && g.state !== "denied" ? chip("block", "전체 차단") : ""}${g.violation ? chip("block", "미승인 사용") : ""}</td>
  <td>${["denied", "pending", "expired"].includes(g.state) || switchOff ? connectorControlChip(connectorItems, g.key) : NONE}</td>
  <td class="small">${vendor ? chip("restrict", VENDOR_CONSOLE[vendor.console_state] || vendor.console_state) : NONE}</td>
  <td class="num nowrap">${connectorButtons(g)}</td></tr>`; };
const GROUP_HEAD = html`<thead><tr><th>이름</th><th>하네스</th><th>종류</th><th class="num">보고 엔드포인트</th><th>승인 상태</th><th>통제 적용 상태</th><th>벤더 콘솔</th><th></th></tr></thead>`;
const BUILTIN_HEAD = (first) => html`<thead><tr><th>${first}</th><th>하네스</th><th>경로</th><th class="num">보고 엔드포인트</th><th>상태</th><th></th></tr></thead>`;
function builtinTabs(conn, items) {
  const builtins = conn.builtins || [], catalog = new Set(builtins.map((b) => b.key));
  const reported = conn.items.filter((g) => !catalog.has(g.key));
  const features = builtins.filter((b) => b.kind === "feature");
  const switches = builtins.filter((b) => b.kind === "connector");
  const off = new Set(switches.filter((b) => b.state === "denied").map((b) => b.harness));
  const extraFeatures = reported.filter((g) => g.builtin && g.kinds.includes("feature"));
  const connectors = reported.filter((g) => g.builtin && !g.kinds.includes("feature"));
  const review = reported.filter((g) => !g.builtin);
  return html`<div class="stack">
    <div class="row-actions connector-tab-actions"><button class="btn" type="button" data-act="connector-policy">커넥터 설정 내보내기</button></div>
    ${panel("기본 기능", html`<table class="data">${BUILTIN_HEAD("기능")}<tbody>${features.map(builtinRow)}</tbody></table>
      ${extraFeatures.length ? html`<table class="data">${GROUP_HEAD}<tbody>${extraFeatures.map((g) => groupRow(g, items))}</tbody></table>` : ""}`, { flush: true })}
    ${panel("커넥터 전체 사용 설정", switches.length ? html`<table class="data">${BUILTIN_HEAD("커넥터")}<tbody>${switches.map(builtinRow)}</tbody></table>` : empty("항목 없음"), { flush: true })}
    ${panel("개별 커넥터", connectors.length ? html`<table class="data">${GROUP_HEAD}<tbody>${connectors.map((g) => groupRow(g, items, off.has(g.harness)))}</tbody></table>` : empty("보고된 항목 없음"), { flush: true })}
    ${panel("추가 연결 승인 관리", review.length ? html`<table class="data">${GROUP_HEAD}<tbody>${review.map((g) => groupRow(g, items))}</tbody></table>`
      : empty("보고된 항목 없음"), { flush: true, sub: conn.review_days ? `검토 기한 ${conn.review_days}일` : "" })}</div>`;
}
let connectorGroups = [], connectorItems = [];

const STATE_DECISION = { gateway_enforced: "Allow", endpoint_enforced: "Allow", vendor_enforced: "",
  observed_only: "Alert", unknown_not_enrolled: "", bypass_possible: "Block" };
const COV_LISTS = { full_entries: "entries", entries: "entries", listeners: "listeners", os_events: "os-events" };
const covPaging = Object.fromEntries(Object.keys(COV_LISTS).map((key) => [key, { cursors: [null], index: 0, next: null }]));
const resetCoveragePaging = () => Object.values(covPaging).forEach((state) => Object.assign(state, { cursors: [null], index: 0, next: null }));
async function covPage(inv, list, classification = "shadow,retired-residue") {
  const source = list === "full_entries" ? "entries" : list;
  const state = covPaging[list], first = { ...inv.pages[source], rows: inv[source] };
  const saved = current.query.getAll(`${list}_cursor`);
  if (saved.length) {
    state.cursors = saved.map((v) => v || null);
    state.index = Math.min(saved.length - 1, Math.max(0, Number(current.query.get(`${list}_page`)) || 0));
  } else Object.assign(state, { cursors: [null], index: 0, next: null });
  const page = !state.index ? first : await gw(`endpoint/inventory/${COV_LISTS[list]}?${new URLSearchParams({
    limit: first.limit, cursor: state.cursors[state.index], ...(list === "os_events" || !classification ? {} : { classification }), ...Object.fromEntries(listFilter(list)) })}`);
  state.next = page.next_cursor;
  return page;
}
const covPager = (list, page) => {
  const p = pager(covPaging[list], page);
  return p.count > 1 || p.hasPrev ? html`<div class="pager"><button class="pager-button" type="button" data-act="cov-page" data-list="${list}" data-dir="-1" aria-label="이전 페이지" title="이전 페이지" ${p.hasPrev ? "" : raw("disabled")}>‹</button>
    <span>${p.number} / ${p.count}</span>
    <button class="pager-button" type="button" data-act="cov-page" data-list="${list}" data-dir="1" aria-label="다음 페이지" title="다음 페이지" ${p.hasNext ? "" : raw("disabled")}>›</button></div>` : "";
};
const covCount = (page, shown) => { const c = countView(page, shown); return { sub: c.label, end: c.truncated ? chip("alert", `일부 표시 ${c.shown}건`) : "" }; };
const evidenceChip = (state) => { const v = provenanceView({ state }); return v.state === "unreported" ? NONE : chip(v.tone, v.label); };
const recordRow = (kind, id, cells) => html`<tr class="clickable" tabindex="0" data-act="endpoint-record" data-kind="${kind}" data-id="${id}">${cells}</tr>`;
function connectionStateCharts(items) {
  return { "c-connections-matrix": () => charts.stacked(Object.values(INTEGRATION_CLASS),
    Object.entries(CONTROL_STATE).map(([k, [, label]]) => ({ name: label, color: charts.color(STATE_DECISION[k]),
      data: Object.keys(INTEGRATION_CLASS).map((c) => items.filter((i) => i.class === c && i.state === k).length) })),
    { horizontal: true, onClick: (e) => {
      const c = Object.keys(INTEGRATION_CLASS)[e.dataIndex], state = Object.keys(CONTROL_STATE)[e.seriesIndex];
      if (c && state) location.hash = `#/connections?t=items&class=${c}&state=${state}`;
    } }) };
}
const unapprovedItem = (i) => i.class === "shadow_or_unknown" || ["pending", "unapproved", "expired"].includes(i.approval?.state);
const UNVERIFIED_STATES = ["bypass_possible", "observed_only", "unknown_not_enrolled"];
const serviceName = (name) => String(name || "").replace(/^claude\.ai\s+/i, "");
function targetLabel(i) {
  const target = String(i.target || "");
  if (/^https?:\/\//.test(target)) { try { return new URL(target).hostname; } catch { return ""; } }
  return /^(local:|sha256:|stdio)/.test(target) ? "로컬 프로세스" : "";
}
const DISCOVERY_TERMS = [["stdio-process", "표준 입출력"], ["local-process", "로컬 프로세스"], ["local-socket", "로컬 소켓"]];
const discoveredLabel = (text) => DISCOVERY_TERMS.reduce((out, [word, label]) => out.replace(word, label), String(text || ""));
const itemRank = (i) => (unapprovedItem(i) ? 0 : UNVERIFIED_STATES.includes(i.state) && i.class !== "vendor_native_connector" ? 1 : 2);
const enforcerChip = (i) => (i.class === "vendor_native_connector" && i.state === "observed_only" && ["default", "approved"].includes(i.approval?.state)
  ? chip("outline", "벤더 경유") : controlChip(i.state));
function verifiedText(i) {
  const v = statusView(i);
  return html`<span class="ev ${v.stale ? "stale" : ""}">${v.evLabel === EVIDENCE.none.label ? "미확인" : v.evLabel}</span>`;
}
async function serverControlTabs(query, snapshot = planes()) {
  const [p, conn] = await Promise.all([snapshot, api("/api/connectors")]);
  connectorGroups = conn.items;
  connectorItems = p.items;
  const items = dedupeItems(p.items);
  integrationItems = items;
  const state = query.get("state") || "", cls = query.get("class") || "", q = (query.get("q") || "").toLowerCase();
  const approvalFilter = query.get("approval") === "unapproved";
  const rows = items.filter((i) => (!state || i.state === state) && (!cls || i.class === cls) && (!approvalFilter || unapprovedItem(i))
    && (!q || `${i.name} ${i.target || ""} ${(i.owners || []).join(" ")}`.toLowerCase().includes(q)))
    .map((i, at) => ({ i, at })).sort((a, b) => itemRank(a.i) - itemRank(b.i) || a.at - b.at).map((x) => x.i);
  const review = conn.summary.pending + conn.summary.expired;
  const coverageSelect = (key, label, choices, cur) => html`<label class="list-search">${label}<select data-coverage-filter="${key}" aria-label="${label}">
    <option value="">전체</option>${Object.entries(choices).map(([k,v]) => html`<option value="${k}" ${k === cur ? raw("selected") : ""}>${Array.isArray(v) ? v[1] : v}</option>`)}</select></label>`;
  return [
    { key: "items", label: "연결 통제 현황", n: items.length, body: html`<div class="stack">
      ${panel("연결 유형별 통제 현황", items.length ? chartBox("c-connections-matrix", "연결 유형별 통제 항목 수", "d220") : empty("항목 없음"), { sub: "연결 항목 수" })}
      ${panel("연결별 통제 상태", html`<table class="data"><thead><tr><th>항목</th><th>연결 유형</th><th>승인</th><th>집행 주체</th><th>확인 상태</th><th class="num">우회 가능 경로</th><th>발견</th></tr></thead><tbody>
        ${rows.map((i) => html`<tr class="clickable" tabindex="0" data-act="integration" data-key="${i.key}">
          <td><b>${serviceName(i.name)}</b><span class="sub" title="${i.target || ""}">${[targetLabel(i), i.pcs > 1 ? `엔드포인트 ${i.pcs}대` : ""].filter(Boolean).join(" · ")}</span></td>
          <td class="small">${INTEGRATION_CLASS[i.class] || i.class}${i.harness ? html`<span class="sub">${harnessName(i.harness)}</span>` : ""}</td>
          <td class="small">${unapprovedItem(i) ? chip("block", approvalLabel(i.approval?.state)) : approvalLabel(i.approval?.state)}${i.approval?.expires_at ? html`<span class="sub">${when(i.approval.expires_at)}까지</span>` : ""}</td>
          <td>${enforcerChip(i)}</td>
          <td class="small">${verifiedText(i)}</td>
          <td class="num">${(i.bypass || []).length || NONE}</td>
          <td class="small">${discoveredLabel(i.discovered_from)}${i.discovered_at ? html`<span class="sub">${when(i.discovered_at)}</span>` : ""}</td></tr>`)}
        </tbody></table>${rows.length ? "" : empty("항목 없음", { filtered: !!(state || cls || q || approvalFilter) })}`, { flush: true,
        tools: html`<input type="search" data-coverage-search maxlength="80" value="${query.get("q") || ""}" placeholder="이름·대상·사용자" aria-label="항목 검색" />
          ${coverageSelect("state", "상태", CONTROL_STATE, state)}
          ${coverageSelect("class", "연동 유형", INTEGRATION_CLASS, cls)}<span class="small muted">연결 항목 ${rows.length}/${items.length}개</span>` })}</div>` },
    { key: "vendor", label: "기본 기능 및 커넥터", n: review || undefined, hot: review > 0, body: builtinTabs(conn, items) },
  ];
}

let shadowList = [], shadowInventory = null;
const shadowCount = (rows) => rows.filter((e) => e.classification === "shadow").length;
async function shadowTab(query, inv, pcs) {
  const entriesPage = await covPage(inv, "entries");
  shadowInventory = inv;
  const groups = shadowGroups(entriesPage.rows.filter((e) => e.classification !== "registered"));
  shadowList = groups;
  const endpoint = query.get("endpoint") || "";
  return { key: "shadow", label: "미등록 MCP", n: groups.length || undefined, hot: groups.length > 0, body: panel("미등록 MCP", html`<table class="data"><thead><tr><th>MCP</th><th>연결</th><th class="num">PC</th><th>최근 발견</th><th>분류</th><th></th></tr></thead><tbody>
    ${groups.map((g, i) => html`<tr class="clickable" tabindex="0" data-act="shadow-group" data-index="${i}">
      <td><b>${g.label}</b></td><td class="small clip">${TRANSPORT[g.transport] || "—"} <span class="mono address">${short(g.ref, 40)}</span></td>
      <td class="num">${g.endpoints.size}</td><td class="small nowrap">${ago(g.latest)}</td>
      <td>${chip(...(ENDPOINT_CLASS[g.cls] || ["outline", "확인 불가"]))}</td><td class="num muted" aria-hidden="true">›</td></tr>`)}
    </tbody></table>${groups.length ? "" : empty("미등록 MCP 없음", { filtered: !!endpoint })}${covPager("entries", entriesPage)}`,
    { flush: true, ...covCount(entriesPage, entriesPage.rows.length), tools: endpoint ? html`<a class="btn sm" href="#/connections?t=shadow">전체 PC</a>` : "" }) };
}

function showShadowGroup(index) {
  const g = shadowList[index], inv = shadowInventory;
  if (!g || !inv) return;
  const ids = g.endpoints, agents = inv.agents.filter((a) => ids.has(a.endpoint_id));
  const listeners = listenerCoverage((inv.listeners || []).filter((l) => ids.has(l.endpoint_id))).rows, events = (inv.os_events || []).filter((e) => ids.has(e.endpoint_id));
  const query = new URLSearchParams({ t: "new", name: g.label, purpose: "", source: g.transport === "stdio" ? "" : g.ref });
  openDrawer(g.label, html`<div class="row-actions">${chip(...(ENDPOINT_CLASS[g.cls] || ["outline", "확인 불가"]))}
    <a class="btn sm primary" href="#/intake?${query}">도입 신청 만들기</a></div>`, [
    { key: "pcs", label: "PC", n: agents.length, body: html`<table class="data"><thead><tr><th>사용자</th><th>호스트</th><th>마지막 보고</th><th></th></tr></thead><tbody>
      ${agents.map((a) => html`<tr><td>${a.owner_name || "—"}</td><td>${a.hostname || "—"}</td><td class="small">${ago(a.last_seen_at)}</td>
        <td class="num nowrap">${a.managed_state === "quarantined" ? chip("block", "격리") : html`<button class="btn sm danger" type="button" data-act="device-quarantine" data-id="${a.endpoint_id}" data-name="${a.hostname || a.endpoint_id}">PC 격리</button>`}</td></tr>`)}
      </tbody></table>` },
    { key: "files", label: "설정 파일", n: g.entries.length, body: html`<table class="data"><thead><tr><th>엔드포인트</th><th>설정 파일</th><th>출처</th><th>증거</th></tr></thead><tbody>
      ${g.entries.map((e) => recordRow("config", e.id, html`<td>${entityRef(e.endpoint_id)}</td><td class="small mono address">${e.config_path}</td><td class="small">${originLabel(e.origin)}</td><td>${evidenceChip(e.provenance_state)}</td>`))}</tbody></table>` },
    { key: "listeners", label: "수신기", n: listeners.length, body: listeners.length ? html`<table class="data"><thead><tr><th>시각</th><th>엔드포인트</th><th>주소·프로세스</th><th>증거</th></tr></thead><tbody>
      ${listeners.map((l) => recordRow("listener", l.id, html`<td class="small nowrap">${when(l.observedAt)}</td><td>${entityRef(l.endpointId)}</td><td class="small mono address">${l.address}${l.port ? `:${l.port}` : ""}</td><td>${evidenceChip(l.provenance)}</td>`))}</tbody></table>` : empty("수신기 관측 없음") },
    { key: "denials", label: "차단 기록", n: events.length, body: events.length ? html`<table class="data"><thead><tr><th>시각</th><th>엔드포인트</th><th>종류</th><th>대상</th></tr></thead><tbody>
      ${events.map((e) => recordRow("os-event", e.id, html`<td class="nowrap">${when(e.observed_at)}</td><td>${entityRef(e.endpoint_id)}</td>
        <td>${chip("block", e.kind === "network-denied" ? "네트워크 차단" : e.kind === "execution-denied" ? "실행 차단" : "차단 기록")}</td><td class="mono small address">${osEventTarget(e)}</td>`))}</tbody></table>` : empty("수신된 차단 기록 없음") },
  ]);
}

ROUTES.connections = async (_, tab, query = new URLSearchParams()) => {
  const snapshot = planes();
  const filter = deviceQuery(query, ["endpoint"]);
  const [inv, controls] = await Promise.all([gw(`endpoint/inventory?classification=shadow,retired-residue${filter.size ? `&${filter}` : ""}`), serverControlTabs(query, snapshot)]);
  const shadow = await shadowTab(query, inv);
  const count = (s) => integrationItems.filter((i) => i.state === s).length;
  const gaps = shadowPcs(inv.agents);
  const unapproved = integrationItems.filter(unapprovedItem);
  return {
    html: page({
      head: head("연결 통제"),
      kpis: html`${kpiStrip([["미승인 연결", unapproved.length, "block", "#/connections?t=items&approval=unapproved"],
        ["미등록 MCP 발견 PC", gaps, gaps ? "block" : "", "#/connections?t=shadow"],
        ["게이트웨이 통제", count("gateway_enforced"), "allow", "#/connections?t=items&state=gateway_enforced"],
        ["엔드포인트 통제", count("endpoint_enforced"), "allow", "#/connections?t=items&state=endpoint_enforced"],
        ["벤더 통제", count("vendor_enforced"), "restrict", "#/connections?t=items&state=vendor_enforced"],
        ["통제 미검증", UNVERIFIED_STATES.reduce((sum, key) => sum + count(key), 0), "alert", "#/connections?t=items&state=bypass_possible"]])}
        ${unapproved.length ? panel("미승인 연결", html`<table class="data"><tbody>${unapproved.slice(0, 5).map((i) => html`<tr class="clickable" tabindex="0" data-act="integration" data-key="${i.key}">
          <td><b>${serviceName(i.name)}</b><span class="sub" title="${i.target || ""}">${targetLabel(i)}</span></td><td class="small">${INTEGRATION_CLASS[i.class] || i.class}</td>
          <td class="small">${[...(i.owners || [])].join(", ") || "—"}${i.pcs > 1 ? html`<span class="sub">엔드포인트 ${i.pcs}대</span>` : ""}</td>
          <td class="small">${approvalLabel(i.approval?.state)}</td><td class="small">${discoveredLabel(i.discovered_from)}${i.discovered_at ? html`<span class="sub">${when(i.discovered_at)}</span>` : ""}</td>
          <td class="num"><button class="btn sm" type="button" data-act="integration" data-key="${i.key}">검토</button></td></tr>`)}</tbody></table>`,
          { flush: true, sub: `${unapproved.length}개`, end: unapproved.length > 5 ? html`<a class="btn sm" href="#/connections?t=items&approval=unapproved">전체 보기</a>` : "" }) : ""}`,
      active: ["items", "shadow", "vendor"].includes(tab) ? tab : "items",
      tabs: [controls[0], shadow, controls[1]],
    }),
    charts: connectionStateCharts(integrationItems),
    after: () => { if (tab === "vendor" && query.get("connector")) ACTIONS.connector({ dataset: { key: query.get("connector") } }); },
  };
};

const VENDOR_CONSOLE = { blocked: "차단", limited: "제한 허용", allowed: "허용", unknown: "확인 불가" };
const CHECK_LABEL = { apparmor_enforcing: "실행 통제", nftables_active: "네트워크 통제", firewall_enforcing: "네트워크 통제", pf_enforcing: "네트워크 통제", protected_configs: "설정 보호", ordinary_account: "일반 계정", user_command_helpers: "사용자 명령 헬퍼 없음" };
function checksChip(checks) {
  const entries = Object.entries(checks || {});
  if (!entries.length) return NONE;
  const failed = entries.filter(([, v]) => !v).map(([k]) => CHECK_LABEL[k] || k);
  return failed.length ? chip("block", `미충족 ${failed.join(", ")}`) : chip("allow", `정상 ${entries.length}/${entries.length}`);
}
function osEventTarget(e) {
  const d = e.details || {};
  if (e.kind === "network-denied") return `${d.destination_ip || "—"}${d.destination_port ? `:${d.destination_port}` : ""}${d.protocol ? ` ${d.protocol}` : ""}`;
  return d.executable || d.operation || "—";
}
const MANAGED_MODE = { simple: "간편 모드", isolated: "격리 계정" };
const SIGNUP_STATUS = { pending: ["approval", "대기"], approved: ["allow", "승인"], rejected: ["block", "거부"] };
const MANAGED_EVENT = {
  "kit-issued": ["outline", "설치 파일 발급"], enrolled: ["approval", "설치 보고"], activated: ["allow", "활성화"],
  quarantined: ["block", "격리"], revoked: ["outline", "등록 해제"], "unmanaged-login-denied": ["block", "미관리 로그인 거부"],
  "token-denied": ["block", "토큰 거부"], "mcp-auth-denied": ["block", "MCP 인증 거부"],
};
const managedEventDetail = (d) => (d && (d.reason || d.note || (d.actor ? `처리 ${d.actor}` : "") || (d.expires_at ? `${when(d.expires_at)}까지` : ""))) || "—";

let peopleAccounts = [];
let integrationItems = [];
const chartRow = (...boxes) => html`<div class="grid c${boxes.length} chart-row">${boxes.map(([title, id, label]) => panel(title, chartBox(id, label, "sm")))}</div>`;
const sinceDay = () => new URLSearchParams({ event_kind: "tools/call", since: new Date(Date.now() - 86400000).toISOString(), until: new Date().toISOString() });
const PC_STAGE = { none: ["outline", "—"], signed: ["outline", "미연결"], installed: ["approval", "설치 보고"], active: ["allow", "연결됨"] };
const USER_STATE = { active: ["allow", "사용"], disabled: ["block", "계정 중지"], locked: ["alert", "잠김"], deleted: ["outline", "삭제됨"] };
const USER_FILTERS = [["", "전체"], ["active", "사용"], ["disabled", "계정 중지"], ["locked", "잠김"], ["deleted", "삭제됨"]];
ROUTES.people = async (_, tab, query = new URLSearchParams()) => {
  const status = ["pending", "approved", "rejected"].includes(query.get("signup_status")) ? query.get("signup_status") : "";
  const signupPage = listPageNumber(query, "signup_page"), signupQuery = new URLSearchParams();
  if (status) signupQuery.set("status", status);
  if (signupPage > 1) signupQuery.set("page", signupPage);
  const soft = (promise, fallback) => promise.catch(() => fallback);
  const [{ accounts }, { accounts: deletedAccounts }, signupData, identity, { suspensions }, inv, analysis] = await Promise.all([
    api("/api/accounts"), soft(api("/api/accounts/deleted"), { accounts: [] }), api(`/api/signup-requests${signupQuery.size ? `?${signupQuery}` : ""}`),
    soft(api("/api/identity"), { provider: "local", bindings: [] }), gw("suspensions"),
    soft(gw("endpoint/inventory"), { agents: [] }), soft(gw(`activity/analysis?${sinceDay()}`), null)]);
  const signups = signupData.requests;
  const signupHref = (p, nextStatus = status) => `#/people?${new URLSearchParams({ t: "signups", ...(nextStatus ? { signup_status: nextStatus } : {}), signup_page: p })}`;
  const signupPaging = listPager({ ...signupData, total: signupData.total ?? signups.length, page_size: signupData.page_size || 100 }, signupHref);
  peopleAccounts = accounts;
  const cards = userCards(accounts, deletedAccounts, signups, suspensions);
  const stateFilter = USER_FILTERS.some(([value]) => value === query.get("status")) ? query.get("status") : "";
  const rows = userRows(accounts, deletedAccounts, inv.agents || [], peopleStats(analysis?.people)).filter((a) => !stateFilter || a.state === stateFilter);
  const blockedTop = topBlocked(analysis?.people);
  const filterHref = (value) => `#/people?${new URLSearchParams({ t: "accounts", ...(value ? { status: value } : {}) })}`;
  return {
    html: page({
      head: head("사용자", { actions: html`<button class="btn primary" type="button" data-act="account-invite">사용자 초대</button>` }),
      kpis: kpiStrip([["전체 사용자", cards.total, "", "#/people?t=accounts"], ["계정 사용", cards.active, "", "#/people?t=accounts&status=active"],
        ["계정 중지", cards.disabled, cards.disabled ? "alert" : "", "#/people?t=accounts&status=disabled"],
        ["MCP 이용 제한", cards.stopped, cards.stopped ? "alert" : "", "#/people?t=suspensions"],
        ["가입 대기", cards.pending, cards.pending ? "approval" : "", "#/people?t=signups&signup_status=pending"]]),
      active: ["accounts", "suspensions", "signups", ...(identity.provider === "oidc" ? ["sso"] : [])].includes(tab) ? tab : "accounts",
      tabs: [
        { key: "accounts", label: "사용자", n: rows.length, body: html`<div class="stack">${panel("사용자", html`<table class="data"><thead><tr><th>이름</th><th>부서</th><th>역할</th><th>상태</th><th>PC 연결</th><th class="num">호출 · 차단 24시간</th><th></th></tr></thead><tbody id="account-list">
          ${rows.map((a) => html`<tr><td><b>${a.display_name}</b> <span class="muted small">${a.email && ![a.display_name, a.user_id].includes(a.email) ? a.email : ""}</span></td><td>${a.department || "—"}</td><td>${ROLE[a.role] || a.role}</td>
            <td>${chip(...(USER_STATE[a.state] || ["", a.state]))}</td>
            <td>${a.stage === "none" ? NONE : html`<a href="#/endpoints?${new URLSearchParams({ t: "devices", q: a.display_name })}">${chip(...PC_STAGE[a.stage])}</a>${a.pcs > 1 ? html`<span class="sub">${a.pcs}대</span>` : ""}`}</td>
            <td class="num">${a.state === "deleted" ? "—" : html`${a.calls} · <span class="${a.blocked ? "bad-text" : ""}">${a.blocked}</span>`}</td>
            <td class="num">${a.state === "deleted" ? html`<button class="btn sm primary" type="button" data-act="account-restore" data-id="${a.user_id}" data-name="${a.display_name}">복구</button>`
              : a.user_id === viewer.user_id ? html`<span class="small muted">본인</span>`
              : rowMenu(html`<button type="button" data-act="account-status" data-id="${a.user_id}" data-name="${a.display_name}" data-status="${a.status}">상태 변경</button>
                <button type="button" data-act="suspend-open" data-token="${a.token}" data-name="${a.display_name}">MCP 이용 중지</button>
                <button type="button" data-act="suspend-all" data-token="${a.token}" data-name="${a.display_name}">전체 중지</button>
                <button type="button" data-act="resume-all" data-token="${a.token}" data-name="${a.display_name}">전체 재개</button>
                ${a.role !== "admin" || viewer.user_id === "root" ? html`<button type="button" data-act="account-rename" data-id="${a.user_id}" data-name="${a.display_name}">아이디 변경</button>
                  <button type="button" data-act="account-password" data-id="${a.user_id}" data-name="${a.display_name}" data-role="${a.role}">비밀번호 재설정</button>` : ""}
                ${a.user_id !== "root" ? html`<button type="button" class="danger" data-act="account-delete" data-id="${a.user_id}" data-name="${a.display_name}">삭제</button>` : ""}`)}</td></tr>`)}
          </tbody></table>${rows.length ? "" : empty("사용자 없음", { filtered: !!stateFilter })}<p class="empty" role="status" data-list-empty="account-list" hidden>조건에 맞는 결과 없음</p>`,
          { flush: true, tools: html`${listToolbar("account-list", "이름·이메일·부서 검색")}<div class="row-actions">${USER_FILTERS.map(([value, label]) => html`<a class="btn sm ${value === stateFilter ? "primary" : ""}" href="${filterHref(value)}">${label}</a>`)}</div>` })}
          ${blockedTop.length ? panel("차단 발생 사용자", chartBox("c-people-blocked", "차단 발생 사용자 24시간", "xs"), { sub: "24시간" }) : ""}</div>` },
        { key: "suspensions", label: "MCP 이용 제한", n: suspensions.filter((x) => !x.resumed_at).length,
          body: panel("MCP 이용 제한", html`<table class="data"><thead><tr><th>사용자</th><th>서버</th><th>사유</th><th>중지</th><th>해제 예정</th><th>상태</th><th>재개</th><th></th></tr></thead><tbody>
            ${suspensions.map((x) => html`<tr><td>${x.display_name || "—"}</td><td>${x.server_name || x.server_id}</td><td class="small">${short(x.reason, 60)}</td>
              <td class="small nowrap">${when(x.suspended_at)} · ${x.suspended_by || "—"}</td>
              <td class="small">${x.expires_at ? when(x.expires_at) : "—"}</td>
              <td>${x.resumed_at ? chip("allow", "재개") : chip("block", "중지")}</td>
              <td class="small">${x.resumed_at ? html`${when(x.resumed_at)} · ${x.resumed_by || "—"}` : "—"}</td>
              <td class="num">${x.resumed_at ? "" : html`<button class="btn sm primary" data-act="suspend-resume" data-id="${x.id}" data-name="${x.display_name || ""}" data-server="${x.server_name || x.server_id}">재개</button>`}</td></tr>`)}
            </tbody></table>${suspensions.length ? "" : empty("중지한 이용 없음")}`, { flush: true }) },
        { key: "signups", label: "가입 요청", n: signupPendingTotal(signupData),
          body: panel("가입 요청", html`<table class="data"><thead><tr><th>아이디</th><th>이름</th><th>요청</th><th>상태</th><th></th></tr></thead><tbody>
          ${signups.map((s) => html`<tr><td class="mono">${s.username}</td><td>${s.display_name}</td><td class="nowrap">${when(s.requested_at)}</td>
            <td>${chip(...(SIGNUP_STATUS[s.status] || ["", s.status]))}</td>
            <td class="num nowrap">${s.status === "pending" ? html`<button class="btn sm danger" data-act="signup-reject" data-id="${s.id}">거부</button>
              <button class="btn sm primary" data-act="signup-approve" data-id="${s.id}">승인</button>` : ""}</td></tr>`)}
          </tbody></table>${signups.length ? "" : empty("가입 요청 없음")}`, { flush: true, end: signupPaging,
            tools: html`<div class="row-actions">${[["", "전체"], ["pending", "대기"], ["approved", "승인"], ["rejected", "거부"]].map(([value, label]) => html`<a class="btn sm ${value === status ? "primary" : ""}" href="${signupHref(1, value)}">${label}</a>`)}</div>` }) },
        ...(identity.provider === "oidc" ? [{ key: "sso", label: "SSO", n: identity.bindings.length, body: html`<div class="stack">
          ${panel("SSO", kv([["로그인 방식", identity.label || "SSO"], ["상태", identity.configured ? "사용" : "설정 필요"], ["발급자", identity.issuer || "—"]]),
            { end: identity.configured ? html`<button class="btn sm primary" data-act="identity-bind">SSO 계정 연결</button>` : "" })}
          ${panel("연결된 SSO 계정", identity.bindings.length ? html`<table class="data"><thead><tr><th>사용자</th><th>SSO 계정</th><th>연결</th><th></th></tr></thead><tbody>${identity.bindings.map((b) => html`<tr><td>${b.principal}</td><td class="mono">${b.subject}</td><td>${b.linked_by} · ${when(b.linked_at)}</td><td class="num"><button class="btn sm danger" data-act="identity-unbind" data-id="${b.id}">연결 해제</button></td></tr>`)}</tbody></table>` : empty("연결된 계정 없음"), { flush: true })}</div>` }] : []),
      ],
    }),
    charts: {
      "c-people-blocked": () => charts.bars(blockedTop.map((p) => ({ name: p.total ? `${p.name} · 호출 ${p.total}` : p.name, value: p.value, color: charts.color("Block") })),
        { onClick: (e) => { const row = blockedTop[e.dataIndex]; if (row) location.hash = `#/activity?${new URLSearchParams({ ...Object.fromEntries(sinceDay()), decision: "Block", person: row.name })}`; } }),
    },
  };
};

const MANAGED_STATE = { active: "활성", pending: "활성화 대기", quarantined: "격리" };
const MANAGED_TONE = { active: "allow", pending: "approval", quarantined: "block" };
const deviceQuery = (query = current.query, keys = ["endpoint", "q", "state"]) => new URLSearchParams([...query].filter(([k, v]) => keys.includes(k) && v));
const listFilter = (list) => deviceQuery(current.query, list === "full_entries" ? undefined : ["endpoint"]);
let endpointList = [];
const endpointState = (r) => r.managed_state && MANAGED_STATE[r.managed_state] ? chip(MANAGED_TONE[r.managed_state], MANAGED_STATE[r.managed_state]) : chip("outline", "관리되지 않음");
const osName = (platform) => PLATFORM[String(platform || "").split(/[\s-]/)[0].toLowerCase()] || String(platform || "");
const REPORT_CHIP = { delayed: ["alert", "보고 지연"], stale: ["block", "24시간 이상 미보고"] };
const reportCell = (r) => {
  const state = reportState(r), at = when(r.last_seen_at, { year: true, seconds: true });
  return state === "fresh" ? html`<span title="${at}">${ago(r.last_seen_at)}</span>`
    : html`${chip(...REPORT_CHIP[state])}<span class="sub" title="${at}">${ago(r.last_seen_at)}</span>`;
};
function endpointChecks(r) {
  const entries = Object.entries(r.device?.checks || {});
  if (!entries.length) return NONE;
  if (entries.some(([, ok]) => !ok)) return checksChip(r.device.checks);
  return reportState(r) === "fresh" ? checksChip(r.device.checks)
    : html`${chip("outline", "마지막 확인 정상")}<span class="sub">${ago(r.device.evidence_at || r.last_seen_at)}</span>`;
}
const endpointActions = (r) => html`${["pending", "quarantined"].includes(r.managed_state) && r.policy_hash ? html`<button class="btn sm primary" type="button" data-act="device-activate" data-id="${r.endpoint_id}" data-hash="${r.policy_hash}">활성화</button>` : ""}`;
ROUTES.endpoints = async (_, tab, query = new URLSearchParams()) => {
  const filter = deviceQuery(query);
  const [{ accounts }, inv, o, p] = await Promise.all([
    api("/api/accounts"), gw(`endpoint/inventory${filter.size ? `?${filter}` : ""}`), gw("overview"), planes()]);
  peopleAccounts = accounts;
  const option = (value, label, cur) => html`<option value="${value}" ${value === cur ? raw("selected") : ""}>${label}</option>`;
  const all = endpointRows(inv.agents, p.devices, o.workstations, accounts);
  const silentOnly = query.get("silent") === "1";
  const rows = filterEndpoints(all, { silent: silentOnly });
  endpointList = all;
  const cards = endpointCards(all);
  const hostById = Object.fromEntries(all.map((r) => [r.endpoint_id, r.hostname]));
  const quiet = all.filter((r) => reportState(r) !== "fresh").sort((a, b) => Date.parse(a.last_seen_at || 0) - Date.parse(b.last_seen_at || 0)).slice(0, 5);
  return {
    html: page({
      head: head("엔드포인트", { actions: html`<label class="inline-setting">새 PC 활성화<select data-act-change="endpoint-auto" aria-label="새 PC 활성화">${option("on", "자동", inv.settings?.auto_activate === false ? "off" : "on")}${option("off", "관리자 확인", inv.settings?.auto_activate === false ? "off" : "on")}</select></label>
        <button class="btn" type="button" data-act="device-issue">엔드포인트 등록</button>` }),
      kpis: html`${kpiStrip([["등록 PC", cards.total, "", "#/endpoints?t=devices"], ["최근 15분 보고", cards.reporting],
        ["보고 지연", cards.delayed, cards.delayed ? "alert" : "", "#/endpoints?t=devices&silent=1"],
        ["24시간 이상 미보고", cards.stale, cards.stale ? "block" : "", "#/endpoints?t=devices&silent=1"],
        ["격리", cards.quarantined, "block", "#/endpoints?t=devices&state=quarantined"],
        ["활성화 대기", cards.pending, "approval", "#/endpoints?t=devices&state=pending"]])}
        ${quiet.length ? panel("보고 확인 필요", html`<table class="data compact"><tbody>${quiet.map((r) => html`<tr class="clickable" tabindex="0" data-act="endpoint-device" data-id="${r.endpoint_id}">
          <td><b>${r.owner || "—"}</b></td><td>${r.hostname || "—"}</td><td class="small nowrap">${reportCell(r)}</td>
          <td class="num"><button class="btn sm" type="button" data-act="endpoint-device" data-id="${r.endpoint_id}">보기</button></td></tr>`)}</tbody></table>`, { flush: true, sub: `${cards.silent}대` }) : ""}`,
      active: ["devices", "managed"].includes(tab) ? tab : "devices",
      tabs: [
        { key: "devices", label: "엔드포인트", n: all.length, body: panel("엔드포인트", html`<table class="data"><thead><tr><th>사용자</th><th>호스트</th><th>등록 상태</th><th>최근 보고</th><th>통제 점검</th><th>AI 클라이언트</th><th class="num">발견 MCP</th><th class="num">호출 24시간</th><th></th></tr></thead><tbody>
            ${rows.map((r) => html`<tr class="clickable" tabindex="0" data-act="endpoint-device" data-id="${r.endpoint_id}">
              <td><b>${r.owner || "—"}</b></td><td>${r.hostname || "—"} <span class="muted small" title="${r.platform || ""}">${osName(r.platform)}</span></td>
              <td>${endpointState(r)}</td>
              <td class="small nowrap">${reportCell(r)}</td>
              <td>${endpointChecks(r)}</td>
              <td>${r.harness ? chip("plain", harnessLabel(r.harness)) : NONE}</td>
              <td class="num">${r.shadow ? html`<a href="#/connections?${new URLSearchParams({ t: "shadow", endpoint: r.endpoint_id })}">${chip("block", r.shadow)}</a>` : r.detail?.observation?.inventory?.state === "success" ? "0" : NONE}</td>
              <td class="num">${r.calls}</td><td class="num nowrap">${endpointActions(r)}</td></tr>`)}
            </tbody></table>${rows.length ? "" : empty("엔드포인트 없음", { filtered: filter.size > 0 || silentOnly })}`, { flush: true,
            tools: html`<form class="filters" data-form="devices"><input type="search" name="q" maxlength="120" value="${query.get("q") || ""}" placeholder="사용자·호스트 검색" aria-label="사용자·호스트·엔드포인트 검색" />
              <select name="state" aria-label="관리 상태">${option("", "전체", query.get("state"))}${Object.entries({ ...MANAGED_STATE, unmanaged: "관리되지 않음" }).map(([k, v]) => option(k, v, query.get("state")))}</select>
              <label class="check"><input type="checkbox" name="silent" value="1" ${silentOnly ? raw("checked") : ""} /> 보고 지연만</label>
              <button type="submit" class="btn primary">조회</button><a class="btn" href="#/endpoints?t=devices">초기화</a></form>` }) },
        { key: "managed", label: "연결 이력", n: (inv.managed_events || []).length,
          body: panel("연결 이력", html`<table class="data"><thead><tr><th>시각</th><th>사용자·엔드포인트</th><th>내용</th><th>사유</th></tr></thead><tbody>
            ${(inv.managed_events || []).map((e) => html`<tr><td class="nowrap">${when(e.observed_at)}</td><td>${e.owner_name || "사용자 확인 불가"} <span class="muted small" title="${e.endpoint_id || ""}">${hostById[e.endpoint_id] || "엔드포인트"}</span></td>
              <td>${chip(...(MANAGED_EVENT[e.kind] || ["", e.kind]))}</td><td class="small">${managedEventDetail(e.detail)}</td></tr>`)}</tbody></table>
            ${(inv.managed_events || []).length ? "" : empty("연결 이력 없음")}`, { flush: true }) },
      ],
    }),
    charts: {},
  };
};

async function showEndpoint(id) {
  const seq = routeSeq, detail = ++detailSeq;
  const [inv, net] = await Promise.all([gw(`endpoint/inventory?${new URLSearchParams({ endpoint: id })}`), gw("endpoint/network-quality").catch(() => null)]);
  if (seq !== routeSeq || detail !== detailSeq) return;
  const r = endpointList.find((row) => row.endpoint_id === id) || inv.agents.find((a) => a.endpoint_id === id);
  if (!r) return;
  const device = r.device || null, link = (net?.devices || []).find((d) => d.endpoint_id === id);
  const events = (inv.managed_events || []).filter((e) => e.endpoint_id === id);
  rememberDetail(id, "endpoint-device");
  openDrawer(r.hostname || id, html`<div class="row-actions">${endpointState(r)} ${device ? statusPair(device) : chip("outline", "관찰만")}
      ${endpointActions(r)}${r.status === "revoked" ? chip("outline", "등록 해제됨") : html`<button class="btn sm danger" type="button" data-act="device-revoke" data-id="${id}">등록 해제</button>`}</div>`, [
    { key: "checks", label: "통제 점검", body: html`<div class="stack">${kv([["사용자", r.owner || "—"], ["PC 계정", device?.account || r.local_username || "—"],
        ["엔드포인트 ID", html`<code>${id}</code> <button class="btn sm" type="button" data-act="copy-id" data-value="${id}">복사</button>`],
        ["마지막 보고", r.last_seen_at ? `${when(r.last_seen_at, { year: true, seconds: true })} · ${ago(r.last_seen_at)}` : "—"],
        ["플랫폼", r.platform || "—"], ["관리 방식", MANAGED_MODE[device?.mode] || "—"],
        ["관리 계정", device?.account_state ? controlChip(device.account_state) : "—"], ["엔드포인트 차단 24시간", device ? denialCount(device) || "—" : "—"]])}
      ${device && Object.keys(device.checks || {}).length ? html`<table class="data"><thead><tr><th>점검 항목</th><th>결과</th></tr></thead><tbody>
        ${Object.entries(device.checks).map(([k, v]) => html`<tr><td>${CHECK_LABEL[k] || k}</td><td>${v ? chip("allow", "정상") : chip("block", "미충족")}</td></tr>`)}</tbody></table>` : empty("점검 결과 없음")}
      ${(device?.bypass || []).length ? html`<div class="pill-list">${device.bypass.map((b) => chip("block", b))}</div>` : ""}</div>` },
    { key: "configs", label: "MCP 설정", n: inv.entries.length, body: inv.entries.length ? html`<table class="data"><thead><tr><th>서버</th><th>설정 파일</th><th>분류</th><th>증거</th></tr></thead><tbody>
      ${inv.entries.map((e) => recordRow("config", e.id, html`<td><b>${e.server_label}</b></td><td class="small mono address">${e.config_path}</td>
        <td>${chip(...(ENDPOINT_CLASS[e.classification] || ["outline", "확인 불가"]))}</td><td>${evidenceChip(e.provenance_state)}</td>`))}</tbody></table>` : empty("MCP 설정 없음") },
    { key: "history", label: "이력", n: events.length, body: events.length ? html`<table class="data"><thead><tr><th>시각</th><th>내용</th><th>사유</th></tr></thead><tbody>
      ${events.map((e) => html`<tr><td class="nowrap">${when(e.observed_at)}</td><td>${chip(...(MANAGED_EVENT[e.kind] || ["", e.kind]))}</td><td class="small">${managedEventDetail(e.detail)}</td></tr>`)}</tbody></table>` : empty("연결 이력 없음") },
    { key: "link", label: "통신 품질", body: link ? kv([["중앙값", link.state === "fresh" ? msText(link.rtt_p50_ms) : "—"], ["P95", link.state === "fresh" ? msText(link.rtt_p95_ms) : "—"],
      ["흔들림", link.state === "fresh" ? msText(link.jitter_ms) : "—"], ["실패율", link.state === "fresh" ? pctText(link.failure_pct) : "—"], ["측정", link.probes ?? "—"], ["측정 시각", when(link.measured_at)]])
      : empty(net === null ? "조회 실패" : "측정 없음") },
  ]);
}

function intakeStatus(form, message, field = null) {
  const status = form.querySelector("[data-intake-status]");
  status.textContent = message;
  status.setAttribute("role", field ? "alert" : "status");
  if (field) {
    const input = form.elements.namedItem(field);
    input?.setAttribute?.("aria-invalid", "true");
    if (field === "requested_tool") for (const control of form.querySelectorAll('[name="requested_tool"]')) control.setAttribute("aria-invalid", "true");
    const error = form.querySelector(`[data-field-error="${field}"]`);
    if (error) error.textContent = message;
  }
}
function resetIntakeTools(form) {
  form.dataset.discoveryGeneration = String(Number(form.dataset.discoveryGeneration || 0) + 1);
  delete form.dataset.discoveredEndpoint;
  form.querySelector("[data-requested-tools]").replaceChildren();
  intakeStatus(form, "도구 조회 필요");
}

function requestedToolList(tools) {
  return html`<div class="tool-list">${tools.map((t) => html`<label class="check">
    <input type="checkbox" name="requested_tool" value="${t.name}" checked aria-invalid="false" aria-describedby="intake-requested_tool-error" />
    <span><b class="mono">${t.name}</b>${t.description ? html`<span class="sub">${t.description}</span>` : ""}</span></label>`)}</div>`;
}

let intakeTimer = null;
let intakeRendered = "";
function stopIntake() { clearInterval(intakeTimer); intakeTimer = null; }
let intakeRefreshing = false;
function patchIntakePanel(view, next, key) {
  const oldPanel = view.querySelector(`#p-panel-${key}`);
  const newPanel = next.querySelector(`#p-panel-${key}`);
  if (!oldPanel || !newPanel) return;
  const oldStack = oldPanel.querySelector(":scope > .stack");
  const newStack = newPanel.querySelector(":scope > .stack");
  if (!oldStack || !newStack) { oldPanel.replaceWith(newPanel); return; }
  const oldSections = [...oldStack.children];
  const newSections = [...newStack.children];
  const title = (section) => t(section.querySelector(":scope > header > h2")?.textContent ?? "");
  for (const [index, section] of newSections.entries()) {
    const previous = oldSections.find((item) => title(item) === title(section));
    if (previous) {
      if (!previous.querySelector(".chart") || !section.querySelector(".chart")) previous.replaceWith(section);
    } else {
      const following = newSections.slice(index + 1).map((item) => oldSections.find((old) => title(old) === title(item)))
        .find((item) => item?.isConnected);
      oldStack.insertBefore(section, following || null);
    }
  }
  for (const section of oldSections) if (!newSections.some((item) => title(item) === title(section))) section.remove();
}
async function refreshIntake() {
  if (intakeRefreshing) return;
  intakeRefreshing = true;
  const seq = routeSeq;
  try {
    const out = await ROUTES.intake("", parseHash().query.get("t") || "");
    if (seq !== routeSeq || parseHash().page !== "intake") return;
    const markup = String(out.html);
    if (markup === intakeRendered) return;
    const next = document.createElement("div");
    next.innerHTML = markup;
    const view = $("#view");
    for (const key of ["review", "list", "approved"]) {
      patchIntakePanel(view, next, key);
      const oldCount = view.querySelector(`#p-tab-${key} .n`);
      const newCount = next.querySelector(`#p-tab-${key} .n`);
      if (oldCount && newCount) oldCount.replaceWith(newCount);
    }
    intakeRendered = markup;
  } finally { intakeRefreshing = false; }
}
function catalogResults(data) {
  const requests = data.requests || [], registry = data.registry || [];
  return html`${requests.length ? html`<table class="data"><thead><tr><th>MCP</th><th>신청자</th><th>상태</th>${viewer.admin ? html`<th>사내 저장소</th>` : ""}</tr></thead><tbody>
    ${requests.map((r) => html`<tr><td><b>${r.display_name}</b><span class="sub mono address">${r.endpoint_url || [r.repository_url, r.repository_path].filter(Boolean).join("/") || ""}</span></td>
      <td>${r.submitted_by_name}</td><td>${chip(...(INTAKE_STATUS[r.status] || ["", r.status]))}</td>
      ${viewer.admin ? html`<td>${r.internal_repo_url ? html`<a href="${sameSite(r.internal_repo_url)}" target="_blank" rel="noopener noreferrer">열기 ↗</a>` : NONE}</td>` : ""}</tr>`)}</tbody></table>` : empty("신청 없음", { filtered: !!data.query })}
    ${registry.length ? html`<p class="small muted">등록된 MCP: ${registry.map((r) => r.display_name).join(", ")}</p>` : ""}`;
}
const CONSENT_STATUS = { PENDING: ["alert", "확인 필요"], GRANTED: ["allow", "동의"], DENIED: ["block", "거부"],
  REVOKED: ["outline", "철회"], EXPIRED: ["outline", "만료"] };
let consentRows = [];
async function consentTabs(query = new URLSearchParams()) {
  const data = await api("/api/consents");
  consentRows = data.consents;
  const consents = consentRows.filter((c) => (!query.get("server") || c.server_id === query.get("server")) && (!query.get("tool") || c.tool_name === query.get("tool")));
  const pending = consents.filter((c) => c.status === "PENDING");
  const decided = consents.filter((c) => c.status !== "PENDING");
  const servers = new Map();
  for (const c of pending) {
    if (!servers.has(c.server_id)) servers.set(c.server_id, []);
    servers.get(c.server_id).push(c);
  }
  badges.consent = servers.size;
  const button = (c, decision, label, tone = "") => html`<button class="btn sm ${tone}" data-act="consent" data-id="${c.id}" data-decision="${decision}">${label}</button>`;
  const serverButton = (id, rows, decision, label, tone) => html`<button class="btn sm ${tone}" data-act="consent-server" data-id="${id}" data-consents="${rows.map((c) => c.id).join(",")}" data-decision="${decision}">${label}</button>`;
  const table = (rows) => html`<table class="data"><thead><tr><th>도구</th><th>데이터 등급</th><th>목적</th><th>상태</th><th>시각</th><th></th></tr></thead><tbody>
    ${rows.map((c) => html`<tr><td><code>${c.server_id}.${c.tool_name}</code></td><td>${DATA_CLASS[c.grade] || NONE}</td>
      <td>${c.purpose || NONE}<span class="sub">외부 목적지 ${destinationText(c.terms?.destinations)}${c.terms?.inputs ? ` · 입력 ${c.terms.inputs.join(", ") || "없음"}` : ""}</span></td>
      <td>${chip(...(CONSENT_STATUS[c.status] || ["", "—"]))}</td>
      <td class="small nowrap">${when(c.decided_at || c.requested_at)}${c.status === "GRANTED" && c.expires_at ? html`<span class="sub">${when(c.expires_at)}까지</span>` : ""}</td>
      <td class="num nowrap">${c.status === "PENDING" ? html`${button(c, "deny", "거부")}${button(c, "grant", "동의")}`
        : c.status === "GRANTED" ? button(c, "revoke", "철회") : ["DENIED", "REVOKED"].includes(c.status) ? button(c, "grant", "동의") : ""}</td></tr>`)}
    </tbody></table>`;
  return [
    { key: "pending", label: "확인 필요", n: servers.size, hot: servers.size > 0,
      body: servers.size ? html`<div class="stack">${[...servers].map(([id, rows]) => panel(id, html`
        <div class="row-actions">${chip("alert", `요청 ${rows.length}건`)}${serverButton(id, rows, "deny", "모두 거부")}${serverButton(id, rows, "grant", "모두 허용")}</div>
        ${table(rows)}`))}</div>` : empty("확인할 요청 없음", { filtered: query.has("server") || query.has("tool") }) },
    { key: "history", label: "이력", n: decided.length, body: panel("동의 기록", decided.length ? table(decided) : empty("기록 없음", { filtered: query.has("server") || query.has("tool") }), { flush: true }) },
  ];
}


let approvedMcpSearch = "";
function approvedMcpTable(servers, query = "", consentOf = null) {
  if (!servers.length) return empty("사용 가능한 MCP 없음");
  const searchText = (s) => [s.display_name, s.server_id, s.purpose, ...(s.tools || []).flatMap((tool) => [tool.name, tool.purpose])].filter(Boolean).join(" ");
  const term = query.trim().toLocaleLowerCase();
  return html`<table class="data"><thead><tr><th>MCP</th><th>사용 목적</th><th>제공 도구</th><th>사용 기한</th>${consentOf ? html`<th>내 동의</th>` : ""}<th></th></tr></thead>
    <tbody id="available-mcp">${servers.map((s) => html`<tr data-search="${searchText(s)}" ${searchText(s).toLocaleLowerCase().includes(term) ? "" : raw("hidden")}>
      <td><b>${s.display_name || s.server_id || "—"}</b>${s.execution === "reapproval" ? html`<span class="sub">${chip("alert", "엔드포인트 실행으로 재승인 필요")}</span>` : ""}</td><td title="${s.purpose || ""}">${purposePhrase(s.purpose)}</td><td class="num">${(s.tools || []).length}개</td><td class="nowrap">${expiryCell(s.valid_until)}</td>${consentOf ? html`<td>${consentOf(s)}</td>` : ""}
      <td><button class="btn sm" data-act="available-mcp" data-id="${s.server_id}">이용 방법</button></td></tr>`)}</tbody></table>
      <p class="empty" role="status" data-list-empty="available-mcp" ${servers.some((s) => searchText(s).toLocaleLowerCase().includes(term)) ? raw("hidden") : ""}>조건에 맞는 결과 없음</p>`;
}

function expiryCell(value) {
  const left = remaining(value);
  return left ? html`${left.date}<span class="sub ${left.soon ? "bad-text" : ""}">${left.days}일 남음</span>` : NONE;
}
function approvedMcpAddress(server) {
  if (!server.connection_url || server.execution === "reapproval") return "";
  try {
    const url = new URL(server.connection_url, location.origin);
    return url.origin === location.origin && url.pathname.startsWith("/mcp/") && !url.search && !url.hash && !url.username && !url.password ? url.href : "";
  } catch { return ""; }
}

function showAvailableMcp(server) {
  const address = approvedMcpAddress(server), tools = server.tools || [];
  const execution = { remote: "원격", pc: "엔드포인트", reapproval: "엔드포인트 실행으로 재승인 필요" };
  openDrawer(server.display_name || server.server_id, html`<div class="row-actions">${address ? html`<button class="btn primary" data-act="available-mcp-copy" data-id="${server.server_id}">MCP 주소 복사</button>` : ""}
    ${viewer.kit ? html`<button class="btn" data-act="pc-kit">PC 연결 설정</button>` : ""}</div>`, [
    { key: "usage", label: "이용 방법", body: html`${kv([["사용 목적", server.purpose || "—"], ["연결 경로", "게이트웨이"],
      ["MCP 주소", address ? html`<code>${address}</code>` : "—"], ["실행 방식", execution[server.execution] || "—"], ["사용 기한", when(server.valid_until)]])}` },
    { key: "tools", label: "제공 도구", n: tools.length, body: tools.length ? html`<table class="data"><thead><tr><th>도구</th><th>허용 행위</th><th>사용 목적</th><th>범위 심사</th></tr></thead><tbody>
      ${tools.map((tool) => html`<tr><td><code>${tool.name}</code></td><td>${ACTION[tool.action] || "—"}</td><td>${tool.purpose || "—"}</td><td>${tool.scope_reviewed ? "심사 완료" : "범위 미심사"}</td></tr>`)}</tbody></table>` : empty("제공 도구 없음") },
    { key: "source", label: "출처", body: html`${kv([["출처", server.source_url || "—"], ["고정 커밋", server.commit_sha ? html`<code>${server.commit_sha}</code>` : "—"]])}
      ${server.source_available ? html`<div class="row-actions"><button class="btn" data-act="mcp-source-download" data-id="${server.server_id}" data-commit="${server.commit_sha}">소스 받기</button></div>` : ""}` },
  ]);
}

function intakeNewBody(pre, fromRepo, catalog) {
  const opt = (value, label, on) => html`<option value="${value}" ${on ? raw("selected") : ""}>${label}</option>`;
  return html`<div class="stack">
          ${panel("새 신청", html`<form class="stack form" data-form="intake"><div data-intake-status role="status" aria-live="polite"></div>
          <fieldset><legend>서비스</legend>
            <label>서비스 이름<input name="display_name" aria-invalid="false" aria-describedby="intake-display_name-error" required minlength="2" maxlength="80" placeholder="GitHub MCP" value="${pre.name}" /><span id="intake-display_name-error" data-field-error="display_name" role="alert"></span></label>
            <label>사용 목적<textarea name="purpose" aria-invalid="false" aria-describedby="intake-purpose-error" required minlength="10" maxlength="1000">${pre.purpose}</textarea><span id="intake-purpose-error" data-field-error="purpose" role="alert"></span></label>
          </fieldset>
          <fieldset><legend>연결</legend><div class="grid c2">
            <label>유형<select name="intake_kind" aria-invalid="false" aria-describedby="intake-intake_kind-error" data-intake-kind>${opt("remote-endpoint", "원격 MCP", !fromRepo)}${opt("repository", "소스 코드", fromRepo)}</select><span id="intake-intake_kind-error" data-field-error="intake_kind" role="alert"></span></label>
             <label>연결 방식<select name="requested_transport" aria-invalid="false" aria-describedby="intake-requested_transport-error">${Object.entries(TRANSPORT).map(([value, label]) => opt(value, label, value === (fromRepo ? "stdio" : "streamable-http")))}</select><span id="intake-requested_transport-error" data-field-error="requested_transport" role="alert"></span></label>
            <label data-intake-field="remote-endpoint" ${fromRepo ? raw("hidden") : ""}>MCP 주소<input name="endpoint_url" aria-invalid="false" aria-describedby="intake-endpoint_url-error" type="url" maxlength="500" placeholder="https://…/mcp" value="${fromRepo ? "" : pre.source}" /><span id="intake-endpoint_url-error" data-field-error="endpoint_url" role="alert"></span></label>
            ${pre.asked ? html`<input type="hidden" name="endpoint_request_id" value="${pre.asked}" />` : ""}
            <label data-intake-field="repository" ${fromRepo ? "" : raw("hidden")}>저장소<input name="repository_url" aria-invalid="false" aria-describedby="intake-repository_url-error" type="url" maxlength="300" placeholder="https://github.com/org/repo" value="${fromRepo ? pre.source : ""}" /><span id="intake-repository_url-error" data-field-error="repository_url" role="alert"></span></label>
          </div></fieldset>
          <label>데이터 등급<select name="data_class" aria-invalid="false" aria-describedby="intake-data_class-error">${Object.entries(DATA_CLASS).map(([value, label]) => opt(value, label, value === "nonimportant"))}</select><span id="intake-data_class-error" data-field-error="data_class" role="alert"></span></label>
          <fieldset data-intake-field="remote-endpoint"><legend>필요한 도구</legend>
            <button class="btn" type="button" data-act="intake-discover">도구 불러오기</button>
            <div data-requested-tools></div><span id="intake-requested_tool-error" data-field-error="requested_tool" role="alert"></span>
          </fieldset>
          <div class="row-actions center"><button class="btn primary" type="submit">신청</button></div></form>`)}
          <details class="panel"><summary>기존 신청 검색</summary><div class="filters"><input class="grow" type="search" data-catalog-search
            aria-label="MCP 이름 또는 저장소 검색" placeholder="MCP 이름 또는 저장소" /></div>
            <div id="catalog-results" aria-live="polite">${catalogResults(catalog || { requests: [], registry: [] })}</div></details></div>`;
}

ROUTES.intake = async (arg, tab, query = new URLSearchParams()) => {
  if (arg && viewer.admin) return intakeDetail(arg, tab);
  const tabOrder = viewer.admin ? ["review", "list", "requests", "new"] : ["approved", "new", "list"];
  const [{ requests }, { servers }, catalog, asked, reg] = await Promise.all([api("/api/mcp-requests"), viewer.admin ? Promise.resolve({ servers: [] }) : api("/api/approved-mcp"),
    tab === "new" ? api("/api/mcp-catalog/search") : Promise.resolve(null),
    viewer.admin ? gw("endpoint/requests") : Promise.resolve({ requests: [] }),
    viewer.admin ? gw("registry").catch(() => null) : Promise.resolve(null)]);
  const waiting = requests.filter((r) => ["HOLD", "VALIDATED", "REMOTE_REVIEWED"].includes(r.status));
  const grace = Object.values(reg?.registrations || {}).filter((x) => x?.risk_review?.state === "grace").length;
  const cards = intakeCards(requests, grace), stages = intakeStages(requests), mix = riskMix(requests);
  const waited = (r) => Math.max(0, Math.floor((Date.now() - Date.parse(r.created_at)) / 86400000));
  const tierName = { low: "낮음", medium: "보통", high: "높음", very_high: "매우 높음", none: "미산정" };
  const daysText = cards.days == null ? "—" : cards.days < 0.1 ? "당일" : `${cards.days}일`;
  const stageName = { check: "검사", review: "심사", approved: "승인", rejected: "거부" };
  const stageTone = { check: "outline", review: "approval", approved: "allow", rejected: "block" };
  const tierTone = { low: "allow", medium: "outline", high: "alert", very_high: "block", none: "outline" };
  const distGroup = (title, list) => (list.length ? html`<div class="dist"><span class="dist-title">${title}</span>${list.map(([tone, name, n]) => chip(tone, `${name} ${n}`))}</div>` : "");
  const distribution = requests.length ? html`<div class="dist-strip">${distGroup(`전체 신청 상태 · ${requests.length}건`, stages.filter((x) => x.value).map((x) => [stageTone[x.key], stageName[x.key], x.value]))}
    ${distGroup("위험 등급", Object.entries(mix).filter(([, n]) => n).map(([k, n]) => [tierTone[k], tierName[k], n]))}</div>` : "";
  const pre = { name: query.get("name") || "", purpose: query.get("purpose") || "", source: query.get("source") || "", asked: query.get("asked") || "" };
  const fromRepo = /^https:\/\/github\.com\//.test(pre.source);
  return {
    html: page({
      head: head(viewer.admin ? "도입 심사" : "도입 신청"),
      kpis: viewer.admin ? html`${kpiStrip([["심사 대기", cards.waiting, cards.waiting ? "approval" : "", "#/intake?t=review"], [cards.done ? `평균 처리 · 완료 ${cards.done}건` : "평균 처리", daysText],
        ["위험 높음 대기", cards.high, cards.high ? "alert" : ""], ["재평가 필요", cards.reassess, cards.reassess ? "alert" : ""]])}${distribution}` : "",
      active: tabOrder.includes(tab) ? tab : tabOrder[0],
      tabs: [
        ...(viewer.admin ? [{ key: "review", label: "심사 대기", n: waiting.length, hot: waiting.length > 0, body: panel("심사 대기", waiting.length ? html`<table class="data"><thead><tr><th>서비스</th><th>신청자</th><th>위험 등급</th><th>검사</th><th class="num">대기</th><th>승인</th><th></th></tr></thead><tbody>
          ${waiting.map((r) => html`<tr class="clickable" tabindex="0" data-act="goto" data-href="#/intake/${r.id}"><td><b>${r.display_name}</b></td>
            <td>${r.submitter_name || r.submitted_by || "—"}</td><td>${r.risk?.status === "ok" ? chip(...RISK_TIER[r.risk.tier]) : chip("alert", "보류")}</td><td>${intakeSignals(r)}</td>
            <td class="num">${waited(r)}일</td><td class="small">${r.risk?.status === "ok" ? `${r.risk.approvals}/${r.risk.required}` : "—"}</td>
            <td class="num"><a class="btn sm" href="#/intake/${r.id}">검토</a></td></tr>`)}</tbody></table>` : html`<div class="idle-state"><p class="empty" role="status">심사 대기 없음</p>${requests.length ? html`<a class="btn sm" href="#/intake?t=list">전체 신청 ${requests.length}건 보기</a>` : ""}</div>`, { flush: true }) }] : []),
        { key: "list", label: viewer.admin ? "전체 신청" : "내 신청", n: requests.length, body: html`<div class="stack">
          ${panel("신청", html`<table class="data"><thead><tr><th>서버</th><th>상태</th><th>종료 조건</th><th>위험 등급</th><th>신청</th>${viewer.admin ? html`<th></th>` : ""}</tr></thead><tbody>
          ${requests.map((r) => html`<tr ${viewer.admin ? raw(`class="clickable" tabindex="0" data-act="goto" data-href="#/intake/${r.id}"`) : ""}><td><b>${r.display_name}</b>
              <span class="sub">${r.intake_kind === "remote-endpoint" ? "원격 MCP" : "소스 코드"} · ${TRANSPORT[r.requested_transport] || "—"}${r.registered_server_id ? ` · /mcp/${r.registered_server_id}/` : ""}</span>
              ${r.endpoint_reapproval_required ? chip("alert", "엔드포인트 실행으로 재승인 필요") : ""}</td>
            <td>${chip(...(INTAKE_STATUS[r.status] || ["", r.status]))}
              ${r.status === "HOLD" && r.review_note ? html`<span class="sub">${short(r.review_note, 90)}</span>` : ""}</td>
            <td class="small">${exitConclusionChip(r)}</td>
            <td class="small">${riskCell(r)}</td>
            <td class="small nowrap">${when(r.created_at)}</td>
            ${viewer.admin ? html`<td class="num">${r.own ? chip("outline", "본인 신청") : html`<a class="btn sm" href="#/intake/${r.id}">상세</a>`}</td>` : ""}</tr>`)}</tbody></table>${requests.length ? "" : empty("신청 없음")}`, { flush: true })}</div>` },
        ...(viewer.admin ? [{ key: "requests", label: "엔드포인트 요청", n: asked.requests.length, hot: asked.requests.length > 0,
          body: panel("엔드포인트 요청", asked.requests.length ? html`<table class="data"><thead><tr><th>시각</th><th>엔드포인트</th><th>서버</th><th>사용 목적</th><th></th></tr></thead><tbody>
            ${asked.requests.map((r) => html`<tr><td class="small nowrap">${when(r.created_at)}</td><td>${r.hostname}<span class="sub">${r.owner_name || ""}</span></td>
              <td><b>${r.server_label}</b>${r.source_url ? html`<span class="sub mono">${short(r.source_url, 60)}</span>` : ""}</td><td class="small">${short(r.purpose, 120)}</td>
              <td class="num nowrap"><a class="btn sm primary" href="#/intake?t=new&${new URLSearchParams({ name: r.server_label, purpose: r.purpose, source: r.source_url || "", asked: r.id })}">신청서 작성</a>
                 <button class="btn sm" data-act="endpoint-request-close" data-id="${r.id}" data-name="${r.server_label}" data-endpoint="${r.hostname}">검토 종료</button></td></tr>`)}</tbody></table>` : empty("요청 없음"), { flush: true }) }] : []),
        ...(viewer.admin ? [] : [{ key: "approved", label: "사용 가능한 MCP", body: panel("사용 가능한 MCP", approvedMcpTable(servers, approvedMcpSearch), { flush: true,
          end: html`<a class="panel-shortcut" href="#/intake?t=new"><span>새 신청</span><span aria-hidden="true">↗</span></a>`,
          tools: servers.length ? listToolbar("available-mcp", "이름 또는 기능 검색", approvedMcpSearch) : "" }) }]),
        { key: "new", label: "새 신청", body: intakeNewBody(pre, fromRepo, catalog) },
      ].sort((a, b) => tabOrder.indexOf(a.key) - tabOrder.indexOf(b.key)),
    }),
    charts: {},
    after: () => {
      if (tab === "new") $('[data-form="intake"] [name="display_name"]')?.focus();
      intakeTimer = setInterval(() => {
        if (!document.hidden && parseHash().page === "intake" && parseHash().query.get("t") !== "new"
          && !$("#drawer").classList.contains("open") && !$("#dialog").open && !document.activeElement?.closest?.('[data-list-search="available-mcp"]'))
          refreshIntake().catch((error) => toast(error.message, true));
      }, 5000);
    },
  };
};
const TRANSPORT = { "streamable-http": "웹 연결", sse: "이벤트 스트림", stdio: "프로세스 연결" };

async function supplyChainImpact(query, users = {}) {
  const packageName = query.get("package") || "", versionRange = query.get("range") || "";
  const result = packageName && versionRange
    ? await api("/api/supply-chain/impact", { method: "POST", body: { package: packageName, version_range: versionRange } })
    : null;
  const rows = result ? impactRows(result.servers, users) : [];
  const JUDGE = { "영향 있음": "block", "판단 불가": "alert", "자료 없음": "outline", "영향 없음": "allow" };
  return html`<div class="stack">
    ${panel("영향 조회", html`<form class="filters" data-form="sbom-impact">
      <label>패키지<input name="package" required maxlength="200" value="${packageName}" /></label>
      <label>판본 범위<input name="range" required maxlength="120" value="${versionRange}" placeholder=">=1.2.0 <2.0.0" /></label>
      <button class="btn primary" type="submit">조회</button></form>`)}
    ${result ? html`${kpiStrip([["영향 있음", result.counts.affected, result.counts.affected ? "block" : ""], ["영향 없음", result.counts.unaffected],
      ["판단 불가", result.counts.unknown, result.counts.unknown ? "alert" : ""], ["자료 없음", result.counts.no_data]])}
      ${panel("영향 서버", rows.length ? html`<table class="data"><thead><tr><th>서버</th><th>판정</th><th>판본</th><th class="num">사용자</th><th></th></tr></thead><tbody>
        ${rows.map((r) => html`<tr class="clickable" tabindex="0" data-act="goto" data-href="#/servers/${encodeURIComponent(r.server_id)}"><td><b>${r.server_name}</b></td><td>${chip(JUDGE[r.judgement] || "", r.judgement)}</td>
          <td class="small mono">${r.versions.join(", ") || "—"}</td><td class="num">${r.users ?? "—"}</td>
          <td class="num">${r.judgement === "영향 있음" ? html`<button class="btn sm danger" type="button" data-act="server-suspend" data-id="${r.server_id}" data-name="${r.server_name}">중지</button>` : ""}</td></tr>`)}</tbody></table>` : empty("등록된 서버 없음"),
        { flush: true, end: html`<button class="btn sm danger" data-act="sbom-impact-stop" data-package="${packageName}" data-range="${versionRange}" ${result.counts.affected ? "" : raw("disabled")}>영향 서버 모두 중지</button>` })}` : ""}
  </div>`;
}

const termsVerified = (t) => Boolean(t?.verified_by && t?.evidence_url && Object.keys(EXIT_TERMS).every((k) => t[k] === true));
const RISK_TIER = { low: ["allow", "낮음"], medium: ["outline", "보통"], high: ["alert", "높음"], very_high: ["block", "매우 높음"] };
const RISK_CHOICES = {
  data_class: DATA_CLASS,
  personal_data: { none: "없음", general: "일반 개인정보", unique_id: "고유식별정보", sensitive: "민감정보" },
  external_transfer: { no: "없음", yes: "있음" },
  permission: { r: "읽기", w: "쓰기", x: "실행" },
  autonomy: { approve_each: "건별 확인", supervised: "감독 하 실행", autonomous: "자율 실행" },
};
function riskCell(r) {
  const k = r.risk;
  if (!k) return NONE;
  let waiting = ["HOLD", "VALIDATED", "REMOTE_REVIEWED"].includes(r.status) && viewer.admin;
  if (k.status !== "ok") return html`${chip("alert", "보류")}${waiting ? html`<span class="sub">승인 —</span>` : ""}`;
  waiting &&= k.required > 1;
  return html`${chip(...RISK_TIER[k.tier])}${waiting ? html`<span class="sub">승인 ${k.approvals}/${k.required}</span>` : ""}`;
}
function riskView(risk) {
  if (!risk) return empty("기록 없음");
  return html`<div class="stack">
    ${kv([["위험 등급", risk.status === "ok" ? chip(...RISK_TIER[risk.tier]) : chip("alert", "보류")],
      ["산정 점수", risk.status === "ok" ? String(risk.score) : "—"], ["적용 규칙", (risk.floors || []).join(", ") || "—"],
      ["입력 상태", (risk.messages || []).join(" / ")]])}
    ${panel("영향평가 입력 자료", html`<table class="data"><thead><tr><th>항목</th><th>값</th><th>서식 항목</th></tr></thead><tbody>
      ${(risk.package || []).map((p) => html`<tr><td>${p.item}</td><td>${p.value}</td><td class="small">${p.form}</td></tr>`)}</tbody></table>`, { flush: true })}</div>`;
}
const supportStatus = (date) => !date ? "" : date < new Date().toISOString().slice(0, 10) ? "지원 종료 경과" :
  date <= new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10) ? "지원 종료 임박" : "지원 중";

const ASSURANCE_LABELS = { legal_entity: "법인명", supplier_contact: "연락처", security_contact: "보안 연락처",
  vulnerability_policy_url: "취약점 정책 주소", subprocessors: "하위 처리자", contract_basis_ref: "계약 근거",
  exit_strategy: "종료 전략", support_end: "지원 종료" };

const UNCONFIRMED = "확인 안 됨";
const given = (a, key) => { const v = a?.[key]; return typeof v === "boolean" || (typeof v === "string" && v.trim() && v !== "미확인") ? v : null; };
function assuranceRows(a) {
  const text = (key) => given(a, key) ?? UNCONFIRMED, yes = (key) => given(a, key) === null ? UNCONFIRMED : a[key] ? "제출" : "미제출";
  const end = given(a, "support_end"), tone = supportStatus(end) === "지원 종료 경과" ? "block" : supportStatus(end) === "지원 종료 임박" ? "alert" : "allow";
  return [["공급자 법인명", text("legal_entity")], ["공급자 연락처", text("supplier_contact")], ["보안 연락처", text("security_contact")],
    ["지원 종료일", end ? html`${end} ${chip(tone, supportStatus(end))}` : UNCONFIRMED],
    ["취약점 공개 정책", given(a, "vulnerability_policy_url") ? html`<a href="${a.vulnerability_policy_url}" target="_blank" rel="noopener noreferrer">${a.vulnerability_policy_url}</a>` : UNCONFIRMED],
    ["하위 처리자", text("subprocessors")], ["SBOM 제출", yes("sbom_submitted")], ["VEX 제출", yes("vex_submitted")],
    ["계약 근거", text("contract_basis_ref")], ["종료 전략", text("exit_strategy")]];
}

function intakeProposalView(out) {
  const p = out.proposal, r = out.request, unknown = "확인 안 됨";
  const localRun = out.local_execution || p.local_execution || r.local_execution || r.evidence?.local_execution;
  return html`${kv([["주소", p.endpoint || r.repository_url], ["판본", r.commit_sha || p.catalog?.version || unknown],
      ["용도", p.purpose], ["신청자", r.submitter_name || r.submitted_by], ["서버 ID", p.server_id],
      ["데이터 등급", DATA_CLASS[p.data_class]], ["원격 도메인", r.endpoint_url ? new URL(r.endpoint_url).hostname : "—"],
      ["계약 지문", p.catalog?.catalog_hash || unknown], ["공급자 홈페이지", p.supplier_metadata?.homepage || unknown],
      ["라이선스", p.provenance?.license?.spdx || unknown]])}
    ${localRun ? html`<fieldset><legend>엔드포인트 실행</legend>${kv([
      ["관찰 엔드포인트", localRun.observer_device || unknown],
      ["실행 계정 번호", localRun.observer_uid == null ? unknown : String(localRun.observer_uid)],
      ["격리 구성", localRun.isolation_scope || unknown], ["사용자 매핑", localRun.user_mapping || unknown],
    ])}</fieldset>` : ""}`;
}
function intakeScopeFields(out) {
  const p = out.proposal, pending = out.pending, scope = pending?.scope;
  const selected = scope?.tools || Object.keys(p.tools);
  const count = out.gate.critical?.count || 0;
  return html`${p.blockers.map((b) => html`<div class="note warn">${b.message}</div>`)}
  <fieldset class="tool-pick"><legend>승인 도구</legend>${(p.catalog?.tools || []).filter((t) => t.name in p.tools).map((t) => html`<label>
    <input type="checkbox" name="approved_tool" value="${t.name}" ${selected.includes(t.name) ? raw("checked") : ""} ${pending ? raw("disabled") : ""} />
    <span><b>${t.name}</b>${pending ? html`<span>${ACTION[scope.actions?.[t.name] || p.tools[t.name]]}</span>`
      : html`<select name="action_${t.name}">${Object.entries(ACTION).slice(0, "rwx".indexOf(p.tools[t.name]) + 1).map(([k, v]) =>
        html`<option value="${k}" ${k === p.tools[t.name] ? raw("selected") : ""}>${v}</option>`)}</select>`}<span class="sub">${t.description || "—"}</span>
      ${(p.address_tools || []).includes(t.name) ? (pending ? kv([["허용 주소", destinationText(scope.destinations?.[t.name] || p.tool_reviews[t.name].destinations)]])
        : field.text(`destinations_${t.name}`, "허용 주소", 'maxlength="300"', p.tool_reviews[t.name].destinations.join(", "))) : ""}
      ${(t.warnings || []).length ? chip("alert", "도구 설명 경고") : ""}
      <details><summary>계약·인자 제한</summary><pre>${JSON.stringify({ input: t.input_schema, output: t.output_schema,
        constraints: p.parameter_constraints[t.name], scope: p.tool_reviews[t.name] }, null, 2)}</pre></details></span></label>`)}</fieldset>
  ${count && !pending ? field.text("critical_reason", "치명적 발견 수용 사유", 'required minlength="10" maxlength="1000"') : ""}
  ${p.risk.tier === "very_high" ? field.text("risk_reason", "위험 수용 사유", 'required minlength="10" maxlength="1000"') : ""}`;
}
function intakeDock(out, id) {
  const p = out.proposal, pending = out.pending, scope = pending?.scope;
  const need = p.risk.tier === "high" || p.risk.tier === "very_high" ? 2 : 1;
  return html`<div class="row-actions docked">
    ${pending ? html`<span class="small muted">${pending.approvers.length} / ${need} · ${scope.valid_days}일 · ${AUDIENCE[scope.audience || "all"]}${scope.audience_users?.length ? ` · ${scope.audience_users.join(", ")}` : ""}</span>`
      : html`${field.select("valid_days", "사용 기한", VALIDITY, "90")}${audienceFields("all")}`}
    <button class="btn" type="button" data-act="intake-reject" data-id="${id}">거부</button>
    <button class="btn" type="button" data-act="intake-confirm" data-id="${id}" ${p.blockers.length ? raw("disabled") : ""}>승인</button></div>`;
}

const LOCAL_REASON = { local_file: "로컬 파일", local_tool: "로컬 도구", device: "장치" };

async function askLocalRun(id, request, preset = {}, status = "") {
  const generated = request.evidence?.endpoint_source;
  const cur = request.evidence?.local_run || (generated ? { source: generated } : preset);
  const fd = await ask({ title: `엔드포인트 실행 · ${request.display_name}`, confirm: "확인", fields: html`
    ${status ? chip("alert", status) : ""}
    ${field.select("execution", "실행 방식", { process: "프로세스", container: "컨테이너" }, cur.source ? "process" : "container")}
    ${field.select("source_runtime", "런타임", { python: "Python", node: "Node.js" }, cur.source?.runtime || "python")}
    ${field.text("source_entrypoint", "진입 파일", 'maxlength="256"', cur.source?.entrypoint || "")}
    ${!generated ? html`${field.text("source_lock", "의존성 잠금 파일", 'maxlength="256"', cur.source?.lock || "package-lock.json")}
      ${field.text("source_lock_hash", "의존성 잠금 해시", 'maxlength="64"', cur.source?.lock_sha256 || "")}` : ""}
    ${field.text("image", "이미지", 'maxlength="300"',
      cur.image || (request.repository_path && !status ? `mcp/${request.repository_path.split("/").pop()}` : ""))}
    ${field.text("command", "실행 인자", 'maxlength="2000" placeholder="/workspace/폴더이름"', (cur.command || []).join(" "))}
    ${field.text("mounts", "폴더 (홈 기준 → /workspace/경로, 쉼표 구분, 경로:ro|rw)", 'maxlength="1000" placeholder="폴더이름:ro"',
      (cur.mounts || []).map((m) => `${m.path}:${m.mode}`).join(", "))}
    ${field.text("env", "환경 변수 (이름=값, 쉼표 구분)", 'maxlength="2000" placeholder="이름=값"',
      Object.entries(cur.env || {}).map(([k, v]) => `${k}=${v}`).join(", "))}
    ${field.select("reason_kind", "실행 위치 근거", LOCAL_REASON, cur.reason_kind || "local_file")}
    ${field.text("reason_text", "근거 설명", 'required minlength="10" maxlength="500"', cur.reason_text || "")}` });
  if (!fd) return false;
  const mounts = String(fd.get("mounts") || "").split(",").map((v) => v.trim()).filter(Boolean).map((v) => {
    const [path, mode = "ro"] = v.split(":");
    return { path: path.trim().replace(/^~\//, ""), mode: mode.trim() || "ro" };
  });
  const env = Object.fromEntries(String(fd.get("env") || "").split(",").map((v) => v.trim()).filter(Boolean).map((v) => {
    const at = v.indexOf("=");
    return at < 0 ? [v, ""] : [v.slice(0, at).trim(), v.slice(at + 1).trim()];
  }));
  const result = await api(`/api/mcp-requests/${id}/local-run`, { method: "POST", body: {
    image: fd.get("execution") === "process" ? "" : String(fd.get("image")).trim(),
    ...(fd.get("execution") === "process" ? { source: { commit: request.commit_sha,
      sha256: request.provenance?.artifact?.sha256, runtime: fd.get("source_runtime"),
      entrypoint: String(fd.get("source_entrypoint")).trim(), lock: generated?.lock || String(fd.get("source_lock") || "").trim(),
      lock_sha256: generated?.lock_sha256 || String(fd.get("source_lock_hash") || "").trim() } } : {}), command: String(fd.get("command") || "").trim().split(/\s+/).filter(Boolean),
    mounts, env, reason_kind: fd.get("reason_kind"), reason_text: String(fd.get("reason_text")).trim() } });
  toast(result.message);
  return true;
}

const APPROVABLE = ["HOLD", "VALIDATED", "REMOTE_REVIEWED", "APPROVED"];
let intakeApproval = null;
const intakeSignals = (r) => {
  if (r.intake_kind === "remote-endpoint") return NONE;
  const scan = scanSummary(r.evidence);
  if (!scan.critical && !scan.high && !scan.failed) return chip("allow", "이상 없음");
  return html`${scan.critical ? chip("block", `치명 ${scan.critical}`) : ""}${scan.high ? chip("alert", `높음 ${scan.high}`) : ""}${scan.failed ? chip("alert", "검사 실패") : ""}`;
};
async function intakeDetail(id, tab) {
  const report = await api(`/api/mcp-requests/${id}/report`);
  const r = report.request, evidence = r.evidence || {};
  const registered = r.registered_server_id ? (await gw("registry").catch(() => null))?.registrations?.[r.registered_server_id] : null;
  let out = null;
  if (viewer.admin && !r.own && APPROVABLE.includes(r.status) && (!r.registered_server_id || r.endpoint_reapproval_required)) {
    out = await api(`/api/mcp-requests/${id}/approval-preview`, { method: "POST", body: {} }).catch(() => null);
  }
  lastDocument = report;
  intakeApproval = out ? { id, out } : null;
  const needLocal = out && r.intake_kind === "repository" && out.proposal.blockers.some((b) => b.code === "execution-missing");
  const tabs = intakeTabsOf(id, report, registered), by = Object.fromEntries(tabs.map((t) => [t.key, t]));
  const part = (keys) => html`<div class="stack">${keys.filter((k) => by[k]).map((k) => html`<section><h3>${by[k].label}</h3>${by[k].body}</section>`)}</div>`;
  const assurance = out?.pending?.scope?.supplier_assurance || out?.proposal.supplier_assurance || registered?.supplier_assurance || {};
  const supplier = assuranceRows(assurance).filter(([, v]) => v !== UNCONFIRMED);
  const supplierBody = by.exit ? html`${supplier.length ? kv(supplier) : ""}${by.exit.body}` : supplier.length ? kv(supplier) : empty("공급자 정보 없음");
  const scopeBody = html`<div class="stack">${out ? html`<form id="intake-approve" class="stack form" data-form="intake-approve">${intakeScopeFields(out)}</form>` : ""}
    ${out ? "" : by.scope?.body || ""}${by.definitions ? html`<details><summary>승인 도구 계약</summary>${by.definitions.body}</details>` : ""}</div>`;
  const risk = r.risk, tier = risk?.status === "ok" ? RISK_TIER[risk.tier] : null;
  const view = [
    { key: "summary", label: "요약", body: html`<div class="stack">${out ? panel("제안값", intakeProposalView(out)) : ""}${(by.summary || by.contract).body}</div>` },
    ...(by.findings || by.secrets || by.sbom ? [{ key: "scan", label: "검사", body: part(["findings", "secrets", "sbom"]) }] : []),
    { key: "scope", label: "범위·권한", body: scopeBody },
    { key: "risk", label: "위험·영향평가", body: by.risk.body },
    { key: "supplier", label: "공급자 조건", body: supplierBody },
    { key: "source", label: "출처", body: html`<div class="stack">${by.provenance.body}${r.internal_repo_url ? html`<div class="row-actions"><a class="btn sm" href="${sameSite(r.internal_repo_url)}" target="_blank" rel="noopener noreferrer">사내 저장소 ↗</a></div>` : ""}</div>` },
    { key: "records", label: "승인 기록", n: by.records.n, body: by.records.body },
  ];
  const body = page({
    head: head(r.display_name, { back: html`<a class="back" href="#/intake?t=review">← 도입 심사</a>`,
      status: html`${chip(...(INTAKE_STATUS[r.status] || ["", r.status]))}${riskCell(r)}`,
      actions: html`${r.intake_kind !== "remote-endpoint" && (["HOLD", "FAILED"].includes(r.status) || r.endpoint_reapproval_required) ? html`<button class="btn" data-act="intake-queue" data-id="${id}">재검증</button>` : ""}
        ${needLocal ? html`<button class="btn" data-act="intake-local-run" data-id="${id}">엔드포인트 실행</button>` : ""}
        <button class="btn" data-act="save-json" data-name="intake-${id}-report.json">보고서 JSON 저장</button>` }),
    kpis: kpiStrip([["위험 등급", tier ? tier[1] : "—", risk?.tier === "very_high" ? "block" : risk?.tier === "high" ? "alert" : ""],
      ["치명", evidence.critical ?? "—", "block"], ["높음", evidence.high ?? "—", "alert"],
      ["승인", risk?.status === "ok" ? `${risk.approvals}/${risk.required}` : "—"]]),
    tabs: view, active: view.some((t) => t.key === tab) ? tab : "summary" });
  return { html: body, dock: out ? intakeDock(out, id) : "" };
}

const plainLine = (s) => String(s || "").replace(/<[^>]*>/g, " ").replace(/[*_`#|>]+/g, " ").replace(/\s+/g, " ").trim();
const evidenceLink = (url, label) => /^https:\/\/github\.com\//.test(String(url || ""))
  ? html`<a href="${url}" target="_blank" rel="noopener noreferrer">${label}</a>` : html`${label}`;

const VERDICT = { met: ["allow", "충족"], unmet: ["block", "미충족"], unclear: ["alert", "불명확"] };
const EXIT_TERM_CRITERION = { provider_credential_disclosure: "C1", revocation_evidence: "C2", audit_access_retained: "C4" };
const CHECKING = ["VALIDATION_QUEUED", "VALIDATING"];
function exitConclusionChip(r) {
  const c = r.evidence?.exit_terms_conclusion;
  if (r.requested_transport === "stdio") return NONE;
  if (r.exit_terms?.verified_by) return termsVerified(r.exit_terms) ? chip("allow", "확인 완료") : chip("block", "조건 미충족");
  if (r.exit_terms?.risk_accepted_by) return chip("alert", "위험 수용");
  if (c?.grade) return gradeChip(c.grade, "예상 ");
  return CHECKING.includes(r.status) ? chip("outline", "확인 중") : NONE;
}
function exitTermsView(id, r, investigation, c) {
  const open = ["HOLD", "VALIDATION_QUEUED", "VALIDATING", "VALIDATED"].includes(r.status);
  const record = open && r.requested_transport !== "stdio"
    ? html`<div class="row-actions"><button class="btn sm" data-act="intake-terms" data-id="${id}" data-name="${r.display_name}">직접 확인 기록</button></div>` : "";
  if (!c?.grade) return html`<div class="stack">${empty(CHECKING.includes(r.status) ? "확인 중" : "확인 결과 없음")}
    ${open && !CHECKING.includes(r.status) ? html`<div class="row-actions center"><button class="btn primary" data-act="intake-queue" data-id="${id}">다시 확인</button></div>` : ""}${record}</div>`;
  return html`<div class="stack">
    <div class="row-actions">${gradeChip(c.grade, "예상 ")}<span class="small muted">문서 ${investigation?.scanned_files ?? 0}개</span></div>
    ${c.summary ? html`<p>${c.summary}</p>` : ""}
    <table class="data"><thead><tr><th>조건</th><th>판정</th><th>근거</th></tr></thead><tbody>
      ${Object.keys(EXIT_TERM_CRITERION).filter((key) => c.terms?.[key]).map((key) => [key, c.terms[key]]).map(([key, t]) => html`<tr>
        <td class="nowrap"><b>${EXIT_TERM_CRITERION[key]}</b> ${EXIT_TERMS[key]}</td>
        <td>${chip(...(VERDICT[t.verdict] || ["", t.verdict]))}</td>
        <td class="small">${(t.evidence || []).length ? t.evidence.map((e) => html`<div>${evidenceLink(e.url, `${e.path}:${e.line}`)}<span class="sub">${short(plainLine(e.excerpt), 140)}</span></div>`) : NONE}</td></tr>`)}
    </tbody></table>
    ${r.exit_terms?.verified_by ? panel("직접 확인", html`${chip(termsVerified(r.exit_terms) ? "allow" : "block", termsVerified(r.exit_terms) ? "충족" : "미충족")}
      <p>${r.exit_terms.note}</p><p class="small">${evidenceLink(r.exit_terms.evidence_url, r.exit_terms.evidence_url)}</p>`) : ""}
    ${r.exit_terms?.risk_accepted_by ? panel("위험 수용", html`<p>${r.exit_terms.risk_acceptance}</p>
      <p class="small muted">${r.exit_terms.risk_accepted_by} · ${when(r.exit_terms.risk_accepted_at)}</p>`) : ""}
    ${record}
  </div>`;
}

const verdictChip = (ok, yes = "일치", no = "미확인") => (ok ? chip("allow", yes) : chip("alert", no));
function intakeProvenanceView(p) {
  if (!p?.kind) return empty("기록 없음");
  const hosted = p.kind === "provider-hosted", a = p.artifact || {}, v = p.verification;
  return kv([
    ["공급 주소", html`<span class="mono">${p.source_url}</span>`],
    ["버전", p.version ? html`<code>${p.version}</code>` : NONE],
    ["라이선스", hosted ? "해당 없음" : p.license?.spdx ? `${p.license.spdx} · ${p.license.source === "operator" ? "승인자 기재" : "검사기"}` : NONE],
    ["배포 파일 해시", hosted ? "해당 없음" : a.sha256 ? html`<code>${a.sha256}</code>` : NONE],
    ["파일", !hosted && a.files != null ? `${a.files}개 · ${a.bytes}바이트` : ""],
    ["사본 대조", hosted ? "해당 없음" : v ? html`${verdictChip(v.match === true, "일치", "불일치")}<span class="sub">${when(v.at)} · ${v.by}</span>` : verdictChip(false)],
    ["서명·빌드 증명", hosted ? "해당 없음" : v?.provenance_status || "확인 안 됨"],
  ]);
}
const outcomeChip = (o) => chip(...(REVIEW_OUTCOME[o] || ["", o]));
function reviewRecords(events, r) {
  const consent = events.filter((e) => e.kind === "user-consent");
  const operator = events.filter((e) => !["user-consent", "runtime-egress"].includes(e.kind));
  return html`<div class="stack">
    ${panel("사용자 동의", html`<table class="data"><thead><tr><th>신청자</th><th>시각</th><th>목적</th></tr></thead><tbody>
      ${(consent.length ? consent : [{ actor: r.submitted_by, created_at: r.created_at, reason: r.purpose }]).map((e) => html`<tr><td>${e.actor}</td>
        <td class="small nowrap">${when(e.created_at)}</td><td>${e.reason || NONE}</td></tr>`)}</tbody></table>`, { flush: true })}
    ${panel("운영자 승인", operator.length ? html`<table class="data"><thead><tr><th>시각</th><th>구분</th><th>처리자</th><th>결과</th><th>사유</th></tr></thead><tbody>
      ${operator.map((e) => html`<tr><td class="small nowrap">${when(e.created_at)}</td><td>${REVIEW_KIND[e.kind] || e.kind}</td><td>${e.actor}</td>
        <td>${outcomeChip(e.outcome)}</td><td>${e.reason ? short(e.reason, 120) : NONE}</td></tr>`)}</tbody></table>` : empty("기록 없음"), { flush: true })}
  </div>`;
}
const destinationText = (list) => ((list || []).length ? list.join(", ") : "없음");
function scopeTerms(item) {
  const terms = [item.inputs && `입력 ${item.inputs.join(", ") || "없음"}`, item.mask && "입력 민감정보 가림",
    item.grade === "nonimportant" && `외부 전송 ${DATA_CLASS.nonimportant} 등급까지`,
    item.accepts_from?.length && `중요정보 수신 ${item.accepts_from.join(", ")}`, item.consent && "사용자 동의",
    item.high_impact && `중대 영향 · ${(item.impact_domains || []).map((d) => IMPACT_DOMAIN[d] || "—").join(" · ")}`].filter(Boolean);
  return terms.length ? html`<div class="pill-list">${terms.map((t) => chip("plain", t))}</div>` : NONE;
}
function scopeTable(tools, reviews, dataClass, serverId = null, addressTools = []) {
  const names = Object.keys(tools || {});
  if (!names.length) return empty("범위 없음");
  return html`${dataClass ? kv([["데이터 등급", DATA_CLASS[dataClass] || dataClass]]) : ""}
    <table class="data"><thead><tr><th>도구</th><th>행위</th><th>목적</th><th>자산</th><th>외부 목적지</th><th>조건</th></tr></thead><tbody>
    ${names.map((name) => { const item = reviews?.[name]; return html`<tr><td><code>${name}</code></td>
      <td>${chip({ r: "allow", w: "alert", x: "block" }[tools[name]] || "", ACTION[tools[name]] || tools[name])}</td>
      ${item ? html`<td>${item.purpose}</td><td>${item.asset}</td><td>${destinationText(item.destinations)}</td><td>${scopeTerms(item)}
        ${serverId ? html`<button class="btn sm" data-act="impact-scope" data-id="${serverId}" data-tool="${name}">중대 영향 심사</button>` : ""}
        ${serverId && addressTools.includes(name) ? html`<button class="btn sm" data-act="destination-scope" data-id="${serverId}" data-tool="${name}">허용 주소</button>` : ""}</td>`
        : html`<td colspan="4">${chip("block", "범위 미심사")}</td>`}</tr>`; })}</tbody></table>`;
}
function toolSunsetRow(serverId, name) {
  const state = registry?.tool_sunset?.tools?.[`${serverId}/${name}`];
  return state ? [state.last_use ? when(state.last_use, { seconds: true }) : NONE,
    state.deadline ? when(state.deadline, { seconds: true }) : NONE, state.status || NONE] : [NONE, NONE, NONE];
}
function gateView(gate) {
  if (!gate) return NONE;
  const db = gate.vuln_db;
  return html`<div class="stack">
    ${gate.scanners.length ? html`<table class="data"><thead><tr><th>검사기</th><th>버전</th><th>결과</th><th>시각</th></tr></thead><tbody>
      ${gate.scanners.map((x) => html`<tr><td>${x.scanner}</td><td>${x.version || NONE}</td>
        <td>${x.status ? chip(...(SCAN_STATE[x.status] || ["", x.status])) : NONE}</td><td class="small">${x.scanned_at ? when(x.scanned_at) : "—"}</td></tr>`)}</tbody></table>` : ""}
    ${db ? kv([["취약점 DB 갱신", db.updated_at ? html`${when(db.updated_at)}<span class="sub">${db.age_days}일 전 · 기준 ${db.max_days}일</span>` : NONE]]) : ""}
    ${gate.critical?.count ? kv([["치명적 발견", html`${gate.critical.count}건 ${gate.critical.covered ? chip("restrict", "수용 중") : chip("block", "수용 필요")}`]]) : ""}
    ${gate.blockers.length ? html`<div class="pill-list">${gate.blockers.map((b) => chip("block", b.message))}</div>` : ""}</div>`;
}

function intakeTabsOf(id, report, registered) {
  const r = report.request, evidence = r.evidence || {}, investigation = report.exit_terms_discovery;
  const accepted = report.risk_acceptances || [];
  if (r.intake_kind === "remote-endpoint") {
    const review = evidence.remote_contract, approval = evidence.remote_approval;
    return [
      {key: "contract", label: "계약·범위", body: html`<div class="stack">
        ${panel("서비스", kv([["MCP 주소", html`<span class="mono">${r.endpoint_url}</span>`], ["사용 목적", r.purpose]]))}
        ${panel("계약 검토", review ? kv([["검토 내용", review.review_note], ["검토자", `${review.reviewed_by} · ${when(review.reviewed_at)}`],
          ["허용 사용자", audienceText(review.allowed_principals)], ["사용 기한", when(review.valid_until)],
          ["서버", `${review.advertised_name} ${review.version}`], ["계약 해시", html`<code>${review.registration.catalog_hash}</code>`],
          ["승인 도구", Object.keys(review.registration.tools || {}).join(", ")]]) : empty("검토 전"))}
        ${panel("허용 인자 범위", review ? html`<pre>${JSON.stringify(review.parameter_constraints || {}, null, 2)}</pre>` : empty("검토 전"))}
        ${panel("도입 승인", approval ? kv([["승인", `${approval.actor} · ${when(approval.at)}`], ["위험 수용", approval.risk_acceptance],
          ["검토 해시", html`<code>${approval.review_digest}</code>`]]) : empty("승인 전"))}
      </div>`},
      {key: "scope", label: "범위", body: review ? scopeTable(review.registration.tools, review.registration.tool_reviews, review.registration.data_class) : empty("검토 전")},
      {key: "risk", label: "영향평가", body: riskView(report.risk)},
      {key: "provenance", label: "출처", body: intakeProvenanceView(r.provenance)},
      {key: "records", label: "승인 기록", body: reviewRecords(report.events || [], r)},
      {key: "definitions", label: "승인 도구 계약", body: review ? html`<pre>${JSON.stringify(review.tools, null, 2)}</pre>` : empty("검토 전")},
    ];
  }
  const scanners = Object.entries(evidence.scanners || {});
  const allFindings = report.reports.flatMap((scan) => (scan.summary?.findings || []).map((f) => ({ ...f, scanner: scan.scanner })));
  const findings = allFindings.filter((f) => f.scanner !== "Gitleaks");
  const secretFindings = allFindings.filter((f) => f.scanner === "Gitleaks");
  const inventory = report.reports.find((scan) => scan.scanner === "Syft")?.summary || {};
  return [
    { key: "summary", label: "요약", body: html`<div class="stack">
      ${panel("검증 결과", html`<p>${r.review_note || "검증 대기"}</p>
        <p class="mono small">${r.repository_url}<br />${r.commit_sha || "—"}</p>
        ${kpiStrip([["SBOM 구성요소", evidence.sbom_components ?? "—"], ["치명", evidence.critical ?? "—", "block"],
          ["높음", evidence.high ?? "—", "alert"], ["보통", evidence.medium ?? "—"]])}`)}
      ${panel("검사 단계", scanners.length ? html`<table class="data"><thead><tr><th>검사기</th><th>결과</th><th>오류</th></tr></thead>
        <tbody>${scanners.map(([name, s]) => html`<tr><td>${name}</td><td>${chip(s.status === "DONE" ? "allow" : "block", s.status === "DONE" ? "완료" : "실패")}</td><td>${s.error || "—"}</td></tr>`)}</tbody></table>` : empty("검사 대기"))}
      ${panel("검사 기준", gateView(report.gate))}
      ${panel("원본 보고서", report.artifacts.length ? html`<div class="row-actions">${report.artifacts.map((a) => html`
        <button class="btn sm" data-act="intake-download" data-id="${id}" data-kind="${a.kind}" data-name="${a.filename}">${ARTIFACT_KIND[a.kind] || a.kind} JSON</button>`)}</div>` : empty("생성된 보고서 없음"))}
    </div>` },
    { key: "findings", label: "취약점·코드 검사", n: findings.length, body: html`
      ${report.reports.some((s) => s.summary?.truncated && s.scanner !== "Syft") ? html`<p class="small muted">검사기별 최대 200건</p>` : ""}
      ${findings.length ? html`<table class="data"><thead><tr><th>검사기·등급</th><th>발견</th><th>대상</th><th>설치 → 수정 버전</th></tr></thead>
      <tbody>${findings.map((f) => html`<tr><td>${f.scanner}<span class="sub">${f.severity}</span></td>
        <td><b>${f.id}</b><span class="sub">${f.title}</span></td><td>${f.target}<span class="sub">${f.package || ""}</span></td>
        <td>${f.installed_version || "—"} → ${f.fixed_version || "—"}</td></tr>`)}</tbody></table>`
        : empty(scanners.some(([, s]) => s.status === "FAILED") || r.status === "FAILED" ? "검사 실패" : ["VALIDATED", "APPROVED", "REJECTED"].includes(r.status) ? "발견 없음" : "검사 대기")}` },
    {key: "secrets", label: "비밀 정보 검사", n: secretFindings.length, body: html`
      ${secretFindings.length ? html`<table class="data"><thead><tr><th>규칙·등급</th><th>파일</th><th>행</th></tr></thead><tbody>${secretFindings.map((f) => html`<tr><td>${f.id}<span class="sub">${f.severity}</span></td><td>${f.target}</td><td>${f.line || "—"}</td></tr>`)}</tbody></table>` : empty(evidence.scanners?.gitleaks?.status === "DONE" ? "발견 없음" : "검사 대기")}`},
    { key: "sbom", label: "SBOM", n: inventory.components, body: html`
      ${inventory.truncated ? html`<p class="small muted">최대 200개</p>` : ""}
      ${(inventory.inventory || []).length ? html`<table class="data"><thead><tr><th>이름</th><th>버전</th><th>유형</th><th>식별자·라이선스</th></tr></thead>
        <tbody>${inventory.inventory.map((c) => html`<tr><td>${c.name}</td><td>${c.version || "—"}</td><td>${c.type}</td>
          <td class="small">${c.purl || "—"}<span class="sub">${(c.licenses || []).map((l) => l.expression || l.license?.id || l.license?.name || "미상").join(", ")}</span></td></tr>`)}</tbody></table>`
        : empty(inventory.components === 0 ? "구성요소 없음" : r.status === "FAILED" ? "생성 실패" : "생성 대기")}` },
    { key: "exit", label: "종료 조건", body: exitTermsView(id, r, investigation, evidence.exit_terms_conclusion) },
    { key: "scope", label: "범위", body: registered ? scopeTable(registered.tools, registered.tool_reviews, registered.data_class) : empty("등록 전") },
    { key: "risk", label: "영향평가", body: riskView(report.risk) },
    { key: "provenance", label: "출처", body: intakeProvenanceView(r.provenance) },
    { key: "records", label: "승인 기록", n: accepted.length || undefined, body: html`<div class="stack">${reviewRecords(report.events || [], r)}
      ${accepted.length ? panel("위험 수용", html`<table class="data"><thead><tr><th>수용자</th><th>기한</th><th>건수</th><th>사유</th></tr></thead><tbody>
        ${accepted.map((a) => html`<tr><td>${a.accepted_by}</td><td class="small nowrap">${when(a.expires_at)}</td><td class="num">${a.critical_count}</td><td>${short(a.reason, 120)}</td></tr>`)}</tbody></table>`, { flush: true }) : ""}</div>` },
  ];
}

ROUTES.termination = async (caseId, tab, query = new URLSearchParams()) => {
  if (caseId) return caseView(caseId, tab);
  const attention = ["required", "overdue"].includes(query.get("attention")) ? query.get("attention") : "";
  const casePage = Math.max(1, Math.floor(Number(query.get("page")) || 1));
  const params = new URLSearchParams();
  if (attention) params.set("attention", attention);
  if (casePage > 1) params.set("page", casePage);
  const [{ relationships }, result] = await Promise.all([gw("termination/relationships"), gw(`termination/cases${params.size ? `?${params}` : ""}`)]);
  const { cases, summary } = result;
  for (const r of relationships) r.actual_grade = cases.find((c) => String(c.id) === String(r.latest_case))?.grade;
  const caseTotal = result.total ?? cases.length, totalPages = Math.max(1, Math.ceil(caseTotal / (result.page_size || 50)));
  const caseHref = (p) => `#/termination?${new URLSearchParams({ ...(attention ? { attention } : {}), page: p })}`;
  termRelationships = relationships;
  const card = terminationCards(summary), stages = stageCounts(cases, PROCEDURE), grades = gradeCounts(cases);
  const expected = (c) => relationships.find((r) => r.id === c.relationship_id)?.readiness?.best_attainable_grade;
  return {
    html: page({
      head: head("종료·폐기"),
      kpis: html`${kpiStrip([["진행 중", card.open, "", "#/termination"], ["종결 대기", card.waiting, "approval"],
        ["회수 미완료", card.unresolved, card.unresolved ? "alert" : ""],
        ["기한 초과", card.overdue, card.overdue ? "block" : "", "#/termination?attention=overdue"],
        ["폐기 후 잔존 설정", card.residue, card.residue ? "alert" : "", "#/connections?t=shadow"]])}
        ${cases.length ? chartRow(["단계별 처리", "c-term-stage", "단계별 종료 처리 건수"], ["판정 등급", "c-term-grade", "판정 등급별 건수"]) : ""}`,
      active: "cases",
      tabs: [
        { key: "cases", label: "종료 처리", n: caseTotal, body: !caseTotal && !attention ? html`<div class="idle-state"><p class="empty" role="status">진행 중인 종료 없음</p><a class="btn" href="#/servers">MCP 서버 보기</a></div>` : panel(attention === "required" ? "종료 조치 필요" : attention === "overdue" ? "종료 기한 초과" : "종료 처리", html`<table class="data"><thead><tr><th>MCP 서버</th><th>상태</th><th>단계</th><th class="num">미회수 대상</th><th>기한</th><th>예상 결과</th><th>실제 결과</th></tr></thead><tbody>
            ${cases.map((c) => { const due = caseDue(c, summary.sla_days); return html`<tr class="clickable" tabindex="0" data-act="open-case" data-id="${c.id}">
              <td><b>${c.display_name}</b></td>
              <td>${chip(c.status === "CLOSED" ? "outline" : "approval", CASE_STATUS[c.status] || c.status)}${c.overdue ? chip("block", "기한 초과") : ""}</td>
              <td><span class="rail" role="img" aria-label="${PROCEDURE[Math.min(caseDone(c), PROCEDURE.length - 1)]}" title="${PROCEDURE[Math.min(caseDone(c), PROCEDURE.length - 1)]}">${PROCEDURE.map((_, i) => html`<i class="${i < caseDone(c) ? "done" : i === caseDone(c) ? "now" : ""}"></i>`)}</span></td>
              <td class="num ${c.outstanding ? "bad-text" : ""}">${c.outstanding}개</td>
              <td class="small nowrap ${c.overdue ? "bad-text" : ""}">${due ? when(due) : "—"}</td>
              <td>${expected(c) ? gradeChip(expected(c)) : NONE}</td><td>${c.grade ? gradeChip(c.grade) : NONE}</td></tr>`; })}
            </tbody></table>${cases.length ? "" : empty("종료 처리 없음")}`, { flush: true,
              tools: html`<div class="row-actions"><a class="btn sm ${!attention ? "primary" : ""}" href="#/termination">전체</a><a class="btn sm ${attention === "required" ? "primary" : ""}" href="#/termination?attention=required">조치 필요</a><a class="btn sm ${attention === "overdue" ? "primary" : ""}" href="#/termination?attention=overdue">기한 초과</a></div>`,
              end: totalPages > 1 ? html`<div class="row-actions">${casePage > 1 ? html`<a class="btn sm" href="${caseHref(casePage - 1)}">이전</a>` : ""}<span>${casePage} / ${totalPages}</span>${casePage < totalPages ? html`<a class="btn sm" href="${caseHref(casePage + 1)}">다음</a>` : ""}</div>` : "" }) },
      ],
    }),
    charts: cases.length ? {
      "c-term-stage": () => charts.bars(stages.map((s) => ({ name: s.name, value: s.value }))),
      "c-term-grade": () => charts.donut(grades.map((g) => ({ name: GRADE[g.key], value: g.value, color: charts.color({ T1: "Allow", T2: "Alert", T3: "Block" }[g.key]) }))),
    } : {},
  };
};

let termRelationships = [];
const REVOKE_KEY = { gateway_access: "게이트웨이 접근", endpoint_configs: "엔드포인트 설정", server_held: "서버 보유 자격" };
const revokeTotal = (revoke = {}) => Object.keys(REVOKE_KEY).reduce((sum, k) => sum + (Number(revoke[k]) || 0), 0);
const operatorLabel = (r) => (r.deployment === "provider" ? `제공자 ${r.provider || ""}`.trim() : "사내");
function relationshipRow(r) {
  const ready = r.readiness || {};
  const startable = r.lifecycle === "OPERATING" && r.status === "ACTIVE";
  return html`<tr class="clickable" tabindex="0" data-act="relationship" data-id="${r.id}">
    <td><b>${r.display_name}</b><span class="sub">${short(r.purpose || "", 60)}</span></td>
    <td>${operatorLabel(r)}${r.status !== "ACTIVE" ? html`<span class="sub">${chip(...(REL_STATUS[r.status] || ["", r.status]))}</span>` : ""}</td>
    <td class="num">${r.users ?? 0}</td><td class="num">${r.calls ?? 0}</td><td class="num">${revokeTotal(ready.would_revoke)}</td>
    <td>${gradeChip(ready.best_attainable_grade)}</td><td>${gradeChip(r.actual_grade)}</td><td>${r.latest_case ? html`<a href="#/termination/${r.latest_case}?t=evidence">근거</a>` : "—"}</td>
    <td class="num nowrap">${startable ? html`<button class="btn sm danger" data-act="open-termination" data-id="${r.id}" data-name="${r.display_name}" data-grade="${ready.best_attainable_grade || ""}">종료 시작</button>`
      : r.latest_case ? html`<a class="btn sm" href="#/termination/${r.latest_case}">처리 내역</a>` : ""}</td></tr>`;
}
function showRelationship(id) {
  const r = termRelationships.find((row) => row.id === id);
  if (!r) return;
  const ready = r.readiness || {};
  const terms = r.exit_terms || {};
  rememberDetail(id, "relationship");
  openDrawer(r.display_name, html`<div class="row-actions">${gradeChip(ready.best_attainable_grade, "예상 ")}${chip(...(REL_STATUS[r.status] || ["", r.status]))}
    ${r.latest_case ? html`<a class="btn sm" href="#/termination/${r.latest_case}">최근 종료 처리</a>` : ""}</div>`, [
    { key: "info", label: "개요", body: kv([["이용 목적", r.purpose], ["운영", operatorLabel(r)],
      ["이용자", r.users ?? 0], ["호출", r.calls ?? 0],
      ["허용 자원", (r.allowed_resources || []).map(resourceName).join(", ")]]) },
    { key: "revoke", label: "회수 대상", n: revokeTotal(ready.would_revoke), body: kv(Object.entries(REVOKE_KEY).map(([k, label]) => [label, ready.would_revoke?.[k] ?? 0])) },
    ...(r.deployment === "provider" ? [{ key: "terms", label: "종료 조건", body: html`<div class="pill-list">${Object.entries(EXIT_TERMS).map(([k, label]) => bool(terms[k], label))}</div>
      ${(ready.blockers || []).length ? html`<ul class="small">${ready.blockers.map((b) => html`<li>${b}</li>`)}</ul>` : ""}` }] : []),
  ]);
}

let currentCase = null;
const PROCEDURE = ["이용 관계 확정", "강제 경로 차단", "모집단 열거", "회수 조치", "상태 증거", "판정", "종결"];

function procedureState(d) {
  const c = d.case;
  const closed = c.status === "CLOSED";
  const stateEvidence = d.evidence.some((e) => e.meaning?.state);
  const unverifiable = d.targets.some((t) => t.status === "UNVERIFIABLE");
  const flags = [true, Boolean(c.cutover_at), d.targets.length > 0 && !unverifiable,
    d.targets.length > 0 && d.targets.every((t) => ["REVOKED", "EXPIRED"].includes(t.status)), stateEvidence,
    Boolean(c.grade) && ["ASSESSED", "CLOSED"].includes(c.status), closed];
  const now = closed ? -1 : flags.indexOf(false);
  return PROCEDURE.map((title, i) => ({ title, done: closed ? flags[i] : i < now, now: !closed && i === now,
    gap: closed ? !flags[i] : i === now && i === 2 && unverifiable }));
}

function terminationOverview(d) {
  const c = d.case, act = d.activity || {}, closed = c.status === "CLOSED";
  return html`${panel("종료 개요", html`${kv([["종료 사유", c.reason || "—"], ["제공자", c.provider || "—"],
    ["시작", when(c.opened_at)], ["차단", when(c.cutover_at, { seconds: true })],
    ["처리 기한", c.due_at ? html`${when(c.due_at)} ${chip(closed ? "outline" : c.overdue ? "block" : "outline", closed ? "종결" : c.overdue ? "기한 초과" : "기한 내")}` : "—"],
    ["마지막 시도", when(act.last_attempt, { seconds: true })], ["실행 미확인", act.unknown ?? "—"],
    ["재판정 사유", c.criteria?.stale_note || "—"]])}
    <h3>허용 자원</h3>${(c.allowed_resources || []).length ? html`<div class="pill-list">${c.allowed_resources.map((a) => html`<span class="chip outline mono">${resourceName(a)}${typeof a === "object" && a.action ? ` / ${ACTION[a.action] || "—"}` : ""}</span>`)}</div>` : empty("기록 없음")}`)}
    ${closed ? panel("종결 후 잔여 상태", kv([["종결", when(c.closed_at)], ["판정 결과", c.grade ? gradeChip(c.grade) : "—"],
      ["미회수", d.targets.filter((t) => t.status === "OUTSTANDING").length], ["확인 불가", d.targets.filter((t) => t.status === "UNVERIFIABLE").length],
      ["엔드포인트 잔존", d.endpoint_residue ?? "—"], ["위험 수용 근거", c.risk_acceptance_note || "—"], ["위험 수용자", c.risk_accepted_by || "—"]])) : ""}`;
}

function terminationFollowup(d) {
  const closed = d.case.status === "CLOSED";
  const rows = d.targets.map((target) => {
    const gaps = ["C1", "C2", "C3", "C4"].flatMap((key) => target.criteria?.[key]?.met === false ? target.criteria[key].gaps?.length ? target.criteria[key].gaps : [CRITERIA[key]] : []);
    const task = target.status === "UNVERIFIABLE" ? "대상 범위 확인" : target.status === "OUTSTANDING" ? "회수 상태 확인"
      : target.criteria?.C4?.met === false ? "상태 증거 확인" : gaps.length ? "미충족 기준 확인" : !target.criteria ? "판정 자료 확인" : "";
    return { target, gaps, task };
  }).filter((row) => row.task);
  return panel(closed ? "종결 후 확인 항목" : "확인 및 조치", html`${rows.length ? html`<table class="data"><thead><tr><th>대상</th><th>확인 사항</th><th>다음 조치</th></tr></thead><tbody>
    ${rows.map(({ target, gaps, task }) => html`<tr><td>${target.label}</td><td>${gaps.length ? gaps.map((gap) => html`<span class="sub">${gap}</span>`) : TARGET_STATUS[target.status]?.[1] || "—"}</td>
      <td><button class="btn sm" data-act="target" data-id="${target.id}">${task}</button></td></tr>`)}</tbody></table>` : empty("확인할 항목 없음")}
    ${!closed ? html`<div class="row-actions">${!d.targets.length ? html`<button class="btn" data-act="add-target">회수 대상 추가</button>` : ""}<button class="btn" data-act="collect">증거 수집</button>
      ${d.case.status === "ASSESSED" ? html`<button class="btn" data-act="close-case">종결 검토</button>` : html`<button class="btn" data-act="assess">판정</button>`}</div>` : ""}`, { flush: rows.length > 0 });
}

function terminationHistory(d) {
  const labels = { opened: "종료 시작", cutover: "경로 차단", "target-state": "회수 상태 확인", evidence: "증거 등록", assessed: "판정", "risk-accepted": "위험 수용", closed: "종결" };
  return html`<details class="termination-history"><summary>처리 이력</summary>${kv([["기록 범위", "현재 보존된 기록"]])}
    ${(d.timeline || []).length ? html`<table class="data"><thead><tr><th>시각</th><th>처리</th><th>처리자</th><th>대상 및 내용</th></tr></thead><tbody>
      ${d.timeline.map((event) => html`<tr><td>${when(event.at, { seconds: true })}</td><td>${labels[event.kind] || "—"}</td><td>${event.actor || "—"}</td>
        <td>${event.target_id ? html`<button class="btn sm" data-act="target" data-id="${event.target_id}">${event.detail || "상세 확인"}</button>` : event.detail || "—"}</td></tr>`)}</tbody></table>` : empty("기록 없음")}</details>`;
}

async function caseView(caseId, tab) {
  const d = await gw(`termination/cases/${caseId}`);
  currentCase = d;
  const c = d.case;
  const criteria = c.criteria || {};
  const closed = c.status === "CLOSED";
  const act = d.activity || {};
  const outstanding = d.targets.filter((t) => t.status === "OUTSTANDING").length;
  const stateEvidence = d.evidence.filter((e) => e.meaning?.state).length;
  return {
    html: page({
      head: html`${head(c.engagement_label, {
        back: html`<a class="back" href="#/termination?t=cases">← 종료 및 폐기</a>`,
        status: html`${chip(closed ? "outline" : "approval", CASE_STATUS[c.status] || c.status)}${gradeChip(c.grade)}`,
        actions: html`${c.grade ? html`<button class="btn" data-act="report">판정서</button>` : ""}
          ${c.deployment === "provider" ? html`<button class="btn" data-act="disclosure">고지 요청서</button>` : ""}
          ${closed ? html`<button class="btn" data-act="reopen-case">종료 처리 재개</button>` : ""}
          ${!closed ? html`<button class="btn" data-act="collect">증거 수집</button><button class="btn primary" data-act="assess">판정</button>` : ""}
          ${c.status === "ASSESSED" ? html`<button class="btn danger solid" data-act="close-case">종결</button>` : ""}` })}
        <ol class="stepper" aria-label="종료 판정 절차">${procedureState(d).map((s, i) => html`
          <li class="step ${s.done ? "done" : ""} ${s.now ? "now" : ""} ${s.gap ? "gap" : ""}"><span class="n">${s.done ? "✓" : i + 1}</span><b>${s.title}</b></li>`)}</ol>`,
      kpis: kpiStrip([["미회수", outstanding, "alert"], ["확인 불가", d.targets.filter((t) => t.status === "UNVERIFIABLE").length, "alert"], ["차단 후 실행", act.executed || 0, "block"], ["차단 후 거부", act.blocked || 0],
        ["엔드포인트 잔존", d.endpoint_residue || 0, "alert"]]),
      active: tab === "scope" ? "verdict" : tab || "verdict",
      tabs: [
        { key: "verdict", label: "종료 현황", body: html`<div class="stack">${terminationOverview(d)}${terminationFollowup(d)}<div class="grid c12">
          ${panel("등급", html`${c.grade ? html`<div class="grade-big ${c.grade}">${GRADE[c.grade]}</div>` : html`<div class="grade-big">—</div>`}
            ${criteria.assessed_at ? html`<p class="muted small">${when(criteria.assessed_at)}</p>` : ""}
            ${c.grade && c.grade !== "T1" && (criteria.determined_by || []).length ? kv([["결정 대상", criteria.determined_by.join(", ")]]) : ""}
            ${(criteria.notes || []).map((n) => html`<p class="note bad">${n}</p>`)}
            ${kv([["위험 수용", c.risk_acceptance_note ? `${c.risk_acceptance_note} (${c.risk_accepted_by})` : ""], ["종결 사유", c.close_note],
              ["재개 사유", criteria.reopened_note]])}`)}
          ${panel("기준별 충족 대상", html`<div class="crit">${["C1", "C2", "C3", "C4"].map((k) => { const cr = criteria[k]; return html`<div class="c">
              <h4>${CRITERIA[k]} ${cr ? chip(cr.met ? "allow" : "block", cr.met ? "충족" : "미충족") : chip("outline", "미판정")}</h4>
              ${cr?.gaps?.length ? html`<ul>${cr.gaps.slice(0, 3).map((g) => html`<li>${g}</li>`)}${cr.gaps.length > 3 ? html`<li>+${cr.gaps.length - 3}</li>` : ""}</ul>` : ""}</div>`; })}</div>`,
            { sub: `대상 ${d.targets.length}개` })}</div>${terminationHistory(d)}</div>` },
        { key: "targets", label: "회수 대상", n: d.targets.length, hot: outstanding > 0, body: panel("회수 대상", html`<table class="data">
          <thead><tr><th>대상</th><th>상태</th><th>기준</th><th>등급</th><th></th></tr></thead><tbody>
          ${d.targets.map((t) => html`<tr class="clickable" tabindex="0" data-act="target" data-id="${t.id}">
            <td><b>${t.label}</b><span class="sub">${TARGET_KIND[t.kind] || t.kind} · ${HOLDER[t.holder] || t.holder} · ${DISCOVERED[t.discovered_by] || t.discovered_by}</span></td>
            <td>${chip(...(TARGET_STATUS[t.status] || ["", t.status]))}</td>
            <td>${t.criteria ? html`<span class="cdots">${["C1", "C2", "C3", "C4"].map((k) => html`<span class="${t.criteria[k]?.met ? "met" : ""}" title="${CRITERIA[k]}">${CRITERIA[k].slice(0, 1)}</span>`)}</span>` : html`<span class="small muted">—</span>`}</td>
            <td>${t.grade ? chip(t.grade, t.grade) : ""}</td>
            <td class="num nowrap">${!closed && t.kind === "server-held-credential" && t.verification === "gitea-token" && t.status === "OUTSTANDING"
              ? html`<button class="btn sm danger" data-act="revoke-credential" data-id="${t.id}">조직 권한으로 폐기</button>` : ""}
              ${!closed ? html`<button class="btn sm" data-act="target-status" data-id="${t.id}">상태 기록</button>` : ""}</td></tr>`)}
          </tbody></table>`, { flush: true, tools: closed ? "" : html`<button class="btn sm" data-act="add-target">대상 추가</button>` }) },
        { key: "evidence", label: "증거", n: d.evidence.length, body: panel("증거", html`<div class="evidence">${d.evidence.map(evidenceItem)}</div>
          ${d.evidence.length ? "" : empty("증거 없음")}`, { sub: `상태 증거 ${stateEvidence}`, tools: closed ? "" : html`<button class="btn sm" data-act="add-evidence">증거 등록</button>` }) },

      ],
    }),
  };
}
function evidenceResult(e) {
  const d = e.detail || {};
  switch (e.kind) {
    case "gateway-denial": return d.blocked ? chip("allow", `실행 전 차단 · ${d.policy_id}`) : chip("block", `차단 안 됨 · ${DECISION[d.decision]?.[1] || d.decision || "—"} ${d.policy_id || ""}`);
    case "credential-check": return d.present === false ? chip("allow", "자격 없음") : d.present ? chip("block", "자격 남음") : chip("alert", `확인 실패 · HTTP ${d.http_status}`);
    case "resource-rejection": return d.rejected ? chip("allow", `자원 서버 거부 · ${d.http_status}`) : chip("block", `자원 서버 수락 · ${d.http_status}`);
    case "endpoint-inventory": return d.absent ? chip("allow", "설정 사라짐") : chip("block", `설정 남음 · ${when(d.last_report)}`);
    case "introspection": return d.active === false ? chip("allow", "비활성") : d.active ? chip("block", "활성") : "";
    case "revocation-response": return chip("outline", `처리 응답 ${d.http_status ?? ""}`.trim());
    case "liveness-probe": return d.reachable ? chip("alert", `응답함 ${d.status_code ?? ""}`.trim()) : chip("outline", "응답 없음");
    case "session-termination": return d.session_issued === false ? chip("outline", "세션 없음")
      : d.session_still_works ? chip("block", "세션 유지됨") : chip("outline", "세션 종료 요청");
    default: return d.statement ? chip("outline", "진술") : "";
  }
}

function evidenceItem(e) {
  const m = e.meaning || {};
  const target = currentCase?.targets.find((t) => t.id === e.target_id);
  return html`<div class="e">
    <div class="head"><b>${m.label || e.kind}</b>${m.state ? chip("allow", "상태 증거") : chip("outline", "처리 증거")}
      ${evidenceResult(e)}<span class="small muted">${when(e.observed_at, { seconds: true })} · ${e.source}</span></div>
    <div class="small">${e.subject}${target && target.label !== e.subject ? html` <span class="muted">→ ${target.label}</span>` : ""}</div>
    ${Object.keys(e.detail || {}).length ? html`<details><summary class="small">상세</summary>${json(e.detail)}</details>` : ""}</div>`;
}

function showTarget(id) {
  const t = currentCase?.targets.find((row) => row.id === id);
  if (!t) return;
  const own = currentCase.evidence.filter((e) => e.target_id === id);
  rememberDetail(id, "target");
  openDrawer(t.label, html`<div class="row-actions">${chip(...(TARGET_STATUS[t.status] || ["", t.status]))}${gradeChip(t.grade)}</div>`, [
    { key: "info", label: "대상", body: kv([["종류", TARGET_KIND[t.kind] || t.kind], ["보유 주체", HOLDER[t.holder] || t.holder],
      ["발견 경로", DISCOVERED[t.discovered_by] || t.discovered_by], ["식별자", t.subject_ref ? html`<code>${t.subject_ref}</code>` : ""],
      ["확인 방법", VERIFICATION[t.verification] || t.verification], ["만료 시각", t.expires_at ? when(t.expires_at, { seconds: true }) : ""],
      ["회수 시각", t.revoked_at ? when(t.revoked_at, { seconds: true }) : ""],
      ["자원 서버", t.criteria?.provider_side ? PROVIDER_SIDE[t.criteria.provider_side.state] : ""], ["메모", t.note]]) },
    { key: "criteria", label: "기준", body: t.criteria ? html`<div class="crit">${["C1", "C2", "C3", "C4"].map((k) => html`<div class="c"><h4>${CRITERIA[k]}
      ${chip(t.criteria[k].met ? "allow" : "block", t.criteria[k].met ? "충족" : "미충족")}</h4>
      ${t.criteria[k].gaps.length ? html`<ul>${t.criteria[k].gaps.map((g) => html`<li>${g}</li>`)}</ul>` : ""}</div>`)}</div>` : empty("미판정") },
    { key: "evidence", label: "증거", n: own.length, body: html`<div class="evidence">${own.map(evidenceItem)}</div>${own.length ? "" : empty("증거 없음")}` },
  ]);
}

let policyLedger = [];
const policyLabel = (id) => policyLedger.find((row) => row.policy_id === id)?.name || id || "—";
let loadedAlerts = [];
function alertGroups(alerts) {
  const groups = new Map();
  for (const a of alerts) {
    const [target] = alertTarget(a);
    const e = a.evidence || {};
    const evidence = Object.fromEntries(Object.entries(e).filter(([key]) => key !== "record_id").sort(([a], [b]) => a.localeCompare(b)));
    const key = JSON.stringify([a.kind, a.origin, evidence, a.reason, target, alertDetail(a)]);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(a);
  }
  return [...groups.values()].map((rows) => ({ rows, first: rows.reduce((v,a) => a.created_at < v ? a.created_at : v, rows[0].created_at),
    last: rows.reduce((v,a) => a.created_at > v ? a.created_at : v, rows[0].created_at) }));
}
const freshAlertGroups = (alerts) => alertGroups(alerts.filter((a) => !alertSeen(a))).length;
const alertSeen = (a) => alertsSeen().some(([low, high]) => Number(a.id) >= low && Number(a.id) <= high);
const ALERT_HOURS = [["24", "24시간"], ["168", "7일"], ["720", "30일"], ["", "전체"]];
const alertsTab = (alertData, q) => {
  if (!alertData) return empty("", { failed: true });
  const state = ["new", "read"].includes(q.get("alert_state")) ? q.get("alert_state") : "";
  const all = alertGroups(alertData.alerts);
  const fresh = all.filter(({ rows }) => rows.some((a) => !alertSeen(a)));
  const groups = state === "new" ? fresh : state === "read" ? all.filter(({ rows }) => rows.every(alertSeen)) : all;
  const events = fresh.reduce((sum, { rows }) => sum + rows.filter((a) => !alertSeen(a)).length, 0);
  const link = (label, next, extra = "") => {
    const to = new URLSearchParams(q);
    to.set("t", "alerts"); to.delete("alert_state"); to.delete("before");
    if (next) to.set("alert_state", next);
    return html`<a class="btn sm" href="#/activity?${to}" ${next === state ? raw('aria-current="true"') : ""}>${label}${extra}</a>`;
  };
  const hoursLink = ([hours, label]) => {
    const to = new URLSearchParams(q);
    to.set("t", "alerts"); to.delete("before"); to.delete("hours");
    if (hours) to.set("hours", hours);
    return html`<a class="seg-btn" href="#/activity?${to}" aria-pressed="${String((q.get("hours") || "") === hours)}">${label}</a>`;
  };
  const more = new URLSearchParams(q);
  more.set("t", "alerts");
  if (alertData.next_before) more.set("before", alertData.next_before);
  return html`<div class="feed-toolbar row-actions inbox-filters">${link("전체", "", html` <b class="n">${all.length}</b>`)}${link("신규", "new", html` <b class="n">${fresh.length}</b>`)}${link("읽음", "read", html` <b class="n">${all.length - fresh.length}</b>`)}
    <span class="seg" role="group" aria-label="기간">${ALERT_HOURS.map(hoursLink)}</span>
    <span class="feed-count">신규 ${fresh.length}그룹 · 발생 ${events}건</span>
    <button class="btn sm" type="button" data-act="alerts-ack-all" ${fresh.length ? "" : raw("disabled")}>모두 읽음 ${fresh.length}그룹</button></div>
    ${groups.length ? html`<table class="data rows-32"><thead><tr><th>시각</th><th>종류</th><th>대상</th><th>서버 · 도구</th><th>사유</th><th class="num">발생</th><th>상태</th><th></th></tr></thead><tbody>
    ${groups.map(({ rows, last }) => {
      const a = rows[0], [target] = alertTarget(a), e = a.evidence || {};
      const [host, ...rest] = target.split(" · ");
      const resource = [a.server_name || e.label || e.server_id, e.tool_name || e.tool || (a.origin === "endpoint-tool" ? e.place : "")].filter(Boolean).join(" · ");
      return html`<tr class="clickable" tabindex="0" data-act="alert-detail" data-id="${a.id}"><td class="nowrap">${when(last, { seconds: true })}</td>
        <td>${chip("alert", ALERT_KIND[a.kind] || "경보")}</td><td class="cut"><b>${host}</b>${rest.length ? html`<span class="sub">${rest.join(" · ")}</span>` : ""}</td><td class="cut">${resource || "—"}</td>
        <td class="cut">${alertReason(a) || "—"}</td><td class="num">${rows.length}건</td>
        <td>${rows.every(alertSeen) ? chip("outline", "읽음") : chip("alert", "신규")}</td><td class="num"><button class="btn sm" type="button" data-act="alert-detail" data-id="${a.id}">보기</button></td></tr>`;
    })}</tbody></table>` : empty("경보 없음", { filtered: Boolean(state) })}
    ${alertData.has_more ? html`<a class="btn" href="#/activity?${more}">더 보기</a>` : ""}`;
};
let policyEvidence = {};
let organizationPolicies = [];

const policyExecutor = (p) => ({ opa: "정책 엔진", gateway: "게이트웨이", endpoint: "엔드포인트", vendor: "벤더" }[p.enforced_by] || "—");
const policyEnvironment = (env) => ({ prod: "운영 환경", stage: "사전 검증 환경", dev: "개발 환경" }[env] || "—");
const policyLinks = (p) => Array.isArray(p.pol_ids) ? [...new Set(p.pol_ids.filter((id) => /^POL-[A-Z]-\d{2}$/.test(id)))] : [];
const policyRecorded = (p) => Number.isSafeInteger(p.recent?.count) && p.recent.count > 0;
const policyRecordLabel = (p) => policyRecorded(p) ? "기록 있음" : p.recent?.count === 0 ? "기록 없음" : "미확인";
const policySourceLabel = (ledger) => ledger.source_state === "loaded" ? "조회 확인" : ledger.source_state === "unavailable" ? "조회 실패" : "미확인";
const policyDeployLabel = (ledger, key) => typeof ledger.deployment?.[key] !== "boolean" ? "미확인"
  : ledger.deployment[key] ? "일치" : "불일치";

function auditTools() {
  return html`<div class="row-actions"><button class="btn primary" data-act="audit-export" title="현재 조회 조건의 감사 필드를 최대 500건씩 내보냅니다.">증빙 내보내기</button><button class="btn" id="audit-export-next" data-act="audit-export-next" hidden>다음 증빙 내보내기</button></div>`;
}

const incidentsPanel = (incidentData) => panel("사고 보고 기한", incidentData === null ? html`<div class="note bad">조회 실패</div>` : html`${incidentData.incidents.length ? html`<table class="data"><thead><tr><th>사고</th><th>관할·단계</th><th>기한</th><th>남은 시간</th><th>상태</th></tr></thead><tbody>${incidentData.incidents.flatMap((incident) => incident.deadlines.map((deadline) => html`<tr class="clickable" tabindex="0" data-act="incident-evidence" data-id="${incident.id}">
        <td>${incident.title}<span class="sub">${when(incident.detected_at)}</span></td><td>${deadline.jurisdiction_name}<span class="sub">${deadline.stage_name}</span></td><td>${deadline.due_at ? when(deadline.due_at) : "—"}</td><td>${deadline.remaining_seconds == null ? "—" : `${deadline.remaining_seconds < 0 ? "초과 " : ""}${Math.floor(Math.abs(deadline.remaining_seconds) / 86400)}일 ${Math.floor(Math.abs(deadline.remaining_seconds) % 86400 / 3600)}시간`}</td><td>${deadline.status}</td></tr>`))}</tbody></table>` : empty("사고 기록 없음")}`, {flush:true, sub: incidentData ? `타이머 ${incidentData.timer_status}` : ""});

let lastVerify = null;
const siemChip = (siem) => {
  if (!siem) return chip("alert", "관제 전달 조회 실패");
  if (!siem.configured) return chip("outline", "관제 전달 설정 안 됨");
  if (siem.pending > 0) return chip("alert", `관제 전달 미전달 ${siem.pending}건`);
  return chip("allow", siem.last_delivered ? `관제 전달 정상 · ${ago(siem.last_delivered)}` : "관제 전달 정상");
};
function auditTab(retention) {
  const f = feed.filters;
  const input = (key, label, type, value) => html`<label>${label}<input data-filter="${key}" ${["since", "until"].includes(key) ? raw('data-ko="1" placeholder="2026.11.13 18:28"') : ""} type="${type}" value="${value}" aria-label="${label}" /></label>`;
  return html`<div class="stack">
    ${panel("무결성", kv([["결과", lastVerify ? chip(lastVerify.intact ? "allow" : "block", lastVerify.intact ? "정상" : "손상") : "—"],
      ["검증 시각", lastVerify ? when(lastVerify.at, { seconds: true }) : "—"], ["검증 건수", lastVerify?.checked ?? "—"]]),
      { end: html`<button class="btn" type="button" data-act="audit-verify">지금 검증</button>` })}
    ${panel("보존 기간", retention ? kv([["보존 기간", `${retention.days}일`], ["관할", (retention.jurisdictions || []).join(", ") || "—"],
      ["하한", `${retention.floor_days}일`], ["변경", retention.updated_at ? when(retention.updated_at) : "—"]]) : empty("", { failed: true }),
      { end: retention ? html`<button class="btn" type="button" data-act="audit-retention" data-days="${retention.days}" data-floor="${retention.floor_days}"
        data-jurisdictions="${JSON.stringify(retention.jurisdictions || [])}">변경</button>` : "" })}
    ${panel("내보내기", html`<div class="filters">${input("since", "시작", "text", koInput(f.since))}${input("until", "종료", "text", koInput(f.until))}
      ${input("policy", "정책", "search", f.policy)}${auditTools()}</div>`)}</div>`;
}

const EVENT_KIND = { "tools/call": "도구 호출", "mcp-connection": "연결 거부" };
const TOOL_PATH = { gateway: ["brand", "게이트웨이"], connector: ["restrict", "커넥터"], local: ["alert", "로컬 MCP"] };
const byteText = (n) => { const v = Number(n) || 0; return v < 1024 ? `${v} B` : v < 1048576 ? `${(v / 1024).toFixed(1)} KB` : `${(v / 1048576).toFixed(1)} MB`; };
function endpointCallsTab(toolData) {
  return { key: "tools", label: "엔드포인트 관찰", n: toolData?.total, body: panel("엔드포인트 관찰", !toolData ? empty("", { failed: true }) : toolData.rows.length ? html`<table class="data"><thead><tr><th>시각</th><th>엔드포인트</th><th>하네스</th><th>경로</th><th>MCP 서버 · 도구</th><th>게이트웨이 판정</th><th>도구 실행</th><th>업무 결과</th><th class="num">입력</th><th class="num">출력 크기</th></tr></thead><tbody>${toolData.rows.map((e) => html`<tr ${e.decision_id ? raw(`class="clickable" tabindex="0" data-act="decision" data-id="${Number(e.decision_id)}"`) : ""}>
        <td class="small nowrap">${when(e.called_at, { seconds: true })}</td><td>${e.hostname || e.endpoint_id}<span class="sub">${[e.owner_name, e.account].filter((v, i, all) => v && v !== e.hostname && all.indexOf(v) === i).join(" · ")}</span></td>
        <td>${chip("plain", harnessName(e.harness))}</td><td>${chip(...(TOOL_PATH[e.path] || ["outline", e.path]))}</td>
        <td><b>${e.server_name || e.server}</b><span class="sub mono">${e.tool}</span></td>
        <td>${e.decision ? html`${decisionChip(e.decision)}<span class="sub">${policyLabel(e.policy_id)}</span>${e.link_strength === "supporting" ? html`<span class="sub">보조 연결</span>` : ""}` : e.outcome_axes?.decision || "—"}</td>
        <td>${e.outcome_axes?.execution || "—"}</td><td>${e.outcome_axes?.task ? outcomeSummary({ task: e.outcome_axes.task }) : e.failed === true ? chip("block", "도구 오류") : "—"}</td>
        <td class="num">${e.input_bytes == null ? "—" : byteText(e.input_bytes)}</td><td class="num">${e.output_bytes == null ? "—" : byteText(e.output_bytes)}</td></tr>`)}</tbody></table>` : empty("엔드포인트 관찰 기록 없음"), { flush: true, sub: toolData ? `관찰 ${toolData.total}건` : "" }) };
}

let policyWindow = { key: "24h", since: new Date(), until: new Date(), activity: null, enforcement: "enforce" };
const POLICY_RANGES = { "24h": ["24시간", 24], "7d": ["7일", 168], "30d": ["30일", 720] };
const POLICY_MODE = { auto: "자동 집행", feature: "제품 기능", manual: "수동 점검", structural: "구조적 차단" };
const POLICY_MODE_TONE = { auto: "brand", feature: "outline", manual: "alert", structural: "plain" };
const POLICY_STAGES = ["도입", "등록", "실행", "관리", "폐기"];
const POLICY_STAGE_ORDER = { I: 0, R: 1, E: 2, O: 3, D: 4 };
const POLICY_STATE = { on: "켜짐", locked: "항상 켜짐", report: "보고 전용", off: "꺼짐" };
const policyStage = (p) => POLICY_STAGES[POLICY_STAGE_ORDER[p.id.split("-")[1]]] || p.stage;
const policyRulesOf = (p) => (p.runtime_rule_ids || []).map((id) => policyLedger.find((rule) => rule.policy_id === id)).filter(Boolean);
const ruleInForce = (rule) => ["운영", "제한"].includes(rule.status);

function policyState(p, enforcement) {
  if (p.mode !== "auto") return "";
  const rules = policyRulesOf(p);
  if (!rules.length) return "";
  if (!rules.some(ruleInForce)) return "off";
  const active = rules.filter(ruleInForce);
  if (active.every((rule) => rule.monitor_behavior === "protected")) return "locked";
  return enforcement === "monitor" && active.some((rule) => rule.monitor_behavior === "eligible") ? "report" : "on";
}

function policyCounts(p, byRule) {
  const sum = Object.fromEntries([...DECISIONS, "total"].map((d) => [d, 0]));
  for (const rule of p.runtime_rule_ids || []) for (const [key, n] of Object.entries(byRule.get(rule) || {})) sum[key] += n;
  return sum;
}
function policyActivityByRule(activity) {
  const byRule = new Map();
  for (const row of activity?.rows || []) {
    const entry = byRule.get(row.policy_id) || {};
    entry[row.decision] = (entry[row.decision] || 0) + Number(row.n);
    entry.total = (entry.total || 0) + Number(row.n);
    byRule.set(row.policy_id, entry);
  }
  return byRule;
}
const policyFilters = (query) => ({ stage: POLICY_STAGES.includes(query.get("stage")) ? query.get("stage") : "", mode: POLICY_MODE[query.get("mode")] ? query.get("mode") : "",
  state: POLICY_STATE[query.get("state")] ? query.get("state") : "", has: query.get("has") === "1", text: (query.get("q") || "").trim().toLowerCase() });
const policyMatches = (row, f) => (!f.stage || row.stage === f.stage) && (!f.mode || row.mode === f.mode) && (!f.state || row.state === f.state)
  && (!f.has || Number(row.total) > 0) && (!f.text || row.text.includes(f.text));
function applyPolicyFilters(expand = false) {
  const control = (name) => $(`[data-policy-filter="${name}"]`);
  const f = { stage: control("stage")?.value || "", mode: control("mode")?.value || "", state: control("state")?.value || "", has: Boolean(control("has")?.checked),
    text: (control("text")?.value || "").trim().toLowerCase() };
  if (expand && (f.stage || f.mode || f.state || f.has || f.text)) {
    for (const body of document.querySelectorAll("#organization-policy-list tbody[data-group]")) {
      body.dataset.collapsed = "false";
      body.querySelector(".group-toggle")?.setAttribute("aria-expanded", "true");
    }
  }
  const shown = new Map();
  for (const row of document.querySelectorAll("#organization-policy-list tr[data-policy]")) {
    const match = policyMatches(row.dataset, f);
    row.hidden = !match || row.closest("tbody")?.dataset.collapsed === "true";
    if (match) shown.set(row.dataset.group, (shown.get(row.dataset.group) || 0) + 1);
  }
  for (const body of document.querySelectorAll("#organization-policy-list tbody[data-group]")) body.hidden = !shown.has(body.dataset.group);
  const none = $("[data-list-empty=\"organization-policy-list\"]");
  if (none) none.hidden = shown.size > 0;
}

function policyMiniBar(counts, label, peak) {
  if (!counts.total) return html`<span class="muted">0</span>`;
  let x = 0;
  const rects = DECISIONS.filter((d) => counts[d] > 0).map((d) => {
    const width = counts[d] / peak * 100, rect = `<rect class="${d.toLowerCase()}" x="${x.toFixed(2)}" y="0" width="${width.toFixed(2)}" height="8"/>`;
    x += width;
    return rect;
  }).join("");
  return html`<svg class="minibar" viewBox="0 0 100 8" preserveAspectRatio="none" width="56" height="8" role="img" aria-label="${label}"><title>${label}</title>${raw(rects)}</svg><span class="num">${counts.total}</span>`;
}

function policyCharts(rows, activity, analysis, range) {
  const series = analysisSeries(analysis);
  const tone = (name) => charts.tone(name);
  const modes = Object.keys(POLICY_MODE);
  const byRule = policyActivityByRule(activity);
  const top = [...byRule.entries()].filter(([id]) => id).map(([id, c]) => ({ id, value: (c.Block || 0) + (c.Alert || 0) + (c.Approval || 0) + (c.Restrict || 0), blocked: c.Block || 0, alerted: c.Alert || 0 }))
    .filter((x) => x.value > 0).sort((a, b) => b.value - a.value).slice(0, 8);
  const go = (href) => { location.hash = href; };
  const logs = (extra) => new URLSearchParams({ event_kind: "tools/call", since: range.since.toISOString(), until: range.until.toISOString(), ...extra });
  const modeColor = { auto: tone("--brand"), feature: tone("--muted-series"), structural: tone("--ink-3"), manual: tone("--alert") };
  return {
    "c-policy-stage": () => charts.stacked(POLICY_STAGES, modes.map((mode) => ({ name: POLICY_MODE[mode], color: modeColor[mode],
      data: POLICY_STAGES.map((stage) => rows.filter((p) => policyStage(p) === stage && p.mode === mode).length) })),
    { onClick: (e) => { const mode = modes.find((m) => POLICY_MODE[m] === e.seriesName || t(POLICY_MODE[m]) === e.seriesName); go(`#/policy?${new URLSearchParams({ stage: POLICY_STAGES[e.dataIndex], ...(mode ? { mode } : {}) })}`); } }),
    "c-policy-top": () => charts.bars(top.map((x) => ({ name: policyLabel(x.id), value: x.value, color: charts.color(x.blocked >= x.alerted ? "Block" : "Alert") })),
      { onClick: (e) => { const row = top[e.dataIndex]; if (row) go(`#/activity?${logs({ policy: row.id })}`); } }),
    "c-policy-trend": () => charts.lines(series.map((b) => b.label), [
      { name: DECISION.Block[1], data: series.map((b) => b.Block), color: charts.color("Block") },
      { name: DECISION.Alert[1], data: series.map((b) => b.Alert), color: charts.color("Alert") },
      { name: DECISION.Approval[1], data: series.map((b) => b.Approval), color: charts.color("Approval") },
      { name: DECISION.Restrict[1], data: series.map((b) => b.Restrict), color: charts.color("Restrict") }],
    { onClick: (e) => { const b = series[e.dataIndex]; if (b) go(`#/activity?${logs({ since: new Date(b.at).toISOString(), until: new Date(b.at + bucketLength(analysis)).toISOString() })}`); } }),
  };
}

ROUTES.policy = async (_, tab, query = new URLSearchParams()) => {
  const key = POLICY_RANGES[query.get("range")] ? query.get("range") : "24h";
  const hours = POLICY_RANGES[key][1], until = new Date(), since = new Date(until.getTime() - hours * 3600000);
  const soft = (promise) => promise.catch(() => null);
  const [{ enforcement }, ledger, activity, analysis] = await Promise.all([gw("enforcement"), gw("policy/ledger"), soft(gw(`policy/activity?hours=${hours}`)),
    soft(gw(`activity/analysis?${new URLSearchParams({ event_kind: "tools/call", since: since.toISOString(), until: until.toISOString() })}`))]);
  policyLedger = ledger.policies;
  policyEvidence = ledger;
  organizationPolicies = ledger.organization?.policies || [];
  policyWindow = { key, hours, since, until, activity, enforcement };
  const range = policyWindow;
  const f = policyFilters(query);
  const byRule = policyActivityByRule(activity);
  const label = POLICY_RANGES[key][0];
  const rows = organizationPolicies.map((p) => ({ p, counts: policyCounts(p, byRule), state: policyState(p, enforcement) }));
  const modeCount = (mode) => organizationPolicies.filter((p) => p.mode === mode).length;
  const sum = (list) => list.reduce((total, row) => total + (Number(row.n) || 0) * (["Block", "Alert", "Approval"].includes(row.decision) ? 1 : 0), 0);
  const recent = activity ? sum(activity.rows) : null, before = activity ? sum(activity.previous) : null;
  const total = organizationPolicies.length;
  const sorted = [...rows].sort((a, b) => (b.p.mode === "manual") - (a.p.mode === "manual") || (b.counts.total - b.counts.Allow) - (a.counts.total - a.counts.Allow) || a.p.id.localeCompare(b.p.id));
  const groups = new Map();
  for (const row of [...sorted].sort((a, b) => a.p.group.localeCompare(b.p.group))) {
    if (!groups.has(row.p.group)) groups.set(row.p.group, []);
    groups.get(row.p.group).push(row);
  }
  const ordered = [...groups.entries()].sort(([a], [b]) => POLICY_STAGE_ORDER[a[0]] - POLICY_STAGE_ORDER[b[0]] || a.localeCompare(b));
  const peak = Math.max(1, ...rows.map((row) => row.counts.total));
  const filtering = Boolean(f.stage || f.mode || f.state || f.has || f.text);
  const stateCount = (key) => rows.filter((row) => row.state === key).length;
  const switchedOn = stateCount("on") + stateCount("locked") + stateCount("report"), switchedOff = stateCount("off");
  const rowData = (row) => ({ stage: policyStage(row.p), mode: row.p.mode, state: row.state, total: row.counts.total, text: `${row.p.id} ${row.p.title}`.toLowerCase() });
  const filterOption = (name, items, current) => html`<select data-policy-filter="${name}" aria-label="${name === "stage" ? "단계" : name === "mode" ? "집행 방식" : "현재 상태"}"><option value="">${name === "stage" ? "모든 단계" : name === "mode" ? "모든 집행 방식" : "모든 상태"}</option>
    ${Object.entries(items).map(([value, text]) => html`<option value="${value}" ${value === current ? raw("selected") : ""}>${text}</option>`)}</select>`;
  const table = ordered.map(([group, items]) => {
    const manual = items.filter((row) => row.p.mode === "manual").length;
    const quiet = !filtering && !items.some((row) => row.p.mode === "manual" || row.state === "off" || row.counts.total > 0);
    return html`<tbody data-group="${group}" data-collapsed="${String(quiet)}" ${items.some((row) => policyMatches(rowData(row), f)) ? "" : raw("hidden")}>
      <tr class="group-row"><th colspan="7" scope="colgroup"><button class="group-toggle" type="button" data-act="policy-group" aria-expanded="${String(!quiet)}"><span class="group-name"><b>${items[0].p.stage}</b> ${items[0].p.group_title}</span>
        <span class="muted">정책 ${items.length}${manual ? ` · 수동 ${manual}` : ""}</span></button></th></tr>
      ${items.map((row) => { const d = rowData(row), p = row.p, rules = policyRulesOf(p);
        return html`<tr class="clickable" tabindex="0" data-act="organization-policy" data-id="${p.id}" data-policy data-group="${group}" data-stage="${d.stage}" data-mode="${d.mode}" data-state="${d.state}" data-total="${d.total}" data-text="${d.text}" ${policyMatches(d, f) && !quiet ? "" : raw("hidden")}>
          <td class="mono">${p.id}</td><td>${p.title}</td><td>${p.priority}</td><td>${chip(POLICY_MODE_TONE[p.mode], POLICY_MODE[p.mode])}</td>
          <td>${row.state ? chip(row.state === "off" ? "outline" : row.state === "report" ? "alert" : "allow", POLICY_STATE[row.state]) : NONE}</td>
          <td class="activity-cell">${(p.runtime_rule_ids || []).length ? policyMiniBar(row.counts, DECISIONS.filter((x) => row.counts[x] > 0).map((x) => `${DECISION[x][1]} ${row.counts[x]}`).join(" · "), peak) : NONE}</td>
          <td>${rules.length ? html`${chip("outline", rules[0].name)}${rules.length > 1 ? html`<span class="muted">외 ${rules.length - 1}</span>` : ""}` : NONE}</td></tr>`; })}</tbody>`;
  });
  const controls = html`<div class="policy-filters">
    ${filterOption("stage", Object.fromEntries(POLICY_STAGES.map((s) => [s, s])), f.stage)}${filterOption("mode", POLICY_MODE, f.mode)}${filterOption("state", POLICY_STATE, f.state)}
    <label class="check"><input type="checkbox" data-policy-filter="has" ${f.has ? raw("checked") : ""} /> 판정이 있는 정책만</label>
    <input type="search" data-policy-filter="text" placeholder="번호·제목 검색" aria-label="번호·제목 검색" maxlength="120" value="${query.get("q") || ""}" />
    <span class="policy-fold"><button class="btn sm" type="button" data-act="policy-groups" data-open="true">전체 펼치기</button><button class="btn sm" type="button" data-act="policy-groups" data-open="false">전체 접기</button></span></div>`;
  const cards = html`<div class="kpis policy-kpis six">
    ${kpiCard("자동 집행 방식", modeCount("auto"), `켜짐 ${switchedOn} · 꺼짐 ${switchedOff}`, { href: "#/policy?mode=auto", of: total })}
    ${kpiCard("제품 기능 연결", modeCount("feature"), "", { href: "#/policy?mode=feature", of: total })}
    ${kpiCard("수동 점검 방식", modeCount("manual"), "", { href: "#/policy?mode=manual", of: total })}
    ${kpiCard("구조적 차단·범위 밖", modeCount("structural"), "", { href: "#/policy?mode=structural", of: total })}
    ${kpiCard("현재 꺼짐", switchedOff, "", { href: "#/policy?state=off", tone: switchedOff > 0 ? "alert" : "", of: modeCount("auto") })}
    ${kpiCard("규칙 판정", recent, recent == null ? "" : html`<span class="base">직전 ${label} ${before}건</span>`, { href: `#/activity?${new URLSearchParams({ event_kind: "tools/call", since: since.toISOString(), until: until.toISOString() })}` })}
  </div>`;
  const box = (cls, title, id, labelText, sub = "") => html`<div class="${cls}">${panel(title, chartBox(id, labelText, "d220"), { sub })}</div>`;
  const policyTab = html`${cards}
    <div class="dash-grid">${box("c4", "단계별 집행 방식", "c-policy-stage", "단계별 집행 방식 정책 수")}${box("c4", "상위 판정 정책", "c-policy-top", "차단·경보 상위 정책")}${box("c4", "판정 추이", "c-policy-trend", "판정 건수 추이")}</div>
    ${panel("정책", total ? html`<table class="data policy-table" id="organization-policy-list"><thead><tr><th>번호</th><th>제목</th><th>우선순위</th><th>집행 방식</th><th>현재 상태</th>
      <th title="연결된 운영 규칙이 낸 판정 건수입니다. 규칙을 함께 쓰는 정책은 같은 호출을 중복해서 셉니다.">규칙 판정 ${label}</th><th>연결 규칙</th></tr></thead>${table}</table>
      <p class="empty" role="status" data-list-empty="organization-policy-list" hidden>조건에 맞는 결과 없음</p>`
      : empty(ledger.organization?.source_state === "available" ? "등록된 조직 정책 없음" : "조직 정책 원본 조회 실패"), { flush: true, tools: controls })}`;
  return {
    html: page({
      head: head("보안 관리 정책", { status: html`${modeChip(enforcement)}${engineChip(ledger.deployment)}<span class="muted">${when(ledger.checked_at)}</span>`,
        actions: html`<div class="seg" role="group" aria-label="기간">${Object.entries(POLICY_RANGES).map(([k, [text]]) => html`<button class="seg-btn" type="button" data-act="policy-range" data-range="${k}" aria-pressed="${String(k === key)}">${text}</button>`)}</div>
          <button class="btn" data-act="enforcement" data-mode="${enforcement === "enforce" ? "monitor" : "enforce"}">${enforcement === "enforce" ? "관찰 모드로 전환" : "집행 모드로 전환"}</button>` }),
      active: tab === "ledger" ? "ledger" : "organization",
      tabs: [{ key: "organization", label: "정책", n: total, body: policyTab },
        { key: "ledger", label: "운영 규칙", n: policyLedger.length, body: panel("운영 규칙", html`<table class="data"><thead><tr><th>규칙</th><th>집행 주체</th><th>등록 상태</th><th>정의된 결과</th><th>최근 24시간 판정</th><th>관련 보안 정책</th></tr></thead><tbody>
          ${policyLedger.map((p) => html`<tr class="clickable" tabindex="0" data-act="policy" data-id="${p.policy_id}">
            <td><b>${p.name}</b><span class="sub mono">${p.policy_id}</span></td><td>${policyExecutor(p)}</td><td>${["운영", "중지", "폐기"].includes(p.status) ? p.status : "—"}</td>
            <td>${UNSUPPORTED_POLICY.has(p.policy_id) ? chip("outline", "지원 안 함") : outcomeDecision(p.outcome) ? decisionChip(outcomeDecision(p.outcome)) : "—"}</td>
            <td>${chip(policyRecorded(p) ? "plain" : "outline", policyRecordLabel(p))}</td><td>${policyLinks(p).join(", ") || "매핑 미확인"}</td></tr>`)}
          </tbody></table>${policyLedger.length ? "" : empty(ledger.source_state === "loaded" ? "등록된 정책 없음" : "정책 원본 조회 실패")}`, { flush: true }) }],
    }),
    charts: policyCharts(organizationPolicies, activity, analysis, range, policyLedger),
    after: () => { if (query.get("mode") || query.get("stage")) $("#organization-policy-list")?.scrollIntoView?.({ block: "nearest" }); },
  };
};

const field = {
  text: (name, label, attrs = "", value = null) => html`<label>${label}<input name="${name}" ${raw(attrs)} ${value === null ? "" : html`value="${value}"`} /></label>`,
  area: (name, label, attrs = "") => html`<label>${label}<textarea name="${name}" ${raw(attrs)}></textarea></label>`,
  select: (name, label, options, cur = "") => html`<label>${label}<select name="${name}">${Object.entries(options).map(([v, l]) =>
    html`<option value="${v}" ${v === cur ? raw("selected") : ""}>${Array.isArray(l) ? l[1] : l}</option>`)}</select></label>`,
};

function scopeFields(names, dataClass = "public") {
  return html`<fieldset><legend>도구 범위</legend>
    ${field.text("scope_purpose", "목적", 'required minlength="4" maxlength="200"')}
    ${field.text("scope_asset", "자산", 'required minlength="2" maxlength="200"')}
    ${field.text("scope_destinations", "외부 목적지 (쉼표 구분)", 'maxlength="300"')}
    <div class="grid c2">${field.select("scope_grade", "외부 전송 등급", { public: DATA_CLASS.public, nonimportant: DATA_CLASS.nonimportant }, dataClass === "nonimportant" ? "nonimportant" : "public")}
      ${field.text("scope_accepts", "중요정보를 받을 서버 (쉼표 구분)", 'maxlength="300"')}</div>
    <label class="check"><input type="checkbox" name="scope_mask" /> 입력 민감정보 가림</label>
    <label class="check"><input type="checkbox" name="scope_consent" /> 사용자 동의</label>
    ${field.select("scope_impact", "중대 영향", { none: "해당 없음", ...IMPACT_DOMAIN }, "none")}
    <details><summary>도구별 조정</summary>${names.map((name) => html`<div class="grid c2">
      ${field.text(`purpose:${name}`, html`<code>${name}</code> 목적`, 'maxlength="200"')}
      ${field.text(`asset:${name}`, "자산", 'maxlength="200"')}
      ${field.text(`destinations:${name}`, "외부 목적지", 'maxlength="300"')}
      ${field.text(`inputs:${name}`, "허용 입력 항목 (쉼표 구분)", 'maxlength="500"')}
      ${field.select(`impact:${name}`, "중대 영향", { "": "공통 설정", none: "해당 없음", ...IMPACT_DOMAIN })}</div>`)}</details></fieldset>`;
}
const hostList = (text) => String(text || "").split(",").map((h) => h.trim().toLowerCase()).filter(Boolean);
function collectScopes(fd, names) {
  const own = (key, name) => String(fd.get(`${key}:${name}`) || "").trim();
  const impact = (name) => own("impact", name) || String(fd.get("scope_impact") || "none");
  return Object.fromEntries(names.map((name) => [name, {
    purpose: own("purpose", name) || String(fd.get("scope_purpose")).trim(),
    asset: own("asset", name) || String(fd.get("scope_asset")).trim(),
    destinations: hostList(own("destinations", name) || fd.get("scope_destinations")),
    inputs: own("inputs", name) ? own("inputs", name).split(",").map((v) => v.trim()).filter(Boolean) : null,
    mask: fd.get("scope_mask") === "on", consent: fd.get("scope_consent") === "on",
    grade: String(fd.get("scope_grade") || "public"),
    high_impact: impact(name) !== "none", impact_domains: impact(name) === "none" ? [] : [impact(name)],
    accepts_from: String(fd.get("scope_accepts") || "").split(",").map((v) => v.trim()).filter(Boolean) }]));
}

const ACTIONS = {
  async "sbom-impact-stop"(el) {
    const fd = await ask({ title: "영향 서버 중지", fields: field.text("reason", "사유", 'required minlength="4" maxlength="500"'),
      confirm: "중지", danger: true });
    if (!fd) return;
    const result = await api("/api/supply-chain/impact/stop", { method: "POST", body: {
      package: el.dataset.package, version_range: el.dataset.range, reason: fd.get("reason").trim(),
    } });
    toast(`중지 ${result.counts.succeeded}건 · 건너뜀 ${result.counts.skipped}건 · 실패 ${result.counts.failed}건`, result.counts.failed > 0);
    reload();
  },
  async consent(el) {
    await api(`/api/consents/${el.dataset.id}`, { method: "POST", body: { decision: el.dataset.decision } });
    toast({ grant: "동의했습니다.", deny: "거부했습니다.", revoke: "철회했습니다." }[el.dataset.decision]);
    reload(); refreshBadges();
  },
  async "consent-server"(el) {
    const ids = el.dataset.consents.split(",").map(Number);
    const rows = consentRows.filter((c) => c.server_id === el.dataset.id && ids.includes(c.id));
    if (!rows.length || rows.length !== ids.length) return;
    if (!await ask({ title: el.dataset.decision === "grant" ? "모두 허용" : "모두 거부",
      fields: kv([["서버", el.dataset.id], ["도구 수", rows.length],
        ["목적지", [...new Set(rows.flatMap((c) => c.terms?.destinations || []))].join(", ") || "—"],
        ["데이터 등급", [...new Set(rows.map((c) => DATA_CLASS[c.grade] || "—"))].join(", ")]]),
      confirm: "확인", danger: el.dataset.decision !== "grant" })) return;
    await api(`/api/consents/server/${encodeURIComponent(el.dataset.id)}`, { method: "POST", body: {
      decision: el.dataset.decision, consent_ids: el.dataset.consents.split(",").map(Number),
    } });
    toast(el.dataset.decision === "grant" ? "허용했습니다." : "거부했습니다.");
    reload(); refreshBadges();
  },
  async "alert-detail"(el) {
    const seq = routeSeq, detail = ++detailSeq;
    const a = loadedAlerts.find((r) => String(r.id) === String(el.dataset.id))
      || (await gw(`audit/alerts?alert_id=${encodeURIComponent(el.dataset.id)}`)).alerts[0];
    if (!a) return;
    const [target, href] = alertTarget(a);
    if (seq !== routeSeq || detail !== detailSeq) return;
    rememberDetail(a.id, "alert-detail");
    openDrawer("경보", kv([["사유", alertDetail(a) || ALERT_KIND[a.kind] || "—"],
      ["실행", a.execution || "미확인"], ["조치", href || alertCallsHref(a) ? html`${href ? html`<a class="btn sm" href="${href}">${a.kind === "unapproved-endpoint-mcp" || (a.evidence?.policy_id || "").startsWith("MCP-SHADOW-") ? "미등록 MCP 보기" : "대상 보기"}</a>` : ""}${alertCallsHref(a) ? html`<a class="btn sm" href="${alertCallsHref(a)}">관련 호출</a>` : ""}` : "—"],
      ["종류", ALERT_KIND[a.kind] || "—"], ["대상", target], ["엔드포인트 식별자", a.evidence?.endpoint_id || "—"], ["시각", when(a.created_at)]]));
  },
  async "audit-event"(el) {
    const seq = routeSeq, detail = ++detailSeq;
    const event = await gw(`audit/events/${el.dataset.id}`);
    if (seq !== routeSeq || detail !== detailSeq) return;
    rememberDetail(event.id, "audit-event");
    openDrawer(`감사 이벤트 #${event.id}`, html`${decisionAction(event)}<div class="row-actions">${decisionChip(event.decision)}${event.invalid ? chip("outline", "무효 처리") : ""}<code>${event.policy_id}</code></div>`,
      [{key:"record", label:"기록", body:html`${outcomeChips(event.outcome_axes)}${kv([
        ["시각", when(event.created_at)], ["사용자", event.user_token], ["서버", event.server_id], ["도구", event.tool_name],
        ["호출 유형", EVENT_KIND[event.event_kind] || "—"], ["추적 ID", event.trace_id],
        ["행위", ACTION[event.action] || "—"], ["데이터 등급", DATA_CLASS[event.data_class] || "—"],
        ["승인 요청", event.approval_id], ["응답 해시", event.response_sha256], ["감사 해시", event.entry_sha256],
        ["무효 처리", event.invalid ? `${event.invalid.reason} · ${event.invalid.by} · ${when(event.invalid.at)}` : "—"]])}`}]);
  },
  async "incident-evidence"(el) {
    const seq = routeSeq, detail = ++detailSeq;
    const result = await gw(`audit/incidents/${el.dataset.id}`);
    const pack = result.evidence_package;
    if (seq !== routeSeq || detail !== detailSeq) return;
    rememberDetail(el.dataset.id, "incident-evidence");
    openDrawer("사고 증빙", html`<code>${result.incident.id}</code>`, [{key:"evidence", label:"증빙", body:kv([
      ["영향 호출", `${pack.included_count} / ${pack.query_count}`], ["건수 일치", pack.count_matches ? "정상" : "불일치"],
      ["전체 호출", pack.total_count], ["무효 호출", pack.invalid_count], ["유효 호출", pack.valid_count],
      ["해시 사슬", pack.chain_verification?.intact ? "정상" : "무결성 미확인"], ["패키지 해시", pack.package_sha256],
      ["패키지 검증", result.package_hash_valid ? "정상" : "실패"]])}]);
  },
  async "audit-export"() {
    await exportCallEvidence();
  },
  async "audit-export-next"() {
    await exportCallEvidence(true);
  },
  async "identity-bind"() {
    const fd = await ask({title:"SSO 계정 연결", fields:html`${field.text("principal", "사용자 ID", "required maxlength=150")}${field.text("subject", "SSO 사용자 ID (sub)", "required maxlength=255")}`, confirm:"연결"});
    if (!fd) return;
    const r = await api("/api/identity/bindings", {method:"POST", body:{principal:fd.get("principal").trim(), subject:fd.get("subject").trim()}});
    toast(r.message); reload();
  },
  async "identity-unbind"(el) {
    if (!await ask({title:"SSO 연결 해제", body:"로그인 세션도 함께 종료됩니다.", confirm:"해제", danger:true})) return;
    const r = await api(`/api/identity/bindings/${el.dataset.id}`, {method:"DELETE"});
    toast(r.message); reload();
  },
  async "account-invite"() {
    const result = await ask({ title: "사용자 초대", confirm: "초대 링크 만들기", fields: html`
      ${field.area("usernames", "아이디 (쉼표·줄바꿈 구분)", "required maxlength=1700")}
      ${field.text("department", "부서", "required minlength=2 maxlength=80")}` });
    if (!result) return;
    const usernames = String(result.get("usernames")).split(/[,\s]+/).filter(Boolean);
    const issued = await api("/api/account-invitations", { method: "POST", body: { usernames, department: result.get("department") } });
    openDrawer("초대 링크", html`${issued.invitations.map((item) => html`<section class="panel"><div class="body"><b>${item.username}</b><p><a href="${item.url}" target="_blank" rel="noopener noreferrer">${item.url}</a></p><span class="small muted">${when(item.expires_at)}까지 · 1회용</span></div></section>`)}`);
  },
  sidebar() {
    const closed = !document.documentElement.classList.contains("nav-collapsed");
    setNavCollapsed(closed);
    if (!matchMedia("(max-width: 900px)").matches) localStorage.setItem(NAV_KEY, String(closed));
    charts.redrawAll();
  },
  theme() {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    localStorage.setItem(THEME_KEY, next);
    charts.redrawAll();
  },
  async logout() {
    await api("/auth/logout", { method: "POST" }).catch(() => {});
    localStorage.removeItem(TOKEN_KEY);
    location.replace("/login");
  },
  "close-drawer": closeDrawer,
  async tab(el) {
    const key = el.dataset.tab;
    const bar = el.closest(".tabs");
    const scope = bar.parentElement;
    for (const b of bar.querySelectorAll(".tab")) {
      const on = b.dataset.tab === key;
      b.setAttribute("aria-selected", String(on));
      b.tabIndex = on ? 0 : -1;
    }
    for (const p of scope.querySelectorAll(":scope > .tabpanel")) p.hidden = p.dataset.panel !== key;
    if (!el.closest(".drawer")) {
      rememberTab(key);
    } else {
      const q = new URLSearchParams(current.query); q.set("dt", key);
      current.query = q; history.replaceState(history.state, "", routeHash(q));
    }
    charts.mountVisible(scope);
    if (key === "new" && ["intake", "my"].includes(current.page)) {
      scope.querySelector('[data-form="intake"] [name="display_name"]')?.focus();
      const input = scope.querySelector("[data-catalog-search]");
      const query = input.value.trim();
      const data = await api(`/api/mcp-catalog/search?q=${encodeURIComponent(query)}`).catch(() => null);
      if (!data) { if (input.isConnected && input.value.trim() === query) $("#catalog-results").innerHTML = String(empty("", { failed: true })); return; }
      if (input.isConnected && input.value.trim() === data.query)
        $("#catalog-results").innerHTML = String(catalogResults(data));
    }
  },
  decision: (el) => showDecision(el.dataset.id),
  "endpoint-device": (el) => showEndpoint(el.dataset.id),
  relationship: (el) => showRelationship(el.dataset.id),
  approval: (el) => showApproval(el.dataset.id),
  "approval-refresh": () => reload(),
  "performance-refresh": () => reload(),
  skip: () => $("#view").focus(),
  live(el) {
    feed.live = !feed.live;
    el.innerHTML = String(icon(feed.live ? "pause" : "play"));
    el.setAttribute("aria-label", feed.live ? "일시정지" : "실시간 재개");
    el.title = feed.live ? "일시정지" : "실시간 재개";
    el.setAttribute("aria-pressed", String(!feed.live));
    if (feed.live && feed.pending.length) {
      feed.highlight = feed.pending.map((row) => row.id);
      feed.pending = [];
      feed.page = 1;
      feed.analysisAt = 0;
      reload();
    } else renderFeedStatus();
  },
  async "analysis-refresh"() {
    const seq = routeSeq, key = feedQuery({}).toString();
    const extra = feed.query ? { q: feed.query } : {};
    const analysis = await gw(`activity/analysis?${feedQuery(extra)}`);
    if (seq !== routeSeq || key !== feedQuery({}).toString()) return;
    feed.analysis = analysis;
    feed.analysisKey = feedQuery({}).toString();
    feed.analysisAt = Date.now();
    $("#analysis-total").textContent = `전체 ${analysis.total ?? 0}건`;
    $("#analysis-updated-time").textContent = koClock();
    for (const [id, build] of Object.entries(feedCharts(analysis))) {
      if ($(`#${id}`)) charts.redraw(id, build);
    }
    renderAnalysisDetails();
  },
  "feed-page"(el) {
    feed.page = Math.max(1, Number(el.dataset.page) || 1);
    rememberFeed();
    if (feed.page === 1 && feed.pending.length) {
      feed.highlight = feed.pending.map((row) => row.id);
      feed.pending = [];
    }
    reload();
  },
  "feed-reset"() {
    feed.filters = defaultFeedFilters();
    feed.query = "";
    feed.page = 1;
    rememberFeed();
    reload();
  },
  "feed-custom"(el) {
    const bar = el.closest(".filters"), custom = bar?.querySelector(".feed-custom");
    if (custom) custom.hidden = !custom.hidden;
  },
  "feed-window"(el) {
    feed.filters.since = Number(el.dataset.hours) === 24 ? defaultFeedFilters().since : Number(el.dataset.hours) > 0 ? new Date(Date.now() - Number(el.dataset.hours) * 3600000).toISOString() : "";
    feed.filters.until = "";
    feed.page = 1;
    rememberFeed();
    reload();
  },
  goto(el) { location.hash = el.dataset.href; },
  "cov-page"(el) {
    const state = covPaging[el.dataset.list];
    if (Number(el.dataset.dir) > 0) {
      if (!state.next) return;
      state.cursors[state.index + 1] = state.next;
      state.index += 1;
    } else if (state.index) state.index -= 1;
    const q = new URLSearchParams(current.query), key = el.dataset.list;
    q.delete(`${key}_cursor`);
    for (const cursor of state.cursors) q.append(`${key}_cursor`, cursor || "");
    q.set(`${key}_page`, state.index);
    current.query = q; history.replaceState(history.state, "", routeHash(q));
    reload();
  },
  async "endpoint-record"(el) {
    const seq = routeSeq, detail = ++detailSeq;
    const [record, related] = await Promise.all([gw(`endpoint/records/${el.dataset.kind}/${el.dataset.id}`),
      gw(`endpoint/correlation?kind=${el.dataset.kind}&record_id=${el.dataset.id}`).catch(() => null)]);
    if (seq !== routeSeq || detail !== detailSeq) return;
    rememberDetail(record.id, record.record_kind);
    const view = provenanceView(record.provenance);
    const details = record.details || {};
    openDrawer(`${RECORD_KIND[record.record_kind]} #${record.id}`, html`<div class="drawer-summary">${record.record_kind === "os-event" ? chip(...denialClass(record.denial_class)) : ""}
      ${chip("outline", originLabel(record.origin))}<span class="muted small">${when(record.at, { seconds: true })}</span></div>`, [
      { key: "record", label: "기록", body: kv(record.record_kind === "os-event" ? [
        ["엔드포인트", record.endpoint_id], ["호스트", record.hostname], ["종류", record.kind === "network-denied" ? "네트워크 차단" : "실행 차단"],
        ["대상", osEventTarget(record)], ["실행 시도 프로세스", details.parent_executable], ["프로파일", details.profile],
        ["작업", details.operation], ["발생", when(record.observed_at, { seconds: true })], ["수신", when(record.received_at, { seconds: true })]]
        : record.record_kind === "listener" ? [
        ["엔드포인트", record.endpoint_id], ["호스트", record.hostname], ["주소", `${record.address}${record.port ? `:${record.port}` : ""}`],
        ["프로세스", record.process_name], ["서버", record.server_name], ["MCP 여부", MCP_EVIDENCE_LABEL[record.mcp_evidence]],
        ["분류", (ENDPOINT_CLASS[record.classification] || [, ""])[1]], ["관측", when(record.observed_at, { seconds: true })]]
        : [["엔드포인트", record.endpoint_id], ["호스트", record.hostname], ["설정 파일", record.config_path], ["서버", record.server_label],
        ["연결", `${TRANSPORT[record.transport] || "—"} ${short(record.endpoint_ref, 80)}`], ["분류", (ENDPOINT_CLASS[record.classification] || [, ""])[1]],
        ["보고", when(record.reported_at, { seconds: true })]]) },
      { key: "source", label: "출처", body: kv([
        ["출처", originLabel(record.origin)], ["수집기", COLLECTOR[record.provenance?.collector] || record.provenance?.collector],
        ["수신", when(record.provenance?.received_at, { seconds: true })], ["원본 해시", view.raw === "—" ? "" : html`<code>${view.raw}</code>`],
        ["보고 해시", view.agent === "—" ? "" : html`<code>${view.agent}</code>`], ["저장 해시", view.server === "—" ? "" : html`<code>${view.server}</code>`],
        ["대조", view.state === "unreported" ? "" : chip(view.tone, view.label)],
        ["변환", view.steps.length ? html`<div class="pill-list">${view.steps.map((s) => chip("outline", transformLabel(s)))}</div>` : ""]]) },
      { key: "related", label: "연관 기록", n: related ? related.records.length : undefined, body: relatedBody(related) },
    ]);
  },
  "coverage-filter"(el) {
    const q = new URLSearchParams(current.query);
    if (el.dataset.value) q.set(el.dataset.key, el.dataset.value); else q.delete(el.dataset.key);
    q.set("t", "items");
    location.hash = `#/connections?${q}`;
  },
  async integration(el) {
    const i = integrationItems.find((x) => x.key === el.dataset.key);
    if (!i) return;
    const v = i.vendor_control;
    const connector = connectorGroups.find((g) => g.key === i.item_key);
    const gatewayId = i.key.startsWith("gateway:") ? i.key.slice(8) : "";
    const rel = gatewayId ? (await gw("termination/relationships").catch(() => ({ relationships: [] })))
      .relationships?.find((r) => r.server_id === gatewayId) : null;
    const plane = (name, applies, body) => html`<tr><th>${name}</th><td>${applies ? body : NONE}</td></tr>`;
    rememberDetail(el.dataset.key, "integration");
    openDrawer(i.name, html`<div class="row-actions">${statusPair(i)}${chip("outline", INTEGRATION_CLASS[i.class] || i.class)}
      ${connector ? html`<a class="btn sm primary" href="#/connections?${new URLSearchParams({ t: "vendor", connector: connector.key })}">승인 관리</a>` : ""}
      ${i.class === "vendor_native_connector" ? html`<button class="btn sm" type="button" data-act="vendor-control" data-key="${i.item_key}" data-name="${i.name}">벤더 콘솔 확인 기록</button>` : ""}</div>`, [
      { key: "planes", label: "통제", body: html`<table class="data"><tbody>
        ${plane("게이트웨이", i.managed_by === "gateway", html`${chip(i.state === "bypass_possible" ? "block" : "allow", i.state === "bypass_possible" ? "게이트웨이 경로만 통제" : "게이트웨이 통제")}<span class="sub">${i.evidence}</span>`)}
        ${plane("엔드포인트", i.managed_by === "endpoint" || i.evidence_kind === "kernel", html`${controlChip(i.state)}<span class="sub">${i.evidence}</span>`)}
        ${plane("벤더", i.class === "vendor_native_connector" || (i.residual || []).length > 0, v
          ? html`${chip("restrict", VENDOR_CONSOLE[v.console_state] || v.console_state)}<span class="sub">수동 확인 · ${v.verified_by} · ${when(v.verified_at)}${(v.oauth_scopes || []).length ? ` · 범위 ${v.oauth_scopes.join(", ")}` : ""}${v.role_access ? ` · 역할 ${v.role_access}` : ""}</span>`
          : html`${chip("outline", "확인 기록 없음")}${(i.residual || []).map((r) => html`<span class="sub">${r}</span>`)}`)}
        </tbody></table>${kv([["우회 경로", (i.bypass || []).length ? html`<div class="pill-list">${i.bypass.map((b) => chip("block", b))}</div>` : "없음"],
          ["사용자·엔드포인트", `${(i.owners || [i.owner]).filter(Boolean).join(", ") || "—"}${i.pcs > 1 ? ` · 엔드포인트 ${i.pcs}대` : i.device ? ` · ${i.device}` : ""}`],
          ["발견", `${discoveredLabel(i.discovered_from)}${i.discovered_at ? ` · ${when(i.discovered_at, { year: true })}` : ""}`],
          ["대상", i.target ? html`<span class="mono">${i.target}</span> <button class="btn sm" type="button" data-act="copy-id" data-value="${i.target}">복사</button>` : ""], ["마지막 확인", i.last_verified_at ? when(i.last_verified_at, { year: true }) : ""]])}` },
      { key: "approval", label: "승인", body: kv([["상태", approvalLabel(i.approval?.state)], ["만료 시각", i.approval?.expires_at ? when(i.approval.expires_at) : ""],
        ["결정자", i.approval?.decided_by], ["검토 기한", i.approval?.review_days ? `${i.approval.review_days}일` : ""]]) },
      ...(gatewayId ? [{ key: "exit", label: "종료 시", body: rel ? kv([
        ["예상 등급", gradeChip(rel.readiness?.best_attainable_grade, "예상 ")],
        ...Object.entries(REVOKE_KEY).map(([k, label]) => [label, rel.readiness?.would_revoke?.[k] ?? 0]),
        ["제약", (rel.readiness?.blockers || []).join(" · ")]]) : empty("이용 관계 없음") }] : []),
    ]);
  },
  async "vendor-control"(el) {
    const fd = await ask({ title: `벤더 콘솔 확인 · ${el.dataset.name}`, confirm: "기록",
      fields: html`${field.select("console_state", "콘솔 상태", VENDOR_CONSOLE, "unknown")}
        ${field.text("allowed_actions", "허용 동작 (쉼표 구분)", 'maxlength="600"')}
        ${field.text("oauth_scopes", "OAuth 범위 (쉼표 구분)", 'maxlength="600"')}
        ${field.text("role_access", "역할 접근", 'maxlength="200"')}
        ${field.text("evidence_url", "근거 주소", 'maxlength="500"')}
        ${field.area("note", "메모", 'maxlength="500"')}` });
    if (!fd) return;
    const list = (k) => fd.get(k).split(",").map((s) => s.trim()).filter(Boolean);
    await api("/api/integrations/vendor-control", { method: "PUT", body: { key: el.dataset.key, console_state: fd.get("console_state"),
      allowed_actions: list("allowed_actions"), oauth_scopes: list("oauth_scopes"), role_access: fd.get("role_access").trim(),
      evidence_url: fd.get("evidence_url").trim(), note: fd.get("note").trim() } });
    toast("기록했습니다."); closeDrawer(); reload();
  },
  async "audit-verify"() {
    const r = await gw("audit/verify");
    lastVerify = { ...r, at: new Date().toISOString() };
    if (r.intact) toast(`무결성 정상 · ${r.checked}건`);
    else toast(`무결성 손상 · #${r.broken_at ?? "마지막"}: ${r.reason}`, true);
    reload();
  },
  async "audit-retention"(el) {
    const fd = await ask({ title: "보존 기간 변경", fields: field.text("days", "보존 일수", `type="number" required min="${el.dataset.floor}" step="1"`, el.dataset.days), confirm: "저장" });
    if (!fd) return;
    await gw("audit/retention", { method: "PUT", body: { days: Number(fd.get("days")), jurisdictions: JSON.parse(el.dataset.jurisdictions || "[]") } });
    toast("보존 기간을 저장했습니다.");
    reload();
  },
  "alerts-ack-all"() {
    markAlertsSeen(loadedAlerts);
    reload();
  },
  async approve(el) {
    const a = approvalRows.find((row) => row.id === el.dataset.id);
    if (!a?.pending || a.own) return;
    let r;
    if (a?.explanation) {
      const b = await gw(`approvals/${a.id}/evidence`);
      const fd = await ask({ title: "중대 영향 호출 승인", fields: html`${impactExplanation(b.explanation)}${APPROVAL_WINDOW_FIELD()}
        <label class="check"><input type="checkbox" name="confirmed" required /> 요청 범위·정책 근거 확인</label>`, confirm: "승인" });
      if (!fd) return;
      r = await gw(`approvals/${a.id}/approve`, { method: "POST", body: { evidence_sha256: b.evidence_sha256, reason: "scope_confirmed",
        window_minutes: Number(fd.get("window_minutes") ?? 30) } });
    } else {
      const fd = await ask({ title: "호출 승인", fields: html`${kv([["도구", `${a.server_id}.${a.tool}`], ["승인 사유", a.reason || "—"]])}${APPROVAL_WINDOW_FIELD()}`,
        confirm: "승인" });
      if (!fd) return;
      r = await api(`/approvals/${el.dataset.id}/approve`, { method: "POST", body: { window_minutes: Number(fd.get("window_minutes") ?? 30) } });
    }
    toast(`승인했습니다 · ${r.window_minutes ? `${r.window_minutes}분 동안` : "1회"} 사용할 수 있습니다`);
    reload(); refreshBadges();
  },
  async "intent-resolve"(el) {
    const executed = el.dataset.outcome === "executed";
    const fd = await ask({ title: executed ? "실행됨으로 기록" : "실행 안 됨으로 기록", fields: field.area("note", "확인 내용", 'maxlength="500"'), confirm: "기록" });
    if (!fd) return;
    await gw(`dispatch-intents/${el.dataset.id}/resolve`, { method: "POST", body: { outcome: el.dataset.outcome, note: fd.get("note") } });
    toast("기록했습니다."); reload();
  },
  async reject(el) {
    const a = approvalRows.find((row) => row.id === el.dataset.id);
    if (!a?.pending) return;
    if (a?.explanation) {
      const b = await gw(`approvals/${a.id}/evidence`);
      if (!await ask({ title: "중대 영향 호출 거부", fields: impactExplanation(b.explanation), confirm: "요청 부적합 · 거부", danger: true })) return;
      await gw(`approvals/${a.id}/reject`, { method: "POST", body: { note: "request_inappropriate", evidence_sha256: b.evidence_sha256 } });
      toast("거부했습니다."); reload(); refreshBadges(); return;
    }
    const fd = await ask({ title: "승인 요청 거부", fields: field.area("note", "사유", 'required maxlength="500"'), confirm: "거부", danger: true });
    if (!fd) return;
    await api(`/approvals/${el.dataset.id}/reject`, { method: "POST", body: { note: fd.get("note") } });
    toast("거부했습니다."); reload(); refreshBadges();
  },
  async "approval-revoke"(el) {
    const b = await gw(`approvals/${el.dataset.id}/evidence`);
    if (!await ask({ title: "승인 번복", fields: impactExplanation(b.explanation), confirm: "승인 판단 변경 · 번복", danger: true })) return;
    await gw(`approvals/${el.dataset.id}/revoke`, { method: "POST", body: { evidence_sha256: b.evidence_sha256 } });
    toast("번복을 기록했습니다."); reload();
  },
  async "approval-close"(el) {
    if (!await ask({ title: "승인 종료", body: "남은 사용 기간을 지금 끝냅니다. 이후 호출은 다시 승인을 받아야 합니다.", confirm: "종료", danger: true })) return;
    await gw(`approvals/${el.dataset.id}/revoke`, { method: "POST" });
    toast("승인을 종료했습니다."); reload();
  },
  async "approval-export"(el) {
    const b = await gw(`approvals/${el.dataset.id}/evidence`);
    const url = URL.createObjectURL(new Blob([JSON.stringify(b, null, 2)], { type: "application/json" }));
    Object.assign(document.createElement("a"), { href: url, download: `mint-decision-${el.dataset.id}.json` }).click();
    URL.revokeObjectURL(url);
  },
  async "catalog-refresh"() {
    const { results } = await gw("catalog/refresh", { method: "POST" });
    const drift = Object.values(results || {}).filter((status) => status !== "READY").length;
    toast(drift ? `계약 변경 서버 ${drift}개` : "모든 서버 계약 일치", Boolean(drift));
    reload();
  },
  async "server-check"(el) {
    const r = await gw(`registry/${encodeURIComponent(el.dataset.id)}/check`, { method: "POST" });
    if (r.state === "healthy") toast(`연결 정상 · ${r.advertised_name || r.server_id} ${r.version} · ${Math.round(r.latency_ms)}ms`);
    else if (r.state === "retired") toast("폐기된 서버는 확인하지 않습니다.");
    else toast(`연결 실패 · ${r.error}`, true);
  },
  async "approve-contract"(el) {
    const fd = await ask({ title: "계약 변경 승인", fields: field.area("note", "검토 내용", 'required minlength="5" maxlength="500"'), confirm: "승인본 갱신" });
    if (!fd) return;
    await gw(`registry/${el.dataset.id}/approve-contract`, { method: "POST", body: { note: fd.get("note") } });
    toast("승인본을 갱신했습니다."); reload();
  },
  async "account-status"(el) {
    const fd = await ask({ title: `${el.dataset.name} 계정 상태`,
      fields: html`<fieldset><legend>상태</legend>${Object.entries({ active: "사용", disabled: "중지", locked: "잠김" }).map(([value, label]) =>
        html`<label class="check"><input type="radio" name="status" value="${value}" ${value === el.dataset.status ? raw("checked") : ""} required />${label}</label>`)}</fieldset>
        ${field.text("note", "메모", 'maxlength="300"')}` });
    if (!fd) return;
    const r = await api(`/api/accounts/${el.dataset.id}/status`, { method: "PUT", body: { status: fd.get("status"), note: fd.get("note") || "" } });
    await reload();
    toast(r.message);
  },
  async "account-rename"(el) {
    const fd = await ask({ title: `${el.dataset.name} 아이디 변경`,
      fields: field.text("user_id", "새 아이디", 'required minlength="3" maxlength="32" pattern="[a-z][a-z0-9]*(?:[._\\-][a-z0-9]+)*" autocomplete="off"', el.dataset.id),
      confirm: "변경" });
    if (!fd) return;
    const r = await api(`/api/accounts/${encodeURIComponent(el.dataset.id)}/name`, { method: "PUT", body: { user_id: fd.get("user_id").trim().toLowerCase() } });
    await reload();
    toast(r.message);
  },
  async "account-password"(el) {
    const min = el.dataset.role === "admin" ? 12 : 8;
    const fd = await ask({ title: `${el.dataset.name} 비밀번호 재설정`,
      fields: html`${field.text("new_password", "새 비밀번호", `type="password" required minlength="${min}" maxlength="150" autocomplete="new-password"`)}
        ${field.text("confirm_password", "새 비밀번호 확인", `type="password" required minlength="${min}" maxlength="150" autocomplete="new-password"`)}`,
      confirm: "변경" });
    if (!fd) return;
    if (fd.get("new_password") !== fd.get("confirm_password")) { toast("새 비밀번호가 서로 다릅니다.", true); return; }
    const r = await api(`/api/accounts/${encodeURIComponent(el.dataset.id)}/password`, { method: "PUT", body: { new_password: fd.get("new_password") } });
    toast(r.message);
  },
  async password() {
    const min = viewer.admin ? 12 : 8;
    const fd = await ask({ title: "비밀번호 변경",
      fields: html`${field.text("current_password", "현재 비밀번호", 'type="password" required maxlength="150" autocomplete="current-password"')}
        ${field.text("new_password", "새 비밀번호", `type="password" required minlength="${min}" maxlength="150" autocomplete="new-password"`)}
        ${field.text("confirm_password", "새 비밀번호 확인", `type="password" required minlength="${min}" maxlength="150" autocomplete="new-password"`)}`,
      confirm: "변경" });
    if (!fd) return;
    if (fd.get("new_password") !== fd.get("confirm_password")) { toast("새 비밀번호가 서로 다릅니다.", true); return; }
    const r = await api("/auth/password", { method: "POST", body: { current_password: fd.get("current_password"), new_password: fd.get("new_password") } });
    toast(r.message);
  },
  async "suspend-open"(el) {
    const { servers } = await gw("registry");
    const fd = await ask({ title: `${el.dataset.name} · MCP 이용 중지`,
      fields: html`${field.select("server_id", "서버", Object.fromEntries(servers.map((s) => [s.id, s.display_name || s.id])))}
        ${field.text("reason", "사유", 'required minlength="4" maxlength="500"', "관리자 수동 중지")}`,
      confirm: "이용 중지", danger: true });
    if (!fd) return;
    await gw("suspensions", { method: "POST", body: { user_token: el.dataset.token, server_id: fd.get("server_id"), reason: fd.get("reason").trim() } });
    toast("이용을 중지했습니다."); reload();
  },
  async "suspend-resume"(el) {
    const fd = await ask({ title: `${el.dataset.name} · ${el.dataset.server} 이용 재개`,
      fields: field.text("note", "메모", 'required minlength="4" maxlength="500"', "중지 해소"), confirm: "재개" });
    if (!fd) return;
    await gw(`suspensions/${encodeURIComponent(el.dataset.id)}/resume`, { method: "POST", body: { note: fd.get("note").trim() } });
    toast("이용을 재개했습니다."); reload();
  },
  async "suspend-all"(el) {
    const fd = await ask({ title: `${el.dataset.name} · 전체 MCP 이용 중지`,
      fields: field.text("reason", "사유", 'required minlength="4" maxlength="500"', "관리자 수동 중지"),
      confirm: "전체 중지", danger: true });
    if (!fd) return;
    const r = await gw("user-suspensions/stop-all", { method: "POST", body: { user_token: el.dataset.token, reason: fd.get("reason").trim() } });
    toast(`중지 ${r.suspended.length}건 · 건너뜀 ${r.skipped.length}건 · 실패 ${r.failed.length}건`, r.failed.length > 0);
    reload();
  },
  async "resume-all"(el) {
    const fd = await ask({ title: `${el.dataset.name} · 전체 MCP 이용 재개`,
      fields: field.text("note", "메모", 'required minlength="4" maxlength="500"', "중지 해소"), confirm: "전체 재개" });
    if (!fd) return;
    const r = await gw("user-suspensions/resume-all", { method: "POST", body: { user_token: el.dataset.token, note: fd.get("note").trim() } });
    toast(`재개 ${r.resumed.length}건 · 건너뜀 ${r.skipped.length}건 · 실패 ${r.failed.length}건`, r.failed.length > 0);
    reload();
  },
  async "account-delete"(el) {
    const fd = await ask({ title: `${el.dataset.name} 계정 삭제`,
      body: "로그인과 사내 저장소 접근이 즉시 차단됩니다.", confirm: "계정 삭제", danger: true });
    if (!fd) return;
    const r = await api(`/api/accounts/${encodeURIComponent(el.dataset.id)}`, { method: "DELETE" });
    await reload();
    toast(r.message);
  },
  async "account-restore"(el) {
    const fd = await ask({ title: `${el.dataset.name} 계정 복구`,
      body: "이전 엔드포인트와 동의는 복구되지 않습니다.", confirm: "계정 복구" });
    if (!fd) return;
    const r = await api(`/api/accounts/${encodeURIComponent(el.dataset.id)}/restore`, { method: "POST" });
    await reload();
    toast(r.message);
  },
  async "signup-approve"(el) {
    const r = await api(`/api/signup-requests/${el.dataset.id}/approve`, { method: "POST" });
    toast(r.message); reload();
  },
  async "signup-reject"(el) {
    await api(`/api/signup-requests/${el.dataset.id}/reject`, { method: "POST" });
    toast("가입 신청을 거부했습니다."); reload();
  },
  "pc-kit"() {
    const kit = viewer.kit;
    const preferred = preferredKitPlatform();
    const os = (kit.platforms || []).includes(preferred) ? preferred : (kit.platforms || [])[0];
    openDrawer("내 PC 연결", html`<div data-kit>${kitView(kit, os)}</div>`);
  },
  "pc-kit-os"(el) {
    el.closest("[data-kit]").innerHTML = String(kitView(viewer.kit, el.dataset.os));
  },
  async "pc-kit-download"(el) {
    const label = el.textContent;
    el.disabled = true;
    el.textContent = "준비 중…";
    try {
      const os = el.dataset.os || "linux";
      const isolated = el.closest("[data-kit]")?.querySelector('[name="kit-isolated"]')?.checked ? "&isolated=true" : "";
      const query = (os === "macos" ? "&delivery=command" : "&packaging=oneclick") + isolated;
      const action = `/api/pc-kit?platform=${encodeURIComponent(os)}${query}`;
      const response = await fetch(`${action}&issue_ticket=true`,
        { method: "POST", headers: { authorization: `Bearer ${token}` } })
        .catch(() => { throw new Error("설치 파일을 받지 못했습니다."); });
      if (!response.ok) {
        const r = await response.json().catch(() => ({}));
        throw new Error(detailText(r.detail) || "설치 파일을 받지 못했습니다.");
      }
      const result = await response.json().catch(() => ({}));
      if (!/^[A-Za-z0-9_-]{43}$/.test(result.ticket || "")) throw new Error("설치 파일을 받지 못했습니다.");
      let frame = document.getElementById("pc-kit-download-frame");
      if (!frame) {
        frame = document.createElement("iframe");
        frame.id = frame.name = "pc-kit-download-frame";
        frame.hidden = true;
        document.body.append(frame);
      }
      const form = document.createElement("form");
      form.method = "POST"; form.action = action; form.target = frame.name;
      form.enctype = "application/x-www-form-urlencoded"; form.hidden = true;
      const input = document.createElement("input");
      input.type = "hidden"; input.name = "ticket"; input.value = result.ticket;
      form.append(input); document.body.append(form);
      try { form.submit(); } finally { form.remove(); }
      toast("다운로드를 시작했습니다. 브라우저 다운로드 목록을 확인하세요.");
    } finally {
      el.textContent = label;
      el.disabled = false;
    }
  },
  async "device-activate"(el) {
    const fd = await ask({ title: `엔드포인트 활성화 · ${el.dataset.id}`,
      fields: field.area("note", "확인 내용", 'required minlength="20" maxlength="1000"'), confirm: "활성화" });
    if (!fd) return;
    await gw(`endpoint/devices/${encodeURIComponent(el.dataset.id)}/activate`, { method: "POST", body: { policy_hash: el.dataset.hash, note: fd.get("note") } });
    toast("엔드포인트를 활성화했습니다."); reload();
  },
  async "device-issue"() {
    const owners = Object.fromEntries([["", "지정 안 함"], ...peopleAccounts.filter((a) => a.status === "active")
      .map((a) => [a.token, `${a.display_name} · ${a.department || ROLE[a.role] || a.role}`])]);
    const fd = await ask({ title: "엔드포인트 등록",
      fields: html`${field.text("endpoint_id", "엔드포인트 ID", 'required minlength="3" maxlength="120" pattern="[A-Za-z0-9._\\-]+" placeholder="laptop-001"')}
        ${field.text("hostname", "호스트명", 'required maxlength="200"')}
        ${field.select("platform", "플랫폼", { windows: "Windows", linux: "Linux", macos: "macOS", unknown: "기타" }, "linux")}
        ${field.select("owner_token", "사용자", owners)}
        <fieldset><legend>수집 항목</legend>
          <label class="check"><input type="checkbox" name="scopes" value="inventory" checked /> MCP 설정</label>
          <label class="check"><input type="checkbox" name="scopes" value="enforcement" /> 엔드포인트 차단 기록</label>
          <label class="check"><input type="checkbox" name="scopes" value="netscan" /> 내부망 MCP 탐색</label></fieldset>`,
      confirm: "등록" });
    if (!fd) return;
    const scopes = fd.getAll("scopes");
    if (!scopes.length) { toast("수집 항목을 하나 이상 선택하세요.", true); return; }
    const r = await gw("endpoint/devices", { method: "POST", body: {
      endpoint_id: fd.get("endpoint_id").trim(), hostname: fd.get("hostname").trim(), platform: fd.get("platform"),
      owner_token: fd.get("owner_token") || null, scopes } });
    await reload();
    lastDocument = r.enrollment_key;
    openDrawer("엔드포인트 등록 키", html`<p class="note warn">이 키는 다시 표시되지 않습니다.</p>
      ${kv([["엔드포인트", html`<code>${r.endpoint_id}</code>`], ["수집 항목", r.scopes.map((s) => ({ inventory: "MCP 설정", enforcement: "엔드포인트 차단 기록", netscan: "내부망 MCP 탐색" })[s] || s).join(", ")], ["등록 키", html`<code>${r.enrollment_key}</code>`]])}
      <div class="row-actions"><button class="btn sm primary" type="button" data-act="copy-doc">키 복사</button></div>`);
  },
  async "device-revoke"(el) {
    const fd = await ask({ title: `엔드포인트 등록 해제 · ${el.dataset.id}`, confirm: "해제", danger: true });
    if (!fd) return;
    await gw(`endpoint/devices/${encodeURIComponent(el.dataset.id)}`, { method: "DELETE" });
    toast("등록을 해제했습니다."); reload();
  },
  async "intake-queue"(el) {
    const r = await api(`/api/mcp-requests/${el.dataset.id}/queue-validation`, { method: "POST" });
    toast(r.message); reload();
  },
  "intake-report": (el) => { location.hash = `#/intake/${el.dataset.id}`; },
  async "available-mcp"(el) {
    const { servers } = await api("/api/approved-mcp");
    const server = servers.find((s) => s.server_id === el.dataset.id);
    if (!server) { toast("현재 사용할 수 없는 MCP입니다.", true); return; }
    showAvailableMcp(server);
  },
  async "available-mcp-copy"(el) {
    const { servers } = await api("/api/approved-mcp");
    const server = servers.find((s) => s.server_id === el.dataset.id);
    const address = server ? approvedMcpAddress(server) : "";
    if (!address) { toast("현재 사용할 수 없는 MCP입니다.", true); return; }
    await navigator.clipboard.writeText(address);
    toast("MCP 주소를 복사했습니다.");
  },
  async "mcp-source-download"(el) {
    const response = await fetch(`/api/approved-mcp/${encodeURIComponent(el.dataset.id)}/source?commit=${encodeURIComponent(el.dataset.commit)}`,
      { headers: { authorization: `Bearer ${token}` } });
    if (!response.ok) {
      if (response.status === 401) { localStorage.removeItem(TOKEN_KEY); location.replace("/login"); }
      const body = await response.json().catch(() => ({}));
      throw new Error(detailText(body.detail) || `다운로드하지 못했습니다 (${response.status}).`);
    }
    const url = URL.createObjectURL(await response.blob());
    Object.assign(document.createElement("a"), { href: url, download: `${el.dataset.id}-${el.dataset.commit.slice(0, 12)}.zip` }).click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },
  async "intake-download"(el) {
    const response = await fetch(`/api/mcp-requests/${el.dataset.id}/artifacts/${encodeURIComponent(el.dataset.kind)}`,
      { headers: { authorization: `Bearer ${token}` } });
    if (!response.ok) {
      if (response.status === 401) { localStorage.removeItem(TOKEN_KEY); location.replace("/login"); }
      const body = await response.json().catch(() => ({}));
      throw new Error(detailText(body.detail) || `다운로드하지 못했습니다 (${response.status}).`);
    }
    const url = URL.createObjectURL(await response.blob());
    Object.assign(document.createElement("a"), { href: url, download: el.dataset.name }).click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },
  async "registry-export"(el) {
    const format = el.dataset.format;
    const response = await fetch(`/gw/registry/export?format=${encodeURIComponent(format)}`, { headers: { authorization: `Bearer ${token}` } });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(detailText(body.detail) || `등록부를 내보내지 못했습니다 (${response.status}).`);
    }
    const blob = await response.blob(), url = URL.createObjectURL(blob);
    Object.assign(document.createElement("a"), { href: url, download: `mint-registry.${format}` }).click();
    toast(`등록부 SHA-256 · ${response.headers.get("X-Registry-SHA256") || "—"}`);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },
  async "intake-terms"(el) {
    const fd = await ask({ title: `종료 조건 확인 · ${el.dataset.name}`,
      fields: html`<fieldset><legend>제공자가 약속한 항목</legend>
          ${Object.entries(EXIT_TERMS).map(([k, label]) => html`<label class="check"><input type="checkbox" name="${k}" /> ${label}</label>`)}</fieldset>
        ${field.text("evidence_url", "근거 문서 (HTTPS)", 'type="url" required pattern="https://.+" maxlength="500"')}
        ${field.area("note", "확인 내용", 'required minlength="10" maxlength="1000"')}`,
      confirm: "기록" });
    if (!fd) return;
    const body = { evidence_url: fd.get("evidence_url").trim(), note: fd.get("note").trim() };
    for (const k of Object.keys(EXIT_TERMS)) body[k] = fd.get(k) === "on";
    const r = await api(`/api/mcp-requests/${el.dataset.id}/exit-terms`, { method: "PUT", body });
    toast(r.message); reload();
  },
  "intake-one-click": (el) => { location.hash = `#/intake/${el.dataset.id}`; },
  async "intake-local-run"(el) {
    const out = intakeApproval?.out;
    if (out && await askLocalRun(el.dataset.id, out.request, out.local_run_preset, out.local_run_status)) route();
  },
  async "intake-confirm"(el) {
    const ctx = intakeApproval, form = $("#intake-approve");
    if (!ctx || ctx.id !== el.dataset.id || !form) return;
    const fd = new FormData(form), out = ctx.out, scope = out.pending?.scope;
    const selected = scope?.tools || fd.getAll("approved_tool");
    if (!selected.length) { toast("도구를 하나 이상 선택하세요.", true); return; }
    const critical = String(fd.get("critical_reason") || "").trim(), accepted = String(fd.get("risk_reason") || "").trim();
    if ((!scope && out.gate.critical?.count && critical.length < 10) || (out.proposal.risk.tier === "very_high" && accepted.length < 10)) { toast("수용 사유를 10자 이상 입력하세요.", true); return; }
    const actions = scope ? scope.actions || {} : Object.fromEntries(selected.map((name) => [name, fd.get(`action_${name}`)])
      .filter(([name, action]) => action && action !== out.proposal.tools[name]));
    const destinations = scope ? scope.destinations || {} : Object.fromEntries(selected
      .filter((name) => (out.proposal.address_tools || []).includes(name)).map((name) => [name, hostList(fd.get(`destinations_${name}`))]));
    const assurance = scope?.supplier_assurance || Object.fromEntries(Object.keys(ASSURANCE_LABELS).map((key) => [key, given(out.proposal.supplier_assurance, key)])
      .filter(([, value]) => typeof value === "string"));
    const result = await api(`/api/mcp-requests/${ctx.id}/approve-and-register`, { method: "POST", body: {
      proposal_sha256: out.proposal_sha256, tools: selected, valid_days: scope?.valid_days || Number(fd.get("valid_days")),
      critical_reason: critical, risk_reason: accepted, supplier_assurance: assurance, actions, destinations,
      ...(scope ? { audience: scope.audience || "all", audience_users: scope.audience_users || [] } : audienceBody(fd)) } });
    toast(result.message);
    refreshBadges();
    if (result.pending) route(); else location.hash = `#/servers/${encodeURIComponent(out.proposal.server_id)}`;
  },
  async "intake-discover"(el) {
    const form = el.closest("form");
    if (form.dataset.discoverBusy === "true") return;
    const endpoint = form.elements.endpoint_url.value.trim();
    if (!/^https:\/\//.test(endpoint)) { intakeStatus(form, "MCP 주소 확인 필요", "endpoint_url"); return; }
    const generation = form.dataset.discoveryGeneration || "0";
    form.dataset.discoverBusy = "true"; el.disabled = true;
    intakeStatus(form, "도구 조회 중");
    try {
      const found = await api("/api/mcp-requests/discover", { method: "POST", body: { endpoint } });
      if ((form.dataset.discoveryGeneration || "0") !== generation || form.elements.endpoint_url.value.trim() !== endpoint) return;
      form.querySelector("[data-requested-tools]").innerHTML = String(requestedToolList(found.tools));
      form.dataset.discoveredEndpoint = endpoint;
      intakeStatus(form, found.tools.length ? "도구 조회 완료" : "도구 없음");
    } catch (error) {
      if ((form.dataset.discoveryGeneration || "0") === generation) intakeStatus(form, "도구 조회 실패", "endpoint_url");
    } finally { form.dataset.discoverBusy = "false"; el.disabled = false; }
  },
  async "server-suspend"(el) {
    const fd = await ask({ title: `긴급 중지 · ${el.dataset.name}`, body: "이 서버의 호출이 즉시 차단됩니다.", fields: field.text("reason", "사유", 'required minlength="4" maxlength="500"'),
      confirm: "중지", danger: true });
    if (!fd) return;
    await gw(`ops/servers/${encodeURIComponent(el.dataset.id)}/suspend`, { method: "POST", body: { reason: fd.get("reason").trim() } });
    closeDrawer(); toast("서버를 중지했습니다."); reload();
  },
  async "server-resume"(el) {
    const fd = await ask({ title: `재개 · ${el.dataset.name}`, fields: field.text("note", "확인 내용", 'required minlength="4" maxlength="500"'), confirm: "재개" });
    if (!fd) return;
    await gw(`ops/servers/${encodeURIComponent(el.dataset.id)}/resume`, { method: "POST", body: { note: fd.get("note").trim() } });
    closeDrawer(); toast("서버를 재개했습니다."); reload();
  },
  async "device-quarantine"(el) {
    const fd = await ask({ title: `PC 격리 · ${el.dataset.name}`, body: "이 PC는 승인된 서버에 연결할 수 없게 되고, 관리자가 다시 활성화할 때까지 유지됩니다.",
      fields: field.text("note", "사유", 'required minlength="4" maxlength="1000"'), confirm: "격리", danger: true });
    if (!fd) return;
    await gw(`endpoint/devices/${encodeURIComponent(el.dataset.id)}/quarantine`, { method: "POST", body: { note: fd.get("note").trim() } });
    closeDrawer(); toast("PC를 격리했습니다."); reload();
  },
  "shadow-group": (el) => showShadowGroup(Number(el.dataset.index)),
  async "server-audience"(el) {
    const s = registry?.servers.find((row) => row.id === el.dataset.id);
    if (!s) return;
    const fd = await ask({ title: `사용 대상 · ${s.display_name}`, fields: audienceFields((registry.registrations?.[el.dataset.id]?.allowed_principals || []).includes("*") ? "all" : "requester"), confirm: "변경" });
    if (!fd) return;
    await gw(`registry/servers/${encodeURIComponent(el.dataset.id)}/audience`, { method: "POST",
      body: (({ audience, audience_users }) => ({ audience, users: audience_users }))(audienceBody(fd)) });
    closeDrawer(); toast("사용 대상을 변경했습니다."); reload();
  },
  async "endpoint-request-close"(el) {
    if (!await ask({ title: "검토 종료", fields: kv([["서버", el.dataset.name || "—"], ["엔드포인트", el.dataset.endpoint || "—"],
      ["결과", "도입 요청 검토 종료"]]), confirm: "검토 종료", danger: true })) return;
    await gw(`endpoint/requests/${encodeURIComponent(el.dataset.id)}/close`, { method: "POST" });
    toast("검토를 종료했습니다."); reload(); refreshBadges();
  },
  async "intake-accept-risk"(el) {
    const fd = await ask({ title: `위험 수용 · ${el.dataset.name}`,
      fields: html`${field.select("days", "수용 기한", { 7: "7일", 14: "14일", 30: "30일" }, "7")}
        ${field.area("reason", "수용 사유", 'required minlength="10" maxlength="1000"')}`, confirm: "수용" });
    if (!fd) return;
    const r = await api(`/api/mcp-requests/${el.dataset.id}/accept-risk`, { method: "POST", body: { reason: fd.get("reason").trim(), days: Number(fd.get("days")) } });
    toast(r.message); reload();
  },
  async "tool-scope"(el) {
    const s = registry?.servers.find((row) => row.id === el.dataset.id);
    const registration = registry?.registrations?.[el.dataset.id];
    if (!s || !registration) return;
    const pending = Object.keys(registration.tools || {}).filter((name) => !registration.tool_reviews?.[name]);
    const fd = await ask({ title: `도구 범위 심사 · ${s.display_name}`, fields: scopeFields(pending, registration.data_class), confirm: "기록" });
    if (!fd) return;
    const r = await gw(`registry/servers/${encodeURIComponent(el.dataset.id)}/tool-reviews`, { method: "POST", body: { reviews: collectScopes(fd, pending) } });
    closeDrawer(); toast(`도구 ${r.reviewed.length}개의 범위를 기록했습니다.`); reload();
  },
  async "impact-scope"(el) {
    const item = registry?.registrations?.[el.dataset.id]?.tool_reviews?.[el.dataset.tool];
    if (!item) return;
    const fd = await ask({ title: "중대 영향 심사", fields: html`<fieldset><legend>영향 영역</legend>
      ${Object.entries(IMPACT_DOMAIN).map(([key, label]) => html`<label class="check"><input type="checkbox" name="impact" value="${key}" ${(item.impact_domains || []).includes(key) ? raw("checked") : ""} /> ${label}</label>`)}</fieldset>`, confirm: "기록" });
    if (!fd) return;
    const { purpose, asset, destinations, inputs, mask, grade, accepts_from, consent } = item;
    const domains = fd.getAll("impact");
    await gw(`registry/servers/${encodeURIComponent(el.dataset.id)}/tool-reviews`, { method: "POST", body: {
      reviews: { [el.dataset.tool]: { purpose, asset, destinations, inputs, mask, grade, accepts_from, consent,
        high_impact: domains.length > 0, impact_domains: domains } } } });
    toast("기록했습니다."); closeDrawer(); reload();
  },
  async "destination-scope"(el) {
    const item = registry?.registrations?.[el.dataset.id]?.tool_reviews?.[el.dataset.tool];
    if (!item) return;
    const fd = await ask({ title: `허용 주소 · ${el.dataset.tool}`,
      fields: field.text("destinations", "허용 주소", 'maxlength="300"', (item.destinations || []).join(", ")), confirm: "기록" });
    if (!fd) return;
    const { purpose, asset, inputs, mask, grade, accepts_from, consent, high_impact, impact_domains } = item;
    await gw(`registry/servers/${encodeURIComponent(el.dataset.id)}/tool-reviews`, { method: "POST", body: {
      reviews: { [el.dataset.tool]: { purpose, asset, destinations: hostList(fd.get("destinations")), inputs, mask, grade, accepts_from, consent,
        high_impact: Boolean(high_impact), impact_domains: impact_domains || [] } } } });
    toast("기록했습니다."); closeDrawer(); reload();
  },
  async "intake-reject"(el) {
    const fd = await ask({ title: "도입 신청 거부", fields: field.text("note", "사유", 'required minlength="2" maxlength="500"'), confirm: "거부", danger: true });
    if (!fd) return;
    await api(`/api/mcp-requests/${el.dataset.id}/reject`, { method: "POST", body: { note: fd.get("note") } });
    toast("거부했습니다."); refreshBadges();
    if (current.arg) location.hash = "#/intake?t=review"; else reload();
  },
  "organization-policy"(el) {
    const p = organizationPolicies.find((row) => row.id === el.dataset.id);
    if (!p) return;
    rememberDetail(p.id, "organization-policy");
    const rules = policyRulesOf(p);
    const counts = policyCounts(p, policyActivityByRule(policyWindow.activity));
    const state = policyState(p, policyWindow.enforcement);
    const logs = (rule) => `#/activity?${new URLSearchParams({ event_kind: "tools/call", policy: rule.policy_id, since: policyWindow.since.toISOString(), until: policyWindow.until.toISOString() })}`;
    openDrawer(p.id, html`<b>${p.title}</b><div class="row-actions">${chip(POLICY_MODE_TONE[p.mode], POLICY_MODE[p.mode])}${state ? chip(state === "off" ? "outline" : state === "report" ? "alert" : "allow", POLICY_STATE[state]) : ""}</div>`, [
      { key: "status", label: "운영 현황", body: html`${kv([["기간", POLICY_RANGES[policyWindow.key][0]], ["판정", counts.total],
        ...DECISIONS.filter((d) => counts[d] > 0).map((d) => [DECISION[d][1], counts[d]])])}
        ${rules.length ? html`<div class="row-actions">${rules.map((rule) => html`<a class="btn sm" href="${logs(rule)}">${rule.name} <span aria-hidden="true">↗</span></a>`)}</div>` : empty("연결된 운영 규칙 없음")}` },
      { key: "rules", label: "규칙과 기능", body: html`${rules.length ? html`<div class="row-actions">${rules.map((rule) => html`<button class="btn" type="button" data-act="policy" data-id="${rule.policy_id}">${rule.name}</button>`)}</div>` : empty("운영 대응 규칙 없음")}
        ${p.mode === "structural" ? html`<p class="note">게이트웨이가 중개하지 않음</p>` : ""}` },
      { key: "definition", label: "정책 정의", body: kv([["정책 번호", p.id], ["적용 단계", p.stage], ["정책 대상", p.name], ["우선순위", p.priority],
        ["정책 내용", p.content], ["적용 조건", p.condition], ["통과 요건", p.pass_condition], ["차단 요건", p.block_condition],
        ["필요 증빙", p.required_evidence]]) },
      ...(p.mode === "manual" ? [{ key: "manual", label: "수동 점검", body: kv([["점검 항목", p.pass_condition || p.content], ["필요 증빙", p.required_evidence]]) }] : []),
    ]);
  },
  policy(el) {
    const p = policyLedger.find((row) => row.policy_id === el.dataset.id);
    if (!p) return;
    rememberDetail(el.dataset.id, "policy");
    const links = policyLinks(p);
    const logs = new URLSearchParams({ t: "events", policy: p.policy_id });
    if (policyEvidence.record_window_hours === 24 && Number.isFinite(Date.parse(policyEvidence.checked_at))) {
      logs.set("since", new Date(Date.parse(policyEvidence.checked_at) - 86400000).toISOString());
      logs.set("until", policyEvidence.checked_at);
    }
    openDrawer(p.name, html`<a class="btn" href="#/activity?${logs}">판정 기록 보기</a>`, [
      { key: "definition", label: "정책 정의", body: kv([["정책 ID", p.policy_id], ["목적", p.purpose],
        ["조건", p.condition], ["대상 범위", p.scope], ["정의된 결과", p.outcome], ["처리 방식", p.enforcement]]) },
      { key: "evidence", label: "집행 근거", body: kv([["집행 주체", policyExecutor(p)],
        ["관찰 모드 처리", { protected: "관찰 모드에서도 차단 유지", eligible: "관찰 모드 전환 가능" }[p.monitor_behavior] || "—"],
        ["등록 상태", ["운영", "중지", "폐기"].includes(p.status) ? p.status : "—"],
        ["최근 24시간 판정", policyRecordLabel(p)], ["최종 판정 기록 수", p.recent?.count ?? "—"],
        ["마지막 판정 시각", when(p.recent?.last_seen_at)], 
        ["평가 우선순위", p.priority ?? "—"],
        ["대상 환경", Array.isArray(p.environments) ? p.environments.map(policyEnvironment).join(", ") : "—"]]) },
      { key: "mapping", label: "정책 연결", body: kv([["관련 보안 정책", links.join(", ") || "매핑 미확인"],
        ["연결 근거", links.length ? "정책 관리대장의 명시적 연결" : "검토된 연결 정보 없음"]]) },
    ]);
  },
  async enforcement(el) {
    const mode = el.dataset.mode;
    const fd = await ask({ title: mode === "monitor" ? "관찰 모드로 전환" : "집행 모드로 전환", body: mode === "monitor" ? "관찰 전환 대상 정책은 기록만 하고 실행됩니다. 상시 차단 정책은 유지됩니다." : "", confirm: "전환", danger: mode === "monitor" });
    if (!fd) return;
    await gw("enforcement", { method: "PUT", body: { mode } });
    toast("전환했습니다."); reload();
  },
  "dash-range"(el) {
    const key = el.dataset.range;
    if (key === "custom") {
      const range = dashboardRange(current.query);
      dashboardGo({ range: key, since: range.since.toISOString(), until: range.until.toISOString() });
    } else dashboardGo({ range: key === "24h" ? "" : key, since: "", until: "" });
  },
  "dash-refresh": () => route(),
  "policy-range"(el) {
    const q = new URLSearchParams(current.query);
    q.set("range", el.dataset.range);
    location.hash = `#/policy?${q}`;
  },
  "policy-groups"(el) {
    const open = el.dataset.open === "true";
    for (const body of document.querySelectorAll("#organization-policy-list tbody[data-group]")) {
      body.dataset.collapsed = String(!open);
      body.querySelector(".group-toggle")?.setAttribute("aria-expanded", String(open));
    }
    applyPolicyFilters();
  },
  "policy-group"(el) {
    const body = el.closest("tbody"), closed = body.dataset.collapsed !== "true";
    body.dataset.collapsed = String(closed);
    el.setAttribute("aria-expanded", String(!closed));
    applyPolicyFilters();
  },
  "open-case": (el) => { location.hash = `#/termination/${el.dataset.id}`; },
  async "open-termination"(el) {
    const grade = el.dataset.grade;
    const fd = await ask({
      title: `종료 시작 · ${el.dataset.name}`, body: `이 MCP 서버의 호출이 즉시 차단됩니다.${grade ? ` 예상 결과: ${GRADE[grade] || ""}` : ""}`,
      fields: field.area("reason", "종료 사유", 'required minlength="10" maxlength="1000"'),
      confirm: "차단하고 종료 시작", danger: true });
    if (!fd) return;
    const d = await gw("termination/cases", { method: "POST", body: { relationship_id: el.dataset.id, reason: fd.get("reason") } });
    toast(`차단했습니다 · 회수 대상 ${d.targets.length}개`);
    refreshBadges();
    location.hash = `#/termination/${d.case.id}`;
  },
  target: (el) => showTarget(el.dataset.id),
  async collect() {
    const kinds = { gateway: "게이트웨이 차단 확인", endpoint: "엔드포인트 설정 대조", credentials: "하위 시스템 자격 확인",
      liveness: "서버 도달 확인", session: "세션 종료 요청" };
    const fd = await ask({ title: "증거 수집",
      fields: html`<fieldset>${Object.entries(kinds).map(([k, label]) => html`<label class="check"><input type="checkbox" name="kinds" value="${k}" ${["gateway", "endpoint", "credentials"].includes(k) ? raw("checked") : ""} /> ${label}</label>`)}</fieldset>`,
      confirm: "수집" });
    if (!fd) return;
    const chosen = fd.getAll("kinds");
    if (!chosen.length) { toast("항목을 하나 이상 선택하세요.", true); return; }
    const r = await gw(`termination/cases/${currentCase.case.id}/collect`, { method: "POST", body: { kinds: chosen } });
    toast(`증거 ${r.collected.length}건을 기록했습니다.`); reload();
  },
  async assess() {
    const d = await gw(`termination/cases/${currentCase.case.id}/assess`, { method: "POST" });
    toast(`판정 ${GRADE[d.case.grade]}`, d.case.grade === "T3"); reload(); refreshBadges();
  },
  async "revoke-credential"(el) {
    const fd = await ask({ title: "하위 시스템 자격 폐기", confirm: "폐기", danger: true });
    if (!fd) return;
    await gw(`termination/targets/${el.dataset.id}/revoke-credential`, { method: "POST" });
    toast("폐기를 확인했습니다."); reload();
  },
  async "target-status"(el) {
    const t = currentCase.targets.find((row) => row.id === el.dataset.id);
    const fd = await ask({ title: `상태 기록 · ${t.label}`,
      fields: html`${field.select("status", "상태", TARGET_STATUS, t.status)}${field.area("note", "메모", 'maxlength="1000"')}`, confirm: "기록" });
    if (!fd) return;
    await gw(`termination/targets/${t.id}`, { method: "PUT", body: { status: fd.get("status"), note: fd.get("note") || null } });
    toast("기록했습니다."); reload();
  },
  async "add-target"() {
    const kinds = Object.fromEntries(Object.entries(TARGET_KIND).filter(([k]) => !["gateway-route", "gateway-access"].includes(k)));
    const fd = await ask({ title: "회수 대상 추가",
      fields: html`${field.select("kind", "종류", kinds)}${field.text("label", "이름", 'required maxlength="300"')}
        ${field.select("holder", "보유 주체", HOLDER, "provider")}${field.select("discovered_by", "발견 경로", DISCOVERED, "provider-disclosure")}
        ${field.area("note", "메모", 'maxlength="1000"')}`, confirm: "추가" });
    if (!fd) return;
    await gw(`termination/cases/${currentCase.case.id}/targets`, { method: "POST",
      body: { kind: fd.get("kind"), label: fd.get("label"), holder: fd.get("holder"), discovered_by: fd.get("discovered_by"), note: fd.get("note") || null } });
    toast("대상을 추가했습니다."); reload();
  },
  async "add-evidence"() {
    const kinds = Object.fromEntries(Object.entries(currentCase.evidence_kinds).map(([k, m]) => [k, m.label]));
    const targets = Object.fromEntries([["", "케이스 전체"], ...currentCase.targets.map((t) => [t.id, t.label])]);
    const fd = await ask({ title: "증거 등록",
      fields: html`${field.select("kind", "종류", kinds, "provider-attestation")}${field.select("target_id", "대상", targets)}
        ${field.text("subject", "식별자", 'required maxlength="300"')}${field.text("source", "출처", 'required maxlength="300"')}
        ${field.area("statement", "내용", 'maxlength="1000"')}`, confirm: "등록" });
    if (!fd) return;
    await gw(`termination/cases/${currentCase.case.id}/evidence`, { method: "POST", body: {
      kind: fd.get("kind"), subject: fd.get("subject"), source: fd.get("source"), target_id: fd.get("target_id") || null,
      detail: fd.get("statement") ? { statement: fd.get("statement") } : {} } });
    toast("증거를 등록했습니다."); reload();
  },
  async "close-case"() {
    const t3 = currentCase.case.grade === "T3";
    const fd = await ask({ title: `종결 · ${GRADE[currentCase.case.grade]}`,
      fields: html`${field.area("note", "종결 사유", 'required maxlength="1000"')}${t3 ? field.area("risk_acceptance", "위험 수용 근거", 'required maxlength="1000"') : ""}`,
      confirm: "종결", danger: true });
    if (!fd) return;
    await gw(`termination/cases/${currentCase.case.id}/close`, { method: "POST", body: { note: fd.get("note"), risk_acceptance: fd.get("risk_acceptance") || null } });
    toast("종결했습니다."); reload(); refreshBadges();
  },
  async "reopen-case"() {
    const fd = await ask({ title: "케이스 재개", fields: field.area("reason", "재개 사유", 'required maxlength="1000"'), confirm: "재개" });
    if (!fd) return;
    await gw(`termination/cases/${currentCase.case.id}/reopen`, { method: "POST", body: { reason: fd.get("reason") } });
    toast("재개했습니다."); reload(); refreshBadges();
  },
  async report() {
    const r = await gw(`termination/cases/${currentCase.case.id}/report`);
    lastDocument = r;
    openDrawer("종료 판정서", html`<div class="grade-big ${r.grade}">${r.grade || "—"} · ${r.grade_label}</div>
      <div class="row-actions"><button class="btn sm" data-act="save-json" data-name="termination-report-${r.case_id}.json">JSON 저장</button></div>`, [
      { key: "verdict", label: "판정", body: html`<p>${r.rationale}</p>${kv([["이용 관계", `${r.relationship_id || ""} · ${r.engagement}`], ["제공자", r.relationship.provider],
        ["사유", r.reason], ["차단", when(r.cutover_at, { seconds: true })], ["판정", when(r.assessed_at)], ["종결", when(r.closed_at)],
        ["위험 수용", r.risk_acceptance_note ? `${r.risk_acceptance_note} (${r.risk_accepted_by})` : ""]])}` },
      { key: "criteria", label: "기준", body: html`${r.criteria.map((c) => html`<p><b>${c.criterion}</b> ${chip(c.met ? "allow" : "block", c.met ? "충족" : "미충족")} <span class="small muted">${c.label}</span></p>
        ${c.gaps.length ? html`<ul class="small">${c.gaps.map((g) => html`<li>${g}</li>`)}</ul>` : ""}`)}` },
      { key: "targets", label: "대상", n: r.targets.length, body: html`${r.targets.map((t) => html`<p class="small">${t.grade ? chip(t.grade, t.grade) : ""} ${t.label} · ${TARGET_STATUS[t.status]?.[1] || t.status}</p>`)}
        ${kv([["증거", r.evidence.length], ["차단 후 실행", r.gateway_observed.executed], ["차단 후 거부", r.gateway_observed.blocked], ["실행 미확인", r.gateway_observed.unknown]])}` },
    ]);
  },
  async disclosure() {
    const r = await gw(`termination/cases/${currentCase.case.id}/disclosure-request`);
    lastDocument = r.markdown;
    openDrawer("제공자 고지 요청서", html`<div class="row-actions">${chip(r.has_contract_basis ? "allow" : "alert", r.has_contract_basis ? "계약 근거 있음" : "계약 근거 없음")}
      ${chip("outline", `미회수 제공자 대상 ${r.outstanding_provider_targets}`)}<button class="btn sm primary" data-act="copy-doc">복사</button></div>
      <pre class="json">${r.markdown}</pre>`);
  },
  connector(el) {
    const g = connectorGroups.find((x) => x.key === el.dataset.key);
    if (!g) return;
    rememberDetail(el.dataset.key, "connector");
    openDrawer(connectorName(g), html`<div class="row-actions">${connectorState(g)}
      ${g.violation ? chip("block", "미승인 사용") : ""}${connectorButtons(g)}</div>
      ${kv([["하네스", g.harness === "claude" ? "Claude Code" : "Codex"], ["통제", connectorControlChip(connectorItems, g.key)], ["종류", g.kinds.map((k) => CONNECTOR_KIND[k] || k).join(" · ")],
        ["대상", html`<span class="mono">${connectorTarget(g)}</span>`], ["처음 보고", when(g.first_seen)],
        ["결정", g.decision ? html`${g.note || "—"}<span class="sub">${g.decided_by} · ${when(g.decided_at)}</span>` : ""]])}
      <h3>사용 엔드포인트</h3>
      <table class="data"><thead><tr><th>사용자</th><th>엔드포인트</th><th>상태</th><th>마지막 보고</th></tr></thead><tbody>
        ${g.holders.map((h) => html`<tr><td>${h.display_name || "—"}</td><td class="mono">${h.workstation}</td>
          <td>${h.active ? chip(["pending", "denied", "expired"].includes(g.state) ? "block" : "plain", harnessStatus(h.status)) : chip("outline", "보고 없음")}</td><td class="small nowrap">${ago(h.last_seen)}</td></tr>`)}
      </tbody></table>`);
  },
  async "connector-decide"(el) {
    const r = await api("/api/connectors/decision", { method: "PUT", body: { key: el.dataset.key, decision: el.dataset.decision } });
    toast(r.message); reload(); refreshBadges();
  },
  async "connector-deny"(el) {
    const fd = await ask({ title: `차단 · ${el.dataset.name}`, fields: field.area("note", "사유", 'required minlength="2" maxlength="500"'),
      confirm: "차단", danger: true });
    if (!fd) return;
    const r = await api("/api/connectors/decision", { method: "PUT", body: { key: el.dataset.key, decision: "denied", note: fd.get("note").trim() } });
    toast(r.message); reload(); refreshBadges();
  },
  async "connector-policy"() {
    lastDocument = await api("/api/connectors/policy");
    ACTIONS["save-json"]({ dataset: { name: "connector-policy.json" } });
  },
  async "copy-id"(el) {
    try { await navigator.clipboard.writeText(el.dataset.value); toast("복사했습니다."); } catch { toast("복사하지 못했습니다.", true); }
  },
  async "copy-doc"() {
    await navigator.clipboard.writeText(String(lastDocument));
    toast("복사했습니다.");
  },
  "save-json"(el) {
    const url = URL.createObjectURL(new Blob([JSON.stringify(lastDocument, null, 2)], { type: "application/json" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: el.dataset.name });
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },
};
let lastDocument = null;

const FORMS = {
  "intake-approve"() {},
  "sbom-impact"(form) {
    const q = new URLSearchParams(new FormData(form));
    const hash = `#/servers?t=supply&${q}`;
    if (location.hash === hash) route(); else location.hash = hash;
  },
  devices(form) {
    const q = new URLSearchParams([...new FormData(form)].filter(([,v]) => String(v).trim()));
    q.set("t", "devices"); resetCoveragePaging();
    const hash = `#/endpoints?${q}`;
    if (location.hash === hash) route(); else location.hash = hash;
  },

  async intake(form) {
    if (form.dataset.submitting === "true") return;
    const fd = new FormData(form);
    if (form.dataset.discoverBusy === "true") { intakeStatus(form, "도구 조회 중"); return; }
    const remote = fd.get("intake_kind") === "remote-endpoint";
    const address = remote ? "endpoint_url" : "repository_url";
    if (!String(fd.get(address) || "").trim()) { intakeStatus(form, "주소 입력 필요", address); return; }
    if (remote && (form.dataset.discoveredEndpoint !== String(fd.get(address)).trim() || !fd.getAll("requested_tool").length)) {
      intakeStatus(form, "도구 선택 필요", "requested_tool"); return;
    }
    form.dataset.submitting = "true";
    try {
    const body = Object.fromEntries(["display_name", "repository_url", "endpoint_url", "intake_kind", "requested_transport", "purpose"].map((k) => [k, String(fd.get(k) || "").trim()]));
    const r = await api("/api/mcp-requests", { method: "POST", body: { ...body, data_class: fd.get("data_class"),
      requested_tools: fd.getAll("requested_tool"), ...(fd.get("endpoint_request_id") ? { endpoint_request_id: fd.get("endpoint_request_id") } : {}) } });
    toast(r.message);
    location.hash = "#/intake?t=list";
    } catch (error) {
      intakeStatus(form, "신청 실패");
      form.querySelector("[data-intake-status]").setAttribute("role", "alert");
      if (Array.isArray(error.detail)) for (const issue of error.detail) {
        const field = issue.loc?.map((name) => name === "requested_tools" ? "requested_tool" : name).find((name) => form.elements.namedItem(String(name)));
        if (field) intakeStatus(form, "입력 확인 필요", String(field));
      }
    } finally { form.dataset.submitting = "false"; }
  },
};

const inboxContext = () => ({ html, raw, chip, kv, when, ago, short, empty, panel, head, kpiStrip, chartBox, json, entityRef, charts, openDrawer,
  api, gw, ACTION, DATA_CLASS, INTAKE_STATUS, MANAGED_STATE, ALERT_KIND, decisionChip, policyLabel, impactExplanation, alertTarget, alertDetail, alertReason,
  alertGroups, alertsSeen, markAlertsSeen, approvalHistory, setApprovalLists, setLedger: (rows) => { policyLedger = rows; }, reload, refreshBadges });
let inboxTimer = null;
ROUTES.inbox = async (arg, tab, query) => {
  const out = await inboxRoute(inboxContext(), query);
  return { ...out, after: () => {
    if (out.open) {
      const next = new URLSearchParams(current.query);
      next.delete("open");
      current.query = next;
      history.replaceState(history.state, "", routeHash(next));
      ACTIONS["inbox-open"]({ dataset: { key: out.open } });
    }
    clearInterval(inboxTimer);
    inboxTimer = setInterval(() => {
      if (current.page !== "inbox") { clearInterval(inboxTimer); return; }
      if (document.hidden || $("#drawer").classList.contains("open") || $("#dialog").open || document.activeElement?.closest?.("#view table")) return;
      reload();
    }, 15000);
  } };
};
const myContext = () => ({ html, chip, when, ago, short, empty, panel, head, page, api, viewer, INTAKE_STATUS, MANAGED_STATE, DATA_CLASS,
  consentTabs, consentRows: () => consentRows, approvedMcpTable, approvedMcpSearch: () => approvedMcpSearch, listToolbar, intakeNewBody });
ROUTES.connections = ROUTES.connections || ((arg, tab, query) => ROUTES.servers(arg, tab || "items", query));

ROUTES.my = (arg, tab, query) => myRoute(myContext(), tab, query);
Object.assign(ACTIONS, inboxActions(inboxContext()));

document.addEventListener("click", (event) => {
  for (const open of document.querySelectorAll("details.row-menu[open]")) {
    if (!open.contains(event.target) || event.target.closest(".menu button, .menu a")) open.open = false;
  }
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") for (const open of document.querySelectorAll("details.row-menu[open]")) open.open = false;
});
$("#drawer").addEventListener("cancel", (event) => { event.preventDefault(); closeDrawer(); });
$("#drawer").addEventListener("click", (event) => {
  if (event.target !== event.currentTarget) return;
  const bounds = event.currentTarget.getBoundingClientRect();
  if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) closeDrawer();
});
document.addEventListener("click", (event) => {
  const link = event.target.closest('a[href^="#/servers/"]');
  if (link && current.page === "servers" && !current.arg && !event.ctrlKey && !event.metaKey) {
    event.preventDefault(); history.pushState({ detailEntry: routeHash() }, "", link.getAttribute("href")); route(); return;
  }
  const el = event.target.closest("[data-act]");
  if (!el) return;
  const inner = event.target.closest("a[href], button, summary, input, select, textarea, label");
  if (inner && inner !== el && el.contains(inner)) return;
  const fn = ACTIONS[el.dataset.act];
  if (!fn) return;
  event.preventDefault();
  const busy = el.tagName === "BUTTON" && el.dataset.act !== "tab";
  if (busy) el.disabled = true;
  Promise.resolve(fn(el)).catch((error) => toast(error.message, true)).finally(() => { if (busy && el.isConnected) el.disabled = false; });
});
document.addEventListener("submit", (event) => {
  const form = event.target.closest("form[data-form]");
  if (!form) return;
  event.preventDefault();
  const button = form.querySelector('[type="submit"]');
  if (button) button.disabled = true;
  Promise.resolve(FORMS[form.dataset.form](form)).catch((error) => toast(error.message, true)).finally(() => { if (button?.isConnected) button.disabled = false; });
});
document.addEventListener("toggle", (event) => {
  if (event.target.matches("details[open]")) charts.mountVisible(event.target);
}, true);
document.addEventListener("change", (event) => {
  if (event.target.name === "requested_transport" && event.target.form?.dataset.form === "intake") resetIntakeTools(event.target.form);
  if (event.target.matches("[data-registry-export]")) {
    const select = event.target, format = select.value;
    if (!["csv", "json"].includes(format)) return;
    select.disabled = true;
    ACTIONS["registry-export"]({ dataset: { format } }).catch((error) => toast(error.message, true))
      .finally(() => { select.value = ""; select.disabled = false; });
    return;
  }
  if (event.target.matches("[data-audience]")) {
    const users = event.target.form.querySelector("[data-audience-users]");
    users.hidden = event.target.value !== "selected";
    if (users.hidden) users.querySelector("input").value = "";
    return;
  }
  if (event.target.matches("[data-intake-kind]")) {
    for (const label of event.target.form.querySelectorAll("[data-intake-field]")) {
      label.hidden = label.dataset.intakeField !== event.target.value;
      if (label.hidden) for (const input of label.querySelectorAll("input,textarea")) input.value = "";
    }
    event.target.form.elements.requested_transport.value = event.target.value === "repository" ? "stdio" : "streamable-http";
    resetIntakeTools(event.target.form);
    return;
  }
  if (event.target.closest("[data-policy-filter]")) { applyPolicyFilters(true); return; }
  const dash = event.target.closest("[data-dash]");
  if (dash) {
    const value = dash.dataset.ko ? (parseKoStamp(dash.value)?.toISOString() || "") : dash.type === "datetime-local" ? (dash.value ? new Date(dash.value).toISOString() : "") : dash.value;
    dashboardGo({ [dash.dataset.dash]: value });
    return;
  }
  const coverageFilter = event.target.closest("[data-coverage-filter]");
  if (coverageFilter) {
    ACTIONS["coverage-filter"]({ dataset: { key: coverageFilter.dataset.coverageFilter, value: coverageFilter.value } });
    return;
  }
  const filter = event.target.closest("[data-filter]");
  if (filter) {
    feed.filters[filter.dataset.filter] = filter.dataset.ko ? (parseKoStamp(filter.value)?.toISOString() || "") : filter.value.trim();
    if (filter.dataset.filter === "execution" && filter.value === "connection-denied") feed.filters.event_kind = "mcp-connection";
    if (filter.dataset.filter === "event_kind" && filter.value === "tools/call" && feed.filters.execution === "connection-denied") feed.filters.execution = "";
    feed.page = 1;
    rememberFeed();
    reload();
    return;
  }
  if (event.target.matches('[data-act-change="endpoint-auto"]')) {
    gw("endpoint/settings", { method: "PUT", body: { auto_activate: event.target.value === "on" } })
      .then(() => toast(event.target.value === "on" ? "새 PC를 자동으로 활성화합니다." : "새 PC는 관리자가 활성화합니다."))
      .catch((error) => { toast(error.message); reload(); });
    return;
  }
  if (event.target.matches('[data-act-change="tool-filter"]')) {
    const q = new URLSearchParams({ t: "tools" });
    if (event.target.value) q.set("server", event.target.value);
    location.hash = `#/servers?${q}`;
  }
});
document.addEventListener("invalid", (event) => {
  if (event.target.form?.dataset.form === "intake") intakeStatus(event.target.form, "입력 확인 필요", event.target.name);
}, true);
document.addEventListener("input", (event) => {
  const intake = event.target.form;
  if (intake?.dataset.form === "intake") {
    event.target.setAttribute("aria-invalid", "false");
    const error = intake.querySelector(`[data-field-error="${event.target.name}"]`);
    if (error) error.textContent = "";
    if (["endpoint_url", "repository_url"].includes(event.target.name)) resetIntakeTools(intake);
  }
  if (event.target.matches("[data-feed-search]")) {
    const input = event.target;
    clearTimeout(input.searchTimer);
    input.searchTimer = setTimeout(() => {
      feed.query = input.value.trim();
      feed.page = 1;
      rememberFeed();
      reload();
    }, 300);
    return;
  }
  const input = event.target.closest("[data-list-search]");
  if (input) {
    if (input.dataset.listSearch === "available-mcp") approvedMcpSearch = input.value;
    const rows = [...(document.getElementById(input.dataset.listSearch)?.children || [])];
    const term = input.value.trim().toLocaleLowerCase();
    let shown = 0;
    for (const row of rows) {
      row.hidden = !(row.dataset.search ?? row.textContent).toLocaleLowerCase().includes(term);
      if (!row.hidden) shown += 1;
    }
    const count = document.querySelector(`[data-list-count="${input.dataset.listSearch}"]`);
    if (count) count.textContent = `${shown}/${rows.length}건`;
    const note = document.querySelector(`[data-list-empty="${input.dataset.listSearch}"]`);
    if (note) note.hidden = shown > 0;
    return;
  }
  if (event.target.matches("[data-catalog-search]")) {
    const input = event.target;
    clearTimeout(input.searchTimer);
    input.searchTimer = setTimeout(async () => {
      const query = input.value.trim();
      try {
        const data = await api(`/api/mcp-catalog/search?q=${encodeURIComponent(query)}`);
        if (input.isConnected && input.value.trim() === data.query) $("#catalog-results").innerHTML = String(catalogResults(data));
      } catch (error) { if (input.isConnected && input.value.trim() === query) $("#catalog-results").innerHTML = String(empty("", { failed: true })); }
    }, 250);
    return;
  }
  if (event.target.matches("[data-coverage-search]")) {
    const input = event.target;
    clearTimeout(input.searchTimer);
    input.searchTimer = setTimeout(() => {
      const q = new URLSearchParams(current.query);
      if (input.value.trim()) q.set("q", input.value.trim()); else q.delete("q");
      q.set("t", "items");
      history.replaceState(null, "", `#/connections?${q}`);
      route().then(() => { const again = $("[data-coverage-search]"); again?.focus(); again?.setSelectionRange(again.value.length, again.value.length); });
    }, 400);
    return;
  }
  if (!event.target.matches("[data-feed-search]")) return;
  feed.query = event.target.value;
  renderFeed();
});
document.addEventListener("keydown", (event) => {
  if ($("#dialog").open) return;
  if ($("#drawer").open && event.key === "Escape") { event.preventDefault(); closeDrawer(); }
  if (["Enter", " "].includes(event.key) && !event.isComposing && event.target.matches("tr[data-act]")) { event.preventDefault(); event.target.click(); }
  if (event.target.matches('[role="tab"]') && ["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
    const tabs = [...event.target.closest(".tabs").querySelectorAll('[role="tab"]')];
    const i = tabs.indexOf(event.target);
    const next = { ArrowLeft: i - 1, ArrowRight: i + 1, Home: 0, End: tabs.length - 1 }[event.key];
    const target = tabs[(next + tabs.length) % tabs.length];
    event.preventDefault();
    target.focus();
    target.click();
  }
});

function startAdminSessionGuard() {
  const warning = $("#session-warning");
  const message = $("#session-warning-text");
  const keepUsing = $("#session-continue");
  const dismiss = $("#session-dismiss");
  const activityKey = `mcp-console-admin-activity-${viewer.user_id}`;
  const { issuedAt, expiresAt: tokenExpiresAt } = tokenTimes(token);
  const maximumAt = (issuedAt || Date.now()) + ADMIN_MAX_MS;
  let lastActivity = Date.now();
  let lastServerTouch = 0;
  let touching = false;
  let ending = false;
  let warningDismissed = false;
  let currentWarningReason = "";

  const touchServerSession = async () => {
    if (touching || Date.now() - lastServerTouch < 60000) return;
    touching = true;
    try {
      await api("/auth/session/activity", { method: "POST" });
      lastServerTouch = Date.now();
    } catch {  }
    finally { touching = false; }
  };

  const recordActivity = (event) => {
    if (!event.isTrusted) return;
    lastActivity = Date.now();
    if (currentWarningReason === "idle") warningDismissed = false;
    localStorage.setItem(activityKey, String(lastActivity));
    touchServerSession();
  };
  for (const name of ["pointerdown", "keydown", "wheel"]) {
    document.addEventListener(name, recordActivity, { passive: true });
  }
  window.addEventListener("storage", (event) => {
    if (event.key === activityKey) {
      lastActivity = Math.max(lastActivity, Number(event.newValue) || 0);
      touchServerSession();
    }
  });
  localStorage.setItem(activityKey, String(lastActivity));
  touchServerSession();

  keepUsing.addEventListener("click", () => {
    lastActivity = Date.now();
    warningDismissed = false;
    localStorage.setItem(activityKey, String(lastActivity));
    touchServerSession();
  });
  dismiss.addEventListener("click", () => {
    warningDismissed = true;
    warning.close();
  });

  const endSession = async (reason) => {
    if (ending) return;
    ending = true;
    await fetch("/auth/logout", { method: "POST", headers: { authorization: `Bearer ${token}` } }).catch(() => {});
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(activityKey);
    location.replace(`/login?session=${reason}`);
  };

  setInterval(() => {
    if (ending) return;
    const now = Date.now();
    if (!document.hidden && now - lastActivity < 60000) touchServerSession();
    const idleAt = lastActivity + ADMIN_IDLE_MS;
    const deadline = Math.min(idleAt, maximumAt, tokenExpiresAt);
    const reason = idleAt <= maximumAt && idleAt <= tokenExpiresAt ? "idle"
      : maximumAt <= tokenExpiresAt ? "maximum" : "authentication";
    const remaining = deadline - now;
    if (remaining <= 0) { endSession(reason); return; }
    if (remaining > SESSION_WARNING_MS) {
      if (warning.open) warning.close();
      warningDismissed = false;
      return;
    }
    if (warningDismissed) return;
    const seconds = Math.ceil(remaining / 1000);
    const minutes = Math.floor(seconds / 60);
    const rest = seconds % 60;
    message.innerHTML = String(kv([["만료 시각", when(new Date(deadline).toISOString(), { seconds: true })], ["상태", `${minutes}분 ${rest}초`], ["만료 사유", reason === "idle" ? "유휴 시간" : reason === "maximum" ? "최대 로그인 시간" : "인증 세션"], ["재로그인", html`<a href="/login">로그인</a>`]]));
    keepUsing.hidden = reason !== "idle";
    currentWarningReason = reason;
    if (!warning.open) warning.showModal();
  }, 1000);
}

(function applyTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  document.documentElement.dataset.theme = saved || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
})();

async function boot() {
  viewer = await api("/auth/me");
  viewer.admin = viewer.roles.includes("admin");
  if (viewer.admin) startAdminSessionGuard();
  const mobile = matchMedia("(max-width: 900px)");
  setNavCollapsed(mobile.matches || localStorage.getItem(NAV_KEY) === "true");
  mobile.addEventListener("change", () => setNavCollapsed(mobile.matches || localStorage.getItem(NAV_KEY) === "true"));
  window.addEventListener("hashchange", route);
  await route();
  if (viewer.kit && viewer.managed_required && !(viewer.managed_devices || []).some((d) => d.status === "active" && d.managed_state === "active")) {
    ACTIONS["pc-kit"]();
  }
  refreshBadges(); setInterval(refreshBadges, 30000);
  refreshAlertBell(); setInterval(refreshAlertBell, 60000);
}
boot().catch((error) => { $("#view").innerHTML = String(html`<div class="note bad">${error.message}</div>`); });
