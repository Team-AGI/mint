import { consentState, reportView } from "./dash.mjs";
const OPEN_REQUEST = ["HOLD", "VALIDATION_QUEUED", "VALIDATING", "VALIDATED", "REMOTE_REVIEWED"];
const TABS = ["available", "consent", "mine", "new"];

const CONSENT = { granted: ["allow", "동의함"], pending: ["alert", "동의 필요"], denied: ["block", "거부"], revoked: ["outline", "철회"],
  before: ["outline", "동의 전"], none: ["outline", "동의 불필요"], unknown: ["outline", "확인 불가"] };

const consentChip = (c, rows, server) => {
  const state = consentState(server, rows);
  const [tone, label] = CONSENT[state];
  return ["pending", "denied", "revoked"].includes(state)
    ? c.html`${c.chip(tone, label)} <a class="btn sm" href="#/my?t=consent&server=${encodeURIComponent(server.server_id)}">동의 검토</a>` : c.chip(tone, label);
};

const deviceCard = (c) => {
  const devices = (c.viewer.managed_devices || []).filter((d) => d.status === "active");
  const newest = (list) => [...list].sort((a, b) => String(reportView(b).at).localeCompare(String(reportView(a).at)))[0];
  const best = newest(devices.filter((d) => d.managed_state === "active")) || devices.find((d) => d.managed_state) || devices[0];
  const view = reportView(best);
  const delayed = view.state === "active" && view.delayed;
  const label = !best ? "미연결" : delayed ? "보고 지연" : c.MANAGED_STATE[view.state] || "—";
  const tone = view.state === "active" && !delayed ? "" : "alert";
  const report = best ? `${best.hostname ? `${best.hostname} · ` : ""}${view.at ? `최근 보고 ${c.ago(view.at)}` : "보고 없음"}` : "";
  return c.html`<div class="kpi ${tone}"><div class="label">내 PC 연결</div><div class="value">${label}</div>
    <div class="foot"><span class="delta">${report}</span>${c.viewer.kit ? c.html`<button class="btn sm" type="button" data-act="pc-kit">연결 설정</button>` : ""}</div></div>`;
};

export async function myRoute(c, tab, query) {
  const [{ requests }, { servers }, consent, catalog] = await Promise.all([c.api("/api/mcp-requests"), c.api("/api/approved-mcp"), c.consentTabs(query),
    tab === "new" ? c.api("/api/mcp-catalog/search") : Promise.resolve(null)]);
  const [pending, history] = consent;
  const rows = c.consentRows();
  const open = requests.filter((r) => OPEN_REQUEST.includes(r.status)).length;
  const pre = { name: query.get("name") || "", purpose: query.get("purpose") || "", source: query.get("source") || "", asked: query.get("asked") || "" };
  const fromRepo = /^https:\/\/github\.com\//.test(pre.source);
  const active = TABS.includes(tab) ? tab : "available";
  const tabs = [
    { key: "available", label: "사용 가능한 MCP", body: c.panel("사용 가능한 MCP",
      c.approvedMcpTable(servers, c.approvedMcpSearch(), (server) => consentChip(c, rows, server)), { flush: true,
        tools: servers.length ? c.listToolbar("available-mcp", "이름 또는 기능 검색", c.approvedMcpSearch()) : "" }) },
    { key: "consent", label: "내 동의", n: pending.n || null, hot: pending.hot, body: c.html`<div class="stack">${pending.body}${history.body}</div>` },
    { key: "mine", label: "전체 신청", n: requests.length, body: c.panel("내 신청", requests.length ? c.html`<table class="data"><thead><tr><th>서비스</th><th>상태</th><th>신청</th></tr></thead><tbody>
      ${requests.map((r) => c.html`<tr><td><b>${r.display_name}</b></td><td>${c.chip(...(c.INTAKE_STATUS[r.status] || ["", r.status]))}${r.status === "HOLD" && r.review_note ? c.html`<span class="sub">${c.short(r.review_note, 90)}</span>` : ""}</td>
        <td class="small nowrap">${c.when(r.created_at)}</td></tr>`)}</tbody></table>` : c.empty("신청 없음"), { flush: true }) },
    { key: "new", label: "새 신청", body: c.intakeNewBody(pre, fromRepo, catalog) },
  ];
  const cards = c.html`<div class="kpis kpis-3 compact">${deviceCard(c)}
    <a class="kpi ${pending.n ? "alert" : ""}" href="#/my?t=consent"><div class="label">동의 필요</div><div class="value">${pending.n}</div></a>
    <a class="kpi" href="#/my?t=mine"><div class="label">진행 중 신청</div><div class="value">${open}</div></a></div>`;
  return { html: c.page({ head: c.head("내 MCP"), kpis: cards, tabs, active }) };
}
