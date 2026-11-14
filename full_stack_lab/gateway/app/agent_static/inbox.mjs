let loaded = [];
const KINDS = [
  ["approval", "호출 승인"], ["intake", "도입 신청"], ["endpoint", "엔드포인트 요청"],
  ["people", "가입·기기"], ["execution", "실행 확인"], ["alert", "경보"],
];
export const KIND_LABEL = { approval: "호출 승인", intake: "도입 신청", endpoint: "엔드포인트 요청", signup: "가입 요청", device: "기기 활성화",
  execution: "실행 확인", alert: "경보" };
const INTAKE_OPEN = ["HOLD", "VALIDATED", "REMOTE_REVIEWED", "FAILED"];
const HOUR = 3600000;

export function alertCallsHref(a) {
  const e = a.evidence || {};
  const at = new Date(a.created_at).getTime();
  if (!Number.isFinite(at) || !(e.server_id || e.policy_id || e.user_token)) return "";
  const q = new URLSearchParams({ since: new Date(at - HOUR).toISOString(), until: new Date(at + HOUR).toISOString() });
  if (e.server_id) q.set("server", e.server_id);
  if (e.policy_id) q.set("policy", e.policy_id);
  if (e.user_token) q.set("principal", e.user_token);
  return `#/activity?${q}`;
}

export const reviewHref = (item) => item.href || `#/inbox?${new URLSearchParams({ f: item.kind, open: item.key })}`;

export const waitText = (ms) => {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return "방금";
  if (s < 3600) return `${Math.floor(s / 60)}분`;
  if (s < 86400) return `${Math.floor(s / 3600)}시간`;
  return `${Math.floor(s / 86400)}일`;
};

const stamp = (value) => { const n = new Date(value).getTime(); return Number.isFinite(n) ? n : 0; };

export async function loadInbox(c) {
  const failed = new Set();
  const ok = (name) => (error) => { failed.add(name); return null; };
  const [first, intents, signups, inventory, requests, asked, alerts, ledger] = await Promise.all([
    c.api("/approvals").catch(ok("approval")),
    c.gw("dispatch-intents").catch(ok("execution")),
    c.api("/api/signup-requests?status=pending").catch(ok("people")),
    c.gw("endpoint/inventory").catch(ok("people")),
    c.api("/api/mcp-requests").catch(ok("intake")),
    c.gw("endpoint/requests").catch(ok("endpoint")),
    c.gw(`audit/alerts?limit=100&read_ranges=${encodeURIComponent(c.alertsSeen().map(([a, b]) => (a === b ? String(a) : `${a}-${b}`)).join(","))}`).catch(ok("alert")),
    c.gw("policy/ledger").catch(() => null),
  ]);
  if (ledger) c.setLedger(ledger.policies || []);
  let pending = first?.approvals || [];
  const pages = first ? Math.min(5, Math.ceil((first.total ?? pending.length) / (first.page_size || 30))) : 0;
  if (pages > 1) {
    const more = await Promise.all(Array.from({ length: pages - 1 }, (_, i) => c.api(`/approvals?page=${i + 2}`).catch(() => null)));
    pending = pending.concat(more.flatMap((page) => page?.approvals || []));
  }
  if (first) c.setApprovalLists(first, { ...first, approvals: pending, page: 1 });
  const items = [];
  for (const a of pending) {
    items.push({ key: `approval:${a.id}`, kind: "approval", type: "approval", at: a.created_at, expires: a.expires_at, own: a.own,
      who: a.display_name || a.requested_by, summary: `${a.server_id}.${a.tool}`, sub: a.reason || a.summary || "", raw: a });
  }
  for (const r of requests?.requests || []) {
    if (!(INTAKE_OPEN.includes(r.status) || (r.status === "APPROVED" && !r.registered_server_id))) continue;
    items.push({ key: `intake:${r.id}`, kind: "intake", type: "intake", at: r.created_at, own: r.own, who: r.submitted_by_name || "—",
      summary: r.display_name, sub: (c.INTAKE_STATUS[r.status] || [])[1] || "", href: `#/intake/${encodeURIComponent(r.id)}`, raw: r });
  }
  for (const r of asked?.requests || []) {
    items.push({ key: `endpoint:${r.id}`, kind: "endpoint", type: "endpoint", at: r.created_at, who: r.owner_name || r.hostname || "—",
      summary: r.server_label, sub: r.purpose || "", raw: r });
  }
  for (const s of signups?.requests || []) {
    if (s.status !== "pending") continue;
    items.push({ key: `signup:${s.id}`, kind: "people", type: "signup", at: s.requested_at, who: s.display_name || s.username,
      summary: s.username, sub: "", raw: s });
  }
  for (const a of inventory?.agents || []) {
    if (a.status === "revoked" || !["pending", "quarantined"].includes(a.managed_state) || !a.policy_hash) continue;
    items.push({ key: `device:${a.endpoint_id}`, kind: "people", type: "device", at: a.last_seen_at, who: a.owner_name || "—",
      summary: a.hostname || a.endpoint_id, sub: c.MANAGED_STATE[a.managed_state] || "", raw: a });
  }
  for (const u of intents?.rows || []) {
    items.push({ key: `execution:${u.request_id}`, kind: "execution", type: "execution", at: u.attempted_at, who: u.display_name || u.user_token,
      summary: `${u.server_id}.${u.tool_name}`, sub: c.ACTION[u.action] || "", raw: u });
  }
  const seen = c.alertsSeen();
  const isSeen = (a) => seen.some(([low, high]) => a.id >= low && a.id <= high);
  for (const group of c.alertGroups((alerts?.alerts || []).filter((a) => !isSeen(a)))) {
    const a = group.rows[0];
    const [target] = c.alertTarget(a);
    items.push({ key: `alert:${a.id}`, kind: "alert", type: "alert", at: group.last, who: target, summary: c.ALERT_KIND[a.kind] || "경보",
      sub: (c.alertReason || c.alertDetail)(a), count: group.rows.length, raw: a, group });
  }
  items.sort((x, y) => stamp(x.at) - stamp(y.at));
  return { items, failed, approvals: first };
}

const waitCell = (c, item) => {
  const now = Date.now();
  const over = item.expires && stamp(item.expires) <= now;
  const age = now - stamp(item.at);
  const tone = over ? "wait-over" : "";
  return c.html`<td class="num nowrap ${tone}" title="${c.when(item.at)}">${item.at ? waitText(age) : "—"}</td>`;
};

const targetCell = (c, item) => {
  if (item.own) return c.chip("outline", "본인 요청");
  const [first, ...rest] = String(item.who ?? "").split(" · ");
  return rest.length ? c.html`<b>${first}</b><span class="sub">${rest.join(" · ")}</span>` : item.who;
};

const row = (c, item) => {
  const open = item.href ? c.html`data-act="goto" data-href="${item.href}"` : c.html`data-act="inbox-open" data-key="${item.key}"`;
  return c.html`<tr class="clickable" tabindex="0" ${c.raw(String(open))}>
    <td class="nowrap">${c.chip(item.type === "alert" ? "alert" : "outline", KIND_LABEL[item.type])}</td>
    <td class="cut"><b>${item.summary}</b>${item.sub ? c.html` <span class="muted">${c.short(item.sub, 60)}</span>` : ""}${item.count > 1 ? c.html`<span class="sub">발생 ${item.count}건</span>` : ""}</td>
    <td class="cut">${targetCell(c, item)}</td>
    ${waitCell(c, item)}
    <td class="num nowrap">${item.expires ? c.when(item.expires) : "—"}</td>
    <td class="num"><button class="btn sm" type="button" ${c.raw(String(open))}>검토</button></td></tr>`;
};

const dated = (items) => items.filter((item) => item.at);
const average = (items) => (dated(items).length ? dated(items).reduce((sum, item) => sum + (Date.now() - stamp(item.at)), 0) / dated(items).length : 0);

export async function inboxRoute(c, query) {
  const filter = KINDS.some(([key]) => key === query.get("f")) ? query.get("f") : "";
  const history = query.get("view") === "history";
  const { items, failed } = await loadInbox(c);
  const counts = Object.fromEntries(KINDS.map(([key]) => [key, items.filter((item) => item.kind === key).length]));
  const shown = filter ? items.filter((item) => item.kind === filter) : items;
  const oldest = dated(items).length ? waitText(Date.now() - Math.min(...dated(items).map((item) => stamp(item.at)))) : "—";
  const events = items.filter((item) => item.kind === "alert").reduce((sum, item) => sum + (item.count || 1), 0);
  const chips = c.html`<nav class="feed-toolbar row-actions inbox-filters" aria-label="유형">
    <a class="btn sm" href="#/inbox" ${filter || history ? "" : c.raw('aria-current="true"')}>전체 <b class="n">${items.length}</b></a>
    ${KINDS.map(([key, label]) => c.html`<a class="btn sm ${counts[key] ? "" : "is-zero"}" href="#/inbox?f=${key}" ${filter === key && !history ? c.raw('aria-current="true"') : ""}>${label} <b class="n ${counts[key] ? "" : "zero"}">${counts[key]}</b></a>`)}
    <a class="btn sm inbox-history" href="#/inbox?view=history" ${history ? c.raw('aria-current="true"') : ""}>처리 이력</a></nav>`;
  const table = shown.length ? c.html`<table class="data rows-32 inbox-table"><thead><tr><th>유형</th><th>요약</th><th>대상</th>
    <th class="num">대기</th><th class="num">만료</th><th></th></tr></thead><tbody>${shown.map((item) => row(c, item))}</tbody></table>`
    : c.empty("처리할 일 없음", { filtered: Boolean(filter) });
  const kpis = c.kpiStrip([["처리할 일", items.length, items.length ? "approval" : ""], ["평균 대기", dated(items).length ? waitText(average(items)) : "—"],
    ["가장 오래된 대기", oldest], ...(counts.alert ? [["경보", `${counts.alert}그룹 · 발생 ${events}건`]] : [])]);
  const status = failed.size ? c.chip("alert", `조회 실패 ${[...failed].map((key) => KIND_LABEL[key] || key).join(", ")}`) : "";
  loaded = items;
  return {
    html: c.html`${c.head("할 일", { status })}${kpis}${chips}
      ${history ? c.approvalHistory() : c.panel("대기 중", table, { flush: true })}`,
    open: query.get("open") || "",
  };
}

const recentCalls = (c, rows) => (rows?.length ? c.html`<table class="data rows-32"><thead><tr><th>시각</th><th>판정</th><th>도구</th></tr></thead><tbody>
  ${rows.map((r) => c.html`<tr><td class="nowrap">${c.when(r.at)}</td><td>${c.decisionChip(r.decision)}</td><td class="cut"><code>${r.server}.${r.tool}</code></td></tr>`)}
  </tbody></table>` : c.empty("최근 호출 없음"));

const decide = (c, ...buttons) => c.html`<div class="row-actions inbox-decide">${buttons.map(([act, label, attrs]) =>
  c.html`<button class="btn" type="button" data-act="${act}" ${c.raw(attrs)}>${label}</button>`)}</div>`;

async function approvalBody(c, item) {
  const a = item.raw;
  const [recent, bundle] = await Promise.all([
    c.gw(`activity?${new URLSearchParams({ principal: a.requested_by, server: a.server_id, event_kind: "tools/call", limit: "5" })}`).catch(() => null),
    a.explanation ? c.gw(`approvals/${a.id}/evidence`).catch(() => null) : null]);
  const rows = (recent?.rows || []).slice(0, 5);
  const buttons = a.own ? c.chip("outline", "본인 요청") : decide(c, ["reject", "거부", `data-id="${a.id}"`], ["approve", "승인", `data-id="${a.id}"`]);
  return { title: item.summary, body: c.html`${c.kv([
    ["요청자", `${a.display_name || a.requested_by}${a.department ? ` · ${a.department}` : ""}`],
    ["도구", c.html`<code>${a.server_id}.${a.tool}</code>`], ["행위", c.ACTION[a.action] || a.action], ["데이터 등급", c.DATA_CLASS[a.data_class] || a.data_class],
    ["적용 정책", a.policy_id ? c.html`${c.policyLabel(a.policy_id)} <span class="muted mono">${a.policy_id}</span>` : ""],
    ["승인 사유", a.reason], ["분류 근거", a.summary], ["요청 시각", c.when(a.created_at, { seconds: true })], ["만료 시각", c.when(a.expires_at)]])}
    ${bundle ? c.html`<h3>설명 증빙</h3>${c.impactExplanation(bundle.explanation)}` : ""}
    <h3>인자</h3>${c.json(a.arguments)}<h3>같은 사용자·서버 최근 호출</h3>${recentCalls(c, rows)}${buttons}` };
}

const bodies = {
  approval: approvalBody,
  signup: async (c, item) => ({ title: item.summary, body: c.html`${c.kv([["아이디", c.html`<code>${item.raw.username}</code>`], ["이름", item.raw.display_name],
    ["요청 시각", c.when(item.raw.requested_at)]])}${decide(c, ["signup-reject", "거부", `data-id="${item.raw.id}"`], ["signup-approve", "승인", `data-id="${item.raw.id}"`])}` }),
  device: async (c, item) => ({ title: item.summary, body: c.html`${c.kv([["사용자", item.who], ["호스트", item.raw.hostname], ["엔드포인트", c.entityRef(item.raw.endpoint_id)],
    ["관리 상태", c.MANAGED_STATE[item.raw.managed_state]], ["마지막 보고", c.ago(item.raw.last_seen_at)]])}
    ${decide(c, ["device-activate", "활성화", `data-id="${item.raw.endpoint_id}" data-hash="${item.raw.policy_hash}"`])}` }),
  execution: async (c, item) => ({ title: item.summary, body: c.html`${c.kv([["사용자", item.who], ["도구", c.html`<code>${item.summary}</code>`], ["행위", item.sub],
    ["전송 시각", c.when(item.raw.attempted_at, { seconds: true })]])}
    ${item.raw.decision_id ? c.html`<a class="btn sm" href="#/activity?d=${item.raw.decision_id}">호출 기록 보기</a>` : ""}
    ${decide(c, ["intent-resolve", "실행 안 됨", `data-id="${item.raw.request_id}" data-outcome="not_executed"`],
      ["intent-resolve", "실행됨", `data-id="${item.raw.request_id}" data-outcome="executed"`])}` }),
  endpoint: async (c, item) => {
    const r = item.raw;
    const draft = new URLSearchParams({ t: "new", name: r.server_label, purpose: r.purpose, source: r.source_url || "", asked: r.id });
    return { title: item.summary, body: c.html`${c.kv([["엔드포인트", r.hostname], ["사용자", r.owner_name], ["MCP", r.server_label],
      ["출처", r.source_url ? c.html`<code>${c.short(r.source_url, 80)}</code>` : ""], ["사용 목적", r.purpose], ["요청 시각", c.when(r.created_at)]])}
      <div class="row-actions inbox-decide"><button class="btn" type="button" data-act="endpoint-request-close" data-id="${r.id}" data-name="${r.server_label}" data-endpoint="${r.hostname}">검토 종료</button>
      <a class="btn" href="#/intake?${draft}">신청서 작성</a></div>` };
  },
  alert: async (c, item) => {
    const a = item.raw;
    const [target, href] = c.alertTarget(a);
    const calls = alertCallsHref(a);
    const rows = item.group.rows;
    return { title: item.summary, body: c.html`${c.kv([["종류", c.ALERT_KIND[a.kind] || "경보"], ["대상", target], ["사유", c.alertDetail(a)],
      ["건수", rows.length], ["최초 시각", c.when(item.group.first)], ["최근 시각", c.when(item.group.last)]])}
      <div class="row-actions inbox-decide"><button class="btn" type="button" data-act="inbox-ack" data-key="${item.key}">읽음 처리</button>
      ${href ? c.html`<a class="btn" href="${href}">대상 보기</a>` : ""}${calls ? c.html`<a class="btn" href="${calls}">관련 호출</a>` : ""}</div>` };
  },
};

export function inboxActions(c) {
  return {
    async "inbox-open"(el) {
      const item = loaded.find((x) => x.key === el.dataset.key);
      if (!item) return;
      const { title, body } = await bodies[item.type](c, item);
      c.openDrawer(title, body);
    },
    "inbox-ack"(el) {
      const item = loaded.find((x) => x.key === el.dataset.key);
      if (!item) return;
      c.markAlertsSeen(item.group.rows);
      c.reload();
      c.refreshBadges();
    },
  };
}
