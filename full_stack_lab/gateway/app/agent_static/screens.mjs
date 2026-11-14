const MINUTE = 60000, HOUR = 3600000, DAY = 86400000;
export const FRESH_MS = 15 * MINUTE;

const at = (value) => { const n = Date.parse(value); return Number.isFinite(n) ? n : null; };
const age = (value, now) => { const n = at(value); return n == null ? Infinity : now - n; };
const count = (rows, test) => rows.filter(test).length;

export const isSilent = (agent, now = Date.now()) => age(agent.last_seen_at, now) > FRESH_MS;
export const reportState = (agent, now = Date.now()) => {
  const gap = age(agent.last_seen_at, now);
  return gap <= FRESH_MS ? "fresh" : gap <= DAY ? "delayed" : "stale";
};

export function endpointCards(agents, now = Date.now()) {
  const live = agents.filter((a) => a.status !== "revoked");
  const state = (key) => count(live, (a) => reportState(a, now) === key);
  const silent = live.length - state("fresh");
  return { total: live.length, reporting: state("fresh"), silent, delayed: state("delayed"), stale: state("stale"),
    quarantined: count(live, (a) => a.managed_state === "quarantined"), pending: count(live, (a) => a.managed_state === "pending") };
}

export function endpointRows(agents, devices, stations, accounts) {
  const byDevice = Object.fromEntries(devices.filter((d) => d.endpoint_id).map((d) => [d.endpoint_id, d]));
  const byStation = Object.fromEntries(stations.map((w) => [w.endpoint_id, w]));
  const byOwner = Object.fromEntries(accounts.map((a) => [a.token, a]));
  return agents.map((a) => {
    const device = byDevice[a.endpoint_id] || null, station = byStation[a.endpoint_id] || null;
    return { ...a, device, harness: station?.harness || "", calls: Number(station?.calls) || 0,
      owner: a.owner_name || station?.display_name || byOwner[a.owner_token]?.display_name || "",
      shadow: Number(a.shadow) || 0, bypass: (device?.bypass || []).length };
  });
}

export function filterEndpoints(rows, { silent = false, now = Date.now() } = {}) {
  return silent ? rows.filter((r) => isSilent(r, now)) : rows;
}

export const PC_STAGES = ["none", "signed", "installed", "active"];
const livePcs = (account, agents) => agents.filter((a) => a.owner_token === account.token && a.status !== "revoked");
export function pcStage(account, agents) {
  const own = livePcs(account, agents);
  if (own.some((a) => a.managed_state === "active")) return "active";
  if (own.length) return "installed";
  return account.status === "active" ? "signed" : "none";
}

export function userCards(accounts, deleted, signups, suspensions) {
  const live = accounts.filter((a) => a.status !== "deleted");
  const stopped = new Set(suspensions.filter((s) => !s.resumed_at).map((s) => s.user_token || s.display_name));
  return { total: live.length, active: count(live, (a) => a.status === "active"), disabled: count(live, (a) => a.status === "disabled"), stopped: stopped.size,
    pending: count(signups, (s) => s.status === "pending"), deleted: deleted.length };
}

export function topBlocked(people, top = 10) {
  return (people || []).filter((p) => !p.other && p.key && Number(p.Block) > 0)
    .sort((a, b) => b.Block - a.Block).slice(0, top).map((p) => ({ name: p.key, value: Number(p.Block), total: Number(p.total) || 0 }));
}

export function peopleStats(people) {
  return Object.fromEntries((people || []).filter((p) => !p.other && p.key).map((p) => [p.key, p]));
}

export function userRows(accounts, deleted, agents, stats = {}) {
  const row = (a, state) => ({ ...a, state, stage: state === "deleted" ? "none" : pcStage(a, agents), pcs: livePcs(a, agents).length,
    calls: stats[a.display_name] ? Number(stats[a.display_name].total) || 0 : 0, blocked: Number(stats[a.display_name]?.Block) || 0 });
  return [...accounts.map((a) => row(a, a.status)), ...deleted.map((a) => row(a, "deleted"))];
}

export function terminationCards(summary) {
  return { open: summary.open_cases || 0, waiting: summary.awaiting_close || 0, overdue: summary.overdue || 0,
    unresolved: summary.unresolved_grades || 0, residue: summary.retired_residue || 0 };
}

export const caseDone = (c) => ({ OPEN: 2, REVOKING: 4, ASSESSED: 6, REOPENED: 2, CLOSED: 7 }[c.status] ?? 2);

export function stageCounts(cases, steps) {
  return steps.map((name, i) => ({ name, value: count(cases, (c) => Math.min(caseDone(c), steps.length - 1) === i) }));
}

export function caseDue(c, slaDays) {
  const n = at(c.opened_at);
  return n == null || !slaDays || c.status === "CLOSED" ? null : new Date(n + slaDays * DAY).toISOString();
}

export function gradeCounts(cases) {
  return ["T1", "T2", "T3"].map((key) => ({ key, value: count(cases, (c) => c.grade === key) }));
}

export function daysLeft(value, now = Date.now()) {
  const n = at(value);
  return n == null ? null : Math.ceil((n - now) / DAY);
}

export function serverCards(servers, registrations, now = Date.now(), soon = 14) {
  const live = servers.filter((s) => s.lifecycle !== "RETIRED");
  const due = count(live, (s) => { const d = daysLeft(registrations?.[s.id]?.valid_until, now); return d != null && d <= soon; });
  return { operating: count(live, (s) => s.lifecycle === "OPERATING" || !s.lifecycle), live: live.length,
    attention: count(live, (s) => ["ERROR", "DRIFT", "PENDING"].includes(s.status)), due,
    unverified: count(live, (s) => s.plane && s.plane.state !== "gateway_enforced" && s.plane.state !== "endpoint_enforced"),
    blocked: count(live, (s) => Number(s.blocked) > 0) };
}

export function serverOrder(servers, registrations, now = Date.now(), soon = 14) {
  const rank = (s) => {
    const d = daysLeft(registrations?.[s.id]?.valid_until, now);
    return d != null && d <= soon ? 0 : ["ERROR", "DRIFT", "PENDING"].includes(s.status) ? 1 : 2;
  };
  const left = (s) => daysLeft(registrations?.[s.id]?.valid_until, now) ?? Infinity;
  return [...servers].sort((a, b) => rank(a) - rank(b) || (rank(a) === 0 ? left(a) - left(b) : 0));
}

export function blockRate(server) {
  return Number(server.calls) > 0 ? Math.round((Number(server.blocked) || 0) / Number(server.calls) * 1000) / 10 : null;
}

export function toolRows(tools, registrations) {
  return tools.map((t) => ({ ...t, scope: registrations?.[t.server_id]?.tool_reviews?.[t.name] || null }));
}

export function shadowGroups(entries) {
  const groups = new Map();
  for (const e of entries) {
    const key = `${e.server_label}\u0000${e.transport}\u0000${e.endpoint_ref}`;
    const g = groups.get(key) || { key, label: e.server_label, transport: e.transport, ref: e.endpoint_ref, cls: e.classification,
      endpoints: new Set(), entries: [], latest: e.reported_at };
    g.endpoints.add(e.endpoint_id);
    g.entries.push(e);
    if (String(e.reported_at) > String(g.latest)) g.latest = e.reported_at;
    if (e.classification === "shadow") g.cls = "shadow";
    groups.set(key, g);
  }
  return [...groups.values()].sort((a, b) => String(b.latest).localeCompare(String(a.latest)));
}

export const shadowPcs = (agents) => count(agents, (a) => a.status !== "revoked" && Number(a.shadow) > 0);

const DECISION_KEYS = ["Allow", "Alert", "Restrict", "Approval", "Block"];
export function seriesRows(series) {
  const rows = new Map();
  for (const r of series || []) {
    const row = rows.get(r.at) || { at: r.at, ...Object.fromEntries(DECISION_KEYS.map((k) => [k, 0])) };
    if (DECISION_KEYS.includes(r.decision)) row[r.decision] += Number(r.n) || 0;
    rows.set(r.at, row);
  }
  return [...rows.values()].sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
}

export function impactRows(servers, users = {}) {
  const order = { "영향 있음": 0, "판단 불가": 1, "자료 없음": 2, "영향 없음": 3 };
  return [...servers].sort((a, b) => (order[a.judgement] ?? 9) - (order[b.judgement] ?? 9))
    .map((s) => ({ ...s, versions: [...new Set((s.evidence || []).map((e) => e.version).filter(Boolean))], users: users[s.server_id] ?? null }));
}

export function intakeCards(requests, reassess = 0) {
  const waiting = requests.filter((r) => ["HOLD", "VALIDATED", "REMOTE_REVIEWED"].includes(r.status));
  const done = (r) => at(r.reviewed_at);
  const finished = requests.filter((r) => ["APPROVED", "REJECTED"].includes(r.status) && done(r) != null && at(r.created_at) != null);
  const days = finished.length ? finished.reduce((s, r) => s + (done(r) - at(r.created_at)), 0) / finished.length / DAY : null;
  return { waiting: waiting.length, days: days == null ? null : Math.round(days * 10) / 10, done: finished.length,
    high: count(waiting, (r) => ["high", "very_high"].includes(r.risk?.tier)),
    reassess: reassess + count(requests, (r) => r.endpoint_reapproval_required) };
}

export function intakeStages(requests) {
  const tally = (list) => count(requests, (r) => list.includes(r.status));
  return [["check", ["VALIDATION_QUEUED", "VALIDATING"]], ["review", ["HOLD", "VALIDATED", "REMOTE_REVIEWED", "FAILED"]],
    ["approved", ["APPROVED"]], ["rejected", ["REJECTED"]]].map(([key, list]) => ({ key, value: tally(list) }));
}

export function riskMix(requests) {
  const tally = { low: 0, medium: 0, high: 0, very_high: 0, none: 0 };
  for (const r of requests) tally[r.risk?.status === "ok" ? r.risk.tier : "none"] += 1;
  return tally;
}

export function scanSummary(evidence = {}) {
  const critical = Number(evidence.critical) || 0, high = Number(evidence.high) || 0;
  return { critical, high, failed: Object.values(evidence.scanners || {}).some((s) => s.status === "FAILED") };
}
