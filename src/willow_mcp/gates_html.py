"""willow_mcp/gates_html.py — the shared look between the static gates
snapshot (`gates_panel.render_html`) and the live dashboard
(`gates_serve.py`).

The first cut of both pages rendered every row as an equally-sized card in
one flat, undifferentiated grid — accurate, but for a real app that's
mostly ~20 rarely-touched permission rows, it reads as a wall of noise to
scroll through rather than a dashboard. This module is the shared fix:

* **Tabs by category** (`row.category` — egress / system / identity /
  permissions, computed in `gates_panel.py`) instead of one long scroll.
  Egress is the default tab: it's the smallest group and the one with a
  clock and actual consequence; the ~20-row permissions list — routine,
  rarely touched — is a tab away, not the first thing you see.
* **A summary strip** above the tabs so the state that matters (is egress
  open, how many permissions are granted, is the lease ticking) is visible
  without clicking into anything.
* **A compact list, not cards, for the permissions tab** — one line per
  row instead of a large card, since there are many of them and most
  people will look at zero to two on a given visit.
* **`state_label` on every button**, not a bare ON/OFF — "GRANTED",
  "BLOCKED", "ACTIVE", "RUNNING" etc. say what the state means without
  requiring the viewer to already know this codebase's vocabulary.

Both pages share this one JS/CSS block (`SHARED_CSS`, `SHARED_JS`) and
differ only in how rows are loaded (`ROWS` baked in once vs fetched live)
and what a button press does (copy a command vs actually call it) — see
the `LOADER_STATIC`/`LOADER_LIVE` and `ON_CLICK_STATIC`/`ON_CLICK_LIVE`
snippets each caller supplies.
"""
from __future__ import annotations

SHARED_CSS = """
  :root {
    --bg: #0b0d12; --card: #161a22; --border: #262c38; --text: #e6e9ef; --muted: #8b93a3;
    --on: #1f9d55; --on-glow: #22c55e; --off: #c0392b; --off-glow: #ef4444; --warn: #b8860b;
    --accent: #3b82f6;
  }
  @media (prefers-color-scheme: light) {
    :root { --bg: #f3f4f6; --card: #ffffff; --border: #dde1e8; --text: #14171f; --muted: #5b6472; }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 1.75rem 1.25rem 4rem; background: var(--bg); color: var(--text);
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }
  h1 { font-size: 1.3rem; margin: 0 0 .25rem; }
  .sub { color: var(--muted); margin: 0 0 1.25rem; font-size: .9rem; max-width: 70ch; }
  .topbar { display: flex; align-items: center; gap: .75rem; margin-bottom: .25rem; }
  .live-dot {
    width: 8px; height: 8px; border-radius: 50%; background: var(--accent); flex-shrink: 0;
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 30%, transparent);
    animation: pulse 2s ease-in-out infinite;
  }
  @keyframes pulse { 0%, 100% { opacity: .5; } 50% { opacity: 1; } }
  @media (prefers-reduced-motion: reduce) { .live-dot { animation: none; } }

  /* ---- summary strip ---- */
  .summary { display: flex; flex-wrap: wrap; gap: .6rem; margin: 0 0 1.5rem; }
  .chip {
    display: flex; align-items: center; gap: .45rem; background: var(--card);
    border: 1px solid var(--border); border-radius: 10px; padding: .55rem .9rem;
    font-size: .82rem;
  }
  .chip .n { font-weight: 700; font-variant-numeric: tabular-nums; }
  .chip.ok .n, .chip.ok .dot { color: var(--on-glow); }
  .chip.bad .n, .chip.bad .dot { color: var(--off-glow); }
  .chip .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; flex-shrink: 0; }

  /* ---- tabs ---- */
  .tabs {
    display: flex; gap: .35rem; margin-bottom: 1.25rem; border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }
  .tab {
    appearance: none; border: none; background: transparent; color: var(--muted);
    font: inherit; font-size: .85rem; padding: .55rem .9rem; cursor: pointer;
    border-bottom: 2px solid transparent; margin-bottom: -1px;
  }
  .tab:hover { color: var(--text); }
  .tab.active { color: var(--text); border-bottom-color: var(--accent); font-weight: 600; }
  .tab .count {
    display: inline-block; margin-left: .35rem; font-size: .72rem; color: var(--muted);
    background: var(--card); border: 1px solid var(--border); border-radius: 999px;
    padding: .05rem .4rem;
  }

  /* ---- card grid (egress / system / identity) ---- */
  .scope-heading {
    margin: 1.5rem 0 .6rem; font-size: .74rem; letter-spacing: .06em; text-transform: uppercase;
    color: var(--muted);
  }
  .scope-heading:first-child { margin-top: 0; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: .9rem; }
  .card {
    background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    padding: 1rem; display: flex; flex-direction: column; gap: .55rem; min-width: 0;
  }
  .card-head { display: flex; align-items: center; gap: .6rem; min-width: 0; }
  .card-head-text { min-width: 0; }
  .label { font-weight: 600; overflow-wrap: anywhere; }
  .tech { font-size: .72rem; color: var(--muted); font-family: ui-monospace, monospace; overflow-wrap: anywhere; }
  .timer { font-variant-numeric: tabular-nums; font-size: .85rem; color: var(--muted); }
  .detail { font-size: .82rem; color: var(--muted); overflow-wrap: anywhere; }
  .note { font-size: .78rem; color: var(--muted); font-style: italic; margin-top: auto; }
  .status { font-size: .78rem; margin-top: auto; min-height: 1.1rem; }
  .status.ok { color: var(--on-glow); }
  .status.err { color: var(--off-glow); }

  /* ---- compact list (permissions) ---- */
  .perm-list { display: flex; flex-direction: column; gap: 1px; background: var(--border);
               border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  .perm-row {
    display: flex; align-items: center; gap: .75rem; background: var(--card); padding: .55rem .9rem;
    min-width: 0;
  }
  .perm-row .perm-text { flex: 1; min-width: 0; display: flex; align-items: baseline; gap: .5rem; flex-wrap: wrap; }
  .perm-row .label { font-size: .88rem; font-weight: 500; }
  .perm-row .tech { font-size: .7rem; }

  /* ---- shared button ---- */
  .btn {
    appearance: none; border: none; border-radius: 999px; padding: .3rem .8rem;
    font-weight: 700; font-size: .68rem; letter-spacing: .03em; color: #fff; cursor: default;
    flex-shrink: 0; white-space: nowrap;
  }
  .btn.on   { background: var(--on);   box-shadow: 0 0 0 3px color-mix(in srgb, var(--on-glow) 30%, transparent); }
  .btn.off  { background: var(--off);  box-shadow: 0 0 0 3px color-mix(in srgb, var(--off-glow) 30%, transparent); }
  .btn.warn { background: var(--warn); }
  .btn.actionable { cursor: pointer; }
  .btn.actionable:hover { filter: brightness(1.15); }

  .action { display: flex; gap: .4rem; align-items: center; margin-top: auto; }
  .action code {
    flex: 1; min-width: 0; background: var(--bg); border: 1px solid var(--border);
    border-radius: 6px; padding: .35rem .5rem; font-size: .74rem; overflow-x: auto;
    white-space: pre; color: var(--text);
  }
  .copy {
    border: 1px solid var(--border); background: transparent; color: var(--text);
    border-radius: 6px; padding: .35rem .55rem; font-size: .74rem; cursor: pointer;
  }
  .copy:hover { background: var(--border); }

  .toast {
    position: fixed; left: 50%; bottom: 26px; transform: translate(-50%, 12px);
    z-index: 50; background: var(--card); border: 1px solid var(--border); color: var(--text);
    padding: .6rem 1rem; border-radius: 20px; font-size: .82rem;
    opacity: 0; pointer-events: none; transition: opacity .2s ease, transform .2s ease;
    max-width: min(90vw, 60ch); text-align: center;
  }
  .toast.show { opacity: 1; transform: translate(-50%, 0); }
  .toast.ok { border-color: color-mix(in srgb, var(--on-glow) 50%, var(--border)); }
  .toast.err { border-color: color-mix(in srgb, var(--off-glow) 50%, var(--border)); }
"""

#: Same order/titles as gates_panel.CATEGORY_ORDER — kept in sync by
#: test_gates_html.py rather than importing Python into a JS string.
_CATEGORY_ORDER_JS = """
const CATEGORY_ORDER = [
  ["egress", "Egress & network"],
  ["build", "Earn-first build leases"],
  ["system", "System"],
  ["identity", "Identity"],
  ["permissions", "Permissions"],
];
"""

#: The DOM-building logic every gates HTML page shares. Callers provide
#: `loadRows()` (how to get the row list) and `onButtonClick(row, btn)`
#: (what a click on an actionable button does) as separate <script> blocks
#: before this one; this file only reads those two names, it doesn't define
#: them, so static vs live can wire them differently without forking the
#: rendering code itself.
SHARED_JS = """
""" + _CATEGORY_ORDER_JS + """
function copyToClipboard(text, btn) {
  const done = () => { const old = btn.textContent; btn.textContent = "copied"; setTimeout(() => btn.textContent = old, 1200); };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
  } else {
    fallbackCopy(text, done);
  }
}
function fallbackCopy(text, done) {
  const ta = document.createElement("textarea");
  ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
  document.body.appendChild(ta); ta.select();
  try { document.execCommand("copy"); done(); } catch (e) {}
  document.body.removeChild(ta);
}

let toastTimer = null;
function showToast(message, ok) {
  const toast = document.getElementById("toast");
  if (!toast) return;
  toast.textContent = message;
  toast.className = "toast show " + (ok === true ? "ok" : ok === false ? "err" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.classList.remove("show"); }, 3200);
}

function fmtRemaining(s) {
  if (s === null || s === undefined || s <= 0) return "no active grant";
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = Math.floor(s % 60);
  const mm = String(m).padStart(2, "0"), ss = String(sec).padStart(2, "0");
  return h > 0 ? `expires in ${h}h${mm}m${ss}s` : `expires in ${m}m${ss}s`;
}

function timerText(row, elapsedFn) {
  if (row.timer_shape === "lease") {
    if (row.remaining_seconds === null || row.remaining_seconds === undefined) return "no active grant";
    const elapsed = elapsedFn ? elapsedFn() : 0;
    return fmtRemaining(row.remaining_seconds - elapsed);
  }
  if (row.timer_shape === "standing") return "standing — no expiry";
  if (row.timer_shape === "process") return "process-lifetime — restart to change";
  return "—";
}

function isActionable(row) {
  return !!(row.action_cli) || row.id.startsWith("perm.") ||
         row.id.startsWith("lease.") ||
         (row.id.startsWith("binding.") && row.state === "off") ||
         (row.id === "worker" && row.state !== "on");
}

function buildButton(row) {
  const btn = document.createElement("button");
  const actionable = isActionable(row);
  btn.className = "btn " + row.state + (actionable ? " actionable" : "");
  btn.textContent = row.state_label || row.state.toUpperCase();
  btn.disabled = !actionable;
  if (actionable) btn.onclick = () => window.onButtonClick(row, btn);
  return btn;
}

function buildSummary(rows) {
  const wrap = document.createElement("div");
  wrap.className = "summary";

  const consentRows = rows.filter(r => r.id.startsWith("consent."));
  const anyConsentOn = consentRows.some(r => r.state === "on");
  const consentChip = document.createElement("div");
  consentChip.className = "chip " + (anyConsentOn ? "ok" : "bad");
  consentChip.innerHTML = `<span class="dot"></span><span>Egress</span><span class="n">${anyConsentOn ? "some allowed" : "blocked"}</span>`;
  wrap.appendChild(consentChip);

  const permRows = rows.filter(r => r.category === "permissions");
  const grantedCount = permRows.filter(r => r.state === "on").length;
  const permChip = document.createElement("div");
  permChip.className = "chip " + (grantedCount > 0 ? "ok" : "");
  permChip.innerHTML = `<span>Permissions granted</span><span class="n">${grantedCount}/${permRows.length}</span>`;
  wrap.appendChild(permChip);

  const leaseRows = rows.filter(r => r.id.startsWith("lease."));
  const activeLease = leaseRows.find(r => r.state === "on");
  const leaseChip = document.createElement("div");
  leaseChip.className = "chip " + (activeLease ? "ok" : "");
  leaseChip.innerHTML = `<span>Lease</span><span class="n">${activeLease ? "active" : "none"}</span>`;
  wrap.appendChild(leaseChip);

  const worker = rows.find(r => r.id === "worker");
  if (worker) {
    const workerChip = document.createElement("div");
    workerChip.className = "chip " + (worker.state === "on" ? "ok" : (worker.state === "warn" ? "bad" : ""));
    workerChip.innerHTML = `<span>Worker</span><span class="n">${worker.state_label}</span>`;
    wrap.appendChild(workerChip);
  }

  return wrap;
}

function buildCard(row, elapsedFn) {
  const card = document.createElement("div");
  card.className = "card";
  const head = document.createElement("div");
  head.className = "card-head";
  const btn = buildButton(row);
  const textWrap = document.createElement("div");
  textWrap.className = "card-head-text";
  const label = document.createElement("div");
  label.className = "label";
  label.textContent = row.friendly;
  const tech = document.createElement("div");
  tech.className = "tech";
  tech.textContent = row.label;
  textWrap.appendChild(label); textWrap.appendChild(tech);
  head.appendChild(btn); head.appendChild(textWrap);
  card.appendChild(head);

  const timer = document.createElement("div");
  timer.className = "timer";
  timer.dataset.rowId = row.id;
  timer.textContent = timerText(row, elapsedFn);
  card.appendChild(timer);

  const detail = document.createElement("div");
  detail.className = "detail";
  detail.textContent = row.detail;
  card.appendChild(detail);

  if (row.action_cli) {
    // Shown in both modes: transparency about what the button does, not
    // just a static-mode artifact. The copy button is a convenience (e.g.
    // to script the same call) — it never depends on which mode this page
    // is running in.
    const action = document.createElement("div");
    action.className = "action";
    const code = document.createElement("code");
    code.textContent = row.action_cli;
    const copyBtn = document.createElement("button");
    copyBtn.className = "copy";
    copyBtn.textContent = "copy";
    copyBtn.onclick = () => copyToClipboard(row.action_cli, copyBtn);
    action.appendChild(code); action.appendChild(copyBtn);
    card.appendChild(action);
  } else if (row.action_note) {
    const note = document.createElement("div");
    note.className = "note";
    note.textContent = row.action_note;
    card.appendChild(note);
  }

  return card;
}

function buildPermRow(row) {
  const rowEl = document.createElement("div");
  rowEl.className = "perm-row";
  rowEl.appendChild(buildButton(row));
  const text = document.createElement("div");
  text.className = "perm-text";
  const label = document.createElement("span");
  label.className = "label";
  label.textContent = row.friendly;
  const tech = document.createElement("span");
  tech.className = "tech";
  tech.textContent = row.label;
  text.appendChild(label); text.appendChild(tech);
  rowEl.appendChild(text);
  return rowEl;
}

function renderCardSection(container, rows, elapsedFn) {
  const scopes = [...new Set(rows.map(r => r.scope))];
  for (const scope of scopes) {
    const heading = document.createElement("div");
    heading.className = "scope-heading";
    heading.textContent = scope;
    container.appendChild(heading);
    const grid = document.createElement("div");
    grid.className = "grid";
    for (const row of rows.filter(r => r.scope === scope)) {
      grid.appendChild(buildCard(row, elapsedFn));
    }
    container.appendChild(grid);
  }
}

function renderPermissionsSection(container, rows) {
  const scopes = [...new Set(rows.map(r => r.scope))];
  for (const scope of scopes) {
    const heading = document.createElement("div");
    heading.className = "scope-heading";
    heading.textContent = scope;
    container.appendChild(heading);
    const list = document.createElement("div");
    list.className = "perm-list";
    for (const row of rows.filter(r => r.scope === scope)) {
      list.appendChild(buildPermRow(row));
    }
    container.appendChild(list);
  }
}

let ACTIVE_TAB = null;

function renderDashboard(rows, elapsedFn) {
  const root = document.getElementById("root");
  const byCategory = {};
  for (const [key] of CATEGORY_ORDER) byCategory[key] = [];
  for (const row of rows) (byCategory[row.category] || (byCategory[row.category] = [])).push(row);

  const present = CATEGORY_ORDER.filter(([key]) => byCategory[key].length > 0);
  if (!ACTIVE_TAB || !byCategory[ACTIVE_TAB] || byCategory[ACTIVE_TAB].length === 0) {
    ACTIVE_TAB = present.length ? present[0][0] : null;
  }

  root.innerHTML = "";
  root.appendChild(buildSummary(rows));

  const tabs = document.createElement("div");
  tabs.className = "tabs";
  for (const [key, title] of present) {
    const tab = document.createElement("button");
    tab.className = "tab" + (key === ACTIVE_TAB ? " active" : "");
    tab.innerHTML = `${title}<span class="count">${byCategory[key].length}</span>`;
    tab.onclick = () => { ACTIVE_TAB = key; renderDashboard(rows, elapsedFn); };
    tabs.appendChild(tab);
  }
  root.appendChild(tabs);

  const content = document.createElement("div");
  if (ACTIVE_TAB === "permissions") {
    renderPermissionsSection(content, byCategory[ACTIVE_TAB] || []);
  } else if (ACTIVE_TAB) {
    renderCardSection(content, byCategory[ACTIVE_TAB] || [], elapsedFn);
  } else {
    content.textContent = "Nothing to show.";
  }
  root.appendChild(content);
}
"""


def page(*, title: str, subtitle: str, top_extra: str, body_scripts: str) -> str:
    """Assemble a full HTML document from the shared CSS/JS plus a caller's
    loader/action scripts. `top_extra` is any markup between the subtitle
    and the `#root` div (the live page's pulsing dot, the static page's
    nothing). `body_scripts` are the mode-specific <script> contents,
    concatenated after SHARED_JS and before the final render() call."""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
{SHARED_CSS}
</style>
</head>
<body>
{top_extra}
<h1>{title}</h1>
<p class="sub">{subtitle}</p>
<div id="root"></div>
<div id="toast" class="toast"></div>
<script>
{SHARED_JS}
{body_scripts}
</script>
</body>
</html>
"""
