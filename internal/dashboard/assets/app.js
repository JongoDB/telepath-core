// telepath dashboard — vanilla JS, no build step. Polls /api/state
// every POLL_MS and renders each card via DOM methods (no innerHTML on
// user-controlled values). Intentionally small: this is an operator
// tool, not a SPA. Keep it simple enough to audit in one sitting.

const POLL_MS = 2000;
const byId = (id) => document.getElementById(id);

// On first load with `?t=<token>`, the server has already set the
// session cookie from the query param. Drop the token from the visible
// URL so accidental screenshots / URL-shares don't leak the credential.
// The cookie keeps subsequent fetches authenticated.
(function stripTokenFromURL() {
  try {
    const u = new URL(window.location.href);
    if (u.searchParams.has("t")) {
      u.searchParams.delete("t");
      const clean = u.pathname + (u.search ? u.search : "") + u.hash;
      window.history.replaceState({}, "", clean || "/");
    }
  } catch (_) { /* non-fatal; older browsers fall through without stripping */ }
})();

// el builds a DOM node. Props map: `class`, `text`, `html` (static
// strings only — never user input), `title`, or any event handler
// (onclick, onkeydown...). Children are strings or nodes.
function el(tag, props, ...children) {
  const n = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null) continue;
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v);
    }
  }
  for (const c of children) {
    if (c == null) continue;
    if (typeof c === "string" || typeof c === "number") n.appendChild(document.createTextNode(String(c)));
    else n.appendChild(c);
  }
  return n;
}

// setContent replaces a node's children with the given nodes. Safer
// than clearing via innerHTML since it avoids parsing anything.
function setContent(node, ...children) {
  while (node.firstChild) node.removeChild(node.firstChild);
  for (const c of children) {
    if (c == null) continue;
    node.appendChild(c);
  }
}

function pill(label, variant) {
  return el("span", { class: "pill " + (variant || "muted") }, String(label).toUpperCase());
}

function kv(rows) {
  const dl = el("dl", { class: "kv" });
  for (const [k, v] of rows) {
    if (v == null || v === "") continue;
    dl.appendChild(el("dt", { text: k }));
    dl.appendChild(el("dd", null, v));
  }
  return dl;
}

function code(text) {
  return el("code", { text: String(text) });
}

function fmtTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// --- Top bar + warnings --------------------------------------------

function renderEngagementBar(bar, eng) {
  if (!eng) {
    setContent(bar,
      el("span", { class: "muted" }, "no active engagement — run "),
      el("code", { text: "telepath engagement load <id>" })
    );
    return;
  }
  const statusClass = (eng.status || "unknown").toLowerCase();
  setContent(bar,
    el("span", { class: "eng-id", text: eng.id || "?" }),
    document.createTextNode(" · "),
    el("span", { class: "eng-client" },
      eng.client_name || "",
      eng.assessment_type ? " · " + eng.assessment_type : ""),
    document.createTextNode(" "),
    el("span", { class: "status-pill " + statusClass, text: (eng.status || "unknown") }),
  );
}

function renderWarnings(el_, warnings) {
  if (!warnings || warnings.length === 0) { el_.hidden = true; setContent(el_); return; }
  el_.hidden = false;
  const ul = el("ul");
  for (const w of warnings) ul.appendChild(el("li", { text: w }));
  setContent(el_, ul);
}

// --- Cards ----------------------------------------------------------

function cardTitle(label, badge) {
  const h = el("h2", null, label);
  if (badge != null) {
    h.appendChild(document.createTextNode(" "));
    h.appendChild(el("span", { class: "badge", text: String(badge) }));
  }
  return h;
}

function renderDaemon(card, s) {
  if (!s.daemon) {
    card.classList.add("offline");
    setContent(card,
      cardTitle("daemon"),
      el("div", { class: "card-body" }, pill("offline", "bad")),
      el("div", { class: "muted" },
        "run ", code("telepath daemon run"), " in another terminal")
    );
    return;
  }
  card.classList.remove("offline");
  const rows = [
    ["version", code(s.daemon.version || "?")],
  ];
  if (s.daemon.socket) rows.push(["socket", code(s.daemon.socket)]);
  setContent(card,
    cardTitle("daemon"),
    el("div", null, pill("running", "good")),
    kv(rows)
  );
}

function renderEngagementCard(card, eng) {
  if (!eng) {
    setContent(card,
      cardTitle("engagement"),
      el("div", null, pill("none loaded", "muted")),
      el("div", { class: "muted" }, "run ", code("telepath engagement load <id>"))
    );
    return;
  }
  const statusClass = (eng.status || "unknown").toLowerCase();
  const rows = [
    ["id", code(eng.id)],
    ["client", eng.client_name || "—"],
    ["type", eng.assessment_type || "—"],
    ["status", el("span", { class: "pill " + statusClass, text: eng.status || "unknown" })],
  ];
  if (eng.operator_id) rows.push(["operator", eng.operator_id]);
  setContent(card, cardTitle("engagement"), kv(rows));
}

function renderTransport(card, t) {
  if (!t) {
    setContent(card,
      cardTitle("transport"),
      el("div", null, pill("down", "muted")),
      el("div", { class: "muted" }, "run ", code("telepath transport up direct"))
    );
    return;
  }
  const variant = t.state === "up" ? "good" : t.state === "error" ? "bad" : "warn";
  const rows = [
    ["kind", code(t.kind || "?")],
  ];
  if (t.detail) rows.push(["detail", t.detail]);
  if (t.hint) rows.push(["hint", el("span", { class: "muted", text: t.hint })]);
  setContent(card,
    cardTitle("transport"),
    el("div", null, pill(t.state || "?", variant)),
    kv(rows)
  );
}

function renderOAuth(card, conns) {
  if (!conns || conns.length === 0) {
    setContent(card,
      cardTitle("oauth"),
      el("div", null, pill("none", "muted")),
      el("div", { class: "muted" },
        "run ", code("telepath oauth begin <provider>"), " for SaaS access")
    );
    return;
  }
  const ul = el("ul", { class: "recent-list" });
  for (const c of conns) {
    const li = el("li", null,
      el("span", { class: "rid", text: c.provider }),
      el("span", { class: "muted", text: "/" + (c.tenant || "default") }),
      document.createTextNode(" "),
      pill(c.expired ? "expired" : "live", c.expired ? "bad" : "good")
    );
    ul.appendChild(li);
  }
  setContent(card, cardTitle("oauth"), ul);
}

function renderFindings(card, count, recent) {
  byId("count-findings").textContent = String(count || 0);
  const title = cardTitle("findings", count || 0);
  if (!recent || recent.length === 0) {
    setContent(card, title, el("div", { class: "muted", text: "no findings recorded yet" }));
    return;
  }
  const ul = el("ul", { class: "recent-list" });
  for (const f of [...recent].reverse()) {
    const sev = (f.severity || "info").toLowerCase();
    ul.appendChild(el("li", null,
      el("span", { class: "rid", text: f.id || "?" }),
      el("span", { class: "rsev " + sev, text: sev }),
      el("span", { text: f.title || "—" })
    ));
  }
  setContent(card, title, ul);
}

function renderNotes(card, count, recent) {
  byId("count-notes").textContent = String(count || 0);
  const title = cardTitle("notes", count || 0);
  if (!recent || recent.length === 0) {
    setContent(card, title, el("div", { class: "muted", text: "no notes recorded yet" }));
    return;
  }
  const ul = el("ul", { class: "recent-list" });
  for (const n of [...recent].reverse()) {
    const snippet = (n.content || "").split("\n")[0].slice(0, 90);
    ul.appendChild(el("li", null,
      el("span", { class: "rid", text: n.id || "?" }),
      el("span", { text: snippet })
    ));
  }
  setContent(card, title, ul);
}

function renderEvidence(card, count) {
  byId("count-evidence").textContent = String(count || 0);
  setContent(card,
    cardTitle("evidence", count || 0),
    el("div", { class: "muted", text: "content-addressed blobs in the engagement vault" })
  );
}

function render(state) {
  renderEngagementBar(byId("engagement-bar"), state.active_engagement);
  renderWarnings(byId("warnings"), state.warnings);
  renderDaemon(byId("card-daemon"), state);
  renderEngagementCard(byId("card-engagement"), state.active_engagement);
  renderTransport(byId("card-transport"), state.transport);
  renderOAuth(byId("card-oauth"), state.oauth);
  renderFindings(byId("card-findings"), state.findings_count, state.recent_findings);
  renderNotes(byId("card-notes"), state.notes_count, state.recent_notes);
  renderEvidence(byId("card-evidence"), state.evidence_count);
  byId("generated-at").textContent = fmtTime(state.generated_at);
}

async function poll() {
  try {
    const r = await fetch("/api/state", { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const state = await r.json();
    render(state);
  } catch (err) {
    renderWarnings(byId("warnings"), ["dashboard backend unreachable: " + (err.message || err)]);
  }
}

byId("refresh").addEventListener("click", poll);

poll();
setInterval(poll, POLL_MS);
