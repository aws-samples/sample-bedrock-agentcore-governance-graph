"use strict";

const $ = (s) => document.querySelector(s);
const state = { region: "us-east-1", graph: null, agents: [], agentName: {}, activeAgent: null, hiddenTypes: new Set(), observe: false, observeWindow: 86400 };

// Safe DOM helper: parse trusted (non-user-controlled) HTML fragments.
// SECURITY NOTE: Only use this for application-generated markup where all
// dynamic values have been escaped with escapeHtml() first. Never pass raw
// user input or unsanitised API data directly.
function trustedFragment(html) {
  const doc = new DOMParser().parseFromString(
    `<body>${html}</body>`, "text/html");
  const frag = document.createDocumentFragment();
  while (doc.body.firstChild) frag.appendChild(doc.body.firstChild);
  return frag;
}

// build the shared query suffix (region + optional Tier-C observe overlay + its lookback window)
const qs = (extra = "") =>
  `region=${encodeURIComponent(state.region)}` +
  `${state.observe ? `&observe=1&observe_window=${state.observeWindow}` : ""}${extra}`;

// node type -> color + short label (Cloudscape / AWS service-icon-ish hues on light canvas)
const TYPE = {
  AgentRuntime:      { c: "#006ce0", s: "AGENT" },  // AWS blue
  Gateway:           { c: "#8c4fff", s: "GW" },     // networking purple
  GatewayTarget:     { c: "#7d52d6", s: "TGT" },
  Tool:              { c: "#5f6b7a", s: "TOOL" },
  Memory:            { c: "#00a1c9", s: "MEM" },
  DataSource:        { c: "#1a9d73", s: "DATA" },   // storage green
  IamRole:           { c: "#d6336c", s: "ROLE" },   // security red/pink
  IamPolicy:         { c: "#c2255c", s: "POL" },
  CedarPolicy:       { c: "#e64980", s: "CEDAR" },
  PolicyEngine:      { c: "#d6336c", s: "PENG" },
  CredentialProvider:{ c: "#d97706", s: "CRED" },   // amber
  WorkloadIdentity:  { c: "#b8860b", s: "WID" },
  ExternalResource:  { c: "#687078", s: "RES" },    // neutral grey
  Registry:          { c: "#8c4fff", s: "REG" },
  RegistryRecord:    { c: "#9c6ade", s: "REC" },
};
const typeMeta = (t) => TYPE[t] || { c: "#7c8898", s: (t || "?").slice(0, 4).toUpperCase() };

let cy = null;

async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
  return r.json();
}

function setLoading(on) { $("#loading").hidden = !on; }

async function loadInventory(refresh = false) {
  state.region = $("#region").value.trim() || "us-east-1";
  state.observe = $("#observe").checked;
  state.observeWindow = parseInt($("#observeWindow").value, 10) || 86400;
  // a rebuild (or region/observe change) invalidates the on-screen graph:
  // it belongs to the previous scope, so clear it back to the empty prompt.
  if (refresh) resetStage();
  setLoading(true);
  try {
    const inv = await api(`/api/inventory?${qs(refresh ? "&refresh=1" : "")}`);
    state.agents = inv.agents;
    state.agentName = Object.fromEntries(inv.agents.map((a) => [a.id, a.name]));
    const acctEl = $("#account");
    acctEl.textContent = "";
    const acctText = document.createTextNode("acct ");
    const acctBold = document.createElement("b");
    acctBold.textContent = inv.account;
    acctEl.appendChild(acctText);
    acctEl.appendChild(acctBold);
    acctEl.appendChild(document.createTextNode(` · ${inv.region} · ${inv.agents.length} agents`));
    $("#agentCount").textContent = inv.agents.length;
    $("#findingsCount").textContent = inv.findingsCount;
    renderAgentList();
  } catch (e) {
    const acctEl = $("#account");
    acctEl.textContent = "";
    const errSpan = document.createElement("span");
    errSpan.className = "dim";
    errSpan.textContent = "error: " + e.message;
    acctEl.appendChild(errSpan);
  } finally {
    setLoading(false);
  }
}

// clear the center graph, findings, drawer, and type filter — used on rebuild
// so a new region/account doesn't leave the previous scope's graph on screen.
function resetStage() {
  state.activeAgent = null;
  state.graph = null;
  if (cy) { cy.destroy(); cy = null; }
  closeDrawer();
  $("#findingsList").textContent = "";
  $("#findingsCount").textContent = "0";
  const tf = $("#typeFilter");
  tf.hidden = true; tf.textContent = "";
  const empty = $("#stageEmpty");
  empty.style.display = "flex";
  empty.textContent = "";
  const p = document.createElement("p");
  p.textContent = "Select an agent to trace its access chain, or show the whole account.";
  empty.appendChild(p);
}

function renderAgentList() {
  const q = $("#filter").value.toLowerCase();
  const ul = $("#agentList");
  ul.textContent = "";
  state.agents
    .filter((a) => a.name.toLowerCase().includes(q) || a.id.toLowerCase().includes(q))
    .forEach((a) => {
      const li = document.createElement("li");
      li.className = state.activeAgent === a.id ? "active" : "";
      const nameDiv = document.createElement("div");
      nameDiv.className = "an";
      nameDiv.textContent = a.name;
      const metaDiv = document.createElement("div");
      metaDiv.className = "am";
      const dot = document.createElement("span");
      dot.className = "dot " + (a.status || "");
      metaDiv.appendChild(dot);
      metaDiv.appendChild(document.createTextNode((a.status || "?") + " · " + (a.protocol || "—")));
      li.appendChild(nameDiv);
      li.appendChild(metaDiv);
      li.onclick = () => selectAgent(a.id);
      ul.appendChild(li);
    });
}

async function selectAgent(agentId) {
  state.activeAgent = agentId;
  renderAgentList();
  await loadGraph(`/api/graph?${qs(`&agent=${encodeURIComponent(agentId)}`)}`);
}

async function showAll() {
  state.activeAgent = null;
  renderAgentList();
  await loadGraph(`/api/graph?${qs()}`);
}

async function loadGraph(url) {
  setLoading(true);
  $("#stageEmpty").style.display = "none";
  try {
    const g = await api(url);
    state.graph = g;
    renderGraph(g);
    renderTypeFilter(g);
    renderFindings(g);
  } catch (e) {
    $("#stageEmpty").style.display = "flex";
    const empty = $("#stageEmpty");
    empty.textContent = "";
    const errP = document.createElement("p");
    errP.style.color = "var(--red)";
    errP.textContent = e.message;
    empty.appendChild(errP);
  } finally {
    setLoading(false);
  }
}

function renderGraph(g) {
  const elements = [];
  for (const n of g.nodes) {
    const m = typeMeta(n.type);
    // shared-by count (fan-in): number of agents that can reach this resource
    const sharedN = (n.attrs && n.attrs.sharedByAgents || []).length;
    const cls = [n.type === "AgentRuntime" ? "agent" : "", sharedN > 1 ? "shared" : ""]
      .filter(Boolean).join(" ");
    elements.push({ data: { id: n.id, label: n.name || m.s, ntype: n.type, color: m.c,
      badge: m.s, shared: sharedN, sharedLabel: sharedN > 1 ? `×${sharedN}` : "" }, classes: cls });
  }
  const present = new Set(g.nodes.map((n) => n.id));
  for (const e of g.edges) {
    if (!present.has(e.from) || !present.has(e.to)) continue;
    elements.push({ data: { id: `${e.from}|${e.to}|${e.type}`, source: e.from, target: e.to,
      etype: e.type, tier: e.tier } });
  }
  // fan-in badges: a small "×N" marker on resources reachable by >1 agent
  for (const n of g.nodes) {
    const sharedN = (n.attrs && n.attrs.sharedByAgents || []).length;
    if (sharedN > 1) {
      elements.push({ data: { id: `badge:${n.id}`, label: `×${sharedN}`, isBadge: true, host: n.id },
        classes: "badge", selectable: false, grabbable: false });
    }
  }

  if (cy) cy.destroy();
  cy = cytoscape({
    container: $("#cy"),
    elements,
    minZoom: 0.15, maxZoom: 3,
    style: [
      { selector: "node", style: {
        "background-color": "data(color)", "background-opacity": 0.9,
        "border-color": "#ffffff", "border-width": 2,
        width: 42, height: 42, shape: "round-rectangle",
        label: "data(label)", color: "#0f141a", "font-size": 9.5,
        "font-family": "Amazon Ember, Open Sans, sans-serif",
        "text-valign": "bottom", "text-margin-y": 6, "text-max-width": 120, "text-wrap": "ellipsis",
        "text-outline-color": "#f2f3f3", "text-outline-width": 2.5,
      }},
      { selector: "node.agent", style: {
        width: 60, height: 60, "border-width": 3, "background-opacity": 1,
        "font-size": 11.5, "font-weight": 700, shape: "round-hexagon",
      }},
      { selector: "node:selected", style: {
        "border-width": 3, "border-color": "#006ce0",
        "overlay-color": "#006ce0", "overlay-opacity": 0.12, "overlay-padding": 8,
      }},
      { selector: "edge", style: {
        width: 1.3, "line-color": "#aab2bd", "target-arrow-color": "#aab2bd",
        "target-arrow-shape": "triangle", "arrow-scale": 0.8,
        "curve-style": "bezier", opacity: 0.85,
      }},
      { selector: 'edge[tier="B"]', style: { "line-style": "dashed", "line-color": "#855900",
        "target-arrow-color": "#855900", opacity: 0.95 }},
      { selector: 'edge[tier="C"]', style: { "line-style": "dotted", "line-color": "#006ce0",
        "target-arrow-color": "#006ce0" }},
      { selector: "edge:selected", style: { "line-color": "#006ce0", width: 2.5, opacity: 1 }},
      { selector: "node.shared", style: { "border-color": "#855900", "border-width": 3 }},
      { selector: "node.badge", style: {
        width: 17, height: 17, shape: "ellipse",
        "background-color": "#855900", "border-color": "#ffffff", "border-width": 1.5,
        label: "data(label)", color: "#ffffff", "font-size": 9, "font-weight": 700,
        "text-valign": "center", "text-halign": "center", "text-margin-y": 0,
        "text-outline-width": 0, "z-index": 20, events: "no",
      }},
      { selector: ".faded", style: { opacity: 0.15 }},
    ],
    layout: layoutFor(g),
  });

  // pin each fan-in badge to the top-right corner of its host node
  const positionBadges = () => {
    cy.nodes(".badge").forEach((b) => {
      const host = cy.getElementById(b.data("host"));
      if (host.length) {
        const p = host.position();
        const r = (host.width() || 42) / 2;
        b.position({ x: p.x + r, y: p.y - r });
      }
    });
  };
  cy.on("layoutstop", positionBadges);
  cy.on("position", "node", (evt) => {
    if (!evt.target.hasClass("badge")) positionBadges();
  });

  cy.on("tap", "node", (evt) => { highlightNeighborhood(evt.target); openDrawer(evt.target.id()); });
  cy.on("tap", (evt) => { if (evt.target === cy) { clearHighlight(); closeDrawer(); } });

  applyTypeFilter();
}

// ---- category (node-type) filter ----
function renderTypeFilter(g) {
  const counts = {};
  for (const n of g.nodes) counts[n.type] = (counts[n.type] || 0) + 1;
  const types = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
  // drop toggles for types no longer present, so hidden state doesn't leak across graphs
  state.hiddenTypes.forEach((t) => { if (!(t in counts)) state.hiddenTypes.delete(t); });

  const el = $("#typeFilter");
  el.hidden = types.length === 0;
  el.textContent = "";
  el.appendChild(trustedFragment(
    types.map((t) => {
      const m = typeMeta(t);
      const off = state.hiddenTypes.has(t) ? " off" : "";
      return `<span class="tf-chip${off}" data-type="${t}">
        <i class="tf-dot" style="background:${m.c}"></i>${t}
        <b class="tf-n">${counts[t]}</b></span>`;
    }).join("") +
    `<span class="tf-actions">
       <button data-act="all">all</button>
       <button data-act="none">none</button>
     </span>`));

  el.querySelectorAll(".tf-chip").forEach((chip) => {
    chip.onclick = () => {
      const t = chip.dataset.type;
      if (state.hiddenTypes.has(t)) state.hiddenTypes.delete(t);
      else state.hiddenTypes.add(t);
      chip.classList.toggle("off");
      applyTypeFilter();
    };
  });
  el.querySelector('[data-act="all"]').onclick = () => {
    state.hiddenTypes.clear();
    el.querySelectorAll(".tf-chip").forEach((c) => c.classList.remove("off"));
    applyTypeFilter();
  };
  el.querySelector('[data-act="none"]').onclick = () => {
    types.forEach((t) => state.hiddenTypes.add(t));
    el.querySelectorAll(".tf-chip").forEach((c) => c.classList.add("off"));
    applyTypeFilter();
  };
}

function applyTypeFilter() {
  if (!cy) return;
  cy.batch(() => {
    cy.nodes().forEach((n) => {
      if (n.hasClass("badge")) {
        // a fan-in badge follows the visibility of its host node
        const host = cy.getElementById(n.data("host"));
        const hide = host.length && state.hiddenTypes.has(host.data("ntype"));
        n.style("display", hide ? "none" : "element");
        return;
      }
      const hide = state.hiddenTypes.has(n.data("ntype"));
      n.style("display", hide ? "none" : "element");
    });
  });
  // edges auto-hide when an endpoint is display:none in Cytoscape
}

function layoutFor(g) {
  // concentric works well for a single-agent access chain (agent at center);
  // breadthfirst falls back nicely for the whole-account view.
  const agents = g.nodes.filter((n) => n.type === "AgentRuntime");
  if (agents.length === 1) {
    return { name: "concentric", concentric: (n) => (n.data("ntype") === "AgentRuntime" ? 10 : n.degree()),
      levelWidth: () => 2, minNodeSpacing: 34, animate: true, animationDuration: 400 };
  }
  return { name: "breadthfirst", directed: true, spacingFactor: 1.15, animate: true, animationDuration: 400 };
}

function highlightNeighborhood(node) {
  const hood = node.closedNeighborhood();
  cy.elements().not(".badge").addClass("faded");
  hood.removeClass("faded");
  // keep a badge as prominent as its host
  cy.nodes(".badge").forEach((b) => {
    b.toggleClass("faded", cy.getElementById(b.data("host")).hasClass("faded"));
  });
}
function clearHighlight() { if (cy) cy.elements().removeClass("faded"); }

function openDrawer(nodeId) {
  const n = state.graph.nodes.find((x) => x.id === nodeId);
  if (!n) return;
  const m = typeMeta(n.type);
  const out = state.graph.edges.filter((e) => e.from === nodeId);
  const inc = state.graph.edges.filter((e) => e.to === nodeId);

  const attrRows = Object.entries(n.attrs || {})
    .filter(([k, v]) => v !== null && v !== undefined && typeof v !== "object" && k !== "sharedByAgents")
    .map(([k, v]) => `<dt>${k}</dt><dd>${escapeHtml(String(v))}</dd>`).join("");

  // multi-tenancy / blast-radius: which agents can reach this resource
  const shared = (n.attrs && n.attrs.sharedByAgents) || [];
  const sharedRows = shared.map((aid) => {
    const nm = state.agentName[aid] || shortId(aid);
    return `<li class="shared-agent" data-agent="${escapeHtml(aid)}">→ ${escapeHtml(nm)}</li>`;
  }).join("");

  const edgeItems = (list, dir) => list.map((e) => {
    const other = dir === "out" ? e.to : e.from;
    const on = state.graph.nodes.find((x) => x.id === other);
    return `<li><span class="etype">${e.type}</span>
      <span class="tierbadge ${e.tier}">${e.tier}</span>
      <span class="etgt">${dir === "out" ? "→" : "←"} ${escapeHtml(on ? on.name : shortId(other))}</span></li>`;
  }).join("");

  const drawerBody = $("#drawerBody");
  drawerBody.textContent = "";
  drawerBody.appendChild(trustedFragment(`
    <span class="d-type" style="background:${hexA(m.c,0.15)};color:${m.c}">${n.type}</span>
    <h3>${escapeHtml(n.name || "(unnamed)")}</h3>
    <div class="d-arn">${escapeHtml(n.id)}</div>
    ${attrRows ? `<div class="d-section"><h4>ATTRIBUTES</h4><dl class="kv">${attrRows}</dl></div>` : ""}
    ${shared.length ? `<div class="d-section"><h4>SHARED WITH (${shared.length} agent${shared.length > 1 ? "s" : ""})</h4><ul class="shared-list">${sharedRows}</ul></div>` : ""}
    ${out.length ? `<div class="d-section"><h4>ACCESSES (${out.length})</h4><ul class="edge-list">${edgeItems(out,"out")}</ul></div>` : ""}
    ${inc.length ? `<div class="d-section"><h4>ACCESSED BY (${inc.length})</h4><ul class="edge-list">${edgeItems(inc,"in")}</ul></div>` : ""}
    <div class="d-section"><h4>PROVENANCE</h4><div class="prov">${escapeHtml(n.sourceApi || "—")}</div></div>
    ${n.raw ? `<div class="d-section"><h4>RAW PAYLOAD</h4><pre class="raw">${escapeHtml(JSON.stringify(n.raw, null, 2))}</pre></div>` : ""}
  `));
  $("#drawer").classList.remove("closed");
  document.querySelector("main").classList.add("drawer-open");

  // click a shared-with agent -> load that agent's chain
  $("#drawerBody").querySelectorAll(".shared-agent").forEach((el) => {
    el.onclick = () => selectAgent(el.dataset.agent);
  });
}
function closeDrawer() {
  $("#drawer").classList.add("closed");
  document.querySelector("main").classList.remove("drawer-open");
}

function renderFindings(g) {
  const list = $("#findingsList");
  $("#findingsCount").textContent = g.findings.length;
  if (!g.findings.length) {
    list.textContent = "";
    list.appendChild(trustedFragment(`<div class="empty-note">No findings for this scope. ✓</div>`));
    return;
  }
  list.textContent = "";
  list.appendChild(trustedFragment(g.findings.map((f) => `
    <div class="finding" data-refs='${escapeHtml(JSON.stringify(f.nodeRefs))}'>
      <span class="sev ${f.severity}">${f.severity.toUpperCase()}</span>
      <span class="frule">${f.rule}</span>
      <span class="fev">${escapeHtml(f.evidence)}</span>
    </div>`).join("")));
  list.querySelectorAll(".finding").forEach((el) => {
    el.onclick = () => {
      const refs = JSON.parse(el.dataset.refs || "[]");
      if (cy && refs.length) {
        const target = cy.getElementById(refs[0]);
        if (target.length) { highlightNeighborhood(target); openDrawer(refs[0]); cy.animate({ center: { eles: target }, zoom: 1.2 }, { duration: 350 }); }
      }
    };
  });
}

// ---- utils ----
function escapeHtml(s) { return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function shortId(id) { return id.length > 40 ? "…" + id.slice(-38) : id; }
function hexA(hex, a) { const n = parseInt(hex.slice(1), 16); return `rgba(${n >> 16 & 255},${n >> 8 & 255},${n & 255},${a})`; }

// ---- wire up ----
$("#refresh").onclick = () => loadInventory(true);
$("#observe").onchange = () => { $("#observeWindow").disabled = !$("#observe").checked; loadInventory(true); };
$("#observeWindow").onchange = () => { if ($("#observe").checked) loadInventory(true); };
$("#region").onkeydown = (e) => { if (e.key === "Enter") loadInventory(true); };
$("#filter").oninput = renderAgentList;
$("#showAll").onclick = showAll;
$("#drawerClose").onclick = closeDrawer;
$("#findingsToggle").onclick = () => $("#findings").classList.toggle("collapsed");

loadInventory();
