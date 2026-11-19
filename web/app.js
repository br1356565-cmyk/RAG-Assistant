// DevOps Audit Assistant: sign-in, weekly brief and chat. No libraries.
// Everything from the server or the model is rendered with textContent, never as HTML.
// Dev mode (local prototype only): a persona picker replaces Entra ID sign-in.
(() => {
  const cfg = window.AUDIT_CONFIG;
  const dev = !!cfg.devMode;
  const store = window.sessionStorage;
  const $ = (id) => document.getElementById(id);

  const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const randomString = () => b64url(crypto.getRandomValues(new Uint8Array(32)));
  const sha256 = (text) => crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

  // ── Entra ID (authorization code + PKCE) ────────────────────────────────
  const authority = dev ? "" : `https://login.microsoftonline.com/${cfg.tenantId}/oauth2/v2.0`;
  const redirectUri = window.location.origin + "/";
  const scope = dev ? "" : `openid profile offline_access ${cfg.apiScope}`;

  async function signIn() {
    const verifier = randomString();
    const state = randomString();
    store.setItem("pkce_verifier", verifier);
    store.setItem("pkce_state", state);
    const params = new URLSearchParams({
      client_id: cfg.clientId, response_type: "code", redirect_uri: redirectUri, scope,
      state, code_challenge: b64url(await sha256(verifier)), code_challenge_method: "S256",
    });
    window.location.assign(`${authority}/authorize?${params}`);
  }

  async function tokenRequest(body) {
    const r = await fetch(`${authority}/token`, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: cfg.clientId, scope, ...body }),
    });
    if (!r.ok) throw new Error("sign-in failed");
    const t = await r.json();
    store.setItem("access_token", t.access_token);
    store.setItem("expires_at", String(Date.now() + (t.expires_in - 60) * 1000));
    if (t.refresh_token) store.setItem("refresh_token", t.refresh_token);
    if (t.id_token) {
      const claims = JSON.parse(atob(t.id_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
      store.setItem("name", claims.name || claims.preferred_username || "");
    }
  }

  async function handleRedirect() {
    if (dev) return;
    const p = new URLSearchParams(window.location.search);
    if (!p.has("code")) return;
    if (p.get("state") !== store.getItem("pkce_state")) throw new Error("state mismatch");
    await tokenRequest({ grant_type: "authorization_code", code: p.get("code"), redirect_uri: redirectUri,
                         code_verifier: store.getItem("pkce_verifier") });
    store.removeItem("pkce_verifier"); store.removeItem("pkce_state");
    window.history.replaceState({}, "", "/");
  }

  async function accessToken() {
    if (dev) return `dev:${store.getItem("persona") || cfg.personas[0].id}`;
    if (store.getItem("access_token") && Date.now() < Number(store.getItem("expires_at"))) {
      return store.getItem("access_token");
    }
    if (store.getItem("refresh_token")) {
      try {
        await tokenRequest({ grant_type: "refresh_token", refresh_token: store.getItem("refresh_token") });
        return store.getItem("access_token");
      } catch (_) { /* fall through to a fresh sign-in */ }
    }
    await signIn();
    return null;
  }

  const authHeaders = async () => {
    const token = await accessToken();
    // CloudFront signs the origin request and overwrites Authorization, so the user's token travels here.
    return token ? { "x-user-authorization": `Bearer ${token}` } : null;
  };

  async function getJSON(path) {
    const headers = await authHeaders();
    if (!headers) return null;
    const r = await fetch(path, { headers });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || `request failed (${r.status})`);
    return data;
  }

  async function postJSON(path, obj) {
    const headers = await authHeaders();
    if (!headers) return null;
    const body = JSON.stringify(obj);
    const r = await fetch(path, {
      method: "POST",
      headers: {
        ...headers,
        "content-type": "application/json",
        // Required for POST bodies through CloudFront origin access control to a Lambda function URL.
        "x-amz-content-sha256": hex(await sha256(body)),
      },
      body,
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(data.error || `request failed (${r.status})`); e.status = r.status; throw e; }
    return { status: r.status, data };
  }

  // ── Rendering helpers (server and model text is always set as text, never HTML) ─────
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  };
  const button = (text, cls, onClick) => {
    const b = el("button", cls || "small", text);
    b.type = "button";
    b.addEventListener("click", onClick);
    return b;
  };
  const chip = (text, kind) => el("span", `chip k-${kind || "neutral"}`, text);
  const ago = (iso) => {
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return new Date(iso).toLocaleDateString();
  };
  const safeStore = {
    get(k) { try { return window.localStorage.getItem(k); } catch (_) { return null; } },
    set(k, v) { try { window.localStorage.setItem(k, v); } catch (_) { /* private mode */ } },
  };
  const sleep = (ms) => new Promise((res) => setTimeout(res, ms));
  const log = $("log");

  // Light formatting for answers: paragraphs, bullet/numbered lists, **bold**, `code`, headings.
  // Built with DOM nodes from text, so nothing the model writes can become markup.
  function inline(parent, text) {
    const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
    for (const p of parts) {
      if (!p) continue;
      if (p.startsWith("**") && p.endsWith("**")) parent.appendChild(el("strong", null, p.slice(2, -2)));
      else if (p.startsWith("`") && p.endsWith("`")) parent.appendChild(el("code", null, p.slice(1, -1)));
      else parent.appendChild(document.createTextNode(p));
    }
  }
  function formatted(text) {
    const box = el("div", "fmt");
    let list = null;
    let para = null;
    for (const raw of String(text || "").split("\n")) {
      const line = raw.trimEnd();
      const bullet = line.match(/^\s*(?:[-*•]|\d+[.)])\s+(.*)$/);
      const head = line.match(/^#{1,4}\s+(.*)$/);
      if (bullet) {
        para = null;
        if (!list) { list = el(/^\s*\d/.test(line) ? "ol" : "ul"); box.appendChild(list); }
        const li = el("li"); inline(li, bullet[1]); list.appendChild(li);
      } else if (head) {
        list = null; para = null;
        const h = el("div", "hd"); inline(h, head[1]); box.appendChild(h);
      } else if (!line.trim()) {
        list = null; para = null;
      } else {
        list = null;
        if (!para) { para = el("p"); box.appendChild(para); } else { para.appendChild(el("br")); }
        inline(para, line);
      }
    }
    return box;
  }

  // ── Theme and navigation ────────────────────────────────────────────────
  const themes = ["auto", "light", "dark"];
  function applyTheme(t) {
    if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
    else delete document.documentElement.dataset.theme;
    $("theme-btn").textContent = `Theme: ${t[0].toUpperCase()}${t.slice(1)}`;
  }
  function cycleTheme() {
    const cur = safeStore.get("theme") || "auto";
    const next = themes[(themes.indexOf(cur) + 1) % themes.length];
    safeStore.set("theme", next);
    applyTheme(next);
  }
  applyTheme(safeStore.get("theme") || "auto");
  $("theme-btn").addEventListener("click", cycleTheme);

  const loaders = {};                         // view -> function that (re)loads it
  let current = null;
  function show(view) {
    if (!document.getElementById(`view-${view}`)) view = "brief";
    const link = document.querySelector(`nav a[data-view="${view}"]`);
    if (link && link.hidden) view = "brief";                     // admin-only views for others
    if (location.hash.slice(1) !== view) history.replaceState(null, "", `#${view}`);   // keep the URL honest

    document.querySelectorAll(".view").forEach((v) => { v.hidden = v.id !== `view-${view}`; });
    document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === view));
    $("top-title").textContent = document.getElementById(`view-${view}`).dataset.title;
    document.body.classList.remove("nav-open");
    if (current !== view && loaders[view]) loaders[view]().catch((err) => console.error(err));
    current = view;
    if (view === "chat") $("q").focus();
  }
  window.addEventListener("hashchange", () => show(location.hash.slice(1)));
  $("menu-btn").addEventListener("click", () => document.body.classList.toggle("nav-open"));
  $("scrim").addEventListener("click", () => document.body.classList.remove("nav-open"));

  // Keyboard: "/" to ask, "g" then a letter to go somewhere, "t" theme, "?" help.
  const help = $("help");
  $("help-btn").addEventListener("click", () => help.showModal());
  $("help-close").addEventListener("click", () => help.close());
  let pendingG = 0;
  document.addEventListener("keydown", (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.target.isContentEditable;
    if (e.key === "Escape") { document.body.classList.remove("nav-open"); if (typing) e.target.blur(); return; }
    if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
    const go = { b: "brief", f: "findings", c: "chat", i: "infra", r: "review", n: "conventions", t: "teams" };
    if (pendingG && Date.now() - pendingG < 1200 && go[e.key]) { location.hash = go[e.key]; pendingG = 0; e.preventDefault(); return; }
    pendingG = 0;
    if (e.key === "g") { pendingG = Date.now(); return; }
    if (e.key === "/") { e.preventDefault(); location.hash = "chat"; show("chat"); $("q").focus(); return; }
    if (e.key === "t") { cycleTheme(); return; }
    if (e.key === "?") { help.showModal(); }
  });

  // A small inline form: a text box and a submit button, replacing the trigger until sent.
  function inlineForm(host, placeholder, sendLabel, onSend) {
    const row = el("div", "inline-form");
    const input = el("input");
    input.placeholder = placeholder;
    input.maxLength = 1000;
    const status = el("span", "muted");
    const send = button(sendLabel, "small", async () => {
      send.disabled = true;
      try { status.textContent = (await onSend(input.value.trim())) || "Sent"; input.disabled = true; }
      catch (err) { status.textContent = err.message; send.disabled = false; }
    });
    row.append(input, send, status);
    host.appendChild(row);
    input.focus();
  }

  // ── Weekly brief ────────────────────────────────────────────────────────
  // Where a finding's fix stands. One request can cover several findings (same package).
  const fixInfo = {
    drafting: ["Fix being drafted", "info"], awaiting_approval: ["Fix waiting for a lead", "warn"],
    approved: ["Approved, opening PR", "info"], opened: ["Fix PR opened", "ok"],
    rejected: ["Fix rejected", "bad"], failed: ["Fix failed", "bad"],
  };
  const canDraft = (it) => it.source === "dependabot" && cfg.fixAgent !== false
    && (!it.fix_request || ["rejected", "failed"].includes(it.fix_request.status));

  function fixLine(fr) {
    const row = el("div", "fixline");
    const [label, kind] = fixInfo[fr.status] || [fr.status, "neutral"];
    row.appendChild(chip(label, kind));
    if (fr.major_upgrade) row.appendChild(chip("major upgrade", "warn"));
    if (fr.pr_url) {
      const a = el("a", null, fr.pr_url.startsWith("file:") ? "dry-run PR" : "View PR");
      a.href = fr.pr_url; a.target = "_blank"; a.rel = "noopener";
      row.appendChild(a);
    } else if (fr.status === "awaiting_approval") {
      const a = el("a", null, "Open in Review"); a.href = "#review";
      row.appendChild(a);
    }
    if (fr.error) row.appendChild(el("span", "muted", fr.error));
    row.appendChild(el("span", "muted", `${fr.requested_by ? `by ${fr.requested_by} · ` : ""}${ago(fr.updated_at)}`));
    return row;
  }

  function fixButton(findingId, label) {
    const wrap = el("span");
    const b = button(label || "Draft a fix", "small ghost", async () => {
      b.disabled = true;
      try {
        const { data } = await postJSON("/api/fixes/request", { finding_id: findingId });
        wrap.replaceChildren(el("span", "muted", data.status === "awaiting_approval"
          ? `Fix drafted (${data.change || "see Review"}${data.covers > 1 ? `, covers ${data.covers} findings` : ""}`
            + `${data.major_upgrade ? ", MAJOR upgrade" : ""}); a team lead approves it in Review.`
          : (data.note || `Fix request ${data.status}`)));
        refreshReviewCount();
      } catch (err) { wrap.replaceChildren(el("span", "muted", err.message)); }
    });
    wrap.appendChild(b);
    return wrap;
  }

  function disputeButton(item, findingId) {
    return button("This is wrong", "small ghost", (e) => {
      e.target.remove();
      inlineForm(item, "What is wrong? (the next run re-investigates it)", "Send", async (note) => {
        await postJSON("/api/findings/dispute", { finding_id: findingId, note });
        return "Thanks: its explanation is hidden until the next run re-checks it (or a lead approves it).";
      });
    });
  }

  const kpi = (n, label, cls) => { const k = el("div", `kpi ${cls || ""}`); k.append(el("b", null, String(n)), el("span", null, label)); return k; };

  async function loadBrief() {
    const box = $("brief");
    const headers = await authHeaders();
    if (!headers) return;
    const r = await fetch("/api/brief", { headers });
    if (!r.ok) { box.replaceChildren(el("div", "muted", "The weekly brief isn't available here.")); return; }
    const b = await r.json();
    $("brief-asof").textContent = b.as_of ? `Data as of ${new Date(b.as_of).toLocaleString()}` : "No weekly run yet";
    box.replaceChildren();
    if (b.unowned_repos !== undefined) {
      const c = el("div", "card team-card");
      c.appendChild(el("div", "team-head")).appendChild(el("h2", null, "Across all teams"));
      const k = el("div", "kpis");
      k.append(kpi(b.unowned_repos, "repos without an owner", b.unowned_repos ? "high" : ""), kpi(b.unowned_findings, "findings on unowned repos"));
      c.appendChild(k);
      box.appendChild(c);
    }
    const teams = b.teams.filter((t) => Object.keys(t.open_by_severity).length || t.top.length);
    if (!teams.length) box.appendChild(el("div", "card empty", "No open findings. 🎉"));
    for (const t of teams) {
      const card = el("div", "card team-card");
      const head = el("div", "team-head");
      head.append(el("h2", null, t.name), el("span", "muted", `${t.this_week.opened} new · ${t.this_week.fixed} fixed since last run`));
      card.appendChild(head);
      const sev = t.open_by_severity;
      const k = el("div", "kpis");
      k.append(kpi(sev.critical || 0, "critical", "crit"), kpi(sev.high || 0, "high", "high"),
               kpi((sev.medium || 0) + (sev.low || 0), "medium / low"), kpi(t.accepted_risks || 0, "accepted risks"));
      if (t.awaiting_review) k.append(kpi(t.awaiting_review, "waiting for a lead", "high"));
      card.appendChild(k);
      if (t.top.length) card.appendChild(el("h2", null, "Fix first"));
      for (const it of t.top) {
        const item = el("div", "item");
        const title = el("div", "item-title");
        title.append(el("span", `sev sev-${it.severity}`, it.severity), document.createTextNode(it.title));
        if (it.reviewed) title.appendChild(el("span", "tag", "reviewed by a lead"));
        item.appendChild(title);
        item.appendChild(el("div", "muted", `${it.resource} · open ${it.open_days} days · ${it.id}`));
        if (it.summary) item.appendChild(el("div", null, it.summary));
        if (it.fix) item.appendChild(el("div", null, `Fix: ${it.fix}`));
        if (it.investigated_on) {
          item.appendChild(el("div", "meta", `Investigated ${it.investigated_on} · impact ${it.impact} · confidence ${it.confidence}`));
        }
        if (it.fix_request) item.appendChild(fixLine(it.fix_request));
        const actions = el("div", "actions");
        if (it.summary) actions.appendChild(disputeButton(item, it.id));
        if (canDraft(it)) actions.appendChild(fixButton(it.id, it.fix_request ? "Draft again" : "Draft a fix"));
        if (actions.childElementCount) item.appendChild(actions);
        card.appendChild(item);
      }
      if (t.open_total > t.top.length) {
        const a = el("a", "see-all", `See all ${t.open_total} open findings →`);
        a.href = "#findings";
        a.addEventListener("click", () => { findingsState.team = t.id; findingsState.page = 1; });
        card.appendChild(a);
      }
      box.appendChild(card);
    }
  }
  loaders.brief = loadBrief;

  // ── Findings (everything, not just the brief's top few) ──────────────────
  const SEVS = ["critical", "high", "medium", "low", "info"];
  const findingsState = { q: "", sev: [], source: "", team: "", fix: "", status: "open", page: 1 };
  let findingsTimer = 0;

  function syncFilters(data) {
    const src = $("f-source");
    if (src.options.length === 1) {
      data.sources.forEach((x) => { const o = el("option", null, x); o.value = x; src.appendChild(o); });
    }
    src.value = findingsState.source;
    const team = $("f-team");
    if (!team.options.length) {
      const all = el("option", null, "All my teams"); all.value = ""; team.appendChild(all);
      data.teams.forEach((x) => { const o = el("option", null, x); o.value = x; team.appendChild(o); });
      team.hidden = data.teams.length < 2;
    }
    team.value = findingsState.team;
    $("f-fix").value = findingsState.fix;
    $("f-status").value = findingsState.status;
    if (document.activeElement !== $("f-q")) $("f-q").value = findingsState.q;   // never clobber typing
    document.querySelectorAll("#f-sev button").forEach((b) => b.setAttribute("aria-pressed", String(findingsState.sev.includes(b.dataset.sev))));
  }

  let findingsSeq = 0;
  async function loadFindings() {
    const box = $("findings");
    const seq = ++findingsSeq;                                   // only the latest response renders
    const p = new URLSearchParams({ status: findingsState.status, page: String(findingsState.page), size: "50" });
    if (findingsState.q) p.set("q", findingsState.q);
    if (findingsState.sev.length) p.set("severity", findingsState.sev.join(","));
    for (const k of ["source", "team", "fix"]) if (findingsState[k]) p.set(k, findingsState[k]);
    let data;
    try { data = await getJSON(`/api/findings?${p}`); } catch (err) {
      if (seq === findingsSeq) box.replaceChildren(el("div", "error-box", err.message));
      return;
    }
    if (!data || seq !== findingsSeq) return;
    syncFilters(data);
    const from = data.total ? (data.page - 1) * data.size + 1 : 0;
    const to = Math.min(data.total, data.page * data.size);
    $("findings-sub").textContent = data.total
      ? `${data.total} finding${data.total > 1 ? "s" : ""} · showing ${from}–${to} · most severe first`
      : "No findings match these filters.";
    const list = el("div", "card flist");
    if (!data.findings.length) list.appendChild(el("div", "empty", "Nothing here. 🎉"));
    for (const it of data.findings) {
      const row = el("div", "frow");
      row.appendChild(el("span", `sev sev-${it.severity}`, it.severity));
      const mid = el("div");
      mid.appendChild(el("div", "t", it.title));
      mid.appendChild(el("div", "muted", [it.resource, it.team || "unowned", it.source,
        it.status === "open" ? `open ${it.open_days} days` : it.status, it.id].join(" · ")));
      if (it.summary) mid.appendChild(el("div", "reasoning", it.summary));
      else if (it.fix) mid.appendChild(el("div", "reasoning", `Fix: ${it.fix}`));
      row.appendChild(mid);
      const fixc = el("div", "fixcell");
      if (it.fix_request) fixc.appendChild(fixLine(it.fix_request));
      if (it.status === "open" && canDraft(it)) fixc.appendChild(fixButton(it.id, it.fix_request ? "Draft again" : "Draft a fix"));
      if (it.url) { const a = el("a", "muted", "Source"); a.href = it.url; a.target = "_blank"; a.rel = "noopener"; fixc.appendChild(a); }
      row.appendChild(fixc);
      list.appendChild(row);
    }
    box.replaceChildren(list);
    const pager = $("findings-pager");
    pager.replaceChildren();
    const pages = Math.max(1, Math.ceil(data.total / data.size));
    if (pages > 1) {
      const prev = button("← Previous", "small ghost", () => { findingsState.page -= 1; loadFindings(); window.scrollTo(0, 0); });
      const next = button("Next →", "small ghost", () => { findingsState.page += 1; loadFindings(); window.scrollTo(0, 0); });
      prev.disabled = data.page <= 1; next.disabled = data.page >= pages;
      pager.append(prev, el("span", "muted", `Page ${data.page} of ${pages}`), next);
    }
  }
  loaders.findings = loadFindings;

  (function setupFindingsFilters() {
    const sev = $("f-sev");
    for (const x of SEVS) {
      const b = button(x, "", () => {
        const on = findingsState.sev.includes(x);
        findingsState.sev = on ? findingsState.sev.filter((y) => y !== x) : [...findingsState.sev, x];
        findingsState.page = 1; loadFindings();
      });
      b.dataset.sev = x; b.setAttribute("aria-pressed", "false");
      sev.appendChild(b);
    }
    const bind = (id, key) => $(id).addEventListener("change", (e) => { findingsState[key] = e.target.value; findingsState.page = 1; loadFindings(); });
    bind("f-source", "source"); bind("f-team", "team"); bind("f-fix", "fix"); bind("f-status", "status");
    $("f-q").addEventListener("input", (e) => {
      clearTimeout(findingsTimer);
      findingsTimer = setTimeout(() => { findingsState.q = e.target.value.trim(); findingsState.page = 1; loadFindings(); }, 300);
    });
    $("findings-filters").addEventListener("submit", (e) => e.preventDefault());
  })();

  // ── Review ──────────────────────────────────────────────────────────────
  const decisionLabel = { approved: "Approved", rejected: "Rejected", active: "Approved", opened: "PR opened" };

  function decide(card, path, payload, choices, after) {
    const row = el("div", "actions");
    const status = el("span", "muted");
    for (const [label, decision, cls] of choices) {
      row.appendChild(button(label, cls, async () => {
        row.querySelectorAll("button").forEach((x) => { x.disabled = true; });
        status.textContent = "Saving…";
        try {
          const { data } = await postJSON(path, { ...(typeof payload === "function" ? payload(decision) : payload), decision });
          if (data.status === "failed") {             // decision recorded, but the PR could not be opened
            status.textContent = `Approved, but no PR was opened: ${data.error || "unknown error"}`;
          } else {
            status.textContent = data.pr_url ? `PR opened: ${data.pr_url}` : (decisionLabel[data.status || data.state] || "Saved");
          }
          card.classList.add("decided");
          refreshReviewCount();
          if (after) after(data);
        } catch (err) {
          status.textContent = err.status === 403 ? "Only a team lead or admin can decide this." : err.message;
          row.querySelectorAll("button").forEach((x) => { x.disabled = false; });
        }
      }));
    }
    row.appendChild(status);
    card.appendChild(row);
    return row;
  }

  function diffBlock(text) {
    const pre = el("pre", "diff");
    String(text || "").split("\n").forEach((line) => {
      const cls = line.startsWith("@@") ? "hunk" : line.startsWith("+") && !line.startsWith("+++") ? "add"
        : line.startsWith("-") && !line.startsWith("---") ? "del" : null;
      pre.appendChild(el("span", cls, `${line}\n`));
    });
    return pre;
  }

  async function loadReview() {
    const panel = $("review");
    let data;
    try { data = await getJSON("/api/reviews"); } catch (err) { panel.replaceChildren(el("div", "muted", err.message)); return; }
    if (!data) return;
    panel.replaceChildren();
    if (!data.can_decide) panel.appendChild(el("div", "warn", "You can see these; a team lead or admin decides them."));
    const total = data.investigations.length + data.notes.length + data.fixes.length;
    if (!total) panel.appendChild(el("div", "card empty", "Nothing is waiting. ✓"));

    const section = (title, items, render) => {
      if (!items.length) return;
      panel.appendChild(el("h2", null, `${title} (${items.length})`));
      const card = el("div", "card");
      items.forEach((x) => card.appendChild(render(x)));
      panel.appendChild(card);
    };
    section("Investigations", data.investigations, (inv) => {
      const item = el("div", "item");
      const title = el("div", "item-title");
      title.append(el("span", `sev sev-${inv.severity}`, inv.severity), document.createTextNode(inv.title),
                   el("span", "tag warn-tag", inv.state === "disputed" ? "disputed by the team" : "low confidence"));
      item.appendChild(title);
      item.appendChild(el("div", "muted", `${inv.resource} · ${inv.finding} · confidence ${
        inv.confidence === null ? "?" : `${Math.round(inv.confidence * 100)}%`} · impact ${inv.impact || "?"}`));
      if (inv.summary) item.appendChild(el("div", null, inv.summary));
      if (inv.fix) item.appendChild(el("div", null, `Suggested fix: ${inv.fix}`));
      if (data.can_decide) {
        const override = el("input", "wide");
        override.placeholder = "Optional: corrected fix to show in the brief";
        override.maxLength = 300;
        item.appendChild(override);
        decide(item, "/api/reviews/investigation",
               () => ({ investigation_id: inv.investigation_id, fix_override: override.value.trim() || undefined }),
               [["Approve", "approved", "small"], ["Reject", "rejected", "small danger"]]);
      }
      return item;
    });
    section("Team notes proposed by the agent", data.notes, (n) => {
      const item = el("div", "item");
      item.appendChild(el("div", "item-title", `${n.kind.replace(/_/g, " ")}${n.finding ? ` · ${n.finding}` : ""}`));
      item.appendChild(el("div", null, n.text));
      item.appendChild(el("div", "muted", `${n.team} · proposed by ${n.author}${n.expires ? ` · expires ${n.expires}` : ""}`));
      if (data.can_decide) decide(item, "/api/reviews/note", { note_id: n.note_id },
                                  [["Approve", "active", "small"], ["Reject", "rejected", "small danger"]]);
      return item;
    });
    section("Fixes to approve", data.fixes, (f) => {
      const item = el("div", "item");
      const title = el("div", "item-title", `${f.repo} · ${f.manifest}`);
      if (f.major_upgrade) title.appendChild(el("span", "tag warn-tag", "major upgrade: check breaking changes"));
      item.appendChild(title);
      const n = (f.covers || []).length;
      item.appendChild(el("div", "muted", `${n > 1 ? `Fixes ${n} findings for ${f.package}` : f.finding} · requested by ${f.requested_by}`));
      if (f.rationale) item.appendChild(el("div", null, f.rationale));
      item.appendChild(diffBlock(f.diff));
      if (data.can_decide && f.own) {
        item.appendChild(el("div", "muted", "You requested this fix; another lead or an admin approves it."));
      } else if (data.can_decide) {
        decide(item, "/api/fixes/decide", { fix_request_id: f.fix_request_id, content_sha256: f.content_sha256 },
               [["Approve and open PR", "approved", "small"], ["Reject", "rejected", "small danger"]]);
      }
      return item;
    });
  }
  loaders.review = loadReview;

  async function refreshReviewCount() {
    try {
      const data = await getJSON("/api/reviews");
      if (!data) return;
      const n = data.investigations.length + data.notes.length + data.fixes.length;
      const b = $("review-count");
      b.textContent = String(n);
      b.hidden = !n;
    } catch (_) { /* reviews not deployed here */ }
  }

  // ── Chat ───────────────────────────────────────────────────────────────
  function add(kind, text, cited, meta) {
    $("chat-empty").hidden = true;
    const div = el("div", `msg ${kind}`);
    if (kind === "bot") div.appendChild(formatted(text)); else div.textContent = text;
    if (cited && cited.length) {
      const row = el("div");
      cited.forEach((id) => row.appendChild(el("span", "cite", id)));
      div.appendChild(row);
    }
    if (meta) div.appendChild(el("div", "meta", meta));
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
    return div;
  }

  function suggestions() {
    const box = $("suggest");
    box.replaceChildren();
    ["What should we fix first this week?", "Is the axios issue actually reachable?",
     "Which critical alerts are in runtime dependencies?", "Why is checkout returning 502s?"].forEach((q) => {
      box.appendChild(button(q, "", () => { $("q").value = q; $("ask").requestSubmit(); }));
    });
  }

  function stepList(list, steps, live) {
    list.replaceChildren();
    (steps.length ? steps : ["Starting"]).forEach((s, i, all) => {
      const cls = live && i === all.length - 1 ? "step current" : /^Not confident|retry/i.test(s) ? "step retry" : "step done";
      list.appendChild(el("li", cls, s));
    });
  }

  function progressBox() {
    $("chat-empty").hidden = true;
    const div = el("div", "msg bot progress");
    const timer = el("div", "meta", "Working… 0s");
    const list = el("ul", "steps");
    div.append(list, timer);
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
    const started = Date.now();
    const tick = setInterval(() => { timer.textContent = `Working… ${Math.round((Date.now() - started) / 1000)}s`; }, 1000);
    return {
      show(steps) { stepList(list, steps, true); log.scrollTop = log.scrollHeight; },
      remove() { clearInterval(tick); div.remove(); },
    };
  }

  function feedbackRow(msg, data) {
    const row = el("div", "actions");
    const status = el("span", "muted");
    const send = async (rating, comment) => {
      await postJSON("/api/feedback", { session_id: data.session_id, job_id: data.job_id, rating, comment,
                                        answer: (data.answer || "").slice(0, 4000) });
      return "Thanks for the feedback.";
    };
    const up = button("👍 Helpful", "small ghost", async () => {
      row.querySelectorAll("button").forEach((b) => { b.disabled = true; });
      try { status.textContent = await send(1); } catch (err) { status.textContent = err.message; }
    });
    const down = button("👎 Not right", "small ghost", () => {
      row.replaceChildren();
      inlineForm(msg, "What was wrong? (optional)", "Send", (comment) => send(-1, comment));
    });
    const copy = button("Copy", "small ghost", async () => {
      try { await navigator.clipboard.writeText(data.answer || ""); status.textContent = "Copied"; }
      catch (_) { status.textContent = "Copy isn't available here"; }
    });
    up.setAttribute("aria-label", "Helpful");
    down.setAttribute("aria-label", "Not right");
    row.append(up, down, copy, status);
    msg.appendChild(row);
  }

  function showAnswer(data) {
    store.setItem("session_id", data.session_id);
    const asOf = data.as_of ? `Data as of ${new Date(data.as_of).toLocaleString()}` : "";
    const conf = typeof data.confidence === "number" ? `confidence ${Math.round(data.confidence * 100)}%` : "";
    const msg = add("bot", data.answer, data.cited,
        [asOf, conf, data.status === "limit" ? "partial answer" : "",
         data.retries ? `checked again ${data.retries}×` : ""].filter(Boolean).join(" · "));
    if (data.low_confidence) {
      const warn = el("div", "warn", "I'm not fully sure about this answer: the evidence I found doesn't cover all of it.");
      if (data.missing && data.missing.length) {
        const ul = el("ul");
        data.missing.forEach((m) => ul.appendChild(el("li", null, m)));
        warn.appendChild(ul);
      }
      msg.appendChild(warn);
    }
    const steps = data.steps || [];
    if (steps.length) {                       // keep the trail, folded, under the answer
      const details = el("details", "trail");
      details.appendChild(el("summary", null, `How I answered (${steps.length} steps)`));
      const list = el("ul", "steps");
      stepList(list, steps, false);
      details.appendChild(list);
      msg.appendChild(details);
    }
    if (data.answer && data.session_id) feedbackRow(msg, data);
  }

  async function ask(question) {
    const res = await postJSON("/api/chat", { question, session_id: store.getItem("session_id") || undefined });
    if (!res) return;
    const data = res.data;
    if (res.status !== 202) return showAnswer(data);      // answered synchronously

    store.setItem("session_id", data.session_id);
    const box = progressBox();
    box.show([]);
    const started = Date.now();
    try {
      while (Date.now() - started < 180000) {
        await sleep(900);
        const job = await getJSON(`/api/chat/job?id=${encodeURIComponent(data.job_id)}`);
        if (!job) return;
        box.show(job.steps || []);
        if (job.status === "done" || job.status === "error") {
          box.remove();
          return showAnswer({ ...(job.result || {}), session_id: data.session_id, job_id: data.job_id,
                              steps: (job.result && job.result.steps) || job.steps });
        }
      }
      throw new Error("the answer is taking too long; please try again");
    } finally {
      box.remove();
    }
  }

  $("ask").addEventListener("submit", async (e) => {
    e.preventDefault();
    const q = $("q");
    const send = $("send");
    const question = q.value.trim();
    if (!question) return;
    add("user", question);
    q.value = ""; send.disabled = true;
    try { await ask(question); } catch (err) { add("bot", `Something went wrong: ${err.message}`); }
    finally { send.disabled = false; q.focus(); }
  });
  $("q").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("ask").requestSubmit(); }
  });
  loaders.chat = async () => {};

  // ── Infra requests (Terraform drafter) ─────────────────────────────────
  const statusChip = {
    drafting: ["Drafting", "info"], needs_input: ["Needs your answer", "warn"], awaiting_approval: ["Waiting for approval", "warn"],
    approved: ["Approved", "ok"], opened: ["PR opened", "ok"], rejected: ["Rejected", "bad"], failed: ["Failed", "bad"],
  };
  const decisionInfo = { new: ["＋", "New Terraform"], reuse: ["↺", "Reuse what exists"], refuse: ["✕", "Shouldn't be built"] };
  let infraSelected = null;
  let infraPoll = 0;

  async function loadInfra() {
    let data;
    try { data = await getJSON("/api/infra"); } catch (err) {
      $("infra-list").replaceChildren(el("div", "muted", err.message)); return;
    }
    if (!data) return;
    $("infra-repos").replaceChildren(...data.repos.map((x) => { const o = el("option"); o.value = x; return o; }));
    if (!$("infra-repo").value) $("infra-repo").value = data.default_repo;
    const list = $("infra-list");
    list.replaceChildren();
    if (!data.requests.length) list.appendChild(el("div", "muted", "No requests yet."));
    for (const r of data.requests) {
      const b = el("button", `req${r.request_id === infraSelected ? " selected" : ""}`);
      b.type = "button";
      b.appendChild(el("div", "t", r.request));
      const m = el("div", "m");
      const [label, kind] = statusChip[r.status] || [r.status, "neutral"];
      m.append(chip(label, kind));
      if (r.decision) m.append(chip(r.decision, "neutral"));
      if (r.warnings) m.append(chip(`${r.warnings} warning${r.warnings > 1 ? "s" : ""}`, "warn"));
      m.append(el("span", "muted", `${r.repo} · ${ago(r.created_at)}`));
      b.appendChild(m);
      b.addEventListener("click", () => selectInfra(r.request_id));
      list.appendChild(b);
    }
  }
  loaders.infra = async () => { await loadInfra(); if (infraSelected) await renderInfra(infraSelected); };

  function selectInfra(id) {
    infraSelected = id;
    document.querySelectorAll(".req").forEach((x) => x.classList.remove("selected"));
    renderInfra(id).catch((err) => $("infra-detail").replaceChildren(el("div", "error-box", err.message)));
    loadInfra();
  }

  async function renderInfra(id) {
    const r = await getJSON(`/api/infra/request?id=${encodeURIComponent(id)}`);
    if (!r || id !== infraSelected) return;
    const box = el("div", "stack");
    const head = el("div", "card");
    const [label, kind] = statusChip[r.status] || [r.status, "neutral"];
    const top = el("div", "item-title");
    top.append(chip(label, kind), el("span", "muted", `${r.repo} · requested by ${r.requested_by} · ${ago(r.created_at)}`));
    head.append(top, el("div", "reasoning", r.request));
    if (r.answer) head.appendChild(el("div", "meta", `Your answer: ${r.answer}`));
    box.appendChild(head);

    if (r.steps && r.steps.length) {
      const c = el("div", "card");
      const live = r.status === "drafting";
      c.appendChild(el("div", "muted", live ? "The drafter is working…" : `What the drafter did (${r.steps.length} steps)`));
      const tl = el("ul", "timeline");
      r.steps.forEach((s, i) => tl.appendChild(el("li", live && i === r.steps.length - 1 ? "current" : "", s)));
      if (live) { c.appendChild(tl); } else {
        const d = el("details"); d.append(el("summary", "muted", "Show steps"), tl); c.appendChild(d);
      }
      box.appendChild(c);
    } else if (r.status === "drafting") {
      box.appendChild(el("div", "card muted", "Starting the drafter…"));
    }

    if (r.status === "needs_input" && r.question) {
      const q = el("div", "card question");
      q.append(el("div", "item-title", "The drafter needs one detail"), el("div", "reasoning", r.question));
      if (r.can_decide) {
        const ta = el("textarea", "reason");
        ta.placeholder = "Your answer";
        const st = el("span", "muted");
        const send = button("Send answer", "small", async () => {
          if (!ta.value.trim()) return;
          send.disabled = true; st.textContent = "Drafting again…";
          try { await postJSON("/api/infra/answer", { request_id: id, answer: ta.value.trim() }); poll(id); }
          catch (err) { st.textContent = err.message; send.disabled = false; }
        });
        const row = el("div", "actions"); row.append(send, st);
        q.append(ta, row);
      } else {
        q.appendChild(el("div", "muted", "Waiting for the requester to answer."));
      }
      box.appendChild(q);
    }

    if (r.decision && r.status !== "needs_input") {
      const [icon, title] = decisionInfo[r.decision] || ["?", r.decision];
      const c = el("div", `card decision ${r.decision}`);
      const ic = el("div", "icon", icon);
      const body = el("div");
      body.append(el("div", "item-title", title), el("div", "reasoning", r.reasoning || ""));
      c.append(ic, body);
      box.appendChild(c);
    }

    if (r.checks && r.checks.length) {
      const c = el("div", "card");
      const failing = r.checks.filter((x) => !x.ok).length;
      c.appendChild(el("div", "item-title", failing ? `Checks: ${failing} warning${failing > 1 ? "s" : ""} for the reviewer` : "Checks: all passed"));
      const ul = el("ul", "checks");
      r.checks.forEach((x) => {
        const li = el("li");
        li.append(chip(x.ok ? "✓" : "!", x.ok ? "ok" : "warn"), el("span", null, x.name), el("span", "d", x.detail || ""));
        ul.appendChild(li);
      });
      c.appendChild(ul);
      box.appendChild(c);
    }

    if (r.files && r.files.length) {
      const c = el("div", "card");
      c.appendChild(el("div", "item-title", `Files (${r.files.length}) · ${r.repo}`));
      const diffs = String(r.diff || "").split(/(?=^--- )/m);
      r.files.forEach((f, i) => {
        const d = el("details", "file");
        d.open = i === 0;
        d.appendChild(el("summary", null, f.path));
        const match = diffs.find((x) => x.includes(`b/${f.path}`));
        d.appendChild(diffBlock(match || f.content));
        c.appendChild(d);
      });
      box.appendChild(c);
    }

    if (r.status === "awaiting_approval") {
      const c = el("div", "card");
      if (r.can_decide) {
        c.appendChild(el("div", "item-title", "Your decision"));
        c.appendChild(el("div", "muted", r.files && r.files.length
          ? `Approving opens a pull request on ${r.repo} with exactly these files; review it again there before merging.`
          : "Approving confirms the drafter's conclusion; nothing is written."));
        const reason = el("textarea", "reason");
        reason.placeholder = "Reason (required to reject): it becomes a proposed convention for future drafts";
        c.appendChild(reason);
        decide(c, "/api/infra/decide", (decision) => ({ request_id: id, files_sha256: r.files_sha256,
                                                         reason: decision === "rejected" ? reason.value.trim() : undefined }),
               [[r.files && r.files.length ? "Approve and open PR" : "Approve", "approved", "small"], ["Reject", "rejected", "small danger"]],
               () => { loadInfra(); setTimeout(() => renderInfra(id), 300); });
      } else {
        c.appendChild(el("div", "muted", "Waiting for an admin to approve or reject."));
      }
      box.appendChild(c);
    }
    if (r.pr_url) {
      const c = el("div", "card");
      const a = el("a", null, r.pr_url); a.href = r.pr_url; a.target = "_blank"; a.rel = "noopener";
      c.append(el("div", "item-title", "Pull request"), a);
      box.appendChild(c);
    }
    if (r.status === "rejected" && r.reject_reason) box.appendChild(el("div", "warn", `Rejected by ${r.approver}: ${r.reject_reason}`));
    if (r.error) box.appendChild(el("div", "error-box", r.error));
    $("infra-detail").replaceChildren(box);
    return r;
  }

  async function poll(id) {
    const mine = ++infraPoll;
    for (let i = 0; i < 200 && mine === infraPoll && id === infraSelected; i += 1) {
      const r = await renderInfra(id).catch(() => null);
      if (!r || r.status !== "drafting") { loadInfra(); return; }
      await sleep(1500);
    }
  }

  $("infra-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = $("infra-text").value.trim();
    const st = $("infra-status");
    if (text.length < 10) { st.textContent = "Describe it in a sentence or two."; return; }
    $("infra-submit").disabled = true; st.textContent = "Starting…";
    try {
      const { data } = await postJSON("/api/infra/request", { request: text, repo: $("infra-repo").value.trim() || undefined });
      $("infra-text").value = ""; st.textContent = "";
      infraSelected = data.request_id;
      await loadInfra();
      poll(data.request_id);
    } catch (err) { st.textContent = err.message; }
    finally { $("infra-submit").disabled = false; }
  });

  // ── Conventions (the drafter's long-term memory) ───────────────────────
  async function loadConventions() {
    const box = $("conventions");
    let data;
    try { data = await getJSON("/api/conventions"); } catch (err) { box.replaceChildren(el("div", "muted", err.message)); return; }
    if (!data) return;
    box.replaceChildren();
    const form = el("div", "card");
    const ta = el("textarea", "reason");
    ta.placeholder = "e.g. Buckets go through modules/s3 with versioning on; no public buckets";
    ta.maxLength = 500;
    const st = el("span", "muted");
    const propose = button("Propose", "small", async () => {
      if (ta.value.trim().length < 5) { st.textContent = "Write the convention first."; return; }
      propose.disabled = true;
      try { await postJSON("/api/conventions/propose", { text: ta.value.trim() }); ta.value = ""; await loadConventions(); }
      catch (err) { st.textContent = err.message; propose.disabled = false; }
    });
    const row = el("div", "actions"); row.append(propose, st);
    form.append(el("div", "item-title", "Propose a convention"), ta, row);
    box.appendChild(form);
    for (const [status, title] of [["proposed", "Waiting for an admin"], ["active", "Active: the drafter follows these"]]) {
      const items = data.conventions.filter((c) => c.status === status);
      box.appendChild(el("h2", null, `${title} (${items.length})`));
      const card = el("div", "card");
      if (!items.length) card.appendChild(el("div", "muted", status === "active" ? "None yet." : "Nothing waiting."));
      for (const c of items) {
        const item = el("div", "item");
        item.appendChild(el("div", null, c.text));
        const m = el("div", "actions");
        m.append(chip(c.team, "neutral"), chip(c.source === "rejection" ? "from a rejected draft" : c.source, c.source === "rejection" ? "warn" : "info"),
                 el("span", "muted", `by ${c.author}${c.approver ? ` · approved by ${c.approver}` : ""} · ${ago(c.created_at)}`));
        item.appendChild(m);
        if (status === "proposed" && data.can_decide) {
          decide(item, "/api/conventions/decide", { id: c.id }, [["Approve", "active", "small"], ["Reject", "rejected", "small danger"]],
                 () => setTimeout(loadConventions, 400));
        }
        card.appendChild(item);
      }
      box.appendChild(card);
    }
  }
  loaders.conventions = loadConventions;

  // ── Teams (dashboard-managed; built for hundreds of repos) ───────────────
  // Teams tab: searchable team list + one team's detail (members, repos, URLs, rules, report, activity).
  // Repositories tab: every repo, filter / sort / page, multi-select and bulk assign, CSV import/export.
  const qs = (o) => new URLSearchParams(Object.entries(o).filter(([, v]) => v !== "" && v !== false && v != null)).toString();
  const field = (type, placeholder, value, max) => {
    const i = el("input"); i.type = type; i.placeholder = placeholder || "";
    if (value !== undefined && value !== null) i.value = value;
    if (max) i.maxLength = max;
    return i;
  };
  const selectOf = (pairs, value) => {
    const s = el("select");
    for (const [v, label] of pairs) { const o = el("option", null, label); o.value = v; s.appendChild(o); }
    if (value !== undefined) s.value = value;
    return s;
  };
  const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
  const SOURCE_LABEL = (r) => !r.team_id ? ["Unowned", "bad"] : r.pinned ? ["Assigned", "ok"]
    : String(r.source).startsWith("dashboard rule") ? ["Rule", "info"] : ["ownership.yml", "neutral"];
  const teamsState = { tab: "teams", selected: null, summary: null, teamFilter: "" };

  async function loadTeams() {
    const box = $("teams");
    let sum;
    try { sum = await getJSON("/api/teams"); } catch (err) { box.replaceChildren(el("div", "muted", err.message)); return; }
    if (!sum) return;
    teamsState.summary = sum;
    if (!teamsState.selected || !sum.teams.some((t) => t.id === teamsState.selected)) teamsState.selected = sum.teams[0]?.id || null;
    box.replaceChildren();
    const tabs = el("div", "subtabs");
    const pages = [["teams", `Teams (${sum.teams.length})`], ["repos", sum.is_admin ? `Repositories (${sum.repos_total})` : "Repositories"]];
    if (sum.is_admin) pages.push(["activity", "Activity"]);
    for (const [id, label] of pages) {
      const b = button(label, `subtab${teamsState.tab === id ? " active" : ""}`, () => { teamsState.tab = id; loadTeams(); });
      tabs.appendChild(b);
    }
    if (sum.is_admin && sum.unowned) {
      tabs.appendChild(button(`${sum.unowned} unowned repos`, "subtab warn", () => {
        teamsState.tab = "repos"; teamsState.repoPreset = { team: "unowned" }; loadTeams();
      }));
    }
    box.appendChild(tabs);
    const body = el("div");
    box.appendChild(body);
    if (teamsState.tab === "repos") repoTable(body, { admin: sum.is_admin, teams: sum.teams, preset: teamsState.repoPreset });
    else if (teamsState.tab === "activity") activityList(body, null);
    else teamsMaster(body, sum);
    teamsState.repoPreset = null;
  }

  function teamsMaster(host, sum) {
    const grid = el("div", "master");
    const list = el("div", "card team-list");
    const search = field("search", "Find a team…", teamsState.teamFilter, 60);
    const rows = el("div");
    const draw = () => {
      rows.replaceChildren();
      const f = search.value.trim().toLowerCase();
      teamsState.teamFilter = search.value;
      for (const t of sum.teams.filter((x) => !f || x.name.toLowerCase().includes(f) || x.id.includes(f))) {
        const r = el("button", `team-row${t.id === teamsState.selected ? " active" : ""}${t.archived ? " archived" : ""}`);
        r.type = "button";
        const top = el("div", "team-row-top");
        top.append(el("span", "team-row-name", t.name));
        if (t.high) top.append(el("span", "pill bad", String(t.high)));
        const meta = el("div", "muted", `${t.members} members · ${t.repos} repos${t.archived ? " · archived" : ""}`);
        r.append(top, meta);
        r.addEventListener("click", () => { teamsState.selected = t.id; draw(); teamDetail(detail, t.id); });
        rows.appendChild(r);
      }
      if (!rows.children.length) rows.appendChild(el("div", "muted pad", "No teams match."));
    };
    search.addEventListener("input", draw);
    list.appendChild(search);
    if (sum.is_admin) {
      const name = field("text", "New team name", "", 80);
      const f = el("div", "inline-form");
      const st = el("div", "muted");
      f.append(name, button("Create", "small", async () => {
        if (name.value.trim().length < 2) { st.textContent = "Name the team first."; return; }
        try { const r = await postJSON("/api/teams/create", { name: name.value.trim() }); teamsState.selected = r.data.team_id; loadTeams(); }
        catch (err) { st.textContent = err.message; }
      }));
      list.append(f, st);
    }
    list.appendChild(rows);
    const detail = el("div");
    grid.append(list, detail);
    host.appendChild(grid);
    draw();
    if (teamsState.selected) teamDetail(detail, teamsState.selected);
    else detail.appendChild(el("div", "card empty", "You are not in any team yet. Ask a security admin to add you."));
  }

  async function teamDetail(host, teamId) {
    host.replaceChildren(el("div", "card muted", "Loading…"));
    let t;
    try { t = await getJSON(`/api/teams/detail?${qs({ team_id: teamId })}`); } catch (err) { host.replaceChildren(el("div", "card muted", err.message)); return; }
    const s = (teamsState.summary.teams || []).find((x) => x.id === teamId) || {};
    const card = el("div", "card");
    const head = el("div", "team-head");
    const title = el("div", "item-title");
    title.append(el("h2", null, t.name), chip(t.id, "neutral"));
    if (t.archived) title.appendChild(chip("archived", "warn"));
    if (t.source === "config") title.appendChild(chip("seeded from ownership.yml", "info"));
    head.appendChild(title);
    if (t.is_admin) {
      const a = el("div", "actions");
      a.append(button("Rename", "small", async () => {
        const n = window.prompt("New team name", t.name);
        if (n && n.trim() !== t.name) { await teamWrite("update", { team_id: t.id, name: n.trim() }); loadTeams(); }
      }), button(t.archived ? "Restore" : "Archive", "small danger", async () => {
        if (t.archived || window.confirm(`Archive ${t.name}? Its members lose access through this team.`)) {
          await teamWrite("update", { team_id: t.id, archived: !t.archived }); loadTeams();
        }
      }));
      head.appendChild(a);
    }
    card.appendChild(head);
    const stats = el("div", "stats");
    for (const [n, label, cls] of [[t.members.length, "members", ""], [s.repos ?? "–", "repos", ""], [t.urls.length, "URLs", ""],
      [s.open ?? "–", "open findings", ""], [s.high ?? "–", "high + critical", s.high ? "bad" : ""], [s.jira_open ?? "–", "Jira open", ""]]) {
      const b = el("div", `stat ${cls}`); b.append(el("div", "stat-n", String(n)), el("div", "muted", label)); stats.appendChild(b);
    }
    card.appendChild(stats);
    const tabs = el("div", "subtabs small");
    const pane = el("div", "pane");
    const views = {
      members: ["Members", () => membersPane(pane, t)],
      repos: ["Repos", () => repoTable(pane, { admin: t.is_admin, teams: teamsState.summary.teams, fixedTeam: t.id })],
      urls: ["URLs (DAST)", () => urlsPane(pane, t)],
      rules: ["Ownership rules", () => rulesPane(pane, t)],
      report: ["Report & Jira", () => reportPane(pane, t)],
      activity: ["Activity", () => activityList(pane, t.id, t.activity)],
    };
    const go = (k) => {
      teamsState.detailTab = k;
      tabs.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.dataset.k === k));
      pane.replaceChildren(); views[k][1]();
    };
    for (const [k, [label]] of Object.entries(views)) { const b = button(label, "subtab", () => go(k)); b.dataset.k = k; tabs.appendChild(b); }
    card.append(tabs, pane);
    host.replaceChildren(card);
    go(views[teamsState.detailTab] ? teamsState.detailTab : "members");
  }

  async function teamWrite(path, body, status) {
    try { const r = await postJSON(`/api/teams/${path}`, body); if (status) status.textContent = ""; return r.data; }
    catch (err) { if (status) status.textContent = err.message; else window.alert(err.message); return null; }
  }
  const refreshDetail = () => loadTeams();

  function membersPane(pane, t) {
    const table = el("table", "grid-table");
    const thead = el("tr"); ["E-mail", "Role", "Added by", ""].forEach((h) => thead.appendChild(el("th", null, h)));
    table.appendChild(thead);
    for (const m of t.members) {
      const tr = el("tr");
      const rc = el("td"); rc.appendChild(chip(m.role, m.role === "lead" ? "info" : "neutral"));
      const act = el("td", "right");
      if (t.can_manage && (t.is_admin || m.role === "member")) {
        if (t.is_admin) act.appendChild(button(m.role === "lead" ? "Make member" : "Make lead", "small", async () => {
          if (await teamWrite("member", { team_id: t.id, email: m.email, role: m.role === "lead" ? "member" : "lead" })) refreshDetail();
        }));
        act.appendChild(button("Remove", "small danger", async () => {
          if (await teamWrite("member", { team_id: t.id, email: m.email, remove: true })) refreshDetail();
        }));
      }
      tr.append(el("td", null, m.email), rc, el("td", "muted", m.added_by), act);
      table.appendChild(tr);
    }
    if (!t.members.length) { const tr = el("tr"); const td = el("td", "muted", "No members yet."); td.colSpan = 4; tr.appendChild(td); table.appendChild(tr); }
    pane.appendChild(table);
    if (!t.can_manage) return;
    const box = el("div", "bulk-add");
    const ta = el("textarea"); ta.placeholder = "Paste e-mails: one per line, or separated by commas"; ta.rows = 3;
    const role = selectOf(t.is_admin ? [["member", "as members"], ["lead", "as leads"]] : [["member", "as members"]]);
    const st = el("span", "muted");
    const add = button("Add people", "small primary", async () => {
      const r = await teamWrite("members", { team_id: t.id, emails: ta.value, role: role.value }, st);
      if (r) { st.textContent = `Added ${r.added}${r.invalid.length ? `; not e-mails: ${r.invalid.join(", ")}` : ""}`; setTimeout(refreshDetail, 900); }
    });
    const row = el("div", "actions"); row.append(role, add, st);
    box.append(el("div", "item-title", "Add people"), ta, row);
    pane.appendChild(box);
  }

  function urlsPane(pane, t) {
    pane.appendChild(el("div", "muted", "Public URLs this team owns. The weekly DAST run does a passive ZAP baseline scan of each (no attack payloads)."));
    const ul = el("ul", "row-list");
    for (const u of t.urls) {
      const li = el("li");
      li.append(el("span", null, u.url), el("span", "muted", `${u.open} open`));
      if (t.is_admin) li.appendChild(button("Remove", "small", async () => {
        if (await teamWrite("asset", { team_id: t.id, kind: "url", value: u.url, remove: true })) refreshDetail();
      }));
      ul.appendChild(li);
    }
    if (!t.urls.length) ul.appendChild(el("li", "muted", "No URLs yet."));
    pane.appendChild(ul);
    if (!t.is_admin) return;
    const v = field("url", "https://app.example.com", "", 300); const st = el("span", "muted");
    const f = el("div", "inline-form");
    f.append(v, button("Add URL", "small", async () => { if (await teamWrite("asset", { team_id: t.id, kind: "url", value: v.value.trim() }, st)) refreshDetail(); }), st);
    pane.appendChild(f);
  }

  function rulesPane(pane, t) {
    pane.appendChild(el("div", "muted", "Repos matching a rule belong to this team unless they are assigned explicitly or an earlier rule already owns them. Rules beat ownership.yml."));
    const ul = el("ul", "row-list");
    for (const r of t.rules) {
      const li = el("li");
      li.append(el("span", null, `${r.kind.replace("_", " ")}: ${r.value}`), el("span", "muted", `by ${r.added_by}`));
      if (t.is_admin) li.appendChild(button("Remove", "small", async () => {
        if (await teamWrite("rule", { team_id: t.id, kind: r.kind, value: r.value, remove: true })) refreshDetail();
      }));
      ul.appendChild(li);
    }
    if (!t.rules.length) ul.appendChild(el("li", "muted", "No rules yet."));
    pane.appendChild(ul);
    if (!t.is_admin) return;
    const kind = selectOf([["name_prefix", "name starts with"], ["name_contains", "name contains"], ["topic", "has GitHub topic"]]);
    const val = field("text", "e.g. pay- or team-payments", "", 100);
    const preview = el("div", "preview muted");
    const st = el("span", "muted");
    const run = debounce(async () => {
      const v = val.value.trim().toLowerCase();
      if (!v) { preview.replaceChildren(); return; }
      try {
        const p = await getJSON(`/api/teams/rule-preview?${qs({ kind: kind.value, value: v })}`);
        preview.replaceChildren(el("div", null, `Matches ${p.count} repos · ${p.would_change} would move to ${t.name} now`));
        const names = el("div", "chips");
        p.repos.slice(0, 40).forEach((r) => names.appendChild(chip(r.repo, r.pinned || String(r.source).startsWith("dashboard") ? "neutral" : "info")));
        if (p.count > 40) names.appendChild(el("span", "muted", ` +${p.count - 40} more`));
        preview.appendChild(names);
      } catch (err) { preview.textContent = err.message; }
    }, 300);
    val.addEventListener("input", run); kind.addEventListener("change", run);
    const f = el("div", "inline-form");
    f.append(kind, val,
      button("Save rule", "small", async () => { if (await teamWrite("rule", { team_id: t.id, kind: kind.value, value: val.value.trim() }, st)) refreshDetail(); }),
      button("Save & apply now", "small primary", async () => {
        const r = await teamWrite("rule", { team_id: t.id, kind: kind.value, value: val.value.trim(), apply_now: true }, st);
        if (r) { st.textContent = `${r.changed} repos moved, ${r.findings_moved} findings moved`; setTimeout(refreshDetail, 1200); }
      }), st);
    pane.append(f, preview);
  }

  function reportPane(pane, t) {
    const s = t.settings;
    const g = el("div", "settings-grid");
    const emailCb = el("input"); emailCb.type = "checkbox"; emailCb.checked = s.email_digest;
    const slack = field("url", s.slack ? `set (${s.slack_hint}); paste a new one to replace` : "https://hooks.slack.com/services/…", "", 300);
    const jiraCb = el("input"); jiraCb.type = "checkbox"; jiraCb.checked = s.jira_enabled;
    const proj = field("text", "Project key, e.g. SEC", s.jira_project, 20);
    const itype = field("text", "Bug", s.jira_issue_type, 40);
    const asg = field("email", "assignee e-mail (optional)", s.jira_assignee, 254);
    const slaC = field("number", "", s.sla_days.critical); slaC.min = 1; slaC.max = 365;
    const slaH = field("number", "", s.sla_days.high); slaH.min = 1; slaH.max = 365;
    [emailCb, slack, jiraCb, proj, itype, asg, slaC, slaH].forEach((x) => { x.disabled = !t.can_manage; });
    for (const [label, input] of [["E-mail every member weekly", emailCb], ["Slack webhook", slack], ["Create Jira tickets", jiraCb],
      ["Jira project", proj], ["Issue type", itype], ["Assignee", asg], ["SLA critical (days)", slaC], ["SLA high (days)", slaH]]) {
      g.append(el("label", "muted", label), input);
    }
    pane.appendChild(g);
    pane.appendChild(el("div", "muted", "Jira: one ticket per repo + rule, high and critical only, closed automatically when fixed; the assignee and leads are reminded in Jira once a ticket passes the SLA."));
    if (!t.can_manage) return;
    const st = el("span", "muted");
    const row = el("div", "actions");
    row.append(button("Save", "small primary", async () => {
      const body = { team_id: t.id, email_digest: emailCb.checked, jira_enabled: jiraCb.checked, jira_project: proj.value.trim(),
                     jira_issue_type: itype.value.trim() || "Bug", jira_assignee: asg.value.trim(),
                     sla_days: { critical: +slaC.value, high: +slaH.value } };
      if (slack.value.trim()) body.slack_webhook = slack.value.trim();
      if (await teamWrite("settings", body, st)) { st.textContent = "Saved."; }
    }));
    if (s.slack) row.appendChild(button("Remove Slack", "small", async () => { if (await teamWrite("settings", { team_id: t.id, slack_webhook: "" }, st)) refreshDetail(); }));
    row.appendChild(st);
    pane.appendChild(row);
  }

  async function activityList(host, teamId, preloaded) {
    let items = preloaded;
    if (!items) {
      try { items = (await getJSON(`/api/teams/activity?${qs({ team_id: teamId || "" })}`)).activity; }
      catch (err) { host.appendChild(el("div", "muted", err.message)); return; }
    }
    const card = el("div", teamId ? "" : "card");
    const ul = el("ul", "row-list");
    const say = (a) => {
      const d = a.detail || {};
      switch (a.action) {
        case "bulk_assign": return `assigned ${d.repos} repos${d.moved ? ` (${d.moved} findings moved)` : ""}`;
        case "bulk_unpin": return `removed the assignment of ${d.repos} repos`;
        case "set_asset": return `assigned ${d.kind} ${d.value}`;
        case "remove_asset": return `unassigned ${d.kind} ${d.value}`;
        case "apply_rule": return `applied rule ${d.kind} ${d.value} to ${d.repos} repos`;
        case "set_rule": return `added rule ${d.kind} ${d.value}`;
        case "remove_rule": return `removed rule ${d.kind} ${d.value}`;
        case "set_member": return `set ${d.email} as ${d.role}`;
        case "remove_member": return `removed ${d.email}`;
        case "create_team": return `created the team`;
        case "update_team": return d.archived === true ? "archived the team" : d.archived === false ? "restored the team" : `renamed the team to ${d.name}`;
        case "settings": return "changed the report / Jira settings";
        default: return a.action;
      }
    };
    for (const a of items) {
      const li = el("li");
      li.append(el("span", null, `${a.actor} ${say(a)}${teamId ? "" : ` · ${a.team_id || ""}`}`), el("span", "muted", ago(a.at)));
      ul.appendChild(li);
    }
    if (!items.length) ul.appendChild(el("li", "muted", "Nothing yet."));
    card.appendChild(ul);
    host.appendChild(card);
  }

  // Repo inventory: server-side filter, sort and paging; selection survives paging; "select all N matching".
  function repoTable(host, opts) {
    const st = { q: "", team: opts.fixedTeam || "", source: "", has_findings: false, sort: "repo", page: 1, size: 50,
                 selected: new Set(), allMatching: false, total: 0, ...(opts.preset || {}) };
    const wrap = el("div", opts.fixedTeam ? "" : "card");
    const bar = el("div", "filters");
    const q = field("search", "Search repo name or topic", st.q, 100);
    const teamSel = selectOf([["", "All teams"], ["unowned", "Unowned"], ...opts.teams.map((t) => [t.id, t.name])], st.team);
    const srcSel = selectOf([["", "Any assignment"], ["dashboard", "Assigned in dashboard"], ["rule", "By a rule"],
                             ["config", "By ownership.yml"], ["unowned", "Unowned"]], st.source);
    const hf = el("label", "muted check"); const hfCb = el("input"); hfCb.type = "checkbox"; hf.append(hfCb, document.createTextNode(" has open findings"));
    const sortSel = selectOf([["repo", "Sort: name"], ["high", "Sort: most high+"], ["open", "Sort: most open"], ["team", "Sort: team"]], st.sort);
    const sizeSel = selectOf([["25", "25 / page"], ["50", "50 / page"], ["100", "100 / page"], ["200", "200 / page"]], String(st.size));
    if (!opts.fixedTeam) bar.append(q, teamSel, srcSel, hf, sortSel, sizeSel); else bar.append(q, srcSel, hf, sortSel, sizeSel);
    if (opts.admin && !opts.fixedTeam) {
      bar.append(button("Export CSV", "small", exportCsv), button("Import CSV", "small", () => importDialog()));
    }
    const bulk = el("div", "bulkbar"); bulk.hidden = true;
    const tableBox = el("div", "table-wrap");
    const pager = el("div", "pager");
    wrap.append(bar, bulk, tableBox, pager);
    host.appendChild(wrap);

    const params = () => ({ q: st.q, team: st.team, source: st.source, has_findings: st.has_findings });
    const reload = async (keepPage) => {
      if (!keepPage) st.page = 1;
      tableBox.replaceChildren(el("div", "muted pad", "Loading…"));
      let d;
      try { d = await getJSON(`/api/teams/repos?${qs({ ...params(), sort: st.sort, page: st.page, size: st.size })}`); }
      catch (err) { tableBox.replaceChildren(el("div", "muted pad", err.message)); return; }
      st.total = d.total;
      renderTable(d); renderPager(d); renderBulk();
    };
    const onFilter = () => { st.selected.clear(); st.allMatching = false; reload(); };
    q.addEventListener("input", debounce(() => { st.q = q.value.trim(); onFilter(); }, 300));
    teamSel.addEventListener("change", () => { st.team = teamSel.value; onFilter(); });
    srcSel.addEventListener("change", () => { st.source = srcSel.value; onFilter(); });
    hfCb.addEventListener("change", () => { st.has_findings = hfCb.checked; onFilter(); });
    sortSel.addEventListener("change", () => { st.sort = sortSel.value; reload(); });
    sizeSel.addEventListener("change", () => { st.size = +sizeSel.value; reload(); });

    function renderTable(d) {
      const table = el("table", "grid-table");
      const head = el("tr");
      const all = el("input"); all.type = "checkbox";
      all.checked = d.repos.length > 0 && d.repos.every((r) => st.selected.has(r.repo));
      all.addEventListener("change", () => { d.repos.forEach((r) => all.checked ? st.selected.add(r.repo) : st.selected.delete(r.repo)); st.allMatching = false; renderTable(d); renderBulk(); });
      const th0 = el("th", "cb"); if (opts.admin) th0.appendChild(all);
      head.appendChild(th0);
      ["Repository", "Team", "How", "Open", "High+"].forEach((h, i) => head.appendChild(el("th", i >= 3 ? "num" : null, h)));
      table.appendChild(head);
      for (const r of d.repos) {
        const tr = el("tr");
        const td0 = el("td", "cb");
        if (opts.admin) {
          const cb = el("input"); cb.type = "checkbox"; cb.checked = st.allMatching || st.selected.has(r.repo);
          cb.addEventListener("change", () => { st.allMatching = false; cb.checked ? st.selected.add(r.repo) : st.selected.delete(r.repo); renderBulk(); all.checked = d.repos.every((x) => st.selected.has(x.repo)); });
          td0.appendChild(cb);
        }
        const name = el("td");
        name.appendChild(el("div", "repo-name", r.repo));
        if (r.topics && r.topics.length) { const c = el("div", "chips"); r.topics.slice(0, 4).forEach((t) => c.appendChild(el("span", "topic", t))); name.appendChild(c); }
        const [lbl, kind] = SOURCE_LABEL(r);
        const how = el("td"); const ch = chip(lbl, kind); ch.title = r.source; how.appendChild(ch);
        tr.append(td0, name, el("td", r.team_id ? null : "muted", r.team_name || "—"), how,
                  el("td", "num", String(r.open)), el("td", `num${r.high ? " bad" : ""}`, String(r.high)));
        table.appendChild(tr);
      }
      if (!d.repos.length) { const tr = el("tr"); const td = el("td", "muted pad", "No repos match these filters."); td.colSpan = 6; tr.appendChild(td); table.appendChild(tr); }
      tableBox.replaceChildren(table);
    }

    function renderPager(d) {
      pager.replaceChildren();
      const from = d.total ? (d.page - 1) * d.size + 1 : 0;
      pager.append(el("span", "muted", `${from}–${Math.min(d.page * d.size, d.total)} of ${d.total}`));
      const prev = button("‹ Prev", "small", () => { st.page -= 1; reload(true); }); prev.disabled = d.page <= 1;
      const next = button("Next ›", "small", () => { st.page += 1; reload(true); }); next.disabled = d.page >= d.pages;
      pager.append(prev, el("span", "muted", `page ${d.page} / ${d.pages}`), next);
    }

    function renderBulk() {
      const n = st.allMatching ? st.total : st.selected.size;
      bulk.hidden = !opts.admin || n === 0;
      if (bulk.hidden) return;
      bulk.replaceChildren();
      bulk.append(el("strong", null, `${n} selected`));
      if (!st.allMatching && st.total > st.selected.size) {
        bulk.append(button(`Select all ${st.total} matching`, "small link", () => { st.allMatching = true; reloadKeep(); }));
      }
      const target = selectOf(opts.teams.filter((t) => !t.archived && t.id !== opts.fixedTeam).map((t) => [t.id, t.name]));
      const msg = el("span", "muted");
      const body = () => (st.allMatching ? { filter: params() } : { repos: [...st.selected] });
      bulk.append(el("span", "muted", "→"), target,
        button("Assign", "small primary", async () => {
          const r = await teamWrite("assign", { team_id: target.value, ...body() }, msg);
          if (r) { msg.textContent = `Assigned ${r.assigned} repos · ${r.findings_moved} findings moved`; st.selected.clear(); st.allMatching = false; setTimeout(() => { loadTeams(); }, 900); }
        }),
        button("Remove assignment", "small", async () => {
          if (!window.confirm(`Remove the explicit assignment of ${n} repos? Their owner is recomputed from rules / ownership.yml on the next weekly run.`)) return;
          const r = await teamWrite("unpin", body(), msg);
          if (r) { msg.textContent = `${r.unpinned} assignments removed`; st.selected.clear(); st.allMatching = false; reload(true); }
        }),
        button("Clear", "small", () => { st.selected.clear(); st.allMatching = false; reloadKeep(); }), msg);
    }
    const reloadKeep = () => reload(true);

    async function exportCsv() {
      const d = await getJSON("/api/teams/repos/export");
      const esc = (v) => /[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v);
      const csv = ["repo,team,source,open,high", ...d.repos.map((r) => [r.repo, r.team, r.source, r.open, r.high].map(esc).join(","))].join("\n");
      const a = el("a"); a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
      a.download = `repo-ownership-${new Date().toISOString().slice(0, 10)}.csv`; a.click();
    }

    function importDialog() {
      const dlg = el("dialog", "import-dlg");
      const ta = el("textarea"); ta.rows = 10; ta.placeholder = "repo,team\nmktp-uk-site,uk_engineering\npay-api,Payments";
      const file = el("input"); file.type = "file"; file.accept = ".csv,.tsv,.txt";
      file.addEventListener("change", async () => { if (file.files[0]) ta.value = await file.files[0].text(); });
      const out = el("div", "muted");
      const close = () => { dlg.close(); dlg.remove(); };
      const go = button("Import", "small primary", async () => {
        const r = await teamWrite("import", { text: ta.value }, out);
        if (!r) return;
        out.replaceChildren(el("div", null, r.message || `Applied ${r.applied} rows · ${r.findings_moved || 0} findings moved`));
        for (const e of r.errors) out.appendChild(el("div", "bad", `line ${e.line}: ${e.error}`));
        if (r.unknown_repos.length) out.appendChild(el("div", null, `Not seen in GitHub yet (assigned anyway): ${r.unknown_repos.join(", ")}`));
        reload();
      });
      const actions = el("div", "actions"); actions.append(go, button("Close", "small", close));
      dlg.append(el("h2", null, "Import repo ownership"),
        el("div", "muted", "One repo per line: repo,team (team id or name). Valid rows are assigned; invalid rows are listed. Nothing is applied if most rows are invalid."),
        file, ta, actions, out);
      document.body.appendChild(dlg); dlg.showModal();
    }

    reload();
  }
  loaders.teams = loadTeams;


  // ── Start ───────────────────────────────────────────────────────────────
  function setupPersonas() {
    const sel = $("persona");
    cfg.personas.forEach((p) => {
      const o = el("option", null, p.label);
      o.value = p.id;
      sel.appendChild(o);
    });
    sel.value = store.getItem("persona") || cfg.personas[0].id;
    sel.hidden = false;
    $("who").replaceChildren(document.createTextNode("Signed in as a persona"), el("span", "dev-tag", "prototype"));
    sel.addEventListener("change", () => {
      store.setItem("persona", sel.value);
      store.removeItem("session_id");
      log.querySelectorAll(".msg").forEach((m) => m.remove());
      $("chat-empty").hidden = false;
      infraSelected = null;
      Object.assign(findingsState, { q: "", sev: [], source: "", team: "", fix: "", status: "open", page: 1 });
      $("f-team").replaceChildren(); $("f-source").replaceChildren(el("option", null, "All sources"));
      $("f-source").options[0].value = "";
      $("infra-detail").replaceChildren(el("div", "card empty", "Pick a request on the left or start a new one."));
      const v = current; current = null;
      syncAdminNav().then(() => show(["infra", "conventions"].includes(v) && document.querySelector(`nav a[data-view=${v}]`).hidden ? "brief" : (v || "brief")));
      refreshReviewCount();
    });
  }

  // The drafter and its conventions are for security admins; the server decides, the nav follows.
  async function syncAdminNav() {
    let admin = false;
    try { admin = !!(await getJSON("/api/infra")); } catch (_) { admin = false; }
    document.querySelectorAll("nav a[data-admin]").forEach((a) => { a.hidden = !admin; });
    if (!admin && ["infra", "conventions"].includes(current)) location.hash = "brief";
  }

  if (dev) setupPersonas();
  suggestions();
  handleRedirect()
    .then(accessToken)
    .then(() => { if (!dev) $("who").textContent = store.getItem("name") || ""; })
    .then(syncAdminNav)
    .then(() => show(location.hash.slice(1) || "brief"))
    .then(refreshReviewCount)
    .catch((err) => { show("chat"); add("bot", `Sign-in problem: ${err.message}`); });
})();
