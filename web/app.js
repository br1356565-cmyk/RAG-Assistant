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
    const go = { b: "brief", c: "chat", i: "infra", r: "review", n: "conventions" };
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
  function fixButton(findingId) {
    const wrap = el("span");
    const b = button("Draft a fix", "small ghost", async () => {
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
        return "Thanks: hidden from the brief until it is re-checked or a lead approves it.";
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
        const actions = el("div", "actions");
        if (it.summary) actions.appendChild(disputeButton(item, it.id));
        if (it.source === "dependabot" && cfg.fixAgent !== false) actions.appendChild(fixButton(it.id));
        if (actions.childElementCount) item.appendChild(actions);
        card.appendChild(item);
      }
      box.appendChild(card);
    }
  }
  loaders.brief = loadBrief;

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
      if (data.can_decide) decide(item, "/api/fixes/decide", { fix_request_id: f.fix_request_id },
                                  [["Approve and open PR", "approved", "small"], ["Reject", "rejected", "small danger"]]);
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
    drafting: ["Drafting", "info"], needs_input: ["Needs your answer", "warn"], awaiting_approval: ["Waiting for a lead", "warn"],
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
    const teamSel = $("infra-team");
    teamSel.replaceChildren(...data.teams.map((t) => { const o = el("option", null, t); o.value = t; return o; }));
    teamSel.hidden = data.teams.length < 2;
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
      m.append(el("span", "muted", `${r.team} · ${ago(r.created_at)}`));
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
    top.append(chip(label, kind), el("span", "muted", `${r.team_id} · requested by ${r.requested_by} · ${ago(r.created_at)}`));
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
      if (r.is_requester || r.can_decide) {
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
      c.appendChild(el("div", "item-title", `Files (${r.files.length}) · teams/${r.team_id}/`));
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
          ? "Approving opens a pull request with exactly these files; CI runs fmt/validate/plan there."
          : "Approving confirms the drafter's conclusion; nothing is written."));
        const reason = el("textarea", "reason");
        reason.placeholder = "Reason (required to reject): it becomes a proposed convention for future drafts";
        c.appendChild(reason);
        decide(c, "/api/infra/decide", (decision) => ({ request_id: id, reason: decision === "rejected" ? reason.value.trim() : undefined }),
               [[r.files && r.files.length ? "Approve and open PR" : "Approve", "approved", "small"], ["Reject", "rejected", "small danger"]],
               () => { loadInfra(); setTimeout(() => renderInfra(id), 300); });
      } else {
        c.appendChild(el("div", "muted", "Waiting for a team lead to approve or reject."));
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
      const { data } = await postJSON("/api/infra/request", { request: text, team: $("infra-team").value || undefined });
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
    for (const [status, title] of [["proposed", "Waiting for a lead"], ["active", "Active: the drafter follows these"]]) {
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
      $("infra-detail").replaceChildren(el("div", "card empty", "Pick a request on the left or start a new one."));
      const v = current; current = null; show(v || "brief");
      refreshReviewCount();
    });
  }

  if (dev) setupPersonas();
  suggestions();
  handleRedirect()
    .then(accessToken)
    .then(() => { if (!dev) $("who").textContent = store.getItem("name") || ""; })
    .then(() => show(location.hash.slice(1) || "brief"))
    .then(refreshReviewCount)
    .catch((err) => { show("chat"); add("bot", `Sign-in problem: ${err.message}`); });
})();
