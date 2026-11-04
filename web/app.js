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

  // ── Rendering helpers (text only) ──────────────────────────────────────
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
  const log = $("log");

  function add(kind, text, cited, meta) {
    const div = el("div", `msg ${kind}`, text);
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
          ? `Fix drafted (${data.change || "see Review"}); a team lead approves it in Review.`
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

  async function loadBrief() {
    const box = $("brief");
    box.hidden = true;
    box.replaceChildren();
    const headers = await authHeaders();
    if (!headers) return;
    const r = await fetch("/api/brief", { headers });
    if (!r.ok) return;                       // not deployed in this environment
    const b = await r.json();
    const asOf = b.as_of ? new Date(b.as_of).toLocaleString() : "no run yet";
    box.appendChild(el("div", "brief-head", "This week"));
    box.appendChild(el("div", "muted", `Data as of ${asOf}`));
    if (b.unowned_repos !== undefined) {
      box.appendChild(el("div", "stats",
        `${b.unowned_repos} repos have no owning team · ${b.unowned_findings} findings on unowned repos`));
    }
    const teams = b.teams.filter((t) => Object.keys(t.open_by_severity).length || t.top.length);
    if (!teams.length) box.appendChild(el("div", "muted", "No open findings."));
    for (const t of teams) {
      box.appendChild(el("h2", null, t.name));
      const sev = t.open_by_severity;
      const w = t.this_week;
      box.appendChild(el("div", "stats",
        `${sev.critical || 0} critical · ${sev.high || 0} high open · ${w.opened} new and ${w.fixed} fixed since last run` +
        (t.accepted_risks ? ` · ${t.accepted_risks} accepted risks` : "") +
        (t.awaiting_review ? ` · ${t.awaiting_review} waiting for a lead's review` : "")));
      for (const it of t.top) {
        const item = el("div", "item");
        const title = el("div", "item-title");
        title.appendChild(el("span", `sev sev-${it.severity}`, it.severity));
        title.appendChild(document.createTextNode(it.title));
        if (it.reviewed) title.appendChild(el("span", "tag", "reviewed by a lead"));
        item.appendChild(title);
        item.appendChild(el("div", "muted", `${it.resource} · open ${it.open_days} days · ${it.id}`));
        if (it.summary) item.appendChild(el("div", null, it.summary));
        if (it.fix) item.appendChild(el("div", null, `Fix: ${it.fix}`));
        if (it.investigated_on) {
          item.appendChild(el("div", "muted",
            `Investigated ${it.investigated_on} · impact ${it.impact} · confidence ${it.confidence}`));
        }
        const actions = el("div", "actions");
        if (it.summary) actions.appendChild(disputeButton(item, it.id));
        if (it.source === "dependabot" && cfg.fixAgent !== false) actions.appendChild(fixButton(it.id));
        if (actions.childElementCount) item.appendChild(actions);
        box.appendChild(item);
      }
    }
    box.hidden = false;
  }

  function suggestions() {
    const box = $("suggest");
    box.replaceChildren();
    ["What should we fix first this week?", "Which critical alerts are in runtime dependencies?",
     "What changed since the last run?"].forEach((q) => {
      const b = el("button", null, q);
      b.type = "button";
      b.addEventListener("click", () => { $("q").value = q; $("ask").requestSubmit(); });
      box.appendChild(b);
    });
  }

  // ── Review panel (leads approve or reject; everyone can see what is waiting) ──
  const decisionLabel = { approved: "Approved", rejected: "Rejected", active: "Approved", opened: "PR opened" };

  function decide(card, path, payload, choices) {
    const row = el("div", "actions");
    const status = el("span", "muted");
    for (const [label, decision, cls] of choices) {
      row.appendChild(button(label, cls, async () => {
        row.querySelectorAll("button").forEach((x) => { x.disabled = true; });
        status.textContent = "Saving…";
        try {
          const { data } = await postJSON(path, { ...(typeof payload === "function" ? payload() : payload), decision });
          if (data.status === "failed") {             // decision recorded, but the PR could not be opened
            status.textContent = `Approved, but no PR was opened: ${data.error || "unknown error"}`;
            card.classList.add("decided");
            refreshReviewCount();
            return;
          }
          status.textContent = data.pr_url ? `PR opened: ${data.pr_url}`
            : (decisionLabel[data.status || data.state] || "Saved");
          card.classList.add("decided");
          refreshReviewCount();
          loadBrief().catch(() => {});
        } catch (err) {
          status.textContent = err.status === 403 ? "Only a team lead or admin can decide this." : err.message;
          row.querySelectorAll("button").forEach((x) => { x.disabled = false; });
        }
      }));
    }
    row.appendChild(status);
    card.appendChild(row);
  }

  async function openReview() {
    const panel = $("review");
    if (!panel.hidden) { panel.hidden = true; return; }
    panel.replaceChildren(el("div", "muted", "Loading…"));
    panel.hidden = false;
    let data;
    try { data = await getJSON("/api/reviews"); } catch (err) { panel.replaceChildren(el("div", "muted", err.message)); return; }
    if (!data) return;
    panel.replaceChildren();
    const head = el("div", "brief-head", "Waiting for review");
    head.appendChild(button("Close", "small ghost right", () => { panel.hidden = true; }));
    panel.appendChild(head);
    if (!data.can_decide) panel.appendChild(el("div", "muted", "You can see these; a team lead or admin decides them."));
    const total = data.investigations.length + data.notes.length + data.fixes.length;
    if (!total) panel.appendChild(el("div", "muted", "Nothing is waiting."));

    if (data.investigations.length) panel.appendChild(el("h2", null, "Investigations"));
    for (const inv of data.investigations) {
      const card = el("div", "item");
      const title = el("div", "item-title");
      title.appendChild(el("span", `sev sev-${inv.severity}`, inv.severity));
      title.appendChild(document.createTextNode(inv.title));
      title.appendChild(el("span", "tag", inv.state === "disputed" ? "disputed by the team" : "low confidence"));
      card.appendChild(title);
      card.appendChild(el("div", "muted", `${inv.resource} · ${inv.finding} · confidence ${
        inv.confidence === null ? "?" : Math.round(inv.confidence * 100) + "%"} · impact ${inv.impact || "?"}`));
      if (inv.summary) card.appendChild(el("div", null, inv.summary));
      if (inv.fix) card.appendChild(el("div", null, `Suggested fix: ${inv.fix}`));
      if (data.can_decide) {
        const override = el("input", "wide");
        override.placeholder = "Optional: corrected fix to show in the brief";
        override.maxLength = 300;
        card.appendChild(override);
        decide(card, "/api/reviews/investigation",
               () => ({ investigation_id: inv.investigation_id, fix_override: override.value.trim() || undefined }),
               [["Approve", "approved", "small"], ["Reject", "rejected", "small ghost"]]);
      }
      panel.appendChild(card);
    }

    if (data.notes.length) panel.appendChild(el("h2", null, "Team notes proposed by the agent"));
    for (const n of data.notes) {
      const card = el("div", "item");
      card.appendChild(el("div", "item-title", `${n.kind.replace(/_/g, " ")}${n.finding ? " · " + n.finding : ""}`));
      card.appendChild(el("div", null, n.text));
      card.appendChild(el("div", "muted", `${n.team} · proposed by ${n.author}${n.expires ? " · expires " + n.expires : ""}`));
      if (data.can_decide) decide(card, "/api/reviews/note", { note_id: n.note_id },
                                  [["Approve", "active", "small"], ["Reject", "rejected", "small ghost"]]);
      panel.appendChild(card);
    }

    if (data.fixes.length) panel.appendChild(el("h2", null, "Fixes to approve"));
    for (const f of data.fixes) {
      const card = el("div", "item");
      card.appendChild(el("div", "item-title", `${f.repo} · ${f.manifest}`));
      card.appendChild(el("div", "muted", `${f.finding} · requested by ${f.requested_by}`));
      if (f.rationale) card.appendChild(el("div", null, f.rationale));
      const diff = el("pre", "diff");
      (f.diff || "").split("\n").forEach((line) => {
        diff.appendChild(el("span", line.startsWith("+") && !line.startsWith("+++") ? "add"
          : line.startsWith("-") && !line.startsWith("---") ? "del" : null, line + "\n"));
      });
      card.appendChild(diff);
      if (data.can_decide) decide(card, "/api/fixes/decide", { fix_request_id: f.fix_request_id },
                                  [["Approve and open PR", "approved", "small"], ["Reject", "rejected", "small ghost"]]);
      panel.appendChild(card);
    }
  }

  async function refreshReviewCount() {
    try {
      const data = await getJSON("/api/reviews");
      if (!data) return;
      const n = data.investigations.length + data.notes.length + data.fixes.length;
      const b = $("review-btn");
      b.textContent = n ? `Review (${n})` : "Review";
      b.hidden = false;
    } catch (_) { /* reviews not deployed here */ }
  }

  // ── Chat ───────────────────────────────────────────────────────────────
  // The server answers in the background and records each step ("Checking GitHub advisory
  // GHSA-..."); the page polls for them so you can see what the agent is doing.
  const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

  function progressBox() {
    const div = el("div", "msg bot progress");
    const timer = el("div", "meta", "Working… 0s");
    const list = el("ul", "steps");
    div.append(timer, list);
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
    const started = Date.now();
    const tick = setInterval(() => {
      const s = Math.round((Date.now() - started) / 1000);
      timer.textContent = `Working… ${s}s`;
    }, 1000);
    return {
      show(steps) {
        list.replaceChildren();
        (steps.length ? steps : ["Starting"]).forEach((s, i, all) => {
          const li = el("li", i === all.length - 1 ? "step current" : "step done", s);
          list.appendChild(li);
        });
        log.scrollTop = log.scrollHeight;
      },
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
    up.setAttribute("aria-label", "Helpful");
    down.setAttribute("aria-label", "Not right");
    row.append(up, down, status);
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
      steps.forEach((s) => list.appendChild(el("li", "step done", s)));
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
  $("review-btn").addEventListener("click", () => openReview().catch(() => {}));

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
    $("who").appendChild(el("span", "dev-tag", "prototype"));
    sel.addEventListener("change", () => {
      store.setItem("persona", sel.value);
      store.removeItem("session_id");
      log.querySelectorAll(".msg").forEach((m) => m.remove());
      $("review").hidden = true;
      loadBrief().catch(() => {});
      refreshReviewCount();
    });
  }

  if (dev) setupPersonas();
  suggestions();
  handleRedirect()
    .then(accessToken)
    .then(() => { if (!dev) $("who").textContent = store.getItem("name") || ""; })
    .then(loadBrief)
    .then(refreshReviewCount)
    .catch((err) => add("bot", `Sign-in problem: ${err.message}`));
})();
