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

  // ── Rendering helpers (text only) ──────────────────────────────────────
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
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
  }

  // ── Weekly brief ────────────────────────────────────────────────────────
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
        (t.accepted_risks ? ` · ${t.accepted_risks} accepted risks` : "")));
      for (const it of t.top) {
        const item = el("div", "item");
        const title = el("div", "item-title");
        title.appendChild(el("span", `sev sev-${it.severity}`, it.severity));
        title.appendChild(document.createTextNode(it.title));
        item.appendChild(title);
        item.appendChild(el("div", "muted", `${it.resource} · open ${it.open_days} days · ${it.id}`));
        if (it.summary) item.appendChild(el("div", null, it.summary));
        if (it.fix) item.appendChild(el("div", null, `Fix: ${it.fix}`));
        if (it.investigated_on) {
          item.appendChild(el("div", "muted",
            `Investigated ${it.investigated_on} · impact ${it.impact} · confidence ${it.confidence}`));
        }
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

  // ── Chat ───────────────────────────────────────────────────────────────
  async function ask(question) {
    const headers = await authHeaders();
    if (!headers) return;
    const body = JSON.stringify({ question, session_id: store.getItem("session_id") || undefined });
    const r = await fetch("/api/chat", {
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
    if (!r.ok) throw new Error(data.error || `request failed (${r.status})`);
    store.setItem("session_id", data.session_id);
    const asOf = data.as_of ? `Data as of ${new Date(data.as_of).toLocaleString()}` : "";
    add("bot", data.answer, data.cited, [asOf, data.status === "limit" ? "partial answer" : ""].filter(Boolean).join(" · "));
  }

  $("ask").addEventListener("submit", async (e) => {
    e.preventDefault();
    const q = $("q");
    const button = $("send");
    const question = q.value.trim();
    if (!question) return;
    add("user", question);
    q.value = ""; button.disabled = true;
    try { await ask(question); } catch (err) { add("bot", `Something went wrong: ${err.message}`); }
    finally { button.disabled = false; q.focus(); }
  });
  $("q").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("ask").requestSubmit(); }
  });

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
      loadBrief().catch(() => {});
    });
  }

  if (dev) setupPersonas();
  suggestions();
  handleRedirect()
    .then(accessToken)
    .then(() => { if (!dev) $("who").textContent = store.getItem("name") || ""; })
    .then(loadBrief)
    .catch((err) => add("bot", `Sign-in problem: ${err.message}`));
})();
