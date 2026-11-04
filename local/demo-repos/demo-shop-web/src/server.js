// Storefront API (demo). Deliberately vulnerable: do not deploy.
const express = require("express");
const axios = require("axios");
const _ = require("lodash");
const { renderBanner } = require("./banner");

const app = express();
app.use(express.json());

// Link previews: fetches whatever URL the caller sends, from inside our network.
app.get("/preview", async (req, res) => {
  try {
    const page = await axios.get(req.query.url, { timeout: 3000, maxRedirects: 5 });
    res.json({ status: page.status, title: String(page.data).slice(0, 200) });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// Saved carts: the request body is merged straight into the stored cart.
const carts = {};
app.post("/carts/:id", (req, res) => {
  carts[req.params.id] = _.merge(carts[req.params.id] || {}, req.body);
  res.json(carts[req.params.id]);
});

// Marketing banners: the template text comes from the query string.
app.get("/banner", (req, res) => {
  res.type("text/html").send(renderBanner(req.query.tpl || "Hello <%= name %>", { name: req.query.name || "guest" }));
});

app.get("/health", (_req, res) => res.json({ ok: true }));

app.listen(process.env.PORT || 3000, () => console.log("storefront listening"));
