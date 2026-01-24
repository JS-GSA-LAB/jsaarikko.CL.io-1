import express from "express";
import helmet from "helmet";
import { createProxyMiddleware } from "http-proxy-middleware";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load BOB Asset Tracker data
let bobAssets = [];
try {
  const assetsPath = join(__dirname, "assets.json");
  bobAssets = JSON.parse(readFileSync(assetsPath, "utf8"));
  console.log(`Loaded ${bobAssets.length} BOB assets`);
} catch (err) {
  console.warn("Could not load assets.json:", err.message);
}

/**
 * ENV VARS (set these in Railway):
 * - UPSTREAM_MCP_URL        (required) e.g. "http://134.141.116.46:8000"  (no trailing slash)
 * - MERAKI_API_KEY          (required) Meraki Dashboard API key
 * - XIQ_USERNAME            (optional) ExtremeCloud IQ username/email
 * - XIQ_PASSWORD            (optional) ExtremeCloud IQ password
 * - PROXY_ROUTE             (optional) default "/mcp"
 * - UI_ROUTE                (optional) default "/"
 * - BASIC_AUTH_USER         (optional) if set, enables Basic Auth for UI + proxy
 * - BASIC_AUTH_PASS         (optional) required if BASIC_AUTH_USER set
 * - FORWARD_AUTH_HEADER     (optional) default "true" => forward Authorization header to upstream
 *
 * Notes:
 * - This app provides a simple web UI and a reverse-proxy endpoint.
 * - Your Claude/clients can point to: https://<your-railway-domain>/mcp
 * - Your existing Meraki MCP server remains where it is; Railway just fronts it with a UI + stable URL.
 */

const MERAKI_API_BASE = "https://api.meraki.com/api/v1";
const MERAKI_API_KEY = process.env.MERAKI_API_KEY || "";

// Meraki API helper
async function merakiFetch(endpoint, options = {}) {
  if (!MERAKI_API_KEY) {
    throw new Error("MERAKI_API_KEY not configured");
  }
  const res = await fetch(`${MERAKI_API_BASE}${endpoint}`, {
    method: options.method || "GET",
    headers: {
      "X-Cisco-Meraki-API-Key": MERAKI_API_KEY,
      "Content-Type": "application/json",
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Meraki API error: ${res.status} ${res.statusText} - ${text}`);
  }
  // Handle empty responses (like DELETE)
  const text = await res.text();
  return text ? JSON.parse(text) : { success: true };
}

// ExtremeCloud IQ API
const XIQ_API_BASE = "https://api.extremecloudiq.com";
const XIQ_USERNAME = process.env.XIQ_USERNAME || "";
const XIQ_PASSWORD = process.env.XIQ_PASSWORD || "";

let xiqToken = null;
let xiqTokenExpiry = 0;

// XIQ Login - get bearer token
async function xiqLogin() {
  if (xiqToken && Date.now() < xiqTokenExpiry - 300000) {
    return xiqToken;
  }

  if (!XIQ_USERNAME || !XIQ_PASSWORD) {
    throw new Error("XIQ_USERNAME and XIQ_PASSWORD not configured");
  }

  const res = await fetch(`${XIQ_API_BASE}/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      username: XIQ_USERNAME,
      password: XIQ_PASSWORD,
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`XIQ login failed: ${res.status} ${res.statusText} - ${text}`);
  }

  const data = await res.json();
  xiqToken = data.access_token;
  // Token valid for 24 hours (86400 seconds)
  xiqTokenExpiry = Date.now() + (data.expire_time || 86400) * 1000;
  console.log("XIQ login successful, token expires:", new Date(xiqTokenExpiry).toISOString());
  return xiqToken;
}

// XIQ API helper
async function xiqFetch(endpoint, options = {}) {
  const token = await xiqLogin();
  const res = await fetch(`${XIQ_API_BASE}${endpoint}`, {
    method: options.method || "GET",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`XIQ API error: ${res.status} ${res.statusText} - ${text}`);
  }
  const text = await res.text();
  return text ? JSON.parse(text) : { success: true };
}

const app = express();

const PORT = Number(process.env.PORT || 3000);
const UPSTREAM = (process.env.UPSTREAM_MCP_URL || "").replace(/\/+$/, "");
const PROXY_ROUTE = process.env.PROXY_ROUTE || "/mcp";
const UI_ROUTE = process.env.UI_ROUTE || "/";
const FORWARD_AUTH_HEADER = (process.env.FORWARD_AUTH_HEADER ?? "true").toLowerCase() !== "false";

if (!UPSTREAM) {
  console.error("Missing required env var UPSTREAM_MCP_URL");
  process.exit(1);
}

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));

// Optional Basic Auth for everything
const BASIC_USER = process.env.BASIC_AUTH_USER;
const BASIC_PASS = process.env.BASIC_AUTH_PASS;

function basicAuth(req, res, next) {
  if (!BASIC_USER) return next();
  if (!BASIC_PASS) return res.status(500).send("Server misconfigured: BASIC_AUTH_PASS missing.");

  const header = req.headers.authorization || "";
  const [scheme, value] = header.split(" ");
  if (scheme !== "Basic" || !value) {
    res.setHeader("WWW-Authenticate", 'Basic realm="Meraki MCP Proxy"');
    return res.status(401).send("Auth required.");
  }
  const decoded = Buffer.from(value, "base64").toString("utf8");
  const [u, p] = decoded.split(":");
  if (u === BASIC_USER && p === BASIC_PASS) return next();
  res.setHeader("WWW-Authenticate", 'Basic realm="Meraki MCP Proxy"');
  return res.status(401).send("Invalid credentials.");
}

app.use(basicAuth);

// Health
app.get("/healthz", (_req, res) => res.json({ ok: true }));

// Meraki API: List Organizations
app.get("/api/organizations", async (_req, res) => {
  try {
    const orgs = await merakiFetch("/organizations");
    res.json(orgs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Get Organization details
app.get("/api/organizations/:orgId", async (req, res) => {
  try {
    const org = await merakiFetch(`/organizations/${req.params.orgId}`);
    res.json(org);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Delete Organization
app.delete("/api/organizations/:orgId", async (req, res) => {
  try {
    const result = await merakiFetch(`/organizations/${req.params.orgId}`, { method: "DELETE" });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: List Networks for an Organization
app.get("/api/organizations/:orgId/networks", async (req, res) => {
  try {
    const networks = await merakiFetch(`/organizations/${req.params.orgId}/networks`);
    res.json(networks);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: List Devices for an Organization
app.get("/api/organizations/:orgId/devices", async (req, res) => {
  try {
    const devices = await merakiFetch(`/organizations/${req.params.orgId}/devices`);
    res.json(devices);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Get Device Statuses for an Organization
app.get("/api/organizations/:orgId/devices/statuses", async (req, res) => {
  try {
    const statuses = await merakiFetch(`/organizations/${req.params.orgId}/devices/statuses`);
    res.json(statuses);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Get Network Events
app.get("/api/networks/:networkId/events", async (req, res) => {
  try {
    const { productType, includedEventTypes, startingAfter } = req.query;
    let endpoint = `/networks/${req.params.networkId}/events?perPage=100`;
    if (productType) endpoint += `&productType=${productType}`;
    if (includedEventTypes) endpoint += `&includedEventTypes[]=${includedEventTypes}`;
    if (startingAfter) endpoint += `&startingAfter=${startingAfter}`;
    const events = await merakiFetch(endpoint);
    res.json(events);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Get Device Events by Serial
app.get("/api/devices/:serial/events", async (req, res) => {
  try {
    const events = await merakiFetch(`/devices/${req.params.serial}/lossAndLatencyHistory?timespan=604800&ip=8.8.8.8`);
    res.json(events);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// XIQ API: List Devices
app.get("/api/xiq/devices", async (req, res) => {
  try {
    const page = req.query.page || 1;
    const limit = req.query.limit || 100;
    const data = await xiqFetch(`/devices?page=${page}&limit=${limit}`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// XIQ API: Get Device details
app.get("/api/xiq/devices/:deviceId", async (req, res) => {
  try {
    const data = await xiqFetch(`/devices/${req.params.deviceId}`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// XIQ API: List Sites (Locations)
app.get("/api/xiq/sites", async (req, res) => {
  try {
    const page = req.query.page || 1;
    const limit = req.query.limit || 100;
    const data = await xiqFetch(`/locations/site?page=${page}&limit=${limit}`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// XIQ API: Get Site details
app.get("/api/xiq/sites/:siteId", async (req, res) => {
  try {
    const data = await xiqFetch(`/locations/site/${req.params.siteId}`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// XIQ API: List Clients
app.get("/api/xiq/clients", async (req, res) => {
  try {
    const page = req.query.page || 1;
    const limit = req.query.limit || 100;
    const data = await xiqFetch(`/clients/active?page=${page}&limit=${limit}`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// XIQ API: Get Network Summary
app.get("/api/xiq/network/summary", async (req, res) => {
  try {
    const data = await xiqFetch(`/network/summary`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// BOB Asset Tracker API
app.get("/api/assets", (req, res) => {
  const { owner, type, region, search, page = 1, limit = 50 } = req.query;
  let filtered = [...bobAssets];

  if (owner) {
    filtered = filtered.filter(a => a.owner && a.owner.toLowerCase().includes(owner.toLowerCase()));
  }
  if (type) {
    filtered = filtered.filter(a => a.type && a.type.toLowerCase() === type.toLowerCase());
  }
  if (region) {
    filtered = filtered.filter(a => a.region && a.region.toLowerCase().includes(region.toLowerCase()));
  }
  if (search) {
    const s = search.toLowerCase();
    filtered = filtered.filter(a =>
      (a.deviceName && a.deviceName.toLowerCase().includes(s)) ||
      (a.model && a.model.toLowerCase().includes(s)) ||
      (a.serial && a.serial.toLowerCase().includes(s)) ||
      (a.owner && a.owner.toLowerCase().includes(s))
    );
  }

  const start = (page - 1) * limit;
  const paginated = filtered.slice(start, start + Number(limit));

  res.json({
    total: filtered.length,
    page: Number(page),
    limit: Number(limit),
    data: paginated
  });
});

// BOB Asset Tracker Statistics
app.get("/api/assets/stats", (req, res) => {
  const owners = {};
  const types = {};
  const regions = {};

  for (const a of bobAssets) {
    if (a.owner) owners[a.owner] = (owners[a.owner] || 0) + 1;
    if (a.type) types[a.type] = (types[a.type] || 0) + 1;
    if (a.region) regions[a.region] = (regions[a.region] || 0) + 1;
  }

  res.json({
    total: bobAssets.length,
    byOwner: Object.entries(owners).sort((a, b) => b[1] - a[1]).slice(0, 15),
    byType: Object.entries(types).sort((a, b) => b[1] - a[1]),
    byRegion: Object.entries(regions).sort((a, b) => b[1] - a[1]).slice(0, 15)
  });
});

// UI
app.get(UI_ROUTE, (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Extreme Networks MCP Exchange</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;500&family=Roboto:wght@300;400;500;700&family=Poppins:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --background: #121212;
      --foreground: rgba(255, 255, 255, 0.87);
      --foreground-muted: rgba(255, 255, 255, 0.60);
      --primary: #BB86FC;
      --secondary: #03DAC5;
      --destructive: #CF6679;
      --success: #81C784;
      --warning: #FFB74D;
      --border: rgba(255, 255, 255, 0.12);
      --surface-1dp: rgba(255, 255, 255, 0.05);
      --surface-2dp: rgba(255, 255, 255, 0.07);
      --surface-4dp: rgba(255, 255, 255, 0.09);
      --font-sans: 'Roboto', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'Roboto Mono', 'SF Mono', Monaco, monospace;
      --radius: 0.25rem;
    }
    * { box-sizing: border-box; }
    body {
      font-family: var(--font-sans);
      font-weight: 400;
      margin: 0;
      background: var(--background);
      color: var(--foreground);
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }
    .wrap { max-width: 860px; margin: 0 auto; padding: 32px 20px; }
    .header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }
    .logo {
      width: 40px;
      height: 40px;
      background: linear-gradient(135deg, var(--primary), var(--secondary));
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 18px;
      color: rgba(0, 0, 0, 0.87);
    }
    .brand { font-size: 14px; }
    .brand-name { font-weight: 500; color: var(--foreground); }
    .brand-sub { color: var(--foreground-muted); font-size: 12px; }
    .card {
      background: linear-gradient(var(--surface-2dp), var(--surface-2dp)), var(--background);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      margin: 16px 0;
      transition: background-color 200ms cubic-bezier(0.4, 0, 0.2, 1),
                  border-color 200ms cubic-bezier(0.4, 0, 0.2, 1);
    }
    .card:hover {
      background: linear-gradient(var(--surface-4dp), var(--surface-4dp)), var(--background);
    }
    h1 { font-size: 1.25rem; font-weight: 500; margin: 0 0 8px; color: var(--foreground); }
    h2 { font-size: 1rem; font-weight: 500; margin: 0 0 8px; color: var(--foreground); }
    .muted { color: var(--foreground-muted); font-size: 0.875rem; }
    code {
      font-family: var(--font-mono);
      font-size: 0.875rem;
      background: linear-gradient(var(--surface-1dp), var(--surface-1dp)), var(--background);
      padding: 2px 6px;
      border-radius: 4px;
    }
    pre {
      font-family: var(--font-mono);
      font-size: 0.875rem;
      background: linear-gradient(var(--surface-1dp), var(--surface-1dp)), var(--background);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
      margin: 12px 0;
      overflow-x: auto;
      line-height: 1.6;
    }
    .row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }
    .grid-2 { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }
    @media (max-width: 600px) { .grid-2 { grid-template-columns: 1fr; } }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      border-radius: 999px;
      background: linear-gradient(var(--surface-1dp), var(--surface-1dp)), var(--background);
      border: 1px solid var(--border);
      color: var(--foreground-muted);
      font-size: 0.75rem;
      font-weight: 400;
    }
    .pill b { color: var(--secondary); font-weight: 500; }
    a { color: var(--primary); text-decoration: none; transition: color 200ms cubic-bezier(0.4, 0, 0.2, 1); }
    a:hover { color: var(--secondary); }
    .warn { color: var(--warning); }
    .success { color: var(--success); }
    .status-dot {
      display: inline-block;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--success);
      margin-right: 8px;
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
    .section-title {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 12px;
    }
    .section-title h2 { margin: 0; }
    .icon {
      width: 20px;
      height: 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--primary);
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <div class="logo">E</div>
      <div class="brand">
        <div class="brand-name">Extreme Networks MCP Exchange</div>
        <div class="brand-sub">Meraki MCP Server (RDU)</div>
      </div>
    </div>

    <div class="card">
      <h1><span class="status-dot"></span>Service Active</h1>
      <div class="muted">
        This gateway provides a stable HTTPS endpoint for your Meraki MCP server with built-in health monitoring.
      </div>
      <div class="row">
        <span class="pill">Upstream: <b>\${UPSTREAM}</b></span>
        <span class="pill">Route: <b>\${PROXY_ROUTE}</b></span>
      </div>
    </div>

    <div class="card">
      <div class="section-title">
        <span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg></span>
        <h2>Client Connection</h2>
      </div>
      <div class="muted">Configure your Claude or MCP client to connect to:</div>
      <pre id="clientUrl"></pre>
      <script>
        document.getElementById("clientUrl").textContent = location.origin + "\${PROXY_ROUTE}";
      </script>
      <div class="muted" style="margin-top:12px">
        \${FORWARD_AUTH_HEADER ? "Authorization headers are forwarded to upstream." : "<span class='warn'>Authorization headers are NOT forwarded.</span>"}
      </div>
    </div>

    <div class="card">
      <div class="section-title">
        <span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg></span>
        <h2>Configuration</h2>
      </div>
      <div class="muted">Railway environment variables:</div>
      <pre>UPSTREAM_MCP_URL=\${UPSTREAM || "http://YOUR_MERAKI_MCP_SERVER:PORT"}
PROXY_ROUTE=/mcp
FORWARD_AUTH_HEADER=true</pre>
      <div class="muted" style="margin-top:12px">Optional authentication:</div>
      <pre>BASIC_AUTH_USER=youruser
BASIC_AUTH_PASS=yourpass</pre>
    </div>

    <div class="grid-2">
      <div class="card" style="margin:0">
        <div class="section-title">
          <span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg></span>
          <h2>Health Check</h2>
        </div>
        <div class="muted">Monitor service status:</div>
        <pre><a href="/healthz">/healthz</a></pre>
      </div>

      <div class="card" style="margin:0">
        <div class="section-title">
          <span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span>
          <h2>Meraki Organizations</h2>
        </div>
        <div class="muted">Connected Meraki Dashboard organizations:</div>
        <div id="orgs-container" style="margin-top:12px">
          <div class="muted">Loading...</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="section-title">
        <span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg></span>
        <h2>ExtremeCloud IQ Devices</h2>
      </div>
      <div class="muted">Connected XIQ devices:</div>
      <div id="xiq-devices-container" style="margin-top:12px">
        <div class="muted">Loading...</div>
      </div>
    </div>

    <div class="card">
      <div class="section-title">
        <span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="10" r="3"/><path d="M12 21.7C17.3 17 20 13 20 10a8 8 0 1 0-16 0c0 3 2.7 7 8 11.7z"/></svg></span>
        <h2>ExtremeCloud IQ Sites</h2>
      </div>
      <div class="muted">XIQ site locations:</div>
      <div id="xiq-sites-container" style="margin-top:12px">
        <div class="muted">Loading...</div>
      </div>
    </div>

    <div class="card">
      <div class="section-title">
        <span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
        <h2>ExtremeCloud IQ Clients</h2>
      </div>
      <div class="muted">Active clients:</div>
      <div id="xiq-clients-container" style="margin-top:12px">
        <div class="muted">Loading...</div>
      </div>
    </div>

    <div class="card">
      <div class="section-title">
        <span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg></span>
        <h2>BOB Asset Tracker</h2>
      </div>
      <div class="muted">SE Equipment Inventory</div>
      <div id="bob-stats-container" style="margin-top:12px">
        <div class="muted">Loading...</div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card" style="margin:0">
        <div class="section-title">
          <span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg></span>
          <h2>Assets by Type</h2>
        </div>
        <div id="bob-types-container" style="margin-top:12px">
          <div class="muted">Loading...</div>
        </div>
      </div>

      <div class="card" style="margin:0">
        <div class="section-title">
          <span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></span>
          <h2>Top Asset Owners</h2>
        </div>
        <div id="bob-owners-container" style="margin-top:12px">
          <div class="muted">Loading...</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="section-title">
        <span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg></span>
        <h2>Search Assets</h2>
      </div>
      <div style="margin-top:12px">
        <input type="text" id="asset-search" placeholder="Search by name, model, serial, or owner..." style="width:100%;padding:10px 14px;background:linear-gradient(rgba(255,255,255,0.05),rgba(255,255,255,0.05)),#121212;border:1px solid rgba(255,255,255,0.12);border-radius:8px;color:rgba(255,255,255,0.87);font-family:var(--font-sans);font-size:14px;outline:none;" />
      </div>
      <div id="bob-search-results" style="margin-top:12px;max-height:400px;overflow-y:auto">
        <div class="muted">Enter a search term above</div>
      </div>
    </div>

    </div>

  <script>
    async function loadOrganizations() {
      const container = document.getElementById('orgs-container');
      try {
        const res = await fetch('/api/organizations');
        if (!res.ok) throw new Error('Failed to fetch');
        const orgs = await res.json();
        if (orgs.error) {
          container.innerHTML = '<div class="warn">' + orgs.error + '</div>';
          return;
        }
        if (orgs.length === 0) {
          container.innerHTML = '<div class="muted">No organizations found</div>';
          return;
        }
        container.innerHTML = orgs.map(org =>
          '<div style="padding:10px;margin:6px 0;background:linear-gradient(rgba(255,255,255,0.05),rgba(255,255,255,0.05)),#121212;border:1px solid rgba(255,255,255,0.12);border-radius:8px">' +
          '<div style="font-weight:500;color:rgba(255,255,255,0.87)">' + org.name + '</div>' +
          '<div style="font-size:12px;color:rgba(255,255,255,0.6);font-family:var(--font-mono)">ID: ' + org.id + '</div>' +
          (org.url ? '<a href="' + org.url + '" target="_blank" style="font-size:12px">Dashboard</a>' : '') +
          '</div>'
        ).join('');
      } catch (err) {
        container.innerHTML = '<div class="warn">Error loading organizations</div>';
      }
    }

    async function loadXiqDevices() {
      const container = document.getElementById('xiq-devices-container');
      try {
        const res = await fetch('/api/xiq/devices?limit=10');
        if (!res.ok) throw new Error('Failed to fetch');
        const data = await res.json();
        if (data.error) {
          container.innerHTML = '<div class="warn">' + data.error + '</div>';
          return;
        }
        const devices = data.data || data;
        if (!devices || devices.length === 0) {
          container.innerHTML = '<div class="muted">No devices found</div>';
          return;
        }
        container.innerHTML = devices.slice(0, 10).map(device =>
          '<div style="padding:10px;margin:6px 0;background:linear-gradient(rgba(255,255,255,0.05),rgba(255,255,255,0.05)),#121212;border:1px solid rgba(255,255,255,0.12);border-radius:8px">' +
          '<div style="display:flex;justify-content:space-between;align-items:center">' +
          '<div style="font-weight:500;color:rgba(255,255,255,0.87)">' + (device.hostname || device.name || 'Unknown') + '</div>' +
          '<span style="font-size:11px;padding:2px 8px;border-radius:999px;background:' + (device.connected ? '#81C784' : '#CF6679') + ';color:#000">' + (device.connected ? 'Online' : 'Offline') + '</span>' +
          '</div>' +
          '<div style="font-size:12px;color:rgba(255,255,255,0.6)">' + (device.product_type || device.device_function || '') + '</div>' +
          '<div style="font-size:12px;color:rgba(255,255,255,0.6);font-family:var(--font-mono)">' + (device.mac_address || device.serial_number || '') + '</div>' +
          '</div>'
        ).join('') + (devices.length > 10 ? '<div class="muted" style="margin-top:8px">...and ' + (devices.length - 10) + ' more</div>' : '');
      } catch (err) {
        container.innerHTML = '<div class="warn">Error loading devices</div>';
      }
    }

    async function loadXiqSites() {
      const container = document.getElementById('xiq-sites-container');
      try {
        const res = await fetch('/api/xiq/sites?limit=10');
        if (!res.ok) throw new Error('Failed to fetch');
        const data = await res.json();
        if (data.error) {
          container.innerHTML = '<div class="warn">' + data.error + '</div>';
          return;
        }
        const sites = data.data || data;
        if (!sites || sites.length === 0) {
          container.innerHTML = '<div class="muted">No sites found</div>';
          return;
        }
        container.innerHTML = sites.slice(0, 10).map(site =>
          '<div style="padding:10px;margin:6px 0;background:linear-gradient(rgba(255,255,255,0.05),rgba(255,255,255,0.05)),#121212;border:1px solid rgba(255,255,255,0.12);border-radius:8px">' +
          '<div style="font-weight:500;color:rgba(255,255,255,0.87)">' + (site.name || 'Unnamed') + '</div>' +
          '<div style="font-size:12px;color:rgba(255,255,255,0.6)">' + (site.address || '') + '</div>' +
          '<div style="font-size:12px;color:rgba(255,255,255,0.6);font-family:var(--font-mono)">ID: ' + site.id + '</div>' +
          '</div>'
        ).join('');
      } catch (err) {
        container.innerHTML = '<div class="warn">Error loading sites</div>';
      }
    }

    async function loadXiqClients() {
      const container = document.getElementById('xiq-clients-container');
      try {
        const res = await fetch('/api/xiq/clients?limit=10');
        if (!res.ok) throw new Error('Failed to fetch');
        const data = await res.json();
        if (data.error) {
          container.innerHTML = '<div class="warn">' + data.error + '</div>';
          return;
        }
        const clients = data.data || data;
        if (!clients || clients.length === 0) {
          container.innerHTML = '<div class="muted">No active clients</div>';
          return;
        }
        container.innerHTML = '<div style="font-size:14px;color:var(--secondary);font-weight:500">' + clients.length + ' active clients</div>' +
          clients.slice(0, 5).map(client =>
            '<div style="padding:8px;margin:4px 0;background:linear-gradient(rgba(255,255,255,0.03),rgba(255,255,255,0.03)),#121212;border-radius:6px">' +
            '<span style="color:rgba(255,255,255,0.87)">' + (client.hostname || client.mac_address || 'Unknown') + '</span>' +
            '<span style="font-size:11px;color:rgba(255,255,255,0.5);margin-left:8px">' + (client.ip_address || '') + '</span>' +
            '</div>'
          ).join('');
      } catch (err) {
        container.innerHTML = '<div class="warn">Error loading clients</div>';
      }
    }

    loadOrganizations();
    loadXiqDevices();
    loadXiqSites();
    loadXiqClients();
    loadBobStats();

    async function loadBobStats() {
      const statsContainer = document.getElementById('bob-stats-container');
      const typesContainer = document.getElementById('bob-types-container');
      const ownersContainer = document.getElementById('bob-owners-container');
      try {
        const res = await fetch('/api/assets/stats');
        if (!res.ok) throw new Error('Failed to fetch');
        const stats = await res.json();

        // Stats summary
        statsContainer.innerHTML =
          '<div style="display:flex;gap:16px;flex-wrap:wrap">' +
          '<div style="padding:16px 20px;background:linear-gradient(135deg,var(--primary),var(--secondary));border-radius:12px;flex:1;min-width:120px">' +
          '<div style="font-size:28px;font-weight:700;color:rgba(0,0,0,0.87)">' + stats.total + '</div>' +
          '<div style="font-size:12px;color:rgba(0,0,0,0.6)">Total Assets</div></div>' +
          '<div style="padding:16px 20px;background:linear-gradient(rgba(255,255,255,0.07),rgba(255,255,255,0.07)),#121212;border:1px solid rgba(255,255,255,0.12);border-radius:12px;flex:1;min-width:120px">' +
          '<div style="font-size:28px;font-weight:700;color:var(--secondary)">' + stats.byType.length + '</div>' +
          '<div style="font-size:12px;color:rgba(255,255,255,0.6)">Asset Types</div></div>' +
          '<div style="padding:16px 20px;background:linear-gradient(rgba(255,255,255,0.07),rgba(255,255,255,0.07)),#121212;border:1px solid rgba(255,255,255,0.12);border-radius:12px;flex:1;min-width:120px">' +
          '<div style="font-size:28px;font-weight:700;color:var(--primary)">' + stats.byOwner.length + '</div>' +
          '<div style="font-size:12px;color:rgba(255,255,255,0.6)">SE Owners</div></div>' +
          '<div style="padding:16px 20px;background:linear-gradient(rgba(255,255,255,0.07),rgba(255,255,255,0.07)),#121212;border:1px solid rgba(255,255,255,0.12);border-radius:12px;flex:1;min-width:120px">' +
          '<div style="font-size:28px;font-weight:700;color:var(--warning)">' + stats.byRegion.length + '</div>' +
          '<div style="font-size:12px;color:rgba(255,255,255,0.6)">Regions</div></div>' +
          '</div>';

        // Types breakdown
        const typeColors = {
          'Switch': '#BB86FC',
          'AP': '#03DAC5',
          'SD-WAN': '#FFB74D',
          'PEPLink': '#CF6679',
          'Verkada': '#81C784',
          'XA1400': '#64B5F6',
          'i-Pro': '#F48FB1'
        };
        typesContainer.innerHTML = stats.byType.map(([type, count]) => {
          const pct = Math.round((count / stats.total) * 100);
          const color = typeColors[type] || '#888';
          return '<div style="margin:8px 0">' +
            '<div style="display:flex;justify-content:space-between;margin-bottom:4px">' +
            '<span style="font-size:13px;color:rgba(255,255,255,0.87)">' + type + '</span>' +
            '<span style="font-size:13px;color:rgba(255,255,255,0.6)">' + count + ' (' + pct + '%)</span>' +
            '</div>' +
            '<div style="height:8px;background:rgba(255,255,255,0.08);border-radius:4px;overflow:hidden">' +
            '<div style="height:100%;width:' + pct + '%;background:' + color + ';border-radius:4px"></div>' +
            '</div></div>';
        }).join('');

        // Top owners
        ownersContainer.innerHTML = stats.byOwner.slice(0, 10).map(([owner, count], i) =>
          '<div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.06)">' +
          '<div style="width:24px;height:24px;border-radius:50%;background:linear-gradient(135deg,var(--primary),var(--secondary));display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:600;color:rgba(0,0,0,0.87)">' + (i + 1) + '</div>' +
          '<div style="flex:1">' +
          '<div style="font-size:13px;color:rgba(255,255,255,0.87)">' + owner + '</div>' +
          '</div>' +
          '<div style="font-size:13px;color:var(--secondary);font-weight:500">' + count + ' assets</div>' +
          '</div>'
        ).join('');
      } catch (err) {
        statsContainer.innerHTML = '<div class="warn">Error loading asset stats</div>';
        typesContainer.innerHTML = '';
        ownersContainer.innerHTML = '';
      }
    }

    // Asset search
    let searchTimeout;
    document.getElementById('asset-search').addEventListener('input', function(e) {
      clearTimeout(searchTimeout);
      const query = e.target.value.trim();
      if (!query) {
        document.getElementById('bob-search-results').innerHTML = '<div class="muted">Enter a search term above</div>';
        return;
      }
      searchTimeout = setTimeout(async () => {
        const container = document.getElementById('bob-search-results');
        container.innerHTML = '<div class="muted">Searching...</div>';
        try {
          const res = await fetch('/api/assets?search=' + encodeURIComponent(query) + '&limit=25');
          if (!res.ok) throw new Error('Failed to fetch');
          const data = await res.json();
          if (data.data.length === 0) {
            container.innerHTML = '<div class="muted">No assets found matching "' + query + '"</div>';
            return;
          }
          container.innerHTML = '<div class="muted" style="margin-bottom:8px">' + data.total + ' assets found</div>' +
            data.data.map(asset =>
              '<div style="padding:12px;margin:6px 0;background:linear-gradient(rgba(255,255,255,0.05),rgba(255,255,255,0.05)),#121212;border:1px solid rgba(255,255,255,0.12);border-radius:8px">' +
              '<div style="display:flex;justify-content:space-between;align-items:center">' +
              '<div style="font-weight:500;color:rgba(255,255,255,0.87)">' + (asset.deviceName || asset.model || 'Unknown Device') + '</div>' +
              '<span style="font-size:11px;padding:2px 8px;border-radius:999px;background:rgba(187,134,252,0.2);color:#BB86FC">' + (asset.type || 'Unknown') + '</span>' +
              '</div>' +
              '<div style="font-size:12px;color:rgba(255,255,255,0.6);margin-top:4px">' +
              (asset.model ? 'Model: ' + asset.model + ' | ' : '') +
              (asset.serial ? 'S/N: ' + asset.serial : '') +
              '</div>' +
              '<div style="font-size:12px;color:rgba(255,255,255,0.5);margin-top:4px">' +
              '<span style="color:var(--secondary)">' + (asset.owner || 'Unassigned') + '</span>' +
              (asset.kit ? ' · ' + asset.kit : '') +
              (asset.region ? ' · ' + asset.region : '') +
              '</div></div>'
            ).join('');
        } catch (err) {
          container.innerHTML = '<div class="warn">Error searching assets</div>';
        }
      }, 300);
    });
  </script>
</body>
</html>`);
});

// Reverse proxy to your existing MCP server.
// Supports SSE + websockets (if your upstream uses them) via http-proxy-middleware.
const proxy = createProxyMiddleware({
  target: UPSTREAM,
  changeOrigin: true,
  ws: true,
  xfwd: true,
  logLevel: "warn",
  pathRewrite: (path) => path.replace(new RegExp(`^${PROXY_ROUTE}`), ""),
  onProxyReq: (proxyReq, req) => {
    // Optionally strip Authorization header (some users want to avoid passing tokens through proxy)
    if (!FORWARD_AUTH_HEADER) {
      proxyReq.removeHeader("authorization");
    }
    // Preserve original host if needed (some MCP servers care)
    proxyReq.setHeader("x-original-host", req.headers.host || "");
  }
});

app.use(PROXY_ROUTE, proxy);

app.listen(PORT, () => {
  console.log(`Meraki MCP Proxy running on :${PORT}`);
  console.log(`Upstream: ${UPSTREAM}`);
  console.log(`Proxy: http://localhost:${PORT}${PROXY_ROUTE} -> ${UPSTREAM}`);
});
