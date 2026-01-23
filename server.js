import express from "express";
import helmet from "helmet";
import { createProxyMiddleware } from "http-proxy-middleware";

/**
 * ENV VARS (set these in Railway):
 * - UPSTREAM_MCP_URL        (required) e.g. "http://134.141.116.46:8000"  (no trailing slash)
 * - MERAKI_API_KEY          (required) Meraki Dashboard API key
 * - PEPLINK_CLIENT_ID       (optional) Peplink InControl OAuth client ID
 * - PEPLINK_CLIENT_SECRET   (optional) Peplink InControl OAuth client secret
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
async function merakiFetch(endpoint) {
  if (!MERAKI_API_KEY) {
    throw new Error("MERAKI_API_KEY not configured");
  }
  const res = await fetch(`${MERAKI_API_BASE}${endpoint}`, {
    headers: {
      "X-Cisco-Meraki-API-Key": MERAKI_API_KEY,
      "Content-Type": "application/json",
    },
  });
  if (!res.ok) {
    throw new Error(`Meraki API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

// Peplink InControl API
const PEPLINK_API_BASE = "https://api.ic.peplink.com/rest";
const PEPLINK_TOKEN_URL = "https://api.ic.peplink.com/api/oauth2/token";
const PEPLINK_CLIENT_ID = process.env.PEPLINK_CLIENT_ID || "";
const PEPLINK_CLIENT_SECRET = process.env.PEPLINK_CLIENT_SECRET || "";

let peplinkToken = null;
let peplinkTokenExpiry = 0;

// Get Peplink OAuth token
async function getPeplinkToken() {
  if (peplinkToken && Date.now() < peplinkTokenExpiry - 60000) {
    return peplinkToken;
  }

  if (!PEPLINK_CLIENT_ID || !PEPLINK_CLIENT_SECRET) {
    throw new Error("PEPLINK_CLIENT_ID and PEPLINK_CLIENT_SECRET not configured");
  }

  const res = await fetch(PEPLINK_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: PEPLINK_CLIENT_ID,
      client_secret: PEPLINK_CLIENT_SECRET,
    }),
  });

  if (!res.ok) {
    throw new Error(`Peplink OAuth error: ${res.status} ${res.statusText}`);
  }

  const data = await res.json();
  peplinkToken = data.access_token;
  peplinkTokenExpiry = Date.now() + (data.expires_in * 1000);
  return peplinkToken;
}

// Peplink API helper
async function peplinkFetch(endpoint) {
  const token = await getPeplinkToken();
  const res = await fetch(`${PEPLINK_API_BASE}${endpoint}`, {
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });
  if (!res.ok) {
    throw new Error(`Peplink API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
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

// Peplink API: List Organizations
app.get("/api/peplink/organizations", async (_req, res) => {
  try {
    const data = await peplinkFetch("/o");
    res.json(data.data || data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Peplink API: Get Organization details
app.get("/api/peplink/organizations/:orgId", async (req, res) => {
  try {
    const data = await peplinkFetch(`/o/${req.params.orgId}`);
    res.json(data.data || data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Peplink API: List Groups (locations) for an Organization
app.get("/api/peplink/organizations/:orgId/groups", async (req, res) => {
  try {
    const data = await peplinkFetch(`/o/${req.params.orgId}/g`);
    res.json(data.data || data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Peplink API: List Devices for an Organization
app.get("/api/peplink/organizations/:orgId/devices", async (req, res) => {
  try {
    const data = await peplinkFetch(`/o/${req.params.orgId}/d`);
    res.json(data.data || data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Peplink API: Get Device details
app.get("/api/peplink/devices/:deviceId", async (req, res) => {
  try {
    const data = await peplinkFetch(`/d/${req.params.deviceId}`);
    res.json(data.data || data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Peplink API: Get all locations (groups) with devices
app.get("/api/peplink/locations", async (_req, res) => {
  try {
    // First get all organizations
    const orgsData = await peplinkFetch("/o");
    const orgs = orgsData.data || orgsData;

    // Then get groups for each org
    const locations = [];
    for (const org of orgs) {
      try {
        const groupsData = await peplinkFetch(`/o/${org.id}/g`);
        const groups = groupsData.data || groupsData;
        for (const group of groups) {
          locations.push({
            ...group,
            orgId: org.id,
            orgName: org.name,
          });
        }
      } catch (e) {
        // Skip orgs we can't access
      }
    }
    res.json(locations);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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

    <div class="card">
      <div class="section-title">
        <span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg></span>
        <h2>Health Check</h2>
      </div>
      <div class="muted">Monitor service status:</div>
      <pre><a href="/healthz">/healthz</a></pre>
    </div>

    <div class="card">
      <div class="section-title">
        <span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span>
        <h2>Meraki Organizations</h2>
      </div>
      <div class="muted">Connected Meraki Dashboard organizations:</div>
      <div id="orgs-container" style="margin-top:12px">
        <div class="muted">Loading...</div>
      </div>
    </div>

    <div class="card">
      <div class="section-title">
        <span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="10" r="3"/><path d="M12 21.7C17.3 17 20 13 20 10a8 8 0 1 0-16 0c0 3 2.7 7 8 11.7z"/></svg></span>
        <h2>Peplink Locations</h2>
      </div>
      <div class="muted">Connected Peplink InControl locations:</div>
      <div id="peplink-container" style="margin-top:12px">
        <div class="muted">Loading...</div>
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

    async function loadPeplinkLocations() {
      const container = document.getElementById('peplink-container');
      try {
        const res = await fetch('/api/peplink/locations');
        if (!res.ok) throw new Error('Failed to fetch');
        const locations = await res.json();
        if (locations.error) {
          container.innerHTML = '<div class="warn">' + locations.error + '</div>';
          return;
        }
        if (!locations.length) {
          container.innerHTML = '<div class="muted">No locations found</div>';
          return;
        }
        container.innerHTML = locations.map(loc =>
          '<div style="padding:10px;margin:6px 0;background:linear-gradient(rgba(255,255,255,0.05),rgba(255,255,255,0.05)),#121212;border:1px solid rgba(255,255,255,0.12);border-radius:8px">' +
          '<div style="font-weight:500;color:rgba(255,255,255,0.87)">' + (loc.name || 'Unnamed') + '</div>' +
          '<div style="font-size:12px;color:rgba(255,255,255,0.6)">Org: ' + (loc.orgName || loc.orgId) + '</div>' +
          '<div style="font-size:12px;color:rgba(255,255,255,0.6);font-family:var(--font-mono)">ID: ' + loc.id + '</div>' +
          '</div>'
        ).join('');
      } catch (err) {
        container.innerHTML = '<div class="warn">Error loading locations</div>';
      }
    }

    loadOrganizations();
    loadPeplinkLocations();
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
