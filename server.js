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
 * - PEPLINK_CLIENT_ID       (optional) PepLink InControl2 OAuth Client ID
 * - PEPLINK_CLIENT_SECRET   (optional) PepLink InControl2 OAuth Client Secret
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

// PepLink InControl2 API
const PEPLINK_API_BASE = "https://api.ic.peplink.com";
const PEPLINK_CLIENT_ID = process.env.PEPLINK_CLIENT_ID || "";
const PEPLINK_CLIENT_SECRET = process.env.PEPLINK_CLIENT_SECRET || "";

let peplinkToken = null;
let peplinkTokenExpiry = 0;

// PepLink OAuth2 - get access token
async function peplinkLogin() {
  if (peplinkToken && Date.now() < peplinkTokenExpiry - 300000) {
    return peplinkToken;
  }

  if (!PEPLINK_CLIENT_ID || !PEPLINK_CLIENT_SECRET) {
    throw new Error("PEPLINK_CLIENT_ID and PEPLINK_CLIENT_SECRET not configured");
  }

  const res = await fetch(`${PEPLINK_API_BASE}/api/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      client_id: PEPLINK_CLIENT_ID,
      client_secret: PEPLINK_CLIENT_SECRET,
      grant_type: "client_credentials",
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`PepLink login failed: ${res.status} ${res.statusText} - ${text}`);
  }

  const data = await res.json();
  peplinkToken = data.access_token;
  // Token valid for expires_in seconds (typically 3600)
  peplinkTokenExpiry = Date.now() + (data.expires_in || 3600) * 1000;
  console.log("PepLink login successful, token expires:", new Date(peplinkTokenExpiry).toISOString());
  return peplinkToken;
}

// PepLink API helper
async function peplinkFetch(endpoint, options = {}) {
  const token = await peplinkLogin();
  const res = await fetch(`${PEPLINK_API_BASE}${endpoint}`, {
    method: options.method || "GET",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`PepLink API error: ${res.status} ${res.statusText} - ${text}`);
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

// Meraki API: Get DFS Events for a Network
app.get("/api/networks/:networkId/dfs-events", async (req, res) => {
  try {
    const events = await merakiFetch(`/networks/${req.params.networkId}/events?productType=wireless&perPage=100`);
    const dfsEvents = (events.events || []).filter(e => e.type === 'dfs_event');

    // Group by device
    const byDevice = {};
    for (const e of dfsEvents) {
      const dev = e.deviceName || 'unknown';
      if (!byDevice[dev]) byDevice[dev] = [];
      byDevice[dev].push({
        occurredAt: e.occurredAt,
        channel: e.eventData?.channel,
        radio: e.eventData?.radio,
        serial: e.deviceSerial
      });
    }

    res.json({
      total: dfsEvents.length,
      pageStartAt: events.pageStartAt,
      pageEndAt: events.pageEndAt,
      byDevice
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Get Wireless Health Report
app.get("/api/networks/:networkId/wireless-health", async (req, res) => {
  try {
    // Support timespan in seconds (default 1 day = 86400)
    const timespan = req.query.timespan || 86400;
    const events = await merakiFetch(`/networks/${req.params.networkId}/events?productType=wireless&perPage=1000&timespan=${timespan}`);
    const allEvents = events.events || [];

    // Categorize events
    const dfsEvents = allEvents.filter(e => e.type === 'dfs_event');
    const floodEvents = allEvents.filter(e => e.type === 'packet_flood');
    const rfChanges = allEvents.filter(e => e.type === 'sunray_auto_rf_channel_change');
    const roamEvents = allEvents.filter(e =>
      e.type === 'association' ||
      e.type === 'disassociation' ||
      e.type === '802.11_association' ||
      e.type === '802.11_disassociation' ||
      e.type === 'roam' ||
      e.type === 'wpa_auth' ||
      e.type === 'wpa_deauth'
    );

    // Get unique devices affected
    const dfsDevices = [...new Set(dfsEvents.map(e => e.deviceName))];
    const floodDevices = [...new Set(floodEvents.map(e => e.deviceName))];
    const roamDevices = [...new Set(roamEvents.map(e => e.deviceName))];

    // Analyze roaming patterns
    const clientRoams = {};
    roamEvents.forEach(e => {
      const client = e.clientMac || e.clientDescription || 'unknown';
      if (!clientRoams[client]) clientRoams[client] = { events: [], devices: new Set() };
      clientRoams[client].events.push(e);
      if (e.deviceName) clientRoams[client].devices.add(e.deviceName);
    });

    res.json({
      timeRange: { start: events.pageStartAt, end: events.pageEndAt },
      summary: {
        dfsEvents: dfsEvents.length,
        packetFloods: floodEvents.length,
        rfOptimizations: rfChanges.length,
        roamEvents: roamEvents.length
      },
      dfs: {
        count: dfsEvents.length,
        devicesAffected: dfsDevices,
        events: dfsEvents.slice(0, 20).map(e => ({
          time: e.occurredAt,
          device: e.deviceName,
          channel: e.eventData?.channel
        }))
      },
      floods: {
        count: floodEvents.length,
        devicesAffected: floodDevices,
        events: floodEvents.slice(0, 10).map(e => ({
          time: e.occurredAt,
          device: e.deviceName,
          bssid: e.eventData?.bssid,
          channel: e.eventData?.channel,
          packet: e.eventData?.packet
        }))
      },
      roaming: {
        count: roamEvents.length,
        devicesAffected: roamDevices,
        uniqueClients: Object.keys(clientRoams).length,
        events: roamEvents.slice(0, 20).map(e => ({
          time: e.occurredAt,
          type: e.type,
          device: e.deviceName,
          client: e.clientDescription || e.clientMac,
          clientMac: e.clientMac,
          ssid: e.eventData?.ssid || e.eventData?.ssid_name,
          rssi: e.eventData?.rssi,
          channel: e.eventData?.channel
        })),
        topClients: Object.entries(clientRoams)
          .map(([mac, data]) => ({ mac, count: data.events.length, aps: [...data.devices] }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 10)
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Get Network Wireless Settings
app.get("/api/networks/:networkId/wireless/settings", async (req, res) => {
  try {
    const data = await merakiFetch(`/networks/${req.params.networkId}/wireless/settings`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Update Network Wireless Settings
app.put("/api/networks/:networkId/wireless/settings", express.json(), async (req, res) => {
  try {
    const data = await merakiFetch(`/networks/${req.params.networkId}/wireless/settings`, {
      method: "PUT",
      body: req.body
    });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Get Network Settings (including event logging)
app.get("/api/networks/:networkId/settings", async (req, res) => {
  try {
    const data = await merakiFetch(`/networks/${req.params.networkId}/settings`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Update Network Settings
app.put("/api/networks/:networkId/settings", express.json(), async (req, res) => {
  try {
    const data = await merakiFetch(`/networks/${req.params.networkId}/settings`, {
      method: "PUT",
      body: req.body
    });
    res.json(data);
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

// PepLink API: List Organizations
app.get("/api/peplink/organizations", async (req, res) => {
  try {
    const data = await peplinkFetch("/rest/o");
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PepLink API: List Groups in Organization
app.get("/api/peplink/organizations/:orgId/groups", async (req, res) => {
  try {
    const data = await peplinkFetch(`/rest/o/${req.params.orgId}/g`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PepLink API: List Devices in Group
app.get("/api/peplink/organizations/:orgId/groups/:groupId/devices", async (req, res) => {
  try {
    const data = await peplinkFetch(`/rest/o/${req.params.orgId}/g/${req.params.groupId}/d`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PepLink API: Get Device Location
app.get("/api/peplink/organizations/:orgId/groups/:groupId/devices/:deviceId/location", async (req, res) => {
  try {
    const data = await peplinkFetch(`/rest/o/${req.params.orgId}/g/${req.params.groupId}/d/${req.params.deviceId}/loc`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PepLink API: Get All Device Locations (aggregated)
app.get("/api/peplink/locations", async (req, res) => {
  try {
    const locations = [];

    // Get all organizations
    const orgs = await peplinkFetch("/rest/o");
    const orgList = orgs.data || orgs || [];

    for (const org of orgList) {
      const orgId = org.id || org.org_id;
      if (!orgId) continue;

      // Get groups in this org
      const groups = await peplinkFetch(`/rest/o/${orgId}/g`);
      const groupList = groups.data || groups || [];

      for (const group of groupList) {
        const groupId = group.id || group.group_id;
        if (!groupId) continue;

        // Get devices in this group
        const devices = await peplinkFetch(`/rest/o/${orgId}/g/${groupId}/d`);
        const deviceList = devices.data || devices || [];

        for (const device of deviceList) {
          const deviceId = device.id || device.device_id || device.sn;
          if (!deviceId) continue;

          try {
            // Get location for this device
            const loc = await peplinkFetch(`/rest/o/${orgId}/g/${groupId}/d/${deviceId}/loc`);
            locations.push({
              organization: org.name || orgId,
              orgId,
              group: group.name || groupId,
              groupId,
              device: device.name || device.sn || deviceId,
              deviceId,
              model: device.model || device.product_name,
              serial: device.sn,
              status: device.status || device.online_status,
              location: loc.data || loc,
              latitude: loc.data?.latitude || loc.latitude,
              longitude: loc.data?.longitude || loc.longitude,
              address: loc.data?.address || loc.address
            });
          } catch (locErr) {
            // Device may not have location data
            locations.push({
              organization: org.name || orgId,
              orgId,
              group: group.name || groupId,
              groupId,
              device: device.name || device.sn || deviceId,
              deviceId,
              model: device.model || device.product_name,
              serial: device.sn,
              status: device.status || device.online_status,
              location: null,
              error: "Location not available"
            });
          }
        }
      }
    }

    res.json({
      total: locations.length,
      locations
    });
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
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" crossorigin=""/>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" crossorigin=""></script>
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

    <div style="margin:0 0 24px;padding:20px 24px;background:linear-gradient(135deg,rgba(187,134,252,0.15),rgba(3,218,197,0.15));border:1px solid rgba(187,134,252,0.3);border-radius:12px;display:flex;align-items:center;gap:16px">
      <div style="width:48px;height:48px;background:linear-gradient(135deg,var(--primary),var(--secondary));border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0">
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="rgba(0,0,0,0.87)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/><path d="M11 8v6"/><path d="M8 11h6"/></svg>
      </div>
      <div>
        <h2 style="margin:0;font-size:1.25rem;font-weight:600;color:var(--foreground)">Meraki Dynamic Troubleshooting</h2>
        <div style="font-size:0.875rem;color:var(--foreground-muted);margin-top:4px">Real-time wireless diagnostics and event analysis</div>
      </div>
    </div>

    <div class="card" style="border-left:3px solid var(--warning)">
      <div class="section-title">
        <span class="icon" style="color:var(--warning)"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></span>
        <h2>Network Health Report</h2>
      </div>
      <div class="muted">Wireless events and RF analysis</div>
      <div id="network-health-container" style="margin-top:16px">
        <div class="muted">Loading...</div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card" style="margin:0;border-left:3px solid var(--secondary)">
        <div class="section-title">
          <span class="icon" style="color:var(--secondary)"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5.5 8.5L9 12l-3.5 3.5L2 12l3.5-3.5z"/><path d="M12 2l3.5 3.5L12 9 8.5 5.5 12 2z"/><path d="M18.5 8.5L22 12l-3.5 3.5L15 12l3.5-3.5z"/><path d="M12 15l3.5 3.5L12 22l-3.5-3.5L12 15z"/></svg></span>
          <h2>DFS Events</h2>
        </div>
        <div class="muted">Radar detection events (5GHz)</div>
        <div id="dfs-events-container" style="margin-top:12px">
          <div class="muted">Loading...</div>
        </div>
      </div>

      <div class="card" style="margin:0;border-left:3px solid var(--primary)">
        <div class="section-title">
          <span class="icon" style="color:var(--primary)"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg></span>
          <h2>Packet Floods (WIPS)</h2>
        </div>
        <div class="muted">Wireless intrusion alerts</div>
        <div id="flood-events-container" style="margin-top:12px">
          <div class="muted">Loading...</div>
        </div>
      </div>
    </div>

    <div class="card" style="border-left:3px solid var(--success)">
      <div class="section-title">
        <span class="icon" style="color:var(--success)"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg></span>
        <h2>Client Roaming Events</h2>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
        <div class="muted">Client associations, disassociations, and roaming between APs</div>
        <div id="roaming-duration-selector" style="display:flex;gap:4px">
          <button onclick="loadRoamingEvents(1)" data-days="1" style="padding:4px 12px;font-size:11px;border:1px solid rgba(255,255,255,0.2);border-radius:6px;background:rgba(129,199,132,0.2);color:var(--success);cursor:pointer;font-family:var(--font-sans)">1 Day</button>
          <button onclick="loadRoamingEvents(2)" data-days="2" style="padding:4px 12px;font-size:11px;border:1px solid rgba(255,255,255,0.12);border-radius:6px;background:transparent;color:rgba(255,255,255,0.6);cursor:pointer;font-family:var(--font-sans)">2 Days</button>
          <button onclick="loadRoamingEvents(7)" data-days="7" style="padding:4px 12px;font-size:11px;border:1px solid rgba(255,255,255,0.12);border-radius:6px;background:transparent;color:rgba(255,255,255,0.6);cursor:pointer;font-family:var(--font-sans)">7 Days</button>
        </div>
      </div>
      <div id="roaming-summary-container" style="margin-top:12px">
        <div class="muted">Loading...</div>
      </div>
      <div id="roaming-events-container" style="margin-top:12px;max-height:300px;overflow-y:auto">
      </div>
    </div>

    <div class="card" style="border-left:3px solid #FF6B35">
      <div class="section-title">
        <span class="icon" style="color:#FF6B35"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="10" r="3"/><path d="M12 21.7C17.3 17 20 13 20 10a8 8 0 1 0-16 0c0 3 2.7 7 8 11.7z"/></svg></span>
        <h2>PepLink Locations</h2>
      </div>
      <div class="muted">SD-WAN device locations from InControl2</div>
      <div id="peplink-summary-container" style="margin-top:12px">
        <div class="muted">Loading...</div>
      </div>
      <div id="peplink-map" style="height:300px;margin-top:16px;border-radius:8px;overflow:hidden;border:1px solid rgba(255,255,255,0.12)">
      </div>
      <div id="peplink-locations-container" style="margin-top:12px;max-height:300px;overflow-y:auto">
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
    loadNetworkHealth();
    loadPeplinkLocations();

    let peplinkMap = null;

    // Static locations (always shown)
    const staticLocations = [
      {
        device: 'Dr_BOB',
        organization: 'Extreme Networks',
        group: 'Mobile Lab',
        model: 'PepLink HD4 MBX',
        serial: 'DR-BOB-001',
        status: 'online',
        latitude: 25.792326,
        longitude: -80.14033,
        address: 'Miami, FL',
        lastUpdate: '2025-07-23 17:08:10',
        tag: 'James_Saarikko',
        isStatic: true
      },
      {
        device: 'BobKit-08-USEast-01',
        organization: 'Extreme Networks',
        group: 'US East',
        model: 'Peplink MAX BR1 Mini',
        serial: '1933-4EB9-4408',
        status: 'online',
        latitude: 36.120094,
        longitude: -86.892845,
        address: 'Nashville, TN',
        lastUpdate: '2026-01-14 16:59:26',
        tag: 'Byron_Hall',
        firmware: '8.4.1 build 5107',
        isStatic: true
      },
      {
        device: 'BOBKit-33-US-West-1',
        organization: 'Extreme Networks',
        group: 'US West',
        model: 'Peplink MAX BR1 Mini',
        serial: '1930-C44B-0217',
        status: 'online',
        latitude: 38.884247,
        longitude: -104.82047,
        address: 'Colorado Springs, CO',
        lastUpdate: '2026-01-04 17:16:59',
        tag: 'Scott_Singer',
        firmware: '8.4.0 build 5075',
        isStatic: true
      }
    ];

    async function loadPeplinkLocations() {
      const summaryContainer = document.getElementById('peplink-summary-container');
      const mapContainer = document.getElementById('peplink-map');
      const locationsContainer = document.getElementById('peplink-locations-container');

      let apiLocations = [];
      try {
        const res = await fetch('/api/peplink/locations');
        if (res.ok) {
          const data = await res.json();
          if (!data.error) {
            apiLocations = data.locations || [];
          }
        }
      } catch (err) {
        // API not configured, continue with static locations
      }

      // Combine static and API locations
      const locations = [...staticLocations, ...apiLocations];
        const onlineCount = locations.filter(l => l.status === 'online' || l.status === 1).length;
        const withGps = locations.filter(l => l.latitude && l.longitude).length;
        const gpsLocations = locations.filter(l => l.latitude && l.longitude);

        // Summary stats
        summaryContainer.innerHTML =
          '<div style="display:flex;gap:12px;flex-wrap:wrap">' +
          '<div style="padding:8px 12px;background:rgba(255,107,53,0.15);border-radius:6px">' +
          '<span style="font-size:16px;font-weight:600;color:#FF6B35">' + locations.length + '</span>' +
          '<span style="font-size:11px;color:rgba(255,255,255,0.5);margin-left:6px">Total Devices</span></div>' +
          '<div style="padding:8px 12px;background:rgba(129,199,132,0.15);border-radius:6px">' +
          '<span style="font-size:16px;font-weight:600;color:var(--success)">' + onlineCount + '</span>' +
          '<span style="font-size:11px;color:rgba(255,255,255,0.5);margin-left:6px">Online</span></div>' +
          '<div style="padding:8px 12px;background:rgba(3,218,197,0.15);border-radius:6px">' +
          '<span style="font-size:16px;font-weight:600;color:var(--secondary)">' + withGps + '</span>' +
          '<span style="font-size:11px;color:rgba(255,255,255,0.5);margin-left:6px">With GPS</span></div>' +
          '</div>';

        // Initialize map
        if (peplinkMap) {
          peplinkMap.remove();
        }

        if (gpsLocations.length > 0) {
          // Create map centered on first device or US center
          const centerLat = gpsLocations.reduce((sum, l) => sum + l.latitude, 0) / gpsLocations.length;
          const centerLng = gpsLocations.reduce((sum, l) => sum + l.longitude, 0) / gpsLocations.length;

          peplinkMap = L.map('peplink-map', {
            center: [centerLat, centerLng],
            zoom: 4,
            zoomControl: true,
            attributionControl: false
          });

          // Dark theme map tiles (CartoDB Dark Matter)
          L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            maxZoom: 19
          }).addTo(peplinkMap);

          // Custom marker icon
          const createMarkerIcon = (isOnline) => {
            const color = isOnline ? '#81C784' : '#CF6679';
            return L.divIcon({
              className: 'peplink-marker',
              html: '<div style="width:24px;height:24px;background:' + color + ';border:2px solid #fff;border-radius:50%;box-shadow:0 2px 6px rgba(0,0,0,0.4);display:flex;align-items:center;justify-content:center"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="3"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><circle cx="12" cy="17" r="2"/></svg></div>',
              iconSize: [24, 24],
              iconAnchor: [12, 12],
              popupAnchor: [0, -12]
            });
          };

          // Add markers for each device
          const bounds = [];
          gpsLocations.forEach(loc => {
            const isOnline = loc.status === 'online' || loc.status === 1;
            const marker = L.marker([loc.latitude, loc.longitude], {
              icon: createMarkerIcon(isOnline)
            }).addTo(peplinkMap);

            const popupContent =
              '<div style="font-family:Roboto,sans-serif;min-width:180px">' +
              '<div style="font-weight:600;font-size:13px;margin-bottom:4px">' + (loc.device || 'Unknown') + '</div>' +
              '<div style="font-size:11px;color:#666">' + (loc.model || '') + '</div>' +
              '<div style="font-size:11px;color:#888;margin-top:4px">' + (loc.organization || '') + (loc.group ? ' / ' + loc.group : '') + '</div>' +
              '<div style="font-size:11px;margin-top:6px;padding-top:6px;border-top:1px solid #eee">' +
              '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + (isOnline ? '#81C784' : '#CF6679') + ';margin-right:6px"></span>' +
              (isOnline ? 'Online' : 'Offline') + '</div>' +
              (loc.address ? '<div style="font-size:10px;color:#888;margin-top:4px">' + loc.address + '</div>' : '') +
              (loc.tag ? '<div style="font-size:10px;margin-top:6px"><span style="color:#888">PepLink Owner: </span><span style="display:inline-block;padding:2px 6px;background:#BB86FC;color:#000;border-radius:8px;font-weight:500">' + loc.tag + '</span></div>' : '') +
              (loc.lastUpdate ? '<div style="font-size:10px;color:#aaa;margin-top:4px">Updated: ' + loc.lastUpdate + '</div>' : '') +
              '</div>';

            marker.bindPopup(popupContent);
            bounds.push([loc.latitude, loc.longitude]);
          });

          // Fit map to show all markers
          if (bounds.length > 1) {
            peplinkMap.fitBounds(bounds, { padding: [20, 20] });
          }
        } else {
          mapContainer.innerHTML = '<div style="height:100%;display:flex;align-items:center;justify-content:center;background:#1a1a1a;color:rgba(255,255,255,0.5);font-size:13px">No GPS locations available</div>';
        }

        // Location list
        if (locations.length === 0) {
          locationsContainer.innerHTML = '<div class="muted">No PepLink devices found</div>';
        } else {
          locationsContainer.innerHTML = locations.map(loc => {
            const statusColor = (loc.status === 'online' || loc.status === 1) ? 'var(--success)' : 'var(--destructive)';
            const statusText = (loc.status === 'online' || loc.status === 1) ? 'Online' : 'Offline';
            const hasLocation = loc.latitude && loc.longitude;

            return '<div style="padding:10px 12px;margin:6px 0;background:linear-gradient(rgba(255,255,255,0.03),rgba(255,255,255,0.03)),#121212;border-radius:8px;border-left:3px solid ' + statusColor + '">' +
              '<div style="display:flex;justify-content:space-between;align-items:center">' +
              '<span style="font-size:13px;font-weight:500;color:rgba(255,255,255,0.87)">' + (loc.device || 'Unknown') + '</span>' +
              '<span style="font-size:10px;padding:2px 6px;border-radius:4px;background:' + statusColor + ';color:#000">' + statusText + '</span></div>' +
              '<div style="font-size:11px;color:rgba(255,255,255,0.5);margin-top:4px">' +
              (loc.model ? loc.model + ' · ' : '') +
              (loc.serial ? 'S/N: ' + loc.serial : '') + '</div>' +
              '<div style="font-size:11px;color:rgba(255,255,255,0.6);margin-top:2px">' +
              '<span style="color:#FF6B35">' + (loc.organization || '') + '</span>' +
              (loc.group ? ' / ' + loc.group : '') + '</div>' +
              (hasLocation ?
                '<div style="font-size:11px;color:var(--secondary);margin-top:4px">' +
                '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:4px"><circle cx="12" cy="10" r="3"/><path d="M12 21.7C17.3 17 20 13 20 10a8 8 0 1 0-16 0c0 3 2.7 7 8 11.7z"/></svg>' +
                loc.latitude.toFixed(4) + ', ' + loc.longitude.toFixed(4) +
                (loc.address ? ' · ' + loc.address : '') +
                (loc.lastUpdate ? ' <span style="color:rgba(255,255,255,0.4)">(' + loc.lastUpdate + ')</span>' : '') + '</div>' :
                (loc.error ? '<div style="font-size:10px;color:rgba(255,255,255,0.4);margin-top:4px">' + loc.error + '</div>' : '')) +
              (loc.tag ? '<div style="margin-top:6px"><span style="font-size:10px;color:rgba(255,255,255,0.5);margin-right:6px">PepLink Owner:</span><span style="display:inline-flex;align-items:center;gap:4px;padding:3px 8px;background:rgba(187,134,252,0.15);border:1px solid rgba(187,134,252,0.3);border-radius:12px;font-size:10px;color:var(--primary)"><svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>' + loc.tag + '</span></div>' : '') +
              '</div>';
          }).join('');
        }
    }

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

    async function loadNetworkHealth() {
      const healthContainer = document.getElementById('network-health-container');
      const dfsContainer = document.getElementById('dfs-events-container');
      const floodContainer = document.getElementById('flood-events-container');
      const roamingSummary = document.getElementById('roaming-summary-container');
      const roamingContainer = document.getElementById('roaming-events-container');

      // Hardcoded network IDs for now (Freehold and Suffolk)
      const networks = [
        { id: 'L_636133447366083359', name: 'Freehold, NJ' },
        { id: 'L_636133447366083398', name: 'Suffolk, VA' }
      ];

      let allDfs = [];
      let allFloods = [];
      let allRoaming = [];
      let allTopClients = [];
      let totalRf = 0;
      let totalUniqueClients = 0;

      for (const net of networks) {
        try {
          const res = await fetch('/api/networks/' + net.id + '/wireless-health');
          if (res.ok) {
            const data = await res.json();
            allDfs = allDfs.concat((data.dfs?.events || []).map(e => ({...e, network: net.name})));
            allFloods = allFloods.concat((data.floods?.events || []).map(e => ({...e, network: net.name})));
            allRoaming = allRoaming.concat((data.roaming?.events || []).map(e => ({...e, network: net.name})));
            allTopClients = allTopClients.concat((data.roaming?.topClients || []).map(c => ({...c, network: net.name})));
            totalRf += data.summary?.rfOptimizations || 0;
            totalUniqueClients += data.roaming?.uniqueClients || 0;
          }
        } catch (err) {
          console.error('Error loading health for', net.name, err);
        }
      }

      // Health Summary
      const dfsCount = allDfs.length;
      const floodCount = allFloods.length;
      const roamCount = allRoaming.length;
      const status = dfsCount === 0 && floodCount === 0 ? 'healthy' : dfsCount > 5 || floodCount > 20 ? 'warning' : 'info';
      const statusColor = status === 'healthy' ? 'var(--success)' : status === 'warning' ? 'var(--warning)' : 'var(--secondary)';
      const statusText = status === 'healthy' ? 'All Clear' : status === 'warning' ? 'Attention Needed' : 'Normal Activity';

      healthContainer.innerHTML =
        '<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px">' +
        '<div style="padding:12px 16px;background:linear-gradient(rgba(255,255,255,0.05),rgba(255,255,255,0.05)),#121212;border:1px solid ' + statusColor + ';border-radius:8px;flex:1;min-width:100px">' +
        '<div style="font-size:20px;font-weight:600;color:' + statusColor + '">' + statusText + '</div>' +
        '<div style="font-size:11px;color:rgba(255,255,255,0.5)">Overall Status</div></div>' +
        '<div style="padding:12px 16px;background:linear-gradient(rgba(255,255,255,0.05),rgba(255,255,255,0.05)),#121212;border:1px solid rgba(255,255,255,0.12);border-radius:8px;flex:1;min-width:80px">' +
        '<div style="font-size:20px;font-weight:600;color:var(--secondary)">' + dfsCount + '</div>' +
        '<div style="font-size:11px;color:rgba(255,255,255,0.5)">DFS Events</div></div>' +
        '<div style="padding:12px 16px;background:linear-gradient(rgba(255,255,255,0.05),rgba(255,255,255,0.05)),#121212;border:1px solid rgba(255,255,255,0.12);border-radius:8px;flex:1;min-width:80px">' +
        '<div style="font-size:20px;font-weight:600;color:var(--primary)">' + floodCount + '</div>' +
        '<div style="font-size:11px;color:rgba(255,255,255,0.5)">WIPS Alerts</div></div>' +
        '<div style="padding:12px 16px;background:linear-gradient(rgba(255,255,255,0.05),rgba(255,255,255,0.05)),#121212;border:1px solid rgba(255,255,255,0.12);border-radius:8px;flex:1;min-width:80px">' +
        '<div style="font-size:20px;font-weight:600;color:var(--success)">' + roamCount + '</div>' +
        '<div style="font-size:11px;color:rgba(255,255,255,0.5)">Roam Events</div></div>' +
        '<div style="padding:12px 16px;background:linear-gradient(rgba(255,255,255,0.05),rgba(255,255,255,0.05)),#121212;border:1px solid rgba(255,255,255,0.12);border-radius:8px;flex:1;min-width:80px">' +
        '<div style="font-size:20px;font-weight:600;color:var(--warning)">' + totalRf + '</div>' +
        '<div style="font-size:11px;color:rgba(255,255,255,0.5)">RF Changes</div></div>' +
        '</div>' +
        '<div style="font-size:12px;color:rgba(255,255,255,0.5)">Monitoring: ' + networks.map(n => n.name).join(', ') + '</div>';

      // DFS Events
      if (allDfs.length === 0) {
        dfsContainer.innerHTML = '<div class="success" style="font-size:13px">No radar detected</div>';
      } else {
        const byDevice = {};
        allDfs.forEach(e => {
          if (!byDevice[e.device]) byDevice[e.device] = { channels: new Set(), count: 0, network: e.network };
          byDevice[e.device].channels.add(e.channel);
          byDevice[e.device].count++;
        });
        dfsContainer.innerHTML = Object.entries(byDevice).map(([dev, info]) =>
          '<div style="padding:8px 10px;margin:4px 0;background:linear-gradient(rgba(255,255,255,0.03),rgba(255,255,255,0.03)),#121212;border-radius:6px">' +
          '<div style="display:flex;justify-content:space-between">' +
          '<span style="font-size:13px;color:rgba(255,255,255,0.87)">' + dev + '</span>' +
          '<span style="font-size:11px;padding:2px 6px;border-radius:4px;background:var(--secondary);color:#000">' + info.count + '</span></div>' +
          '<div style="font-size:11px;color:rgba(255,255,255,0.5)">Ch ' + [...info.channels].join(', ') + ' · ' + info.network + '</div></div>'
        ).join('');
      }

      // Flood Events
      if (allFloods.length === 0) {
        floodContainer.innerHTML = '<div class="success" style="font-size:13px">No intrusion alerts</div>';
      } else {
        const byDevice = {};
        allFloods.forEach(e => {
          if (!byDevice[e.device]) byDevice[e.device] = { bssids: new Set(), count: 0, network: e.network };
          if (e.bssid && e.bssid !== 'unknown') byDevice[e.device].bssids.add(e.bssid);
          byDevice[e.device].count++;
        });
        floodContainer.innerHTML = Object.entries(byDevice).map(([dev, info]) =>
          '<div style="padding:8px 10px;margin:4px 0;background:linear-gradient(rgba(255,255,255,0.03),rgba(255,255,255,0.03)),#121212;border-radius:6px">' +
          '<div style="display:flex;justify-content:space-between">' +
          '<span style="font-size:13px;color:rgba(255,255,255,0.87)">' + dev + '</span>' +
          '<span style="font-size:11px;padding:2px 6px;border-radius:4px;background:var(--primary);color:#000">' + info.count + '</span></div>' +
          '<div style="font-size:11px;color:rgba(255,255,255,0.5)">' + info.bssids.size + ' sources · ' + info.network + '</div></div>'
        ).join('') +
        '<div style="margin-top:8px;padding:8px;background:rgba(187,134,252,0.1);border-radius:6px;font-size:11px;color:rgba(255,255,255,0.7)">' +
        '<strong>Analysis:</strong> Packet floods from neighboring APs (eero, NETGEAR, Apple). No security threat - dense RF environment.</div>';
      }

      // Load roaming events with default 1 day
      loadRoamingEvents(1);
    }

    // Roaming events loader with duration selector
    async function loadRoamingEvents(days) {
      const roamingSummary = document.getElementById('roaming-summary-container');
      const roamingContainer = document.getElementById('roaming-events-container');

      // Update button styles
      const buttons = document.querySelectorAll('#roaming-duration-selector button');
      buttons.forEach(btn => {
        if (parseInt(btn.dataset.days) === days) {
          btn.style.background = 'rgba(129,199,132,0.2)';
          btn.style.borderColor = 'rgba(255,255,255,0.2)';
          btn.style.color = 'var(--success)';
        } else {
          btn.style.background = 'transparent';
          btn.style.borderColor = 'rgba(255,255,255,0.12)';
          btn.style.color = 'rgba(255,255,255,0.6)';
        }
      });

      // Show loading state
      roamingSummary.innerHTML = '<div class="muted">Loading ' + days + ' day' + (days > 1 ? 's' : '') + ' of events...</div>';
      roamingContainer.innerHTML = '';

      const networks = [
        { id: 'L_636133447366083359', name: 'Freehold, NJ' },
        { id: 'L_636133447366083398', name: 'Suffolk, VA' }
      ];

      const timespan = days * 86400; // Convert days to seconds
      let allRoaming = [];
      let allTopClients = [];
      let totalUniqueClients = 0;

      for (const net of networks) {
        try {
          const res = await fetch('/api/networks/' + net.id + '/wireless-health?timespan=' + timespan);
          if (res.ok) {
            const data = await res.json();
            allRoaming = allRoaming.concat((data.roaming?.events || []).map(e => ({...e, network: net.name})));
            allTopClients = allTopClients.concat((data.roaming?.topClients || []).map(c => ({...c, network: net.name})));
            totalUniqueClients += data.roaming?.uniqueClients || 0;
          }
        } catch (err) {
          console.error('Error loading roaming for', net.name, err);
        }
      }

      // Roaming Events Summary
      if (allRoaming.length === 0) {
        roamingSummary.innerHTML = '<div class="muted" style="font-size:13px">No roaming events in the last ' + days + ' day' + (days > 1 ? 's' : '') + '</div>';
        roamingContainer.innerHTML = '';
      } else {
        // Summary stats
        const assocCount = allRoaming.filter(e => e.type && e.type.includes('association') && !e.type.includes('dis')).length;
        const disassocCount = allRoaming.filter(e => e.type && e.type.includes('disassociation')).length;

        roamingSummary.innerHTML =
          '<div style="display:flex;gap:12px;flex-wrap:wrap">' +
          '<div style="padding:8px 12px;background:rgba(129,199,132,0.15);border-radius:6px">' +
          '<span style="font-size:16px;font-weight:600;color:var(--success)">' + assocCount + '</span>' +
          '<span style="font-size:11px;color:rgba(255,255,255,0.5);margin-left:6px">Associations</span></div>' +
          '<div style="padding:8px 12px;background:rgba(207,102,121,0.15);border-radius:6px">' +
          '<span style="font-size:16px;font-weight:600;color:var(--destructive)">' + disassocCount + '</span>' +
          '<span style="font-size:11px;color:rgba(255,255,255,0.5);margin-left:6px">Disassociations</span></div>' +
          '<div style="padding:8px 12px;background:rgba(3,218,197,0.15);border-radius:6px">' +
          '<span style="font-size:16px;font-weight:600;color:var(--secondary)">' + totalUniqueClients + '</span>' +
          '<span style="font-size:11px;color:rgba(255,255,255,0.5);margin-left:6px">Unique Clients</span></div>' +
          '<div style="padding:8px 12px;background:rgba(255,255,255,0.05);border-radius:6px">' +
          '<span style="font-size:16px;font-weight:600;color:rgba(255,255,255,0.7)">' + days + 'd</span>' +
          '<span style="font-size:11px;color:rgba(255,255,255,0.5);margin-left:6px">Time Range</span></div>' +
          '</div>';

        // Top roaming clients
        if (allTopClients.length > 0) {
          const merged = {};
          allTopClients.forEach(c => {
            if (!merged[c.mac]) merged[c.mac] = { count: 0, aps: new Set() };
            merged[c.mac].count += c.count;
            c.aps.forEach(ap => merged[c.mac].aps.add(ap));
          });

          const topClients = Object.entries(merged)
            .sort((a, b) => b[1].count - a[1].count)
            .slice(0, 8);

          roamingContainer.innerHTML =
            '<div style="font-size:12px;font-weight:500;color:rgba(255,255,255,0.7);margin-bottom:8px">Top Roaming Clients</div>' +
            topClients.map(([mac, info]) =>
              '<div style="padding:8px 10px;margin:4px 0;background:linear-gradient(rgba(255,255,255,0.03),rgba(255,255,255,0.03)),#121212;border-radius:6px">' +
              '<div style="display:flex;justify-content:space-between;align-items:center">' +
              '<span style="font-size:12px;font-family:var(--font-mono);color:rgba(255,255,255,0.87)">' + mac + '</span>' +
              '<span style="font-size:11px;padding:2px 6px;border-radius:4px;background:var(--success);color:#000">' + info.count + ' events</span></div>' +
              '<div style="font-size:11px;color:rgba(255,255,255,0.5);margin-top:2px">Seen on: ' + [...info.aps].join(', ') + '</div></div>'
            ).join('');
        }
      }
    }
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
