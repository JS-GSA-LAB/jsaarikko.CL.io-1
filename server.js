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

// Meraki API: List all Networks (from first org)
app.get("/api/networks", async (req, res) => {
  try {
    const orgs = await merakiFetch("/organizations");
    if (!orgs || orgs.length === 0) {
      return res.status(500).json({ error: "No organizations found" });
    }
    const orgId = orgs[0].id;
    const networks = await merakiFetch(`/organizations/${orgId}/networks?perPage=1000`);
    res.json({
      orgId,
      networks: (networks || []).map(n => ({ id: n.id, name: n.name, productTypes: n.productTypes }))
    });
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
    const timespan = parseInt(req.query.timespan) || 86400;

    // Fetch general wireless events
    const events = await merakiFetch(`/networks/${req.params.networkId}/events?productType=wireless&perPage=1000&timespan=${timespan}`);
    const allEvents = events.events || [];

    // Fetch Air Marshal/WIPS events separately (they're rare and get lost in general events)
    const wipsEventTypes = ['packet_flood', 'device_packet_flood', 'bcast_deauth', 'bcast_disassoc', 'rogue_ap_association'].join('&includedEventTypes[]=');
    let wipsEvents = [];
    try {
      const wipsResponse = await merakiFetch(`/networks/${req.params.networkId}/events?productType=wireless&perPage=500&timespan=${timespan}&includedEventTypes[]=${wipsEventTypes}`);
      wipsEvents = wipsResponse.events || [];
    } catch (wipsErr) {
      console.error('Error fetching WIPS events:', wipsErr.message);
    }

    // Filter WIPS events by timespan (Meraki API doesn't always respect timespan with includedEventTypes)
    const cutoffTime = new Date(Date.now() - (timespan * 1000));
    wipsEvents = wipsEvents.filter(e => new Date(e.occurredAt) >= cutoffTime);

    // Fetch 6 GHz clients to identify LPI-capable devices
    let sixGhzClientMacs = new Set();
    try {
      const sixGhzStats = await merakiFetch(`/networks/${req.params.networkId}/wireless/clients/connectionStats?band=6&timespan=${Math.min(timespan, 604800)}`);
      if (Array.isArray(sixGhzStats)) {
        sixGhzStats.forEach(client => {
          if (client.mac) sixGhzClientMacs.add(client.mac.toLowerCase());
        });
      }
    } catch (sixGhzErr) {
      console.error('Error fetching 6 GHz clients:', sixGhzErr.message);
    }

    // Categorize events
    const dfsEvents = allEvents.filter(e => e.type === 'dfs_event');
    const floodEvents = wipsEvents.filter(e => e.type === 'packet_flood' || e.type === 'device_packet_flood' || e.type === 'bcast_deauth' || e.type === 'bcast_disassoc');
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
      if (!clientRoams[client]) clientRoams[client] = { events: [], devices: new Set(), hostname: null };
      clientRoams[client].events.push(e);
      if (e.deviceName) clientRoams[client].devices.add(e.deviceName);
      // Capture hostname/clientDescription if available
      if (e.clientDescription && !clientRoams[client].hostname) {
        clientRoams[client].hostname = e.clientDescription;
      }
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
          .map(([mac, data]) => ({
            mac,
            hostname: data.hostname,
            count: data.events.length,
            aps: [...data.devices],
            lpi: sixGhzClientMacs.has(mac.toLowerCase())
          }))
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

// =============================================================================
// AI ROOT CAUSE ANALYSIS ENGINE
// =============================================================================

// Helper: Parse natural language query to extract parameters
function parseRcaQuery(query) {
  const lowerQuery = query.toLowerCase();

  // Extract application mentions
  const apps = [];
  const appPatterns = [
    { pattern: /zoom/i, name: 'Zoom', category: 'video' },
    { pattern: /teams|microsoft teams/i, name: 'Microsoft Teams', category: 'video' },
    { pattern: /webex/i, name: 'Webex', category: 'video' },
    { pattern: /slack/i, name: 'Slack', category: 'collaboration' },
    { pattern: /youtube/i, name: 'YouTube', category: 'streaming' },
    { pattern: /netflix/i, name: 'Netflix', category: 'streaming' },
    { pattern: /wifi|wireless|network/i, name: 'WiFi', category: 'connectivity' },
    { pattern: /internet/i, name: 'Internet', category: 'connectivity' },
    { pattern: /voip|voice|calling/i, name: 'VoIP', category: 'voice' },
  ];

  for (const app of appPatterns) {
    if (app.pattern.test(query)) {
      apps.push(app);
    }
  }

  // Extract location mentions
  let location = null;
  const locationPatterns = [
    /floor\s*(\d+)/i,
    /building\s*(\w+)/i,
    /room\s*(\w+)/i,
    /(\w+)\s*floor/i,
    /level\s*(\d+)/i,
  ];

  for (const pattern of locationPatterns) {
    const match = query.match(pattern);
    if (match) {
      location = { type: pattern.source.includes('floor') ? 'floor' : 'area', value: match[1] };
      break;
    }
  }

  // Extract time references
  let timeframe = 'recent'; // default
  if (/today/i.test(query)) timeframe = 'today';
  else if (/yesterday/i.test(query)) timeframe = 'yesterday';
  else if (/this week/i.test(query)) timeframe = 'week';
  else if (/last hour/i.test(query)) timeframe = 'hour';
  else if (/now|current/i.test(query)) timeframe = 'now';

  // Extract problem type
  let problemType = 'general';
  if (/fail|failing|doesn't work|not working|broken|down/i.test(query)) problemType = 'failure';
  else if (/slow|lag|latency|delay/i.test(query)) problemType = 'performance';
  else if (/disconnect|dropping|drops|intermittent/i.test(query)) problemType = 'intermittent';
  else if (/can't connect|unable to connect|connection/i.test(query)) problemType = 'connectivity';

  return { apps, location, timeframe, problemType, originalQuery: query };
}

// Helper: Calculate timespan in seconds based on timeframe
function getTimespanSeconds(timeframe) {
  switch (timeframe) {
    case 'hour': return 3600;
    case 'now': return 1800; // 30 minutes
    case 'today': return 86400;
    case 'yesterday': return 172800;
    case 'week': return 604800;
    default: return 86400; // 1 day default
  }
}

// RCA API: Analyze network issue
app.post("/api/rca/analyze", express.json(), async (req, res) => {
  try {
    const { question, networkId } = req.body;

    if (!question) {
      return res.status(400).json({ error: "Question is required" });
    }

    // Parse the question
    const parsed = parseRcaQuery(question);
    const timespan = getTimespanSeconds(parsed.timeframe);

    // Get organization and network info
    const orgs = await merakiFetch("/organizations");
    if (!orgs || orgs.length === 0) {
      return res.status(500).json({ error: "No organizations found" });
    }

    const orgId = orgs[0].id;
    const networks = await merakiFetch(`/organizations/${orgId}/networks`);

    // Use provided networkId or first network
    let targetNetwork = networkId
      ? networks.find(n => n.id === networkId)
      : networks[0];

    if (!targetNetwork) {
      return res.status(500).json({ error: "No networks found" });
    }

    // Gather data from multiple sources
    const analysisData = {
      parsed,
      network: targetNetwork,
      findings: [],
      metrics: {},
      recommendations: [],
      confidence: 0,
      summary: ""
    };

    // 1. Get wireless events
    let wirelessEvents = [];
    try {
      const eventsRes = await merakiFetch(
        `/networks/${targetNetwork.id}/events?productType=wireless&perPage=500&timespan=${timespan}`
      );
      wirelessEvents = eventsRes.events || [];
      analysisData.metrics.totalEvents = wirelessEvents.length;
    } catch (e) {
      console.log("Could not fetch wireless events:", e.message);
    }

    // 2. Get device statuses
    let deviceStatuses = [];
    try {
      deviceStatuses = await merakiFetch(`/organizations/${orgId}/devices/statuses`);
      const offlineCount = deviceStatuses.filter(d => d.status === 'offline').length;
      const alertingCount = deviceStatuses.filter(d => d.status === 'alerting').length;
      analysisData.metrics.totalDevices = deviceStatuses.length;
      analysisData.metrics.offlineDevices = offlineCount;
      analysisData.metrics.alertingDevices = alertingCount;

      if (offlineCount > 0) {
        analysisData.findings.push({
          type: 'device_health',
          severity: 'high',
          title: 'Offline Devices Detected',
          detail: `${offlineCount} device(s) are currently offline, which may impact connectivity.`,
          devices: deviceStatuses.filter(d => d.status === 'offline').map(d => d.name || d.serial)
        });
      }

      if (alertingCount > 0) {
        analysisData.findings.push({
          type: 'device_health',
          severity: 'medium',
          title: 'Devices in Alerting State',
          detail: `${alertingCount} device(s) are in alerting state and may need attention.`,
          devices: deviceStatuses.filter(d => d.status === 'alerting').map(d => d.name || d.serial)
        });
      }
    } catch (e) {
      console.log("Could not fetch device statuses:", e.message);
    }

    // 3. Analyze events for patterns
    const eventCounts = {};
    const failureEvents = [];
    const roamingEvents = [];
    const authEvents = [];

    for (const event of wirelessEvents) {
      eventCounts[event.type] = (eventCounts[event.type] || 0) + 1;

      // Categorize events
      if (/disassoc|deauth|fail|reject/i.test(event.type)) {
        failureEvents.push(event);
      }
      if (/roam/i.test(event.type)) {
        roamingEvents.push(event);
      }
      if (/auth|8021x|radius/i.test(event.type)) {
        authEvents.push(event);
      }
    }

    analysisData.metrics.eventBreakdown = eventCounts;

    // 4. Check for authentication issues
    if (authEvents.length > 10) {
      const authFailures = authEvents.filter(e => /fail|reject/i.test(e.type));
      if (authFailures.length > 5) {
        analysisData.findings.push({
          type: 'authentication',
          severity: 'high',
          title: 'Authentication Failures Detected',
          detail: `${authFailures.length} authentication failures in the last ${parsed.timeframe}. This could indicate RADIUS/802.1X issues or credential problems.`,
          count: authFailures.length
        });
      }
    }

    // 5. Check for excessive roaming
    if (roamingEvents.length > 50) {
      analysisData.findings.push({
        type: 'roaming',
        severity: 'medium',
        title: 'High Roaming Activity',
        detail: `${roamingEvents.length} roaming events detected. Excessive roaming can cause brief disconnections affecting real-time applications like ${parsed.apps.map(a => a.name).join(', ') || 'video calls'}.`,
        count: roamingEvents.length
      });

      analysisData.recommendations.push({
        title: 'Optimize Roaming Settings',
        detail: 'Consider adjusting minimum bitrate settings and enabling band steering to reduce unnecessary roaming.'
      });
    }

    // 6. Check for connection failures
    if (failureEvents.length > 20) {
      analysisData.findings.push({
        type: 'connectivity',
        severity: 'high',
        title: 'Connection Failures',
        detail: `${failureEvents.length} connection failure events detected. Clients are having trouble maintaining stable connections.`,
        count: failureEvents.length
      });
    }

    // 7. Application-specific analysis
    if (parsed.apps.some(a => a.category === 'video')) {
      // Video apps need low latency and consistent connectivity
      if (roamingEvents.length > 20 || failureEvents.length > 10) {
        analysisData.findings.push({
          type: 'application',
          severity: 'high',
          title: 'Video Application Impact',
          detail: `Video applications like ${parsed.apps.filter(a => a.category === 'video').map(a => a.name).join(', ')} require stable, low-latency connections. The detected roaming (${roamingEvents.length}) and failure events (${failureEvents.length}) would cause video freezing, audio drops, and call disconnections.`,
          impact: 'Video calls may freeze, audio may cut out, screen sharing may fail'
        });

        analysisData.recommendations.push({
          title: 'Prioritize Video Traffic',
          detail: 'Enable QoS policies to prioritize video conferencing traffic. Consider creating a dedicated SSID with traffic shaping for video applications.'
        });
      }
    }

    // 8. Location-specific analysis
    if (parsed.location) {
      // Filter events/devices by location if device names contain floor info
      const locationPattern = new RegExp(parsed.location.value, 'i');
      const locationDevices = deviceStatuses.filter(d =>
        (d.name && locationPattern.test(d.name)) ||
        (d.tags && d.tags.some(t => locationPattern.test(t)))
      );

      if (locationDevices.length > 0) {
        const locationOffline = locationDevices.filter(d => d.status === 'offline');
        if (locationOffline.length > 0) {
          analysisData.findings.push({
            type: 'location',
            severity: 'critical',
            title: `Coverage Issue on ${parsed.location.type} ${parsed.location.value}`,
            detail: `${locationOffline.length} of ${locationDevices.length} access points on ${parsed.location.type} ${parsed.location.value} are offline. This would cause complete coverage gaps.`,
            devices: locationOffline.map(d => d.name || d.serial)
          });
        }

        analysisData.metrics.locationDevices = locationDevices.length;
        analysisData.metrics.locationOffline = locationOffline.length;
      }
    }

    // 9. Calculate confidence score
    let confidence = 30; // Base confidence
    if (analysisData.findings.length > 0) confidence += 20;
    if (analysisData.findings.some(f => f.severity === 'critical')) confidence += 30;
    if (analysisData.findings.some(f => f.severity === 'high')) confidence += 15;
    if (wirelessEvents.length > 100) confidence += 5;
    confidence = Math.min(confidence, 95);
    analysisData.confidence = confidence;

    // 10. Generate summary
    if (analysisData.findings.length === 0) {
      analysisData.summary = `No significant issues detected for "${question}". Network appears to be operating normally. If problems persist, consider checking client device configurations or application-specific settings.`;
      analysisData.recommendations.push({
        title: 'Client-Side Troubleshooting',
        detail: 'If issues persist, check client device drivers, firewall settings, and application configurations.'
      });
    } else {
      const criticalFindings = analysisData.findings.filter(f => f.severity === 'critical');
      const highFindings = analysisData.findings.filter(f => f.severity === 'high');

      if (criticalFindings.length > 0) {
        analysisData.summary = `CRITICAL: ${criticalFindings[0].title}. ${criticalFindings[0].detail}`;
      } else if (highFindings.length > 0) {
        analysisData.summary = `Root cause analysis found ${highFindings.length} significant issue(s). Primary: ${highFindings[0].title}. ${highFindings[0].detail}`;
      } else {
        analysisData.summary = `Analysis found ${analysisData.findings.length} potential contributing factor(s) for "${question}".`;
      }
    }

    // Add general recommendations based on problem type
    if (parsed.problemType === 'performance') {
      analysisData.recommendations.push({
        title: 'Check Channel Utilization',
        detail: 'High channel utilization can cause slowdowns. Consider enabling auto-channel selection or manually optimizing channel assignments.'
      });
    }

    if (parsed.problemType === 'connectivity') {
      analysisData.recommendations.push({
        title: 'Verify DHCP and DNS',
        detail: 'Connectivity issues often stem from DHCP pool exhaustion or DNS failures. Check DHCP lease availability and DNS server reachability.'
      });
    }

    res.json(analysisData);

  } catch (err) {
    console.error("RCA Analysis error:", err);
    res.status(500).json({ error: err.message });
  }
});

// RCA API: Get quick health summary
app.get("/api/rca/health-summary", async (req, res) => {
  try {
    const orgs = await merakiFetch("/organizations");
    if (!orgs || orgs.length === 0) {
      return res.status(500).json({ error: "No organizations found" });
    }

    const orgId = orgs[0].id;
    const [devices, networks] = await Promise.all([
      merakiFetch(`/organizations/${orgId}/devices/statuses`),
      merakiFetch(`/organizations/${orgId}/networks`)
    ]);

    const summary = {
      totalDevices: devices.length,
      online: devices.filter(d => d.status === 'online').length,
      offline: devices.filter(d => d.status === 'offline').length,
      alerting: devices.filter(d => d.status === 'alerting').length,
      dormant: devices.filter(d => d.status === 'dormant').length,
      networks: networks.length,
      healthScore: 0,
      status: 'unknown'
    };

    // Calculate health score
    if (summary.totalDevices > 0) {
      summary.healthScore = Math.round((summary.online / summary.totalDevices) * 100);
    }

    if (summary.healthScore >= 95) summary.status = 'healthy';
    else if (summary.healthScore >= 80) summary.status = 'warning';
    else summary.status = 'critical';

    res.json(summary);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===========================================
// ROAMING PATH TRACKING API
// ===========================================
app.get("/api/roaming/analysis", async (req, res) => {
  try {
    const orgs = await merakiFetch("/organizations");
    if (!orgs || orgs.length === 0) {
      return res.status(500).json({ error: "No organizations found" });
    }

    const orgId = orgs[0].id;
    const timespan = parseInt(req.query.timespan) || 86400; // Default 24 hours

    const result = {
      timestamp: new Date().toISOString(),
      timespan: timespan,
      clientMovements: [],
      roamingFailures: [],
      stickyClients: [],
      apTransitions: {},
      optimization: {
        score: 0,
        recommendations: [],
        insights: []
      },
      metrics: {}
    };

    // Get networks and devices
    const [networks, devices] = await Promise.all([
      merakiFetch(`/organizations/${orgId}/networks`),
      merakiFetch(`/organizations/${orgId}/devices`)
    ]);

    const wirelessNetworks = networks.filter(n => n.productTypes?.includes('wireless'));
    const accessPoints = devices.filter(d => d.model?.startsWith('MR') || d.model?.startsWith('CW'));

    result.metrics.totalNetworks = wirelessNetworks.length;
    result.metrics.totalAPs = accessPoints.length;

    // Build AP name map for easier lookup
    const apMap = {};
    for (const ap of accessPoints) {
      apMap[ap.serial] = ap.name || ap.serial;
      apMap[ap.mac?.toLowerCase()] = ap.name || ap.serial;
    }

    // Collect roaming events from all wireless networks
    let allRoamingEvents = [];
    let allClients = [];
    let clientConnectionHistory = {};

    for (const network of wirelessNetworks) {
      try {
        // Get wireless events for roaming analysis
        const events = await merakiFetch(`/networks/${network.id}/events?productType=wireless&perPage=1000&timespan=${timespan}`);
        const wirelessEvents = events.events || [];

        // Get network clients
        const clients = await merakiFetch(`/networks/${network.id}/clients?timespan=${timespan}`);
        allClients = allClients.concat(clients.map(c => ({ ...c, network: network.name, networkId: network.id })));

        // Filter for roaming-related events
        const roamingTypes = [
          'association', 'disassociation', 'reassociation',
          '802.11_auth', '802.11_deauth', 'wpa_auth', 'wpa_deauth',
          'client_connected', 'client_disconnected'
        ];

        for (const event of wirelessEvents) {
          const eventType = event.type?.toLowerCase() || '';
          if (roamingTypes.some(t => eventType.includes(t))) {
            allRoamingEvents.push({
              ...event,
              network: network.name,
              networkId: network.id
            });
          }

          // Track client connection history for path analysis
          if (event.clientMac) {
            const mac = event.clientMac.toLowerCase();
            if (!clientConnectionHistory[mac]) {
              clientConnectionHistory[mac] = [];
            }
            // Try multiple fields to identify the AP
            const apId = event.deviceSerial || event.deviceMac || event.deviceName || event.apMac;
            const apName = apMap[event.deviceSerial] || apMap[event.deviceMac?.toLowerCase()] || event.deviceName || 'Unknown';
            clientConnectionHistory[mac].push({
              timestamp: event.occurredAt,
              type: event.type,
              ap: apId,
              apName: apName,
              network: network.name,
              ssid: event.ssidName || event.ssid || event.eventData?.ssid,
              rssi: event.rssi || event.eventData?.rssi,
              channel: event.channel || event.eventData?.channel
            });
          }
        }
      } catch (err) {
        console.error(`Error fetching data for network ${network.name}:`, err.message);
      }
    }

    result.metrics.totalEvents = allRoamingEvents.length;
    result.metrics.totalClients = allClients.length;
    result.metrics.uniqueClients = Object.keys(clientConnectionHistory).length;

    // ===========================================
    // 1. CLIENT MOVEMENT TRACKING
    // ===========================================
    const clientMovements = [];
    const apTransitionCounts = {};

    for (const [clientMac, history] of Object.entries(clientConnectionHistory)) {
      // Sort by timestamp
      history.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

      // Find the client info
      const clientInfo = allClients.find(c => c.mac?.toLowerCase() === clientMac);

      if (history.length >= 2) {
        const movements = [];
        let lastAp = null;
        let roamCount = 0;
        let failedRoams = 0;

        for (let i = 0; i < history.length; i++) {
          const event = history[i];
          const isConnect = event.type?.toLowerCase().includes('association') ||
                           event.type?.toLowerCase().includes('connected') ||
                           event.type?.toLowerCase().includes('auth');

          if (isConnect && event.ap) {
            if (lastAp && lastAp !== event.ap) {
              roamCount++;
              const transitionKey = `${apMap[lastAp] || lastAp} → ${event.apName}`;

              movements.push({
                from: apMap[lastAp] || lastAp,
                to: event.apName,
                timestamp: event.timestamp,
                rssi: event.rssi,
                channel: event.channel
              });

              // Track AP transition frequency
              if (!apTransitionCounts[transitionKey]) {
                apTransitionCounts[transitionKey] = 0;
              }
              apTransitionCounts[transitionKey]++;
            }
            lastAp = event.ap;
          }

          // Detect failed roams (deauth followed by auth failure or timeout)
          if (event.type?.toLowerCase().includes('deauth') || event.type?.toLowerCase().includes('disassociation')) {
            const nextEvent = history[i + 1];
            if (nextEvent) {
              const timeDiff = new Date(nextEvent.timestamp) - new Date(event.timestamp);
              // If reconnection takes more than 5 seconds, consider it a failed/slow roam
              if (timeDiff > 5000) {
                failedRoams++;
              }
            }
          }
        }

        if (movements.length > 0) {
          clientMovements.push({
            clientMac: clientMac,
            clientName: clientInfo?.description || clientInfo?.dhcpHostname || 'Unknown',
            manufacturer: clientInfo?.manufacturer || 'Unknown',
            os: clientInfo?.os || 'Unknown',
            totalRoams: roamCount,
            failedRoams: failedRoams,
            movements: movements.slice(-10), // Last 10 movements
            firstSeen: history[0].timestamp,
            lastSeen: history[history.length - 1].timestamp,
            uniqueAPs: [...new Set(history.filter(h => h.ap).map(h => h.apName))].length
          });
        }
      }
    }

    // Sort by roam count (most active roamers first)
    clientMovements.sort((a, b) => b.totalRoams - a.totalRoams);
    result.clientMovements = clientMovements.slice(0, 50); // Top 50 roaming clients
    result.apTransitions = apTransitionCounts;

    // ===========================================
    // 2. ROAMING FAILURES ANALYSIS
    // ===========================================
    const failurePatterns = {};

    for (const client of clientMovements) {
      if (client.failedRoams > 0) {
        result.roamingFailures.push({
          clientMac: client.clientMac,
          clientName: client.clientName,
          manufacturer: client.manufacturer,
          failureCount: client.failedRoams,
          totalRoams: client.totalRoams,
          failureRate: Math.round((client.failedRoams / Math.max(client.totalRoams, 1)) * 100),
          recentMovements: client.movements.slice(-5)
        });

        // Track failure patterns by manufacturer/OS
        const key = client.manufacturer || 'Unknown';
        if (!failurePatterns[key]) {
          failurePatterns[key] = { count: 0, failures: 0 };
        }
        failurePatterns[key].count++;
        failurePatterns[key].failures += client.failedRoams;
      }
    }

    result.roamingFailures.sort((a, b) => b.failureCount - a.failureCount);
    result.metrics.totalFailures = result.roamingFailures.reduce((sum, f) => sum + f.failureCount, 0);
    result.metrics.clientsWithFailures = result.roamingFailures.length;

    // ===========================================
    // 3. STICKY CLIENT DETECTION
    // ===========================================
    // Sticky clients: Clients that stay connected to one AP despite better options
    // Indicators: Low RSSI but not roaming, connected to distant AP

    for (const client of allClients) {
      const mac = client.mac?.toLowerCase();
      const history = clientConnectionHistory[mac];

      if (!history || history.length === 0) continue;

      // Get the most recent RSSI readings
      const recentEvents = history.slice(-20);
      const rssiValues = recentEvents.filter(e => e.rssi).map(e => e.rssi);

      if (rssiValues.length > 0) {
        const avgRssi = rssiValues.reduce((a, b) => a + b, 0) / rssiValues.length;
        const uniqueAPs = [...new Set(recentEvents.filter(e => e.ap).map(e => e.ap))];

        // Sticky client indicators:
        // 1. Average RSSI below -70 dBm (weak signal)
        // 2. Connected to only 1 AP over extended period
        // 3. Not roaming despite poor signal
        if (avgRssi < -70 && uniqueAPs.length === 1) {
          const stickiness = Math.abs(avgRssi + 50); // Higher = stickier

          result.stickyClients.push({
            clientMac: mac,
            clientName: client.description || client.dhcpHostname || 'Unknown',
            manufacturer: client.manufacturer || 'Unknown',
            os: client.os || 'Unknown',
            currentAP: apMap[uniqueAPs[0]] || uniqueAPs[0],
            avgRssi: Math.round(avgRssi),
            minRssi: Math.min(...rssiValues),
            maxRssi: Math.max(...rssiValues),
            stickinessScore: Math.round(stickiness),
            status: client.status,
            ssid: client.ssid,
            connectionDuration: client.lastSeen ?
              Math.round((new Date() - new Date(client.firstSeen)) / 60000) + ' min' : 'Unknown',
            recommendation: avgRssi < -80 ?
              'Critical: Client should roam to a closer AP' :
              'Monitor: Client may benefit from roaming'
          });
        }
      }
    }

    result.stickyClients.sort((a, b) => b.stickinessScore - a.stickinessScore);
    result.metrics.stickyClients = result.stickyClients.length;

    // ===========================================
    // 4. AI-DRIVEN ROAMING OPTIMIZATION
    // ===========================================
    let optimizationScore = 100;
    const recommendations = [];
    const insights = [];

    // Analyze roaming health
    const totalRoams = clientMovements.reduce((sum, c) => sum + c.totalRoams, 0);
    const totalFailedRoams = clientMovements.reduce((sum, c) => sum + c.failedRoams, 0);
    const overallFailureRate = totalRoams > 0 ? (totalFailedRoams / totalRoams) * 100 : 0;

    // Score deductions based on issues
    if (overallFailureRate > 10) {
      optimizationScore -= 30;
      recommendations.push({
        priority: 'critical',
        title: 'High Roaming Failure Rate',
        issue: `${overallFailureRate.toFixed(1)}% of roaming attempts are failing`,
        action: 'Review 802.11r (Fast BSS Transition) and 802.11k (Neighbor Reports) settings. Ensure all APs have consistent security settings.',
        impact: 'Failed roams cause disconnections and poor user experience'
      });
    } else if (overallFailureRate > 5) {
      optimizationScore -= 15;
      recommendations.push({
        priority: 'high',
        title: 'Elevated Roaming Failures',
        issue: `${overallFailureRate.toFixed(1)}% roaming failure rate detected`,
        action: 'Enable 802.11v (BSS Transition Management) to help clients make better roaming decisions.',
        impact: 'Users may experience brief disconnections during movement'
      });
    }

    // Sticky client analysis
    if (result.stickyClients.length > 5) {
      optimizationScore -= 20;
      recommendations.push({
        priority: 'high',
        title: 'Multiple Sticky Clients Detected',
        issue: `${result.stickyClients.length} clients are not roaming despite poor signal`,
        action: 'Configure minimum RSSI thresholds on APs to encourage clients to roam. Consider enabling Band Steering.',
        impact: 'Sticky clients experience poor performance and may impact other users'
      });
    } else if (result.stickyClients.length > 0) {
      optimizationScore -= 5;
      recommendations.push({
        priority: 'medium',
        title: 'Sticky Clients Present',
        issue: `${result.stickyClients.length} client(s) showing sticky behavior`,
        action: 'Monitor these clients and consider client-side troubleshooting if issues persist.',
        impact: 'Minor performance impact for affected clients'
      });
    }

    // AP transition pattern analysis
    const transitionEntries = Object.entries(apTransitionCounts);
    if (transitionEntries.length > 0) {
      const topTransitions = transitionEntries.sort((a, b) => b[1] - a[1]).slice(0, 5);
      const avgTransitions = transitionEntries.reduce((sum, [, count]) => sum + count, 0) / transitionEntries.length;

      // Check for ping-pong roaming (clients bouncing between same APs)
      const pingPongPairs = [];
      for (const [transition, count] of transitionEntries) {
        const [from, to] = transition.split(' → ');
        const reverseKey = `${to} → ${from}`;
        const reverseCount = apTransitionCounts[reverseKey] || 0;

        if (count > 3 && reverseCount > 3 && !pingPongPairs.some(p => p.includes(from) && p.includes(to))) {
          pingPongPairs.push([from, to, count + reverseCount]);
        }
      }

      if (pingPongPairs.length > 0) {
        optimizationScore -= 15;
        recommendations.push({
          priority: 'high',
          title: 'Ping-Pong Roaming Detected',
          issue: `${pingPongPairs.length} AP pair(s) showing excessive back-and-forth roaming`,
          action: 'Adjust AP power levels to reduce coverage overlap. Review AP placement and consider adjusting roaming thresholds.',
          impact: 'Clients waste battery and experience micro-disconnections',
          details: pingPongPairs.slice(0, 3).map(([a, b, c]) => `${a} ↔ ${b}: ${c} transitions`)
        });
      }

      insights.push({
        type: 'traffic_flow',
        title: 'Top Roaming Paths',
        data: topTransitions.map(([path, count]) => ({ path, count }))
      });
    }

    // Manufacturer-specific issues
    for (const [manufacturer, data] of Object.entries(failurePatterns)) {
      const failureRate = (data.failures / Math.max(data.count, 1)) * 100;
      if (failureRate > 20 && data.count >= 3) {
        insights.push({
          type: 'device_issue',
          title: `${manufacturer} Devices Roaming Poorly`,
          detail: `${data.count} ${manufacturer} device(s) with ${failureRate.toFixed(0)}% failure rate`,
          recommendation: 'These devices may have known roaming issues. Consider firmware updates or driver updates.'
        });
      }
    }

    // Coverage analysis
    const avgUniqueAPs = clientMovements.length > 0 ?
      clientMovements.reduce((sum, c) => sum + c.uniqueAPs, 0) / clientMovements.length : 0;

    if (avgUniqueAPs > 5) {
      insights.push({
        type: 'coverage',
        title: 'High Client Mobility',
        detail: `Clients visit an average of ${avgUniqueAPs.toFixed(1)} APs`,
        recommendation: 'Network has good coverage for mobile users. Ensure fast roaming protocols are enabled.'
      });
    }

    // Add positive insights if doing well
    if (overallFailureRate < 2 && result.stickyClients.length === 0) {
      insights.push({
        type: 'success',
        title: 'Excellent Roaming Performance',
        detail: 'Network roaming is well optimized with minimal failures and no sticky clients'
      });
    }

    // Ensure score doesn't go below 0
    optimizationScore = Math.max(0, optimizationScore);

    result.optimization = {
      score: optimizationScore,
      grade: optimizationScore >= 90 ? 'A' : optimizationScore >= 80 ? 'B' : optimizationScore >= 70 ? 'C' : optimizationScore >= 60 ? 'D' : 'F',
      recommendations: recommendations,
      insights: insights,
      summary: optimizationScore >= 80 ?
        'Network roaming is performing well. Minor optimizations may further improve client experience.' :
        optimizationScore >= 60 ?
        'Network roaming has some issues that should be addressed to improve client experience.' :
        'Network roaming needs significant attention. Multiple issues are impacting client connectivity.'
    };

    result.metrics.optimizationScore = optimizationScore;
    result.metrics.totalRoams = totalRoams;
    result.metrics.totalFailures = totalFailedRoams;
    result.metrics.failureRate = overallFailureRate.toFixed(1) + '%';

    res.json(result);

  } catch (err) {
    console.error("Roaming analysis error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ===========================================
// SWITCH PORT TELEMETRY API
// ===========================================
app.get("/api/switch/telemetry", async (req, res) => {
  try {
    const orgs = await merakiFetch("/organizations");
    if (!orgs || orgs.length === 0) {
      return res.status(500).json({ error: "No organizations found" });
    }

    const result = {
      timestamp: new Date().toISOString(),
      organizations: [],
      switches: [],
      portIssues: [],
      summary: {
        totalSwitches: 0,
        totalPorts: 0,
        portsWithErrors: 0,
        portsWithCRC: 0,
        portsWithDrops: 0,
        poeIssues: 0,
        negotiationIssues: 0,
        offlineSwitches: 0
      }
    };

    // Process each organization
    for (const org of orgs) {
      const orgData = {
        id: org.id,
        name: org.name,
        switches: [],
        issueCount: 0
      };

      try {
        // Get all devices and filter for switches
        const [devices, statuses] = await Promise.all([
          merakiFetch(`/organizations/${org.id}/devices`),
          merakiFetch(`/organizations/${org.id}/devices/statuses`)
        ]);

        // Create status map
        const statusMap = {};
        for (const s of statuses) {
          statusMap[s.serial] = s;
        }

        // Filter for switches (MS and C9 series)
        const switches = devices.filter(d =>
          d.model?.startsWith('MS') || d.model?.startsWith('C9')
        );

        result.summary.totalSwitches += switches.length;

        // Get port statuses for each switch
        for (const sw of switches) {
          const switchStatus = statusMap[sw.serial];
          const switchData = {
            serial: sw.serial,
            name: sw.name || sw.serial,
            model: sw.model,
            network: sw.networkId,
            status: switchStatus?.status || 'unknown',
            lanIp: switchStatus?.lanIp || 'N/A',
            mac: sw.mac,
            ports: [],
            issues: {
              errors: 0,
              crc: 0,
              drops: 0,
              poe: 0,
              negotiation: 0
            },
            totalPorts: 0,
            activePorts: 0
          };

          if (switchStatus?.status === 'offline') {
            result.summary.offlineSwitches++;
          }

          try {
            // Get port statuses
            const ports = await merakiFetch(`/devices/${sw.serial}/switch/ports/statuses`);

            if (ports && Array.isArray(ports)) {
              switchData.totalPorts = ports.length;
              result.summary.totalPorts += ports.length;

              for (const port of ports) {
                const portData = {
                  portId: port.portId,
                  status: port.status || 'disconnected',
                  speed: port.speed || 'N/A',
                  duplex: port.duplex || 'N/A',
                  enabled: port.enabled,
                  poeEnabled: port.poe?.isAllocated,
                  poeClass: port.poe?.class,
                  poePower: port.powerUsageInWh,
                  clientCount: port.clientCount || 0,
                  trafficInKbps: port.trafficInKbps,
                  errors: [],
                  warnings: []
                };

                // Check for issues
                let hasIssue = false;

                // Check for port errors
                if (port.errors && port.errors.length > 0) {
                  portData.errors = port.errors;
                  switchData.issues.errors += port.errors.length;
                  result.summary.portsWithErrors++;
                  hasIssue = true;

                  result.portIssues.push({
                    type: 'error',
                    severity: 'high',
                    switch: switchData.name,
                    switchSerial: sw.serial,
                    port: port.portId,
                    organization: org.name,
                    detail: port.errors.join(', '),
                    status: port.status
                  });
                }

                // Check for CRC errors (in traffic stats or warnings)
                if (port.warnings && port.warnings.some(w => w.toLowerCase().includes('crc'))) {
                  switchData.issues.crc++;
                  result.summary.portsWithCRC++;
                  hasIssue = true;

                  result.portIssues.push({
                    type: 'crc',
                    severity: 'high',
                    switch: switchData.name,
                    switchSerial: sw.serial,
                    port: port.portId,
                    organization: org.name,
                    detail: 'CRC errors detected - possible cable or NIC issue',
                    status: port.status
                  });
                }

                // Check for packet drops
                if (port.warnings && port.warnings.some(w =>
                  w.toLowerCase().includes('drop') || w.toLowerCase().includes('discard')
                )) {
                  switchData.issues.drops++;
                  result.summary.portsWithDrops++;
                  hasIssue = true;

                  result.portIssues.push({
                    type: 'drops',
                    severity: 'medium',
                    switch: switchData.name,
                    switchSerial: sw.serial,
                    port: port.portId,
                    organization: org.name,
                    detail: 'Packet drops detected - check for congestion or buffer issues',
                    status: port.status
                  });
                }

                // Check PoE status issues
                if (port.poe) {
                  if (port.poe.isAllocated === false && port.status === 'Connected') {
                    // Connected but no PoE when it might be expected
                    portData.warnings.push('No PoE allocation');
                  }
                }

                // Check for PoE overload or issues
                if (port.warnings && port.warnings.some(w =>
                  w.toLowerCase().includes('poe') || w.toLowerCase().includes('power')
                )) {
                  switchData.issues.poe++;
                  result.summary.poeIssues++;
                  hasIssue = true;

                  result.portIssues.push({
                    type: 'poe',
                    severity: 'medium',
                    switch: switchData.name,
                    switchSerial: sw.serial,
                    port: port.portId,
                    organization: org.name,
                    detail: 'PoE issue detected',
                    poeClass: port.poe?.class,
                    status: port.status
                  });
                }

                // Check for negotiation issues (speed/duplex mismatch)
                if (port.status === 'Connected') {
                  switchData.activePorts++;

                  // Half duplex is often a sign of negotiation issues
                  if (port.duplex === 'half') {
                    switchData.issues.negotiation++;
                    result.summary.negotiationIssues++;
                    hasIssue = true;

                    result.portIssues.push({
                      type: 'negotiation',
                      severity: 'medium',
                      switch: switchData.name,
                      switchSerial: sw.serial,
                      port: port.portId,
                      organization: org.name,
                      detail: `Half duplex negotiated (${port.speed}) - possible auto-negotiation failure`,
                      speed: port.speed,
                      duplex: port.duplex,
                      status: port.status
                    });
                  }

                  // 10 Mbps on a gigabit port might indicate issues
                  if (port.speed === '10 Mbps' || port.speed === '10') {
                    switchData.issues.negotiation++;
                    result.summary.negotiationIssues++;
                    hasIssue = true;

                    result.portIssues.push({
                      type: 'negotiation',
                      severity: 'low',
                      switch: switchData.name,
                      switchSerial: sw.serial,
                      port: port.portId,
                      organization: org.name,
                      detail: 'Port negotiated at 10 Mbps - check cable quality or device capability',
                      speed: port.speed,
                      duplex: port.duplex,
                      status: port.status
                    });
                  }
                }

                // Check for general warnings
                if (port.warnings && port.warnings.length > 0) {
                  portData.warnings = portData.warnings.concat(port.warnings);
                }

                if (hasIssue || port.status === 'Connected') {
                  switchData.ports.push(portData);
                }
              }
            }
          } catch (portErr) {
            console.error(`Error fetching ports for ${sw.serial}:`, portErr.message);
          }

          // Calculate total issues for this switch
          const totalIssues = Object.values(switchData.issues).reduce((a, b) => a + b, 0);
          if (totalIssues > 0) {
            orgData.issueCount += totalIssues;
          }

          orgData.switches.push(switchData);
          result.switches.push(switchData);
        }
      } catch (orgErr) {
        console.error(`Error processing org ${org.name}:`, orgErr.message);
      }

      result.organizations.push(orgData);
    }

    // Sort issues by severity
    const severityOrder = { high: 0, medium: 1, low: 2 };
    result.portIssues.sort((a, b) =>
      (severityOrder[a.severity] || 3) - (severityOrder[b.severity] || 3)
    );

    // Sort switches by issue count
    result.switches.sort((a, b) => {
      const aTotal = Object.values(a.issues).reduce((x, y) => x + y, 0);
      const bTotal = Object.values(b.issues).reduce((x, y) => x + y, 0);
      return bTotal - aTotal;
    });

    res.json(result);

  } catch (err) {
    console.error("Switch telemetry error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ===========================================
// LIVE NETWORK HEALTH RADAR API
// ===========================================
const FAIL_CONN_WINDOW_S = 900;  // 15 minutes
const CHAN_UTIL_WINDOW_S = 900;  // 15 minutes

function clampScore(n, a = 0, b = 100) {
  return Math.max(a, Math.min(b, n));
}

function isoFromNow(secondsAgo) {
  return new Date(Date.now() - secondsAgo * 1000).toISOString();
}

// Scoring functions (0-100, higher is better)
function scoreWifi({ mrOnlinePct, chanUtilPct, failedPerMin }) {
  const avail = clampScore(mrOnlinePct);
  const utilPenalty = clampScore((chanUtilPct - 30) * 1.2, 0, 60);
  const failPenalty = clampScore(failedPerMin * 8, 0, 60);
  return clampScore(avail - (0.55 * utilPenalty + 0.45 * failPenalty));
}

function scoreWan({ lossPct, latencyMs, jitterMs }) {
  const lossPenalty = clampScore(lossPct * 3.0, 0, 100);
  const latPenalty = clampScore((latencyMs - 20) * 0.6, 0, 100);
  const jitPenalty = clampScore((jitterMs - 5) * 1.5, 0, 100);
  return clampScore(100 - (0.55 * lossPenalty + 0.30 * latPenalty + 0.15 * jitPenalty));
}

function scoreSwitching({ msOnlinePct }) {
  return clampScore(msOnlinePct);
}

function scoreAvailability(onlinePct) {
  return clampScore(onlinePct);
}

app.get("/api/network/health-radar", async (req, res) => {
  try {
    const networkId = req.query.networkId;
    if (!networkId) {
      return res.status(400).json({ error: "Missing networkId query param" });
    }

    const orgs = await merakiFetch("/organizations");
    if (!orgs || orgs.length === 0) {
      return res.status(500).json({ error: "No organizations found" });
    }
    const orgId = orgs[0].id;

    // Get network info
    const networks = await merakiFetch(`/organizations/${orgId}/networks?perPage=1000`);
    const network = networks.find(n => n.id === networkId);
    if (!network) {
      return res.status(404).json({ error: "Network not found" });
    }

    // 1) Device statuses filtered to this network
    const statuses = await merakiFetch(`/organizations/${orgId}/devices/statuses?perPage=1000`);
    const netDevices = (Array.isArray(statuses) ? statuses : []).filter(d => d.networkId === networkId);

    const total = netDevices.length;
    const online = netDevices.filter(d => d.status === "online").length;
    const onlinePct = total ? (online / total) * 100 : 100;

    const isSwitch = (d) => d.productType === "switch" || (d.model || "").startsWith("MS");
    const isWireless = (d) => d.productType === "wireless" || (d.model || "").startsWith("MR") || (d.model || "").startsWith("CW");
    const isAppliance = (d) => d.productType === "appliance" || (d.model || "").startsWith("MX") || (d.model || "").startsWith("Z");

    const ms = netDevices.filter(isSwitch);
    const mr = netDevices.filter(isWireless);
    const mx = netDevices.filter(isAppliance);

    const msOnline = ms.filter(d => d.status === "online").length;
    const mrOnline = mr.filter(d => d.status === "online").length;

    const msOnlinePct = ms.length ? (msOnline / ms.length) * 100 : 100;
    const mrOnlinePct = mr.length ? (mrOnline / mr.length) * 100 : 100;

    // 2) WAN metrics from MX uplink loss/latency
    let wan = { lossPct: 0, latencyMs: 0, jitterMs: 0, mxCount: mx.length };
    try {
      if (mx.length > 0) {
        const ll = await merakiFetch(`/organizations/${orgId}/devices/uplinksLossAndLatency?timespan=300`);
        const mxSerials = new Set(mx.map(d => d.serial).filter(Boolean));
        const rows = Array.isArray(ll) ? ll.filter(r => mxSerials.has(r.serial)) : [];

        let loss = 0, lat = 0, jit = 0;
        for (const r of rows) {
          const ts = r.timeSeries || [];
          for (const t of ts) {
            loss = Math.max(loss, Number(t.lossPercent || 0));
            lat = Math.max(lat, Number(t.latencyMs || 0));
          }
        }
        wan = { lossPct: loss, latencyMs: lat, jitterMs: jit, mxCount: mx.length };
      }
    } catch (e) {
      wan.note = e.message;
    }

    // 3) Wireless failed connections rate
    let failed = { count: 0, perMin: 0, windowS: FAIL_CONN_WINDOW_S };
    try {
      if (mr.length > 0) {
        const t0 = isoFromNow(FAIL_CONN_WINDOW_S);
        const t1 = new Date().toISOString();
        const fc = await merakiFetch(`/networks/${networkId}/wireless/failedConnections?t0=${encodeURIComponent(t0)}&t1=${encodeURIComponent(t1)}&perPage=1000`);
        const count = Array.isArray(fc) ? fc.length : 0;
        failed = { count, perMin: count / (FAIL_CONN_WINDOW_S / 60), windowS: FAIL_CONN_WINDOW_S };
      }
    } catch (e) {
      failed.note = e.message;
    }

    // 4) Channel utilization
    let chan = { utilPct: 0, windowS: CHAN_UTIL_WINDOW_S };
    try {
      if (mr.length > 0) {
        const t0 = isoFromNow(CHAN_UTIL_WINDOW_S);
        const t1 = new Date().toISOString();
        const cu = await merakiFetch(`/networks/${networkId}/wireless/channelUtilizationHistory?t0=${encodeURIComponent(t0)}&t1=${encodeURIComponent(t1)}&resolution=600`);
        const rows = Array.isArray(cu) ? cu : [];
        let acc = 0, n = 0;
        for (const r of rows) {
          const v = Number(r.utilizationTotal ?? r.utilization ?? NaN);
          if (!Number.isNaN(v)) { acc += v; n++; }
        }
        chan = { utilPct: n ? (acc / n) : 0, windowS: CHAN_UTIL_WINDOW_S };
      }
    } catch (e) {
      chan.note = e.message;
    }

    // Calculate scores
    const scores = {
      wifi: Math.round(scoreWifi({ mrOnlinePct, chanUtilPct: chan.utilPct, failedPerMin: failed.perMin })),
      wan: Math.round(scoreWan(wan)),
      switching: Math.round(scoreSwitching({ msOnlinePct })),
      availability: Math.round(scoreAvailability(onlinePct))
    };

    // Overall health score (weighted average)
    const hasWireless = mr.length > 0;
    const hasSwitching = ms.length > 0;
    const hasWan = mx.length > 0;

    let weightedSum = scores.availability * 0.25;
    let totalWeight = 0.25;
    if (hasWireless) { weightedSum += scores.wifi * 0.35; totalWeight += 0.35; }
    if (hasSwitching) { weightedSum += scores.switching * 0.20; totalWeight += 0.20; }
    if (hasWan) { weightedSum += scores.wan * 0.20; totalWeight += 0.20; }

    const overallScore = Math.round(weightedSum / totalWeight);

    res.json({
      network: { id: network.id, name: network.name },
      ts: Date.now(),
      counts: {
        totalDevices: total,
        online,
        mr: mr.length,
        ms: ms.length,
        mx: mx.length
      },
      kpis: {
        mrOnlinePct: Math.round(mrOnlinePct * 10) / 10,
        msOnlinePct: Math.round(msOnlinePct * 10) / 10,
        onlinePct: Math.round(onlinePct * 10) / 10,
        failedConnectionsPerMin: Math.round(failed.perMin * 100) / 100,
        channelUtilPct: Math.round(chan.utilPct * 10) / 10
      },
      failed,
      chan,
      wan,
      scores,
      overallScore,
      radar: {
        labels: ["Wi-Fi", "WAN", "Switching", "Availability"],
        values: [scores.wifi, scores.wan, scores.switching, scores.availability]
      }
    });

  } catch (err) {
    console.error("Health radar error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ===========================================
// PREDICTIVE FAILURE DETECTION API
// ===========================================
const PREDICTIVE_TIMESPAN_S = 3600; // 1 hour lookback for pattern detection

app.get("/api/predictive/failure-detection", async (req, res) => {
  try {
    const orgs = await merakiFetch("/organizations");
    if (!orgs || orgs.length === 0) {
      return res.status(500).json({ error: "No organizations found" });
    }

    const risks = [];
    const deviceHealth = {};
    const eventPatterns = {};

    for (const org of orgs) {
      const orgId = org.id;
      const orgName = org.name;

      // Get all device statuses
      let statuses = [];
      try {
        statuses = await merakiFetch(`/organizations/${orgId}/devices/statuses?perPage=1000`);
      } catch (e) {
        console.warn(`Failed to get statuses for org ${orgName}:`, e.message);
        continue;
      }

      // Get networks for event fetching
      let networks = [];
      try {
        networks = await merakiFetch(`/organizations/${orgId}/networks?perPage=1000`);
      } catch (e) {
        console.warn(`Failed to get networks for org ${orgName}:`, e.message);
      }

      // Analyze device statuses for alerting/offline patterns
      for (const device of (statuses || [])) {
        const deviceKey = device.serial || device.mac;
        const deviceType = device.productType ||
          ((device.model || "").startsWith("MR") || (device.model || "").startsWith("CW") ? "wireless" :
           (device.model || "").startsWith("MS") ? "switch" :
           (device.model || "").startsWith("MX") || (device.model || "").startsWith("Z") ? "appliance" : "unknown");

        deviceHealth[deviceKey] = {
          name: device.name || device.mac,
          model: device.model,
          serial: device.serial,
          status: device.status,
          type: deviceType,
          org: orgName,
          networkId: device.networkId,
          lastReportedAt: device.lastReportedAt
        };

        // Flag devices in alerting state
        if (device.status === "alerting") {
          risks.push({
            type: "device_alerting",
            severity: "high",
            probability: 75,
            timeframe: "30-60 minutes",
            device: device.name || device.mac,
            serial: device.serial,
            model: device.model,
            deviceType: deviceType,
            org: orgName,
            signal: "Device in alerting state",
            detail: `${device.name || device.mac} is currently alerting - may indicate imminent failure`,
            recommendation: "Check device logs and connectivity immediately"
          });
        }

        // Flag offline devices
        if (device.status === "offline") {
          risks.push({
            type: "device_offline",
            severity: "critical",
            probability: 95,
            timeframe: "Immediate",
            device: device.name || device.mac,
            serial: device.serial,
            model: device.model,
            deviceType: deviceType,
            org: orgName,
            signal: "Device offline",
            detail: `${device.name || device.mac} is currently offline`,
            recommendation: "Verify power and network connectivity"
          });
        }
      }

      // Get WAN uplink loss/latency for MX devices
      try {
        const mxDevices = (statuses || []).filter(d =>
          d.productType === "appliance" || (d.model || "").startsWith("MX") || (d.model || "").startsWith("Z")
        );

        if (mxDevices.length > 0) {
          const uplinkData = await merakiFetch(`/organizations/${orgId}/devices/uplinksLossAndLatency?timespan=300`);
          const mxSerials = new Set(mxDevices.map(d => d.serial).filter(Boolean));

          for (const uplink of (uplinkData || [])) {
            if (!mxSerials.has(uplink.serial)) continue;

            const ts = uplink.timeSeries || [];
            let maxLoss = 0, maxLatency = 0, lossSpikes = 0, latencySpikes = 0;

            for (const t of ts) {
              const loss = Number(t.lossPercent || 0);
              const lat = Number(t.latencyMs || 0);
              maxLoss = Math.max(maxLoss, loss);
              maxLatency = Math.max(maxLatency, lat);
              if (loss > 5) lossSpikes++;
              if (lat > 100) latencySpikes++;
            }

            const device = mxDevices.find(d => d.serial === uplink.serial);
            const deviceName = device?.name || uplink.serial;

            // High packet loss indicates uplink instability
            if (maxLoss > 10 || lossSpikes >= 3) {
              risks.push({
                type: "uplink_instability",
                severity: maxLoss > 25 ? "critical" : "high",
                probability: Math.min(40 + maxLoss * 2, 90),
                timeframe: "30-90 minutes",
                device: deviceName,
                serial: uplink.serial,
                model: device?.model,
                deviceType: "appliance",
                org: orgName,
                signal: "Uplink packet loss",
                detail: `Max loss: ${maxLoss.toFixed(1)}%, ${lossSpikes} loss spikes in last 5 min`,
                recommendation: "Check ISP connection, cables, and upstream equipment"
              });
            }

            // High latency indicates potential WAN issues
            if (maxLatency > 150 || latencySpikes >= 3) {
              risks.push({
                type: "uplink_latency",
                severity: maxLatency > 300 ? "high" : "medium",
                probability: Math.min(35 + latencySpikes * 10, 80),
                timeframe: "60-120 minutes",
                device: deviceName,
                serial: uplink.serial,
                model: device?.model,
                deviceType: "appliance",
                org: orgName,
                signal: "High WAN latency",
                detail: `Max latency: ${maxLatency.toFixed(0)}ms, ${latencySpikes} latency spikes`,
                recommendation: "Monitor ISP performance, check for congestion"
              });
            }
          }
        }
      } catch (e) {
        console.warn(`Failed to get uplink data for org ${orgName}:`, e.message);
      }

      // Analyze events for each network
      for (const network of networks) {
        const networkId = network.id;
        const networkName = network.name;

        try {
          // Get recent events
          const t0 = new Date(Date.now() - PREDICTIVE_TIMESPAN_S * 1000).toISOString();
          const events = await merakiFetch(`/networks/${networkId}/events?perPage=1000&startingAfter=${encodeURIComponent(t0)}`);

          if (!events || !events.events) continue;

          const eventList = events.events || [];
          const deviceEvents = {};
          const eventTypes = {};

          // Count events by device and type
          for (const evt of eventList) {
            const deviceSerial = evt.deviceSerial || evt.clientMac || "unknown";
            const eventType = evt.type || "unknown";

            if (!deviceEvents[deviceSerial]) deviceEvents[deviceSerial] = [];
            deviceEvents[deviceSerial].push(evt);

            if (!eventTypes[eventType]) eventTypes[eventType] = 0;
            eventTypes[eventType]++;
          }

          // Detect event bursts (abnormal event volume per device)
          for (const [serial, devEvents] of Object.entries(deviceEvents)) {
            const deviceInfo = deviceHealth[serial] || { name: serial, model: "Unknown" };

            // More than 20 events in an hour is suspicious
            if (devEvents.length > 20) {
              risks.push({
                type: "event_burst",
                severity: devEvents.length > 50 ? "high" : "medium",
                probability: Math.min(50 + devEvents.length, 85),
                timeframe: "60-120 minutes",
                device: deviceInfo.name,
                serial: serial,
                model: deviceInfo.model,
                deviceType: deviceInfo.type || "unknown",
                org: orgName,
                network: networkName,
                signal: "Event burst detected",
                detail: `${devEvents.length} events in last hour - abnormal activity`,
                recommendation: "Investigate device logs for root cause"
              });
            }

            // Check for reboot events
            const rebootEvents = devEvents.filter(e =>
              (e.type || "").toLowerCase().includes("reboot") ||
              (e.type || "").toLowerCase().includes("restart") ||
              (e.description || "").toLowerCase().includes("reboot")
            );

            if (rebootEvents.length > 0) {
              risks.push({
                type: "device_rebooting",
                severity: rebootEvents.length > 2 ? "critical" : "high",
                probability: 70 + rebootEvents.length * 10,
                timeframe: "30-60 minutes",
                device: deviceInfo.name,
                serial: serial,
                model: deviceInfo.model,
                deviceType: deviceInfo.type || "unknown",
                org: orgName,
                network: networkName,
                signal: "Device rebooting",
                detail: `${rebootEvents.length} reboot event(s) detected - device instability`,
                recommendation: "Check power supply, firmware, and hardware health"
              });
            }
          }

          // Check for authentication failures
          const authFailures = eventList.filter(e =>
            (e.type || "").toLowerCase().includes("auth") &&
            ((e.type || "").toLowerCase().includes("fail") || (e.type || "").toLowerCase().includes("reject"))
          );

          if (authFailures.length > 10) {
            risks.push({
              type: "auth_failures",
              severity: authFailures.length > 30 ? "high" : "medium",
              probability: Math.min(45 + authFailures.length, 80),
              timeframe: "60-120 minutes",
              device: networkName,
              deviceType: "network",
              org: orgName,
              network: networkName,
              signal: "Rising auth failures",
              detail: `${authFailures.length} authentication failures in last hour`,
              recommendation: "Check RADIUS server, credentials, or rogue client activity"
            });
          }

          // Check for DHCP failures
          const dhcpFailures = eventList.filter(e =>
            (e.type || "").toLowerCase().includes("dhcp") &&
            ((e.type || "").toLowerCase().includes("fail") || (e.type || "").toLowerCase().includes("timeout") || (e.type || "").toLowerCase().includes("no_lease"))
          );

          if (dhcpFailures.length > 5) {
            risks.push({
              type: "dhcp_failures",
              severity: dhcpFailures.length > 20 ? "high" : "medium",
              probability: Math.min(50 + dhcpFailures.length * 2, 85),
              timeframe: "30-90 minutes",
              device: networkName,
              deviceType: "network",
              org: orgName,
              network: networkName,
              signal: "DHCP failures rising",
              detail: `${dhcpFailures.length} DHCP failures in last hour`,
              recommendation: "Check DHCP server capacity, scope exhaustion, or network segmentation"
            });
          }

          // Check for wireless connection failures (retries)
          const wirelessFailures = eventList.filter(e =>
            (e.type || "").toLowerCase().includes("disassoc") ||
            (e.type || "").toLowerCase().includes("deauth") ||
            ((e.type || "").toLowerCase().includes("association") && (e.type || "").toLowerCase().includes("fail"))
          );

          if (wirelessFailures.length > 15) {
            risks.push({
              type: "wireless_instability",
              severity: wirelessFailures.length > 40 ? "high" : "medium",
              probability: Math.min(40 + wirelessFailures.length, 80),
              timeframe: "60-120 minutes",
              device: networkName,
              deviceType: "network",
              org: orgName,
              network: networkName,
              signal: "Rising wireless retries/failures",
              detail: `${wirelessFailures.length} disassoc/deauth events in last hour`,
              recommendation: "Check RF environment, channel utilization, and client compatibility"
            });
          }

        } catch (e) {
          console.warn(`Failed to analyze events for network ${networkName}:`, e.message);
        }
      }
    }

    // Sort risks by severity and probability
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    risks.sort((a, b) => {
      const sevDiff = (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4);
      if (sevDiff !== 0) return sevDiff;
      return (b.probability || 0) - (a.probability || 0);
    });

    // Calculate summary
    const summary = {
      totalRisks: risks.length,
      critical: risks.filter(r => r.severity === "critical").length,
      high: risks.filter(r => r.severity === "high").length,
      medium: risks.filter(r => r.severity === "medium").length,
      low: risks.filter(r => r.severity === "low").length,
      byType: {}
    };

    for (const r of risks) {
      summary.byType[r.type] = (summary.byType[r.type] || 0) + 1;
    }

    // Overall risk score (0-100, lower is better)
    const riskScore = Math.min(100,
      summary.critical * 25 +
      summary.high * 15 +
      summary.medium * 5 +
      summary.low * 2
    );

    res.json({
      ts: Date.now(),
      lookbackSeconds: PREDICTIVE_TIMESPAN_S,
      riskScore,
      riskLevel: riskScore >= 75 ? "critical" : riskScore >= 50 ? "high" : riskScore >= 25 ? "medium" : "low",
      summary,
      risks: risks.slice(0, 50), // Limit to top 50 risks
      signals: {
        reboots: summary.byType.device_rebooting || 0,
        eventBursts: summary.byType.event_burst || 0,
        uplinkIssues: (summary.byType.uplink_instability || 0) + (summary.byType.uplink_latency || 0),
        authFailures: summary.byType.auth_failures || 0,
        dhcpFailures: summary.byType.dhcp_failures || 0,
        wirelessIssues: summary.byType.wireless_instability || 0,
        offlineDevices: summary.byType.device_offline || 0,
        alertingDevices: summary.byType.device_alerting || 0
      }
    });

  } catch (err) {
    console.error("Predictive failure detection error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ===========================================
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

// ===========================================
// AI CHANGE RISK PREDICTION API
// ===========================================
app.post("/api/change-risk/analyze", express.json(), async (req, res) => {
  try {
    const {
      changeType = "ssid_update",  // ssid_update, firmware_upgrade, vlan_change, security_policy, rf_profile, qos_rules
      targetNetwork = null,
      targetDevice = null,
      changeDescription = ""
    } = req.body;

    const orgs = await merakiFetch("/organizations");
    if (!orgs || orgs.length === 0) {
      return res.status(500).json({ error: "No organizations found" });
    }

    // Data collection containers
    let totalClients = 0;
    let totalAPs = 0;
    let totalSwitches = 0;
    let totalAppliances = 0;
    let onlineDevices = 0;
    let alertingDevices = 0;
    let offlineDevices = 0;
    let recentIncidents = 0;
    let highUtilizationAPs = 0;
    let clientLoadByHour = new Array(24).fill(0);
    let incidentsByHour = new Array(24).fill(0);
    let affectedNetworks = [];
    let affectedDevices = [];
    let rfDensityScore = 0;
    let wanUtilization = 0;
    let historicalFailures = [];

    // Analyze each organization
    for (const org of orgs) {
      const orgId = org.id;
      const orgName = org.name;

      // Get networks
      let networks = [];
      try {
        networks = await merakiFetch(`/organizations/${orgId}/networks?perPage=1000`);
      } catch (e) {
        console.warn(`Failed to get networks for org ${orgName}:`, e.message);
        continue;
      }

      // Filter to target network if specified
      const networksToAnalyze = targetNetwork
        ? networks.filter(n => n.id === targetNetwork || n.name.toLowerCase().includes(targetNetwork.toLowerCase()))
        : networks;

      // Get device statuses
      let statuses = [];
      try {
        statuses = await merakiFetch(`/organizations/${orgId}/devices/statuses?perPage=1000`);
      } catch (e) {
        console.warn(`Failed to get statuses for org ${orgName}:`, e.message);
      }

      // Count devices by type and status
      for (const device of (statuses || [])) {
        const model = device.model || "";
        const isAP = model.startsWith("MR") || model.startsWith("CW");
        const isSwitch = model.startsWith("MS");
        const isAppliance = model.startsWith("MX") || model.startsWith("Z");

        if (isAP) totalAPs++;
        else if (isSwitch) totalSwitches++;
        else if (isAppliance) totalAppliances++;

        if (device.status === "online") onlineDevices++;
        else if (device.status === "alerting") alertingDevices++;
        else if (device.status === "offline") offlineDevices++;

        // Track affected devices based on change type
        if (networksToAnalyze.some(n => n.id === device.networkId)) {
          affectedDevices.push({
            name: device.name || device.mac,
            serial: device.serial,
            model: device.model,
            status: device.status,
            type: isAP ? "wireless" : isSwitch ? "switch" : isAppliance ? "appliance" : "other"
          });
        }
      }

      // Analyze events for historical incidents (last 7 days)
      for (const network of networksToAnalyze.slice(0, 5)) { // Limit to 5 networks for performance
        affectedNetworks.push({ id: network.id, name: network.name });

        try {
          // Get recent events
          const events = await merakiFetch(`/networks/${network.id}/events?perPage=500&productType=wireless&includedEventTypes[]=association&includedEventTypes[]=disassociation&includedEventTypes[]=wpa_auth&includedEventTypes[]=wpa_deauth`);

          if (events && events.events) {
            for (const event of events.events) {
              const eventTime = new Date(event.occurredAt);
              const hour = eventTime.getHours();
              clientLoadByHour[hour]++;

              // Track failures
              if (event.type.includes("fail") || event.type.includes("deauth") || event.type.includes("timeout")) {
                incidentsByHour[hour]++;
                recentIncidents++;
                historicalFailures.push({
                  type: event.type,
                  time: event.occurredAt,
                  device: event.deviceName || event.deviceSerial,
                  detail: event.description
                });
              }
            }
          }
        } catch (e) {
          // Events endpoint may fail for some network types
        }

        // Get wireless health/RF data
        try {
          const health = await merakiFetch(`/networks/${network.id}/wireless/connectionStats?timespan=3600`);
          if (health) {
            const successRate = health.assoc && health.assoc > 0
              ? ((health.assoc - (health.authFail || 0)) / health.assoc) * 100
              : 100;
            if (successRate < 95) highUtilizationAPs++;
          }
        } catch (e) {
          // May not have wireless
        }

        // Get channel utilization for RF density
        try {
          const channelUtil = await merakiFetch(`/networks/${network.id}/wireless/channelUtilizationHistory?timespan=3600`);
          if (channelUtil && channelUtil.length > 0) {
            const avgUtil = channelUtil.reduce((sum, c) => sum + (c.utilization80211 || 0), 0) / channelUtil.length;
            rfDensityScore = Math.max(rfDensityScore, avgUtil);
          }
        } catch (e) {
          // May not have data
        }

        // Get uplink/WAN data
        try {
          const uplinks = await merakiFetch(`/networks/${network.id}/appliance/uplinks/usageHistory?timespan=3600`);
          if (uplinks && uplinks.length > 0) {
            const avgUsage = uplinks.reduce((sum, u) => sum + (u.sent || 0) + (u.received || 0), 0) / uplinks.length;
            wanUtilization = Math.max(wanUtilization, avgUsage / 1000000); // Convert to Mbps
          }
        } catch (e) {
          // May not have appliance
        }

        // Get client count
        try {
          const clients = await merakiFetch(`/networks/${network.id}/clients?timespan=3600&perPage=1000`);
          if (clients) {
            totalClients += clients.length;
          }
        } catch (e) {
          // May fail
        }
      }
    }

    // Calculate risk factors (0-100 scale each)
    const factors = {
      historicalIncidents: Math.min(100, (recentIncidents / Math.max(1, totalAPs)) * 10),
      clientLoad: Math.min(100, (totalClients / Math.max(1, totalAPs)) * 2),
      rfDensity: Math.min(100, rfDensityScore),
      wanUtilization: Math.min(100, wanUtilization / 10 * 100),
      deviceHealth: alertingDevices > 0 ? Math.min(100, (alertingDevices / Math.max(1, onlineDevices + alertingDevices)) * 200) : 0,
      changeComplexity: getChangeComplexity(changeType)
    };

    // Calculate weighted risk score
    const weights = {
      historicalIncidents: 0.20,
      clientLoad: 0.25,
      rfDensity: 0.15,
      wanUtilization: 0.10,
      deviceHealth: 0.15,
      changeComplexity: 0.15
    };

    let riskScore = 0;
    for (const [factor, value] of Object.entries(factors)) {
      riskScore += value * weights[factor];
    }
    riskScore = Math.round(riskScore) / 100; // Normalize to 0-1

    // Calculate blast radius
    const blastRadius = {
      aps: affectedDevices.filter(d => d.type === "wireless").length || totalAPs,
      switches: affectedDevices.filter(d => d.type === "switch").length,
      appliances: affectedDevices.filter(d => d.type === "appliance").length,
      clients: totalClients,
      networks: affectedNetworks.length
    };

    // Determine optimal change window based on usage patterns
    const suggestedWindow = calculateOptimalWindow(clientLoadByHour, incidentsByHour);

    // Generate recommendations
    const recommendations = generateChangeRecommendations(riskScore, factors, changeType, blastRadius);

    // Determine risk level
    let riskLevel = "low";
    if (riskScore >= 0.7) riskLevel = "critical";
    else if (riskScore >= 0.5) riskLevel = "high";
    else if (riskScore >= 0.3) riskLevel = "medium";

    res.json({
      riskScore: riskScore.toFixed(2),
      riskLevel,
      blastRadius,
      suggestedWindow,
      factors: {
        historicalIncidents: { score: Math.round(factors.historicalIncidents), weight: weights.historicalIncidents, detail: `${recentIncidents} incidents detected in analysis period` },
        clientLoad: { score: Math.round(factors.clientLoad), weight: weights.clientLoad, detail: `${totalClients} active clients across ${totalAPs} APs` },
        rfDensity: { score: Math.round(factors.rfDensity), weight: weights.rfDensity, detail: `Channel utilization at ${Math.round(rfDensityScore)}%` },
        wanUtilization: { score: Math.round(factors.wanUtilization), weight: weights.wanUtilization, detail: `WAN throughput ~${Math.round(wanUtilization)} Mbps` },
        deviceHealth: { score: Math.round(factors.deviceHealth), weight: weights.deviceHealth, detail: `${alertingDevices} alerting, ${offlineDevices} offline devices` },
        changeComplexity: { score: Math.round(factors.changeComplexity), weight: weights.changeComplexity, detail: `${changeType.replace(/_/g, " ")} - ${getChangeDescription(changeType)}` }
      },
      recommendations,
      summary: {
        totalDevices: totalAPs + totalSwitches + totalAppliances,
        totalClients,
        networksAffected: affectedNetworks.length,
        recentIncidents,
        currentTime: new Date().toISOString()
      },
      historicalFailures: historicalFailures.slice(0, 10) // Last 10 failures
    });

  } catch (err) {
    console.error("Change risk analysis error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Helper: Get change complexity score
function getChangeComplexity(changeType) {
  const complexityMap = {
    ssid_update: 40,
    security_policy: 60,
    vlan_change: 65,
    qos_rules: 50,
    rf_profile: 55,
    firmware_upgrade: 85,
    network_settings: 70,
    switching_config: 60,
    wan_config: 75
  };
  return complexityMap[changeType] || 50;
}

// Helper: Get change type description
function getChangeDescription(changeType) {
  const descriptions = {
    ssid_update: "SSID name/settings modification",
    security_policy: "Authentication or encryption changes",
    vlan_change: "VLAN assignment or tagging changes",
    qos_rules: "Traffic shaping and priority rules",
    rf_profile: "Radio frequency and channel settings",
    firmware_upgrade: "Device firmware update",
    network_settings: "Network-wide configuration",
    switching_config: "Switch port or VLAN config",
    wan_config: "Uplink or routing changes"
  };
  return descriptions[changeType] || "Configuration change";
}

// Helper: Calculate optimal change window
function calculateOptimalWindow(clientLoad, incidents) {
  // Find hours with lowest combined client load and incidents
  const hourScores = clientLoad.map((load, hour) => ({
    hour,
    score: load + (incidents[hour] * 2), // Weight incidents higher
    load,
    incidents: incidents[hour]
  }));

  hourScores.sort((a, b) => a.score - b.score);

  // Find best window (prefer night/early morning)
  const preferredHours = [22, 23, 0, 1, 2, 3, 4, 5, 6];
  let bestHour = hourScores[0].hour;

  for (const hour of preferredHours) {
    const hourData = hourScores.find(h => h.hour === hour);
    if (hourData && hourData.score <= hourScores[0].score * 1.5) {
      bestHour = hour;
      break;
    }
  }

  // Format window suggestion
  const formatHour = (h) => {
    const ampm = h >= 12 ? "PM" : "AM";
    const hour12 = h % 12 || 12;
    return `${hour12}:00 ${ampm}`;
  };

  const windowStart = bestHour;
  const windowEnd = (bestHour + 2) % 24;

  return {
    recommended: `${formatHour(windowStart)} - ${formatHour(windowEnd)}`,
    startHour: windowStart,
    endHour: windowEnd,
    reason: windowStart >= 22 || windowStart <= 5
      ? "Low client activity and minimal historical incidents"
      : "Lowest activity period based on usage patterns",
    clientLoadAtWindow: clientLoad[windowStart],
    peakHour: clientLoad.indexOf(Math.max(...clientLoad)),
    peakClients: Math.max(...clientLoad)
  };
}

// Helper: Generate recommendations based on analysis
function generateChangeRecommendations(riskScore, factors, changeType, blastRadius) {
  const recommendations = [];

  if (riskScore >= 0.6) {
    recommendations.push({
      priority: "critical",
      title: "Consider Staging the Change",
      detail: "Risk score is high. Consider deploying to a pilot network first before full rollout.",
      icon: "shield"
    });
  }

  if (factors.clientLoad > 60) {
    recommendations.push({
      priority: "high",
      title: "High Client Load Detected",
      detail: `${blastRadius.clients} clients may be affected. Schedule during low-usage window.`,
      icon: "users"
    });
  }

  if (factors.deviceHealth > 30) {
    recommendations.push({
      priority: "high",
      title: "Device Health Issues Present",
      detail: "Some devices are alerting or offline. Resolve these before making changes.",
      icon: "alert"
    });
  }

  if (factors.rfDensity > 50) {
    recommendations.push({
      priority: "medium",
      title: "High RF Density",
      detail: "Channel utilization is elevated. RF changes may cause temporary disruption.",
      icon: "radio"
    });
  }

  if (changeType === "firmware_upgrade") {
    recommendations.push({
      priority: "high",
      title: "Firmware Upgrade Requires Reboot",
      detail: "Devices will reboot during upgrade. Expect 2-5 minute downtime per device.",
      icon: "download"
    });
  }

  if (blastRadius.aps > 20) {
    recommendations.push({
      priority: "medium",
      title: "Large Blast Radius",
      detail: `${blastRadius.aps} APs affected. Consider phased rollout by network or location.`,
      icon: "network"
    });
  }

  // Add rollback recommendation
  recommendations.push({
    priority: "info",
    title: "Prepare Rollback Plan",
    detail: "Document current settings before changes. Enable configuration backup if available.",
    icon: "history"
  });

  return recommendations;
}

// Get available networks for change risk dropdown
app.get("/api/change-risk/networks", async (req, res) => {
  try {
    const orgs = await merakiFetch("/organizations");
    const allNetworks = [];

    for (const org of orgs) {
      try {
        const networks = await merakiFetch(`/organizations/${org.id}/networks?perPage=1000`);
        for (const network of (networks || [])) {
          allNetworks.push({
            id: network.id,
            name: network.name,
            org: org.name,
            productTypes: network.productTypes
          });
        }
      } catch (e) {
        console.warn(`Failed to get networks for org ${org.name}:`, e.message);
      }
    }

    res.json(allNetworks);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===========================================
// NETWORK TOPOLOGY MAP API
// ===========================================

app.get("/api/topology/map", async (req, res) => {
  try {
    const { networkId } = req.query;

    const topology = {
      nodes: [],
      edges: [],
      networks: [],
      clients: [],
      summary: {
        totalDevices: 0,
        appliances: 0,
        switches: 0,
        aps: 0,
        online: 0,
        offline: 0,
        alerting: 0,
        wirelessClients: 0
      }
    };

    const orgs = await merakiFetch("/organizations");
    if (!orgs || orgs.length === 0) {
      return res.status(500).json({ error: "No organizations found" });
    }

    for (const org of orgs) {
      // Get networks
      let networks = [];
      try {
        networks = await merakiFetch(`/organizations/${org.id}/networks?perPage=1000`);
      } catch (e) {
        continue;
      }

      // Filter to specific network if requested
      const targetNetworks = networkId
        ? networks.filter(n => n.id === networkId)
        : networks.slice(0, 10); // Limit to 10 networks for performance

      for (const network of targetNetworks) {
        topology.networks.push({
          id: network.id,
          name: network.name,
          org: org.name,
          productTypes: network.productTypes
        });

        // Add network as a container node
        topology.nodes.push({
          id: `network-${network.id}`,
          type: 'network',
          label: network.name,
          org: org.name,
          productTypes: network.productTypes
        });

        // Get devices in this network
        try {
          const devices = await merakiFetch(`/networks/${network.id}/devices`);

          for (const device of (devices || [])) {
            const model = device.model || "";
            let deviceType = "other";
            let tier = 4;

            if (model.startsWith("MX") || model.startsWith("Z")) {
              deviceType = "appliance";
              tier = 1;
              topology.summary.appliances++;
            } else if (model.startsWith("MS")) {
              deviceType = "switch";
              tier = 2;
              topology.summary.switches++;
            } else if (model.startsWith("MR") || model.startsWith("CW")) {
              deviceType = "ap";
              tier = 3;
              topology.summary.aps++;
            }

            // Get device status
            let status = "unknown";
            try {
              const statuses = await merakiFetch(`/organizations/${org.id}/devices/statuses?serials[]=${device.serial}`);
              if (statuses && statuses[0]) {
                status = statuses[0].status;
              }
            } catch (e) {
              // Status fetch failed
            }

            if (status === "online") topology.summary.online++;
            else if (status === "offline") topology.summary.offline++;
            else if (status === "alerting") topology.summary.alerting++;

            topology.nodes.push({
              id: device.serial,
              type: deviceType,
              tier,
              label: device.name || device.serial,
              model: device.model,
              serial: device.serial,
              mac: device.mac,
              lanIp: device.lanIp,
              wan1Ip: device.wan1Ip,
              wan2Ip: device.wan2Ip,
              status,
              networkId: network.id,
              networkName: network.name,
              lat: device.lat,
              lng: device.lng,
              address: device.address,
              firmware: device.firmware
            });

            topology.summary.totalDevices++;

            // Create edge from network to device
            topology.edges.push({
              from: `network-${network.id}`,
              to: device.serial,
              type: 'network-device'
            });
          }
        } catch (e) {
          console.warn(`Failed to get devices for network ${network.name}:`, e.message);
        }

        // Get LLDP/CDP neighbors for topology connections (network-level)
        try {
          const lldpCdp = await merakiFetch(`/networks/${network.id}/topology/linkLayer`);
          if (lldpCdp && lldpCdp.links) {
            for (const link of lldpCdp.links) {
              // Avoid duplicate edges
              const edgeId = [link.ends[0]?.device?.serial, link.ends[1]?.device?.serial].sort().join('-');
              if (!topology.edges.find(e => e.id === edgeId)) {
                topology.edges.push({
                  id: edgeId,
                  from: link.ends[0]?.device?.serial,
                  to: link.ends[1]?.device?.serial,
                  type: 'lldp',
                  fromPort: link.ends[0]?.port?.portId,
                  toPort: link.ends[1]?.port?.portId,
                  fromDevice: link.ends[0]?.device?.name,
                  toDevice: link.ends[1]?.device?.name,
                  lastReportedAt: link.lastReportedAt
                });
              }
            }
          }
        } catch (e) {
          // LLDP/CDP network topology may not be available
        }

        // Get per-device LLDP/CDP neighbors for more detail
        try {
          const devices = await merakiFetch(`/networks/${network.id}/devices`);
          for (const device of (devices || [])) {
            try {
              const lldpData = await merakiFetch(`/devices/${device.serial}/lldpCdp`);
              if (lldpData) {
                // Process LLDP ports
                if (lldpData.ports) {
                  for (const [portId, portData] of Object.entries(lldpData.ports)) {
                    // Check for LLDP neighbor
                    if (portData.lldp) {
                      const neighbor = portData.lldp;
                      const neighborSerial = neighbor.deviceSerial || neighbor.chassisId;
                      const edgeId = [device.serial, neighborSerial].sort().join('-lldp-');

                      if (!topology.edges.find(e => e.id === edgeId)) {
                        topology.edges.push({
                          id: edgeId,
                          from: device.serial,
                          to: neighborSerial,
                          type: 'lldp',
                          protocol: 'LLDP',
                          fromPort: portId,
                          toPort: neighbor.portId || neighbor.portDescription,
                          fromDevice: device.name || device.serial,
                          toDevice: neighbor.systemName || neighbor.deviceSerial || 'Unknown',
                          toModel: neighbor.systemDescription,
                          toMac: neighbor.chassisId,
                          toIp: neighbor.managementAddress,
                          capabilities: neighbor.systemCapabilities,
                          status: 'active'
                        });
                      }
                    }
                    // Check for CDP neighbor
                    if (portData.cdp) {
                      const neighbor = portData.cdp;
                      const neighborSerial = neighbor.deviceId || neighbor.address;
                      const edgeId = [device.serial, neighborSerial].sort().join('-cdp-');

                      if (!topology.edges.find(e => e.id === edgeId)) {
                        topology.edges.push({
                          id: edgeId,
                          from: device.serial,
                          to: neighborSerial,
                          type: 'cdp',
                          protocol: 'CDP',
                          fromPort: portId,
                          toPort: neighbor.portId,
                          fromDevice: device.name || device.serial,
                          toDevice: neighbor.deviceId || 'Unknown',
                          toPlatform: neighbor.platform,
                          toIp: neighbor.address,
                          capabilities: neighbor.capabilities,
                          nativeVlan: neighbor.nativeVlan,
                          status: 'active'
                        });
                      }
                    }
                  }
                }
              }
            } catch (lldpErr) {
              // LLDP/CDP not available for this device
            }
          }
        } catch (e) {
          // Per-device LLDP fetch failed
        }
      }
    }

    // Fetch wireless clients if requested (limit to first 20 for performance)
    const includeClients = req.query.includeClients === 'true';
    if (includeClients) {
      for (const org of orgs) {
        try {
          const networks = await merakiFetch(`/organizations/${org.id}/networks?perPage=100`);
          const targetNets = networkId
            ? networks.filter(n => n.id === networkId)
            : networks.slice(0, 5);

          for (const network of targetNets) {
            if (!network.productTypes || !network.productTypes.includes('wireless')) continue;

            try {
              const clients = await merakiFetch(`/networks/${network.id}/clients?timespan=300&perPage=20`);
              for (const client of (clients || []).slice(0, 10)) {
                if (client.status !== 'Online') continue;

                topology.clients.push({
                  id: client.id || client.mac,
                  mac: client.mac,
                  description: client.description || client.dhcpHostname || 'Unknown Device',
                  ip: client.ip,
                  vlan: client.vlan,
                  ssid: client.ssid,
                  apSerial: client.recentDeviceSerial,
                  apName: client.recentDeviceName,
                  rssi: client.rssi,
                  status: client.status,
                  deviceType: client.os && client.os.includes('Phone') ? 'Phone' : 'Laptop',
                  networkId: network.id,
                  networkName: network.name
                });
                topology.summary.wirelessClients++;
              }
            } catch (e) {
              // Clients fetch failed
            }
          }
        } catch (e) {
          // Networks fetch failed
        }
      }
    }

    // Sort nodes by tier for layout
    topology.nodes.sort((a, b) => (a.tier || 99) - (b.tier || 99));

    res.json(topology);

  } catch (err) {
    console.error("Topology map error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Get topology for a specific network with more detail
app.get("/api/topology/network/:networkId", async (req, res) => {
  try {
    const { networkId } = req.params;

    const topology = {
      network: null,
      nodes: [],
      edges: [],
      vlans: [],
      uplinks: []
    };

    // Get network info
    try {
      topology.network = await merakiFetch(`/networks/${networkId}`);
    } catch (e) {
      return res.status(404).json({ error: "Network not found" });
    }

    // Get devices
    const devices = await merakiFetch(`/networks/${networkId}/devices`);

    // Get org ID from network
    const orgId = topology.network.organizationId;

    // Get device statuses
    let statusMap = {};
    try {
      const statuses = await merakiFetch(`/organizations/${orgId}/devices/statuses?networkIds[]=${networkId}`);
      for (const s of (statuses || [])) {
        statusMap[s.serial] = s;
      }
    } catch (e) {
      // Status fetch failed
    }

    for (const device of (devices || [])) {
      const model = device.model || "";
      let deviceType = "other";
      let tier = 4;

      if (model.startsWith("MX") || model.startsWith("Z")) {
        deviceType = "appliance";
        tier = 1;
      } else if (model.startsWith("MS")) {
        deviceType = "switch";
        tier = 2;
      } else if (model.startsWith("MR") || model.startsWith("CW")) {
        deviceType = "ap";
        tier = 3;
      }

      const deviceStatus = statusMap[device.serial] || {};

      topology.nodes.push({
        id: device.serial,
        type: deviceType,
        tier,
        label: device.name || device.serial,
        model: device.model,
        serial: device.serial,
        mac: device.mac,
        lanIp: device.lanIp,
        wan1Ip: device.wan1Ip,
        status: deviceStatus.status || "unknown",
        publicIp: deviceStatus.publicIp,
        gateway: deviceStatus.gateway,
        clients: deviceStatus.clientCount
      });
    }

    // Get LLDP/CDP topology
    try {
      const lldpCdp = await merakiFetch(`/networks/${networkId}/topology/linkLayer`);
      if (lldpCdp && lldpCdp.links) {
        for (const link of lldpCdp.links) {
          topology.edges.push({
            from: link.ends[0]?.device?.serial,
            to: link.ends[1]?.device?.serial,
            fromPort: link.ends[0]?.port?.portId,
            toPort: link.ends[1]?.port?.portId,
            type: 'physical'
          });
        }
      }
    } catch (e) {
      // LLDP/CDP not available
    }

    // Get VLANs if appliance network
    try {
      const vlans = await merakiFetch(`/networks/${networkId}/appliance/vlans`);
      topology.vlans = vlans || [];
    } catch (e) {
      // VLANs not enabled or no appliance
    }

    // Get uplink status
    try {
      const uplinks = await merakiFetch(`/networks/${networkId}/appliance/uplinks/statuses`);
      topology.uplinks = uplinks || [];
    } catch (e) {
      // No appliance
    }

    // Sort by tier
    topology.nodes.sort((a, b) => a.tier - b.tier);

    res.json(topology);

  } catch (err) {
    console.error("Network topology error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ===========================================
// AUTONOMOUS EVIDENCE COLLECTION API
// ===========================================

// Evidence collection - gathers comprehensive diagnostic data for incident investigation
app.post("/api/evidence/collect", express.json(), async (req, res) => {
  try {
    const {
      networkId = null,
      deviceSerial = null,
      clientMac = null,
      timespan = 3600, // Default 1 hour
      includePacketCapture = false,
      includeClientLogs = true,
      includeDhcpDns = true,
      includeAuthLogs = true,
      includeRfSnapshot = true,
      includeSecurityEvents = true,
      includeConfigSnapshot = true,
      triggerType = "manual", // manual, anomaly, scheduled
      anomalyDetails = null
    } = req.body;

    const collectionId = `EVD-${Date.now()}-${Math.random().toString(36).substr(2, 6).toUpperCase()}`;
    const collectionStart = new Date().toISOString();

    const evidence = {
      collectionId,
      collectionStart,
      triggerType,
      anomalyDetails,
      parameters: { networkId, deviceSerial, clientMac, timespan },
      data: {},
      summary: { totalEvents: 0, criticalFindings: 0, warnings: 0 },
      timeline: []
    };

    const orgs = await merakiFetch("/organizations");
    if (!orgs || orgs.length === 0) {
      return res.status(500).json({ error: "No organizations found" });
    }

    // Determine target networks
    let targetNetworks = [];
    for (const org of orgs) {
      try {
        const networks = await merakiFetch(`/organizations/${org.id}/networks?perPage=1000`);
        for (const net of (networks || [])) {
          if (!networkId || net.id === networkId) {
            targetNetworks.push({ ...net, orgId: org.id, orgName: org.name });
          }
        }
      } catch (e) {
        console.warn(`Failed to get networks for org ${org.name}:`, e.message);
      }
    }

    // Limit to first 3 networks for performance
    targetNetworks = targetNetworks.slice(0, 3);

    // 1. Device Status Snapshot
    evidence.data.deviceStatus = [];
    for (const org of orgs) {
      try {
        const statuses = await merakiFetch(`/organizations/${org.id}/devices/statuses?perPage=1000`);
        for (const device of (statuses || [])) {
          if (!networkId || device.networkId === networkId) {
            if (!deviceSerial || device.serial === deviceSerial) {
              evidence.data.deviceStatus.push({
                name: device.name || device.mac,
                serial: device.serial,
                mac: device.mac,
                model: device.model,
                status: device.status,
                lanIp: device.lanIp,
                publicIp: device.publicIp,
                lastReportedAt: device.lastReportedAt,
                networkId: device.networkId,
                org: org.name
              });

              if (device.status === "alerting" || device.status === "offline") {
                evidence.summary.criticalFindings++;
                evidence.timeline.push({
                  time: device.lastReportedAt || collectionStart,
                  type: "device_status",
                  severity: device.status === "offline" ? "critical" : "high",
                  message: `${device.name || device.serial} is ${device.status}`,
                  device: device.serial
                });
              }
            }
          }
        }
      } catch (e) {
        console.warn(`Failed to get device statuses:`, e.message);
      }
    }

    // 2. Client Event Logs
    if (includeClientLogs) {
      evidence.data.clientEvents = [];
      for (const network of targetNetworks) {
        try {
          let eventUrl = `/networks/${network.id}/events?perPage=500&productType=wireless&timespan=${timespan}`;
          if (clientMac) {
            eventUrl += `&clientMac=${clientMac}`;
          }
          const events = await merakiFetch(eventUrl);
          if (events && events.events) {
            for (const event of events.events) {
              evidence.data.clientEvents.push({
                occurredAt: event.occurredAt,
                networkId: network.id,
                networkName: network.name,
                type: event.type,
                description: event.description,
                clientId: event.clientId,
                clientMac: event.clientMac,
                clientDescription: event.clientDescription,
                deviceSerial: event.deviceSerial,
                deviceName: event.deviceName,
                ssidNumber: event.ssidNumber,
                eventData: event.eventData
              });
              evidence.summary.totalEvents++;

              // Add to timeline for important events
              if (event.type.includes("fail") || event.type.includes("deauth") || event.type.includes("disassoc")) {
                evidence.timeline.push({
                  time: event.occurredAt,
                  type: "client_event",
                  severity: event.type.includes("fail") ? "high" : "medium",
                  message: `${event.type}: ${event.clientDescription || event.clientMac || 'Unknown client'}`,
                  device: event.deviceName || event.deviceSerial,
                  client: event.clientMac
                });
                evidence.summary.warnings++;
              }
            }
          }
        } catch (e) {
          // May fail for some network types
        }
      }
    }

    // 3. DHCP + DNS Events
    if (includeDhcpDns) {
      evidence.data.dhcpDnsEvents = [];
      for (const network of targetNetworks) {
        try {
          // DHCP events
          const dhcpEvents = await merakiFetch(`/networks/${network.id}/events?perPage=200&productType=appliance&includedEventTypes[]=dhcp_lease&includedEventTypes[]=dhcp_no_leases&timespan=${timespan}`);
          if (dhcpEvents && dhcpEvents.events) {
            for (const event of dhcpEvents.events) {
              evidence.data.dhcpDnsEvents.push({
                occurredAt: event.occurredAt,
                networkId: network.id,
                networkName: network.name,
                type: event.type,
                description: event.description,
                clientMac: event.clientMac,
                eventData: event.eventData,
                category: "dhcp"
              });
              evidence.summary.totalEvents++;

              if (event.type === "dhcp_no_leases") {
                evidence.summary.criticalFindings++;
                evidence.timeline.push({
                  time: event.occurredAt,
                  type: "dhcp",
                  severity: "critical",
                  message: `DHCP pool exhausted: ${event.description}`,
                  network: network.name
                });
              }
            }
          }
        } catch (e) {
          // May not have appliance
        }

        try {
          // DNS/Content filtering events
          const contentEvents = await merakiFetch(`/networks/${network.id}/events?perPage=200&productType=appliance&includedEventTypes[]=content_filtering_block&timespan=${timespan}`);
          if (contentEvents && contentEvents.events) {
            for (const event of contentEvents.events) {
              evidence.data.dhcpDnsEvents.push({
                occurredAt: event.occurredAt,
                networkId: network.id,
                networkName: network.name,
                type: event.type,
                description: event.description,
                clientMac: event.clientMac,
                eventData: event.eventData,
                category: "dns_filtering"
              });
              evidence.summary.totalEvents++;
            }
          }
        } catch (e) {
          // May not have appliance
        }
      }
    }

    // 4. Authentication Logs (802.1x, WPA)
    if (includeAuthLogs) {
      evidence.data.authEvents = [];
      for (const network of targetNetworks) {
        try {
          const authEvents = await merakiFetch(`/networks/${network.id}/events?perPage=300&productType=wireless&includedEventTypes[]=wpa_auth&includedEventTypes[]=wpa_deauth&includedEventTypes[]=8021x_auth&includedEventTypes[]=8021x_deauth&includedEventTypes[]=8021x_eap_failure&timespan=${timespan}`);
          if (authEvents && authEvents.events) {
            for (const event of authEvents.events) {
              evidence.data.authEvents.push({
                occurredAt: event.occurredAt,
                networkId: network.id,
                networkName: network.name,
                type: event.type,
                description: event.description,
                clientMac: event.clientMac,
                clientDescription: event.clientDescription,
                deviceSerial: event.deviceSerial,
                deviceName: event.deviceName,
                ssidNumber: event.ssidNumber,
                eventData: event.eventData
              });
              evidence.summary.totalEvents++;

              // Flag auth failures
              if (event.type.includes("fail") || event.type.includes("deauth")) {
                evidence.timeline.push({
                  time: event.occurredAt,
                  type: "auth",
                  severity: event.type.includes("fail") ? "high" : "medium",
                  message: `Auth ${event.type}: ${event.clientDescription || event.clientMac}`,
                  device: event.deviceName || event.deviceSerial,
                  client: event.clientMac
                });
                evidence.summary.warnings++;
              }
            }
          }
        } catch (e) {
          // May fail
        }
      }
    }

    // 5. RF Snapshot (channel utilization, interference)
    if (includeRfSnapshot) {
      evidence.data.rfSnapshot = {
        channelUtilization: [],
        connectionStats: [],
        clientSignalQuality: []
      };

      for (const network of targetNetworks) {
        try {
          // Channel utilization history
          const channelUtil = await merakiFetch(`/networks/${network.id}/wireless/channelUtilizationHistory?timespan=${Math.min(timespan, 7200)}`);
          if (channelUtil && channelUtil.length > 0) {
            evidence.data.rfSnapshot.channelUtilization.push({
              networkId: network.id,
              networkName: network.name,
              data: channelUtil.slice(0, 50), // Limit data points
              avgUtilization: channelUtil.reduce((sum, c) => sum + (c.utilization80211 || 0), 0) / channelUtil.length,
              avgInterference: channelUtil.reduce((sum, c) => sum + (c.utilizationNon80211 || 0), 0) / channelUtil.length
            });

            const avgUtil = channelUtil.reduce((sum, c) => sum + (c.utilization80211 || 0), 0) / channelUtil.length;
            if (avgUtil > 70) {
              evidence.summary.warnings++;
              evidence.timeline.push({
                time: collectionStart,
                type: "rf",
                severity: avgUtil > 85 ? "high" : "medium",
                message: `High channel utilization: ${Math.round(avgUtil)}% on ${network.name}`,
                network: network.name
              });
            }
          }
        } catch (e) {
          // May not have wireless
        }

        try {
          // Connection stats
          const connStats = await merakiFetch(`/networks/${network.id}/wireless/connectionStats?timespan=${timespan}`);
          if (connStats) {
            evidence.data.rfSnapshot.connectionStats.push({
              networkId: network.id,
              networkName: network.name,
              ...connStats
            });

            // Check for high failure rates
            if (connStats.assoc > 10 && connStats.authFail > 0) {
              const failRate = (connStats.authFail / connStats.assoc) * 100;
              if (failRate > 5) {
                evidence.summary.warnings++;
                evidence.timeline.push({
                  time: collectionStart,
                  type: "rf",
                  severity: failRate > 15 ? "high" : "medium",
                  message: `Auth failure rate ${failRate.toFixed(1)}% on ${network.name}`,
                  network: network.name
                });
              }
            }
          }
        } catch (e) {
          // May fail
        }

        // Client signal quality (if specific client)
        if (clientMac) {
          try {
            const clients = await merakiFetch(`/networks/${network.id}/clients?timespan=${timespan}&perPage=500`);
            const targetClient = (clients || []).find(c => c.mac === clientMac);
            if (targetClient) {
              evidence.data.rfSnapshot.clientSignalQuality.push({
                networkId: network.id,
                networkName: network.name,
                client: targetClient
              });
            }
          } catch (e) {
            // May fail
          }
        }
      }
    }

    // 6. Security Events
    if (includeSecurityEvents) {
      evidence.data.securityEvents = [];
      for (const network of targetNetworks) {
        try {
          // IDS/IPS events
          const secEvents = await merakiFetch(`/networks/${network.id}/events?perPage=200&productType=appliance&includedEventTypes[]=ids_alerted&includedEventTypes[]=ids_blocked&timespan=${timespan}`);
          if (secEvents && secEvents.events) {
            for (const event of secEvents.events) {
              evidence.data.securityEvents.push({
                occurredAt: event.occurredAt,
                networkId: network.id,
                networkName: network.name,
                type: event.type,
                description: event.description,
                eventData: event.eventData,
                category: "ids"
              });
              evidence.summary.totalEvents++;
              evidence.summary.criticalFindings++;

              evidence.timeline.push({
                time: event.occurredAt,
                type: "security",
                severity: "critical",
                message: `Security: ${event.type} - ${event.description}`,
                network: network.name
              });
            }
          }
        } catch (e) {
          // May not have appliance
        }

        try {
          // Rogue AP detection
          const rogueEvents = await merakiFetch(`/networks/${network.id}/events?perPage=100&productType=wireless&includedEventTypes[]=rogue_ap&timespan=${timespan}`);
          if (rogueEvents && rogueEvents.events) {
            for (const event of rogueEvents.events) {
              evidence.data.securityEvents.push({
                occurredAt: event.occurredAt,
                networkId: network.id,
                networkName: network.name,
                type: event.type,
                description: event.description,
                eventData: event.eventData,
                category: "rogue_ap"
              });
              evidence.summary.totalEvents++;
              evidence.summary.warnings++;
            }
          }
        } catch (e) {
          // May fail
        }
      }
    }

    // 7. Configuration Snapshot
    if (includeConfigSnapshot) {
      evidence.data.configSnapshot = {
        ssids: [],
        vlans: [],
        firewallRules: []
      };

      for (const network of targetNetworks) {
        try {
          const ssids = await merakiFetch(`/networks/${network.id}/wireless/ssids`);
          if (ssids) {
            evidence.data.configSnapshot.ssids.push({
              networkId: network.id,
              networkName: network.name,
              ssids: ssids.map(s => ({
                number: s.number,
                name: s.name,
                enabled: s.enabled,
                authMode: s.authMode,
                encryptionMode: s.encryptionMode,
                bandSelection: s.bandSelection,
                visible: s.visible
              }))
            });
          }
        } catch (e) {
          // May not have wireless
        }

        try {
          const vlans = await merakiFetch(`/networks/${network.id}/appliance/vlans`);
          if (vlans) {
            evidence.data.configSnapshot.vlans.push({
              networkId: network.id,
              networkName: network.name,
              vlans: vlans.map(v => ({
                id: v.id,
                name: v.name,
                subnet: v.subnet,
                applianceIp: v.applianceIp,
                dhcpHandling: v.dhcpHandling
              }))
            });
          }
        } catch (e) {
          // May not have appliance or VLANs enabled
        }
      }
    }

    // 8. Packet Capture Info (placeholder - actual capture requires device-level API)
    if (includePacketCapture) {
      evidence.data.packetCaptureInfo = {
        status: "available",
        note: "Packet capture requires device-level access. Use Meraki Dashboard or API to initiate capture.",
        targetDevices: evidence.data.deviceStatus.filter(d =>
          d.model && (d.model.startsWith("MR") || d.model.startsWith("MS") || d.model.startsWith("MX"))
        ).map(d => ({ serial: d.serial, name: d.name, model: d.model }))
      };
    }

    // Sort timeline by time (newest first)
    evidence.timeline.sort((a, b) => new Date(b.time) - new Date(a.time));

    // Complete collection
    evidence.collectionEnd = new Date().toISOString();
    evidence.collectionDuration = `${((new Date(evidence.collectionEnd) - new Date(evidence.collectionStart)) / 1000).toFixed(1)}s`;

    // Generate SIEM-compatible format
    evidence.siemFormat = {
      eventType: "network_evidence_collection",
      collectionId: evidence.collectionId,
      timestamp: evidence.collectionStart,
      triggerType: evidence.triggerType,
      anomalyDetails: evidence.anomalyDetails,
      summary: evidence.summary,
      criticalEvents: evidence.timeline.filter(t => t.severity === "critical"),
      affectedNetworks: targetNetworks.map(n => n.name),
      affectedDevices: evidence.data.deviceStatus.filter(d => d.status !== "online").map(d => d.serial)
    };

    res.json(evidence);

  } catch (err) {
    console.error("Evidence collection error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Get list of devices for evidence collection targeting
app.get("/api/evidence/devices", async (req, res) => {
  try {
    const orgs = await merakiFetch("/organizations");
    const devices = [];

    for (const org of orgs) {
      try {
        const statuses = await merakiFetch(`/organizations/${org.id}/devices/statuses?perPage=1000`);
        for (const device of (statuses || [])) {
          devices.push({
            serial: device.serial,
            name: device.name || device.mac,
            model: device.model,
            status: device.status,
            networkId: device.networkId,
            org: org.name,
            type: (device.model || "").startsWith("MR") || (device.model || "").startsWith("CW") ? "AP" :
                  (device.model || "").startsWith("MS") ? "Switch" :
                  (device.model || "").startsWith("MX") || (device.model || "").startsWith("Z") ? "Appliance" : "Other"
          });
        }
      } catch (e) {
        console.warn(`Failed to get devices for org ${org.name}:`, e.message);
      }
    }

    res.json(devices);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Anomaly detection trigger - checks for anomalies and auto-collects evidence
app.get("/api/evidence/anomaly-check", async (req, res) => {
  try {
    const anomalies = [];
    const orgs = await merakiFetch("/organizations");

    for (const org of orgs) {
      try {
        // Check device statuses for anomalies
        const statuses = await merakiFetch(`/organizations/${org.id}/devices/statuses?perPage=1000`);
        const alertingDevices = (statuses || []).filter(d => d.status === "alerting");
        const offlineDevices = (statuses || []).filter(d => d.status === "offline");

        if (alertingDevices.length > 0) {
          anomalies.push({
            type: "devices_alerting",
            severity: "high",
            org: org.name,
            count: alertingDevices.length,
            devices: alertingDevices.slice(0, 5).map(d => ({ serial: d.serial, name: d.name })),
            recommendation: "Collect evidence for alerting devices"
          });
        }

        if (offlineDevices.length > 3) {
          anomalies.push({
            type: "multiple_devices_offline",
            severity: "critical",
            org: org.name,
            count: offlineDevices.length,
            devices: offlineDevices.slice(0, 5).map(d => ({ serial: d.serial, name: d.name })),
            recommendation: "Possible network outage - collect evidence immediately"
          });
        }
      } catch (e) {
        console.warn(`Anomaly check failed for org ${org.name}:`, e.message);
      }

      // Check for high event rates (indicates issues)
      try {
        const networks = await merakiFetch(`/organizations/${org.id}/networks?perPage=100`);
        for (const network of (networks || []).slice(0, 3)) {
          try {
            const events = await merakiFetch(`/networks/${network.id}/events?perPage=100&productType=wireless&timespan=1800`);
            if (events && events.events) {
              const failEvents = events.events.filter(e =>
                e.type.includes("fail") || e.type.includes("deauth") || e.type.includes("timeout")
              );
              if (failEvents.length > 20) {
                anomalies.push({
                  type: "high_failure_rate",
                  severity: "high",
                  org: org.name,
                  network: network.name,
                  networkId: network.id,
                  count: failEvents.length,
                  recommendation: "High auth/connection failure rate detected"
                });
              }
            }
          } catch (e) {
            // May fail for some network types
          }
        }
      } catch (e) {
        // May fail
      }
    }

    res.json({
      timestamp: new Date().toISOString(),
      anomaliesDetected: anomalies.length > 0,
      anomalyCount: anomalies.length,
      anomalies,
      autoCollectRecommended: anomalies.some(a => a.severity === "critical")
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
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
  <style>
    :root {
      --background: #0d1117;
      --background-sidebar: #161b22;
      --foreground: rgba(255, 255, 255, 0.87);
      --foreground-muted: rgba(255, 255, 255, 0.60);
      --primary: #8b5cf6;
      --primary-hover: #a78bfa;
      --secondary: #03DAC5;
      --destructive: #f87171;
      --success: #4ade80;
      --warning: #fbbf24;
      --border: rgba(255, 255, 255, 0.08);
      --surface-1dp: rgba(255, 255, 255, 0.03);
      --surface-2dp: rgba(255, 255, 255, 0.05);
      --surface-4dp: rgba(255, 255, 255, 0.07);
      --font-sans: 'Roboto', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'Roboto Mono', 'SF Mono', Monaco, monospace;
      --sidebar-width: 220px;
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
      display: flex;
      min-height: 100vh;
    }
    /* Sidebar */
    .sidebar {
      width: var(--sidebar-width);
      background: var(--background-sidebar);
      border-right: 1px solid var(--border);
      position: fixed;
      top: 0;
      left: 0;
      height: 100vh;
      overflow-y: auto;
      z-index: 100;
      display: flex;
      flex-direction: column;
    }
    .sidebar-header {
      padding: 16px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .sidebar-logo {
      width: 32px;
      height: 32px;
      background: linear-gradient(135deg, var(--primary), #6366f1);
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 14px;
      color: white;
    }
    .sidebar-brand {
      font-size: 13px;
      font-weight: 600;
      color: var(--foreground);
    }
    .sidebar-nav {
      flex: 1;
      padding: 12px 8px;
    }
    .nav-section {
      margin-bottom: 8px;
    }
    .nav-section-title {
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: rgba(255,255,255,0.4);
      padding: 8px 12px 4px;
    }
    .nav-item {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 12px;
      border-radius: 6px;
      color: var(--foreground-muted);
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
      border: none;
      background: transparent;
      width: 100%;
      text-align: left;
    }
    .nav-item:hover {
      background: rgba(255,255,255,0.05);
      color: var(--foreground);
    }
    .nav-item.active {
      background: linear-gradient(135deg, rgba(139,92,246,0.2), rgba(99,102,241,0.1));
      color: var(--primary);
      border-left: 3px solid var(--primary);
      margin-left: -3px;
    }
    .nav-item svg {
      width: 18px;
      height: 18px;
      flex-shrink: 0;
    }
    .sidebar-footer {
      padding: 12px 16px;
      border-top: 1px solid var(--border);
      font-size: 11px;
      color: rgba(255,255,255,0.4);
    }
    /* Main Content */
    .main-content {
      margin-left: var(--sidebar-width);
      flex: 1;
      min-height: 100vh;
    }
    .page-header {
      padding: 20px 32px;
      border-bottom: 1px solid var(--border);
      background: var(--background-sidebar);
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 50;
    }
    .page-title {
      font-size: 20px;
      font-weight: 600;
      color: var(--foreground);
      margin: 0;
    }
    .page-subtitle {
      font-size: 13px;
      color: var(--foreground-muted);
      margin-top: 4px;
    }
    .header-actions {
      display: flex;
      gap: 12px;
      align-items: center;
    }
    .header-btn {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 8px 14px;
      background: transparent;
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--foreground-muted);
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .header-btn:hover {
      background: rgba(255,255,255,0.05);
      color: var(--foreground);
      border-color: rgba(255,255,255,0.2);
    }
    .header-btn.primary {
      background: var(--primary);
      border-color: var(--primary);
      color: white;
    }
    .header-btn.primary:hover {
      background: var(--primary-hover);
    }
    .page-content {
      padding: 24px 32px;
    }
    /* Stat Cards */
    .stat-cards {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--background-sidebar);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 20px;
    }
    .stat-card-label {
      font-size: 12px;
      color: var(--foreground-muted);
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .stat-card-value {
      font-size: 28px;
      font-weight: 600;
      color: var(--foreground);
    }
    .stat-card-sub {
      font-size: 12px;
      color: var(--foreground-muted);
      margin-top: 4px;
    }
    .stat-online { color: var(--success); }
    .stat-offline { color: var(--destructive); }
    /* Data Table */
    .data-table-container {
      background: var(--background-sidebar);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
    }
    .data-table-header {
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .data-table-title {
      font-size: 14px;
      font-weight: 600;
      color: var(--foreground);
    }
    .data-table-subtitle {
      font-size: 12px;
      color: var(--foreground-muted);
      margin-top: 2px;
    }
    .search-box {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      background: rgba(255,255,255,0.05);
      border: 1px solid var(--border);
      border-radius: 6px;
      min-width: 280px;
    }
    .search-box input {
      border: none;
      background: transparent;
      color: var(--foreground);
      font-size: 13px;
      outline: none;
      width: 100%;
    }
    .search-box input::placeholder {
      color: rgba(255,255,255,0.4);
    }
    .data-table {
      width: 100%;
      border-collapse: collapse;
    }
    .data-table th {
      text-align: left;
      padding: 12px 16px;
      font-size: 12px;
      font-weight: 600;
      color: var(--foreground-muted);
      border-bottom: 1px solid var(--border);
      background: rgba(255,255,255,0.02);
    }
    .data-table td {
      padding: 14px 16px;
      font-size: 13px;
      color: var(--foreground);
      border-bottom: 1px solid var(--border);
    }
    .data-table tr:hover {
      background: rgba(255,255,255,0.02);
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 500;
    }
    .status-badge.online {
      background: rgba(74,222,128,0.15);
      color: var(--success);
    }
    .status-badge.offline {
      background: rgba(248,113,113,0.15);
      color: var(--destructive);
    }
    .status-badge.alerting {
      background: rgba(251,191,36,0.15);
      color: var(--warning);
    }
    .client-count {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 4px 10px;
      background: rgba(139,92,246,0.15);
      border-radius: 12px;
      font-size: 11px;
      font-weight: 500;
      color: var(--primary);
    }
    /* View panels */
    .view-panel {
      display: none;
    }
    .view-panel.active {
      display: block;
    }
    /* Legacy wrap for embedded content */
    .wrap { max-width: 100%; margin: 0; padding: 0; }
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
    .grid-2 { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
    .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
    @media (max-width: 1000px) { .grid-3 { grid-template-columns: repeat(2, 1fr); } }
    @media (max-width: 700px) { .grid-2, .grid-3 { grid-template-columns: 1fr; } }
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
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    .rca-example:hover {
      filter: brightness(1.2);
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
  <!-- Sidebar Navigation -->
  <nav class="sidebar">
    <div class="sidebar-header">
      <div class="sidebar-logo">E</div>
      <div class="sidebar-brand">MCP Exchange</div>
    </div>
    <div class="sidebar-nav">
      <div class="nav-section">
        <button class="nav-item active" onclick="showView('dashboard')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
          Dashboard
        </button>
      </div>
      <div class="nav-section">
        <div class="nav-section-title">Monitoring</div>
        <button class="nav-item" onclick="showView('devices')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>
          Access Points
        </button>
        <button class="nav-item" onclick="showView('clients')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          Connected Clients
        </button>
        <button class="nav-item" onclick="showView('switches')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
          Switches
        </button>
        <button class="nav-item" onclick="showView('topology')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="5" r="3"/><circle cx="5" cy="19" r="3"/><circle cx="19" cy="19" r="3"/><line x1="12" y1="8" x2="5" y2="16"/><line x1="12" y1="8" x2="19" y2="16"/></svg>
          Topology Map
        </button>
      </div>
      <div class="nav-section">
        <div class="nav-section-title">AI Intelligence</div>
        <button class="nav-item" onclick="showView('rca')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          Root Cause Analysis
        </button>
        <button class="nav-item" onclick="showView('intelligence')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a10 10 0 1 0 10 10H12V2z"/><path d="M12 2a10 10 0 0 1 10 10"/></svg>
          Network Intelligence
        </button>
        <button class="nav-item" onclick="showView('predictive')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          Predictive Alerts
        </button>
        <button class="nav-item" onclick="showView('change-risk')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
          Change Risk
        </button>
        <button class="nav-item" onclick="showView('evidence')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
          Evidence Collection
        </button>
      </div>
      <div class="nav-section">
        <div class="nav-section-title">Events</div>
        <button class="nav-item" onclick="showView('events')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          Network Events
        </button>
        <button class="nav-item" onclick="showView('roaming')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>
          Client Roaming
        </button>
      </div>
      <div class="nav-section">
        <div class="nav-section-title">XIQ</div>
        <button class="nav-item" onclick="showView('xiq')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
          ExtremeCloud IQ
        </button>
      </div>
    </div>
    <div class="sidebar-footer">
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
        <span style="width:8px;height:8px;background:var(--success);border-radius:50%"></span>
        <span style="color:var(--success)">Service Active</span>
      </div>
      <div>Route: ${PROXY_ROUTE}</div>
    </div>
  </nav>

  <!-- Main Content Area -->
  <main class="main-content">
    <!-- Dashboard View -->
    <div id="view-dashboard" class="view-panel active">
      <div class="page-header">
        <div>
          <h1 class="page-title">Dashboard</h1>
          <div class="page-subtitle">Network overview and quick stats</div>
        </div>
        <div class="header-actions">
          <button class="header-btn" onclick="loadDashboardData()">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
            Refresh
          </button>
        </div>
      </div>
      <div class="page-content">
        <div class="stat-cards" id="dashboard-stats">
          <div class="stat-card">
            <div class="stat-card-label">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>
              Total Devices
            </div>
            <div class="stat-card-value" id="stat-total-devices">--</div>
            <div class="stat-card-sub">Managed devices</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-label">Device Status</div>
            <div class="stat-card-value"><span class="stat-online" id="stat-online">--</span> <span style="font-size:14px;color:var(--foreground-muted)">online</span></div>
            <div class="stat-card-sub"><span class="stat-offline" id="stat-offline">--</span> offline</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-label">Total Clients</div>
            <div class="stat-card-value" id="stat-clients">--</div>
            <div class="stat-card-sub">Connected devices</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-label">Organizations</div>
            <div class="stat-card-value" id="stat-orgs">--</div>
            <div class="stat-card-sub" id="orgs-container">Loading...</div>
          </div>
        </div>

        <!-- Quick Access Cards -->
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px">
          <div class="data-table-container" style="padding:20px;cursor:pointer" onclick="showView('rca')">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
              <div style="width:40px;height:40px;background:linear-gradient(135deg,var(--primary),#6366f1);border-radius:8px;display:flex;align-items:center;justify-content:center">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
              </div>
              <div>
                <div style="font-weight:600;color:var(--foreground)">AI Root Cause Analysis</div>
                <div style="font-size:12px;color:var(--foreground-muted)">Ask questions about network issues</div>
              </div>
            </div>
          </div>
          <div class="data-table-container" style="padding:20px;cursor:pointer" onclick="showView('intelligence')">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
              <div style="width:40px;height:40px;background:linear-gradient(135deg,#8b5cf6,#a855f7);border-radius:8px;display:flex;align-items:center;justify-content:center">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M12 2a10 10 0 1 0 10 10H12V2z"/></svg>
              </div>
              <div>
                <div style="font-weight:600;color:var(--foreground)">Network Intelligence</div>
                <div style="font-size:12px;color:var(--foreground-muted)">Roaming, telemetry, health radar</div>
              </div>
            </div>
          </div>
          <div class="data-table-container" style="padding:20px;cursor:pointer" onclick="showView('predictive')">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
              <div style="width:40px;height:40px;background:linear-gradient(135deg,#f97316,#ef4444);border-radius:8px;display:flex;align-items:center;justify-content:center">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/></svg>
              </div>
              <div>
                <div style="font-weight:600;color:var(--foreground)">Predictive Alerts</div>
                <div style="font-size:12px;color:var(--foreground-muted)">Failure detection & forecasting</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Devices View -->
    <div id="view-devices" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">Access Points</h1>
          <div class="page-subtitle">Configure and monitor access points across your network infrastructure</div>
        </div>
        <div class="header-actions">
          <button class="header-btn" onclick="loadDevicesView()">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
            Refresh APs
          </button>
        </div>
      </div>
      <div class="page-content">
        <div class="stat-cards" id="ap-stats">
          <div class="stat-card">
            <div class="stat-card-label">Total Access Points</div>
            <div class="stat-card-value" id="ap-total">--</div>
            <div class="stat-card-sub">Managed devices</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-label">AP Status</div>
            <div class="stat-card-value"><span class="stat-online" id="ap-online">--</span></div>
            <div class="stat-card-sub"><span class="stat-offline" id="ap-offline">--</span> offline</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-label">Total Clients</div>
            <div class="stat-card-value" id="ap-clients">--</div>
            <div class="stat-card-sub">Connected devices</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-label">Hardware Types</div>
            <div class="stat-card-value" id="ap-models">--</div>
            <div class="stat-card-sub">Different models</div>
          </div>
        </div>

        <div class="data-table-container">
          <div class="data-table-header">
            <div>
              <div class="data-table-title">Access Points</div>
              <div class="data-table-subtitle">Click any access point to view detailed information</div>
            </div>
            <div class="search-box">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
              <input type="text" placeholder="Search by name, model, IP, or site..." id="ap-search" onkeyup="filterAPTable()"/>
            </div>
          </div>
          <table class="data-table" id="ap-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>AP Name</th>
                <th>Serial Number</th>
                <th>Network</th>
                <th>Model</th>
                <th>IP Address</th>
                <th>Clients</th>
              </tr>
            </thead>
            <tbody id="ap-table-body">
              <tr><td colspan="7" style="text-align:center;padding:40px;color:var(--foreground-muted)">Click "Refresh APs" to load data</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- RCA View (keeping original content) -->
    <div id="view-rca" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">AI Root Cause Analysis</h1>
          <div class="page-subtitle">Ask natural language questions about network issues</div>
        </div>
      </div>
      <div class="page-content">
        <div class="wrap">

    <div class="card" style="border-left:3px solid var(--primary);background:linear-gradient(135deg,rgba(187,134,252,0.05),rgba(3,218,197,0.05))">
      <div class="section-title">
        <span class="icon" style="color:var(--primary)"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></span>
        <h2>AI Root Cause Analysis</h2>
        <span style="margin-left:auto;padding:4px 10px;background:linear-gradient(135deg,var(--primary),var(--secondary));border-radius:12px;font-size:10px;font-weight:600;color:rgba(0,0,0,0.87);text-transform:uppercase">AI Powered</span>
      </div>
      <div class="muted">Ask natural language questions about network issues</div>

      <div style="margin-top:16px">
        <div style="display:flex;gap:8px">
          <input type="text" id="rca-question" placeholder="Why is Zoom failing on floor 3?" style="flex:1;padding:12px 16px;background:linear-gradient(rgba(255,255,255,0.07),rgba(255,255,255,0.07)),#121212;border:1px solid rgba(187,134,252,0.3);border-radius:8px;color:rgba(255,255,255,0.87);font-family:var(--font-sans);font-size:14px;outline:none;" />
          <button onclick="analyzeRca()" id="rca-button" style="padding:12px 20px;background:linear-gradient(135deg,var(--primary),#9966CC);border:none;border-radius:8px;color:rgba(0,0,0,0.87);font-weight:600;cursor:pointer;display:flex;align-items:center;gap:8px;white-space:nowrap">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
            Analyze
          </button>
        </div>

        <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
          <button onclick="setRcaQuestion('Why is Zoom failing on floor 3?')" class="rca-example" style="padding:6px 12px;background:rgba(187,134,252,0.15);border:1px solid rgba(187,134,252,0.3);border-radius:16px;color:var(--primary);font-size:12px;cursor:pointer">Why is Zoom failing on floor 3?</button>
          <button onclick="setRcaQuestion('What is causing slow WiFi in the building?')" class="rca-example" style="padding:6px 12px;background:rgba(3,218,197,0.15);border:1px solid rgba(3,218,197,0.3);border-radius:16px;color:var(--secondary);font-size:12px;cursor:pointer">What is causing slow WiFi?</button>
          <button onclick="setRcaQuestion('Why are clients disconnecting frequently?')" class="rca-example" style="padding:6px 12px;background:rgba(255,183,77,0.15);border:1px solid rgba(255,183,77,0.3);border-radius:16px;color:#FFB74D;font-size:12px;cursor:pointer">Why are clients disconnecting?</button>
          <button onclick="setRcaQuestion('Teams calls are dropping today')" class="rca-example" style="padding:6px 12px;background:rgba(255,107,53,0.15);border:1px solid rgba(255,107,53,0.3);border-radius:16px;color:#FF6B35;font-size:12px;cursor:pointer">Teams calls dropping</button>
        </div>
      </div>

      <div id="rca-results" style="margin-top:20px;display:none">
        <div id="rca-loading" style="display:none;padding:40px;text-align:center">
          <div style="width:40px;height:40px;border:3px solid rgba(187,134,252,0.3);border-top-color:var(--primary);border-radius:50%;animation:spin 1s linear infinite;margin:0 auto"></div>
          <div style="margin-top:12px;color:var(--foreground-muted)">Analyzing network data...</div>
        </div>

        <div id="rca-content" style="display:none">
          <div id="rca-summary" style="padding:16px;background:rgba(255,255,255,0.05);border-radius:8px;border-left:3px solid var(--primary);margin-bottom:16px">
          </div>

          <div id="rca-confidence" style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
            <span style="font-size:12px;color:rgba(255,255,255,0.6)">Confidence:</span>
            <div style="flex:1;height:8px;background:rgba(255,255,255,0.1);border-radius:4px;overflow:hidden">
              <div id="rca-confidence-bar" style="height:100%;background:linear-gradient(90deg,var(--primary),var(--secondary));border-radius:4px;transition:width 0.5s"></div>
            </div>
            <span id="rca-confidence-value" style="font-size:12px;font-weight:600;color:var(--primary)">0%</span>
          </div>

          <div id="rca-findings" style="margin-bottom:16px">
          </div>

          <div id="rca-recommendations" style="margin-bottom:16px">
          </div>

          <div id="rca-metrics" style="display:flex;gap:12px;flex-wrap:wrap">
          </div>
        </div>
      </div>
    </div>

    <div class="card" style="border-left:3px solid #9C27B0;background:linear-gradient(135deg,rgba(156,39,176,0.05),rgba(103,58,183,0.05))">
      <div class="section-title">
        <span class="icon" style="color:#9C27B0"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a10 10 0 1 0 10 10H12V2z"/><path d="M12 2a10 10 0 0 1 10 10"/><path d="M12 12l8.5-8.5"/></svg></span>
        <h2>AI Network Intelligence</h2>
        <span style="margin-left:auto;padding:4px 10px;background:linear-gradient(135deg,#9C27B0,#673AB7);border-radius:12px;font-size:10px;font-weight:600;color:rgba(255,255,255,0.95);text-transform:uppercase">AI-Powered</span>
      </div>
      <div class="muted">Roaming optimization, switch telemetry, health insights, and predictive failure detection</div>

      <!-- Tab Navigation -->
      <div id="ai-analysis-tabs" style="display:flex;gap:8px;margin-top:16px;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:12px">
        <button onclick="switchAnalysisTab('roaming')" id="tab-roaming" class="ai-tab active" style="padding:10px 20px;background:linear-gradient(135deg,#00BCD4,#00ACC1);border:none;border-radius:8px;color:rgba(0,0,0,0.87);font-weight:600;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:13px">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49"/></svg>
          Roaming
        </button>
        <button onclick="switchAnalysisTab('telemetry')" id="tab-telemetry" class="ai-tab" style="padding:10px 20px;background:rgba(33,150,243,0.15);border:1px solid rgba(33,150,243,0.3);border-radius:8px;color:#2196F3;font-weight:500;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:13px">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
          Telemetry
        </button>
        <button onclick="switchAnalysisTab('radar')" id="tab-radar" class="ai-tab" style="padding:10px 20px;background:rgba(76,175,80,0.15);border:1px solid rgba(76,175,80,0.3);border-radius:8px;color:#4CAF50;font-weight:500;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:13px">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
          Health Radar
        </button>
        <button onclick="switchAnalysisTab('predictive')" id="tab-predictive" class="ai-tab" style="padding:10px 20px;background:rgba(255,87,34,0.15);border:1px solid rgba(255,87,34,0.3);border-radius:8px;color:#FF5722;font-weight:500;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:13px">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          Predictive
        </button>
      </div>

      <!-- Roaming Tab Content -->
      <div id="panel-roaming" class="ai-panel" style="margin-top:20px">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:16px">
          <div>
            <div style="font-size:16px;font-weight:600;color:rgba(255,255,255,0.87)">Roaming Path Tracking</div>
            <div style="font-size:12px;color:rgba(255,255,255,0.5)">Track client movement, detect failures, identify sticky clients</div>
          </div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <div id="roaming-timespan-selector" style="display:flex;gap:4px">
              <button onclick="setRoamingTimespan(3600)" data-timespan="3600" style="padding:4px 10px;font-size:11px;border:1px solid rgba(255,255,255,0.12);border-radius:6px;background:transparent;color:rgba(255,255,255,0.6);cursor:pointer;font-family:var(--font-sans)">1h</button>
              <button onclick="setRoamingTimespan(86400)" data-timespan="86400" style="padding:4px 10px;font-size:11px;border:1px solid rgba(255,255,255,0.2);border-radius:6px;background:rgba(0,188,212,0.2);color:#00BCD4;cursor:pointer;font-family:var(--font-sans)">24h</button>
              <button onclick="setRoamingTimespan(604800)" data-timespan="604800" style="padding:4px 10px;font-size:11px;border:1px solid rgba(255,255,255,0.12);border-radius:6px;background:transparent;color:rgba(255,255,255,0.6);cursor:pointer;font-family:var(--font-sans)">7d</button>
            </div>
            <button onclick="runRoamingAnalysis()" id="roaming-button" style="padding:10px 20px;background:linear-gradient(135deg,#00BCD4,#009688);border:none;border-radius:8px;color:rgba(0,0,0,0.87);font-weight:600;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:13px">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49"/></svg>
              Analyze
            </button>
          </div>
        </div>

        <div id="roaming-results" style="display:none">
          <div id="roaming-loading" style="display:none;padding:40px;text-align:center">
            <div style="width:40px;height:40px;border:3px solid rgba(0,188,212,0.3);border-top-color:#00BCD4;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto"></div>
            <div style="margin-top:12px;color:var(--foreground-muted)">Analyzing client roaming patterns...</div>
          </div>

          <div id="roaming-content" style="display:none">
            <div id="roaming-optimization" style="padding:16px;border-radius:12px;margin-bottom:20px;background:linear-gradient(135deg,rgba(0,188,212,0.2),rgba(0,150,136,0.1))">
              <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px">
                <div>
                  <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,0.6);margin-bottom:4px">Optimization Score</div>
                  <div style="display:flex;align-items:baseline;gap:8px">
                    <span id="roaming-score" style="font-size:40px;font-weight:700;color:#00BCD4">--</span>
                    <span id="roaming-grade" style="font-size:20px;font-weight:600;padding:4px 10px;background:rgba(0,188,212,0.3);border-radius:8px">-</span>
                  </div>
                </div>
                <div id="roaming-summary" style="flex:1;min-width:180px;max-width:350px;font-size:13px;color:rgba(255,255,255,0.7);padding-left:16px;border-left:2px solid rgba(255,255,255,0.1)">--</div>
              </div>
            </div>

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:20px">
              <div style="padding:14px;background:rgba(255,255,255,0.05);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:#00BCD4" id="roaming-metric-clients">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Roaming Clients</div>
              </div>
              <div style="padding:14px;background:rgba(255,255,255,0.05);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:var(--success)" id="roaming-metric-roams">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Total Roams</div>
              </div>
              <div style="padding:14px;background:rgba(255,255,255,0.05);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:var(--destructive)" id="roaming-metric-failures">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Failures</div>
              </div>
              <div style="padding:14px;background:rgba(255,255,255,0.05);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:var(--warning)" id="roaming-metric-sticky">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Sticky Clients</div>
              </div>
            </div>

            <div id="roaming-recommendations" style="margin-bottom:20px"></div>

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px">
              <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:14px">
                <div style="font-weight:600;font-size:13px;color:rgba(255,255,255,0.87);margin-bottom:10px;display:flex;align-items:center;gap:8px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#00BCD4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                  Top Roaming Clients
                </div>
                <div id="roaming-clients-list" style="max-height:200px;overflow-y:auto"><div class="muted">No data</div></div>
              </div>
              <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:14px">
                <div style="font-weight:600;font-size:13px;color:rgba(255,255,255,0.87);margin-bottom:10px;display:flex;align-items:center;gap:8px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--destructive)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                  Roaming Failures
                </div>
                <div id="roaming-failures-list" style="max-height:200px;overflow-y:auto"><div class="muted">No failures</div></div>
              </div>
              <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:14px">
                <div style="font-weight:600;font-size:13px;color:rgba(255,255,255,0.87);margin-bottom:10px;display:flex;align-items:center;gap:8px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--warning)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                  Sticky Clients
                </div>
                <div id="roaming-sticky-list" style="max-height:200px;overflow-y:auto"><div class="muted">No sticky clients</div></div>
              </div>
            </div>

            <div id="roaming-transitions" style="margin-top:16px;background:rgba(255,255,255,0.03);border-radius:8px;padding:14px">
              <div style="font-weight:600;font-size:13px;color:rgba(255,255,255,0.87);margin-bottom:10px;display:flex;align-items:center;gap:8px">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                Top AP Transitions
              </div>
              <div id="roaming-transitions-list" style="display:flex;flex-wrap:wrap;gap:8px"><div class="muted">No data</div></div>
            </div>

            <div id="roaming-insights" style="margin-top:16px"></div>
          </div>
        </div>
      </div>

      <!-- Telemetry Tab Content -->
      <div id="panel-telemetry" class="ai-panel" style="margin-top:20px;display:none">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:16px">
          <div>
            <div style="font-size:16px;font-weight:600;color:rgba(255,255,255,0.87)">Switch Port Telemetry</div>
            <div style="font-size:12px;color:rgba(255,255,255,0.5)">Real-time port status, errors, CRC, drops, PoE across all switches</div>
          </div>
          <button onclick="loadSwitchTelemetry()" id="switch-telemetry-button" style="padding:10px 20px;background:linear-gradient(135deg,#2196F3,#03A9F4);border:none;border-radius:8px;color:rgba(255,255,255,0.95);font-weight:600;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:13px">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
            Load Telemetry
          </button>
        </div>

        <div id="switch-telemetry-results" style="display:none">
          <div id="switch-telemetry-loading" style="display:none;padding:40px;text-align:center">
            <div style="width:40px;height:40px;border:3px solid rgba(33,150,243,0.3);border-top-color:#2196F3;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto"></div>
            <div style="margin-top:12px;color:var(--foreground-muted)">Scanning all switches...</div>
          </div>

          <div id="switch-telemetry-content" style="display:none">
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:10px;margin-bottom:20px">
              <div style="padding:14px;background:rgba(33,150,243,0.1);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:#2196F3" id="telemetry-total-switches">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Switches</div>
              </div>
              <div style="padding:14px;background:rgba(255,255,255,0.05);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:var(--foreground)" id="telemetry-total-ports">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Ports</div>
              </div>
              <div style="padding:14px;background:rgba(207,102,121,0.15);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:var(--destructive)" id="telemetry-errors">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Errors</div>
              </div>
              <div style="padding:14px;background:rgba(255,152,0,0.15);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:#FF9800" id="telemetry-crc">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">CRC</div>
              </div>
              <div style="padding:14px;background:rgba(156,39,176,0.15);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:#9C27B0" id="telemetry-drops">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Drops</div>
              </div>
              <div style="padding:14px;background:rgba(255,183,77,0.15);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:var(--warning)" id="telemetry-poe">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">PoE</div>
              </div>
              <div style="padding:14px;background:rgba(121,85,72,0.15);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:#795548" id="telemetry-negotiation">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Negotiation</div>
              </div>
              <div style="padding:14px;background:rgba(96,125,139,0.15);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:#607D8B" id="telemetry-offline">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Offline</div>
              </div>
            </div>

            <div id="telemetry-issues-container" style="margin-bottom:20px">
              <div style="font-weight:600;font-size:13px;color:rgba(255,255,255,0.87);margin-bottom:10px;display:flex;align-items:center;gap:8px">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--destructive)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                Port Issues
              </div>
              <div id="telemetry-issues-list" style="max-height:250px;overflow-y:auto"><div class="muted">No issues detected</div></div>
            </div>

            <div id="telemetry-switches-container">
              <div style="font-weight:600;font-size:13px;color:rgba(255,255,255,0.87);margin-bottom:10px;display:flex;align-items:center;gap:8px">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2196F3" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                Switches by Organization
              </div>
              <div id="telemetry-switches-list"><div class="muted">No switches found</div></div>
            </div>
          </div>
        </div>
      </div>

      <!-- Health Radar Tab Content -->
      <div id="panel-radar" class="ai-panel" style="margin-top:20px;display:none">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:16px">
          <div>
            <div style="font-size:16px;font-weight:600;color:rgba(255,255,255,0.87)">Live Network Health Radar</div>
            <div style="font-size:12px;color:rgba(255,255,255,0.5)">Per-network health scores across Wi-Fi, WAN, Switching, and Availability</div>
          </div>
          <div style="display:flex;gap:8px;align-items:center">
            <select id="radar-network-select" style="padding:8px 12px;background:#0b1220;color:#e8eefc;border:1px solid rgba(76,175,80,0.3);border-radius:8px;font-size:13px;min-width:200px">
              <option value="">Select Network...</option>
            </select>
            <button onclick="runHealthRadar()" id="radar-button" style="padding:10px 20px;background:linear-gradient(135deg,#4CAF50,#8BC34A);border:none;border-radius:8px;color:rgba(0,0,0,0.87);font-weight:600;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:13px">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
              Analyze
            </button>
          </div>
        </div>

        <div id="radar-results" style="display:none">
          <div id="radar-loading" style="display:none;padding:40px;text-align:center">
            <div style="width:40px;height:40px;border:3px solid rgba(76,175,80,0.3);border-top-color:#4CAF50;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto"></div>
            <div style="margin-top:12px;color:var(--foreground-muted)">Analyzing network health...</div>
          </div>

          <div id="radar-content" style="display:none">
            <div style="display:flex;gap:20px;flex-wrap:wrap">
              <!-- Radar Chart -->
              <div style="flex:1;min-width:320px;max-width:480px">
                <div style="padding:20px;background:rgba(255,255,255,0.03);border-radius:12px;border:1px solid rgba(76,175,80,0.2)">
                  <canvas id="health-radar-chart" style="width:100%;height:300px"></canvas>
                </div>
                <div style="margin-top:12px;text-align:center">
                  <div style="font-size:11px;color:rgba(255,255,255,0.5)">Network: <span id="radar-network-name" style="color:#4CAF50">—</span></div>
                  <div style="font-size:10px;color:rgba(255,255,255,0.4);margin-top:4px">Updated: <span id="radar-timestamp">—</span></div>
                </div>
              </div>

              <!-- KPIs and Details -->
              <div style="flex:1;min-width:280px">
                <!-- Overall Score -->
                <div style="padding:20px;background:linear-gradient(135deg,rgba(76,175,80,0.15),rgba(139,195,74,0.1));border-radius:12px;border:1px solid rgba(76,175,80,0.3);text-align:center;margin-bottom:16px">
                  <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,0.6)">Overall Health Score</div>
                  <div id="radar-overall-score" style="font-size:48px;font-weight:700;color:#4CAF50;margin:8px 0">—</div>
                  <div id="radar-overall-grade" style="display:inline-block;padding:4px 12px;border-radius:12px;font-size:12px;font-weight:600;background:rgba(76,175,80,0.3);color:#4CAF50">—</div>
                </div>

                <!-- Individual Scores -->
                <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:16px">
                  <div style="padding:14px;background:rgba(255,255,255,0.05);border-radius:10px;border-left:3px solid #00BCD4">
                    <div style="font-size:11px;color:rgba(255,255,255,0.5)">Wi-Fi Health</div>
                    <div id="radar-score-wifi" style="font-size:24px;font-weight:700;color:#00BCD4;margin-top:4px">—</div>
                  </div>
                  <div style="padding:14px;background:rgba(255,255,255,0.05);border-radius:10px;border-left:3px solid #FF6B35">
                    <div style="font-size:11px;color:rgba(255,255,255,0.5)">WAN Health</div>
                    <div id="radar-score-wan" style="font-size:24px;font-weight:700;color:#FF6B35;margin-top:4px">—</div>
                  </div>
                  <div style="padding:14px;background:rgba(255,255,255,0.05);border-radius:10px;border-left:3px solid #2196F3">
                    <div style="font-size:11px;color:rgba(255,255,255,0.5)">Switching</div>
                    <div id="radar-score-switching" style="font-size:24px;font-weight:700;color:#2196F3;margin-top:4px">—</div>
                  </div>
                  <div style="padding:14px;background:rgba(255,255,255,0.05);border-radius:10px;border-left:3px solid #9C27B0">
                    <div style="font-size:11px;color:rgba(255,255,255,0.5)">Availability</div>
                    <div id="radar-score-availability" style="font-size:24px;font-weight:700;color:#9C27B0;margin-top:4px">—</div>
                  </div>
                </div>

                <!-- Device Counts -->
                <div style="padding:12px;background:rgba(255,255,255,0.03);border-radius:8px;font-size:12px;color:rgba(255,255,255,0.6)">
                  <div style="font-weight:600;color:rgba(255,255,255,0.8);margin-bottom:8px">Device Counts</div>
                  <div id="radar-device-counts" style="line-height:1.6">—</div>
                </div>

                <!-- KPI Details -->
                <div style="margin-top:12px;padding:12px;background:rgba(255,255,255,0.03);border-radius:8px;font-size:11px;color:rgba(255,255,255,0.5)">
                  <div style="font-weight:600;color:rgba(255,255,255,0.7);margin-bottom:8px">Metrics Detail</div>
                  <div id="radar-kpi-details" style="line-height:1.8">—</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Predictive Failure Detection Tab Content -->
      <div id="panel-predictive" class="ai-panel" style="margin-top:20px;display:none">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:16px">
          <div>
            <div style="font-size:16px;font-weight:600;color:rgba(255,255,255,0.87)">Predictive Failure Detection</div>
            <div style="font-size:12px;color:rgba(255,255,255,0.5)">AI forecasts risk of outage/flapping within 30-120 minutes</div>
          </div>
          <button onclick="runPredictiveAnalysis()" id="predictive-button" style="padding:10px 20px;background:linear-gradient(135deg,#FF5722,#E64A19);border:none;border-radius:8px;color:rgba(255,255,255,0.95);font-weight:600;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:13px">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            Analyze Risks
          </button>
        </div>

        <div id="predictive-results" style="display:none">
          <div id="predictive-loading" style="display:none;padding:40px;text-align:center">
            <div style="width:40px;height:40px;border:3px solid rgba(255,87,34,0.3);border-top-color:#FF5722;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto"></div>
            <div style="margin-top:12px;color:var(--foreground-muted)">Analyzing failure patterns across all devices...</div>
          </div>

          <div id="predictive-content" style="display:none">
            <!-- Risk Score -->
            <div id="predictive-score-container" style="padding:20px;border-radius:12px;margin-bottom:20px;background:linear-gradient(135deg,rgba(255,87,34,0.2),rgba(230,74,25,0.1))">
              <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px">
                <div>
                  <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,0.6);margin-bottom:4px">Risk Score</div>
                  <div style="display:flex;align-items:baseline;gap:8px">
                    <span id="predictive-score" style="font-size:40px;font-weight:700;color:#FF5722">--</span>
                    <span id="predictive-level" style="font-size:16px;font-weight:600;padding:4px 12px;background:rgba(255,87,34,0.3);border-radius:8px;text-transform:uppercase">--</span>
                  </div>
                </div>
                <div id="predictive-summary-text" style="flex:1;min-width:200px;max-width:400px;font-size:13px;color:rgba(255,255,255,0.7);padding-left:16px;border-left:2px solid rgba(255,255,255,0.1)">--</div>
              </div>
            </div>

            <!-- Signal Metrics -->
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:10px;margin-bottom:20px">
              <div style="padding:14px;background:rgba(244,67,54,0.15);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:#F44336" id="predictive-reboots">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Reboots</div>
              </div>
              <div style="padding:14px;background:rgba(255,152,0,0.15);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:#FF9800" id="predictive-bursts">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Event Bursts</div>
              </div>
              <div style="padding:14px;background:rgba(156,39,176,0.15);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:#9C27B0" id="predictive-uplink">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Uplink Issues</div>
              </div>
              <div style="padding:14px;background:rgba(33,150,243,0.15);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:#2196F3" id="predictive-auth">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Auth Failures</div>
              </div>
              <div style="padding:14px;background:rgba(0,188,212,0.15);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:#00BCD4" id="predictive-dhcp">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">DHCP Failures</div>
              </div>
              <div style="padding:14px;background:rgba(76,175,80,0.15);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:#4CAF50" id="predictive-wireless">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Wireless Issues</div>
              </div>
              <div style="padding:14px;background:rgba(96,125,139,0.15);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:#607D8B" id="predictive-offline">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Offline</div>
              </div>
              <div style="padding:14px;background:rgba(255,183,77,0.15);border-radius:8px;text-align:center">
                <div style="font-size:22px;font-weight:700;color:var(--warning)" id="predictive-alerting">--</div>
                <div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px">Alerting</div>
              </div>
            </div>

            <!-- Risk Items -->
            <div id="predictive-risks-container" style="margin-bottom:20px">
              <div style="font-weight:600;font-size:13px;color:rgba(255,255,255,0.87);margin-bottom:10px;display:flex;align-items:center;gap:8px">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#FF5722" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                Predicted Failure Risks
              </div>
              <div id="predictive-risks-list" style="max-height:400px;overflow-y:auto"><div class="muted">No risks detected</div></div>
            </div>

            <!-- Device Type Summary -->
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px">
              <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:14px">
                <div style="font-weight:600;font-size:13px;color:rgba(255,255,255,0.87);margin-bottom:10px;display:flex;align-items:center;gap:8px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#00BCD4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>
                  AP Risks
                </div>
                <div id="predictive-ap-risks" style="font-size:12px;color:rgba(255,255,255,0.6)">--</div>
              </div>
              <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:14px">
                <div style="font-weight:600;font-size:13px;color:rgba(255,255,255,0.87);margin-bottom:10px;display:flex;align-items:center;gap:8px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2196F3" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                  Switch Risks
                </div>
                <div id="predictive-switch-risks" style="font-size:12px;color:rgba(255,255,255,0.6)">--</div>
              </div>
              <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:14px">
                <div style="font-weight:600;font-size:13px;color:rgba(255,255,255,0.87);margin-bottom:10px;display:flex;align-items:center;gap:8px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#FF6B35" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="6" width="20" height="12" rx="2"/><line x1="6" y1="10" x2="6" y2="14"/><line x1="10" y1="10" x2="10" y2="14"/><line x1="14" y1="10" x2="14" y2="14"/><line x1="18" y1="10" x2="18" y2="14"/></svg>
                  MX/Appliance Risks
                </div>
                <div id="predictive-mx-risks" style="font-size:12px;color:rgba(255,255,255,0.6)">--</div>
              </div>
            </div>
          </div>
        </div>
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
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
          <div class="muted">Wireless intrusion alerts</div>
          <div id="wips-timespan-selector" style="display:flex;gap:4px">
            <button onclick="loadFloodEvents(3600)" data-timespan="3600" style="padding:4px 10px;font-size:11px;border:1px solid rgba(255,255,255,0.12);border-radius:6px;background:transparent;color:rgba(255,255,255,0.6);cursor:pointer;font-family:var(--font-sans)">1h</button>
            <button onclick="loadFloodEvents(86400)" data-timespan="86400" style="padding:4px 10px;font-size:11px;border:1px solid rgba(187,134,252,0.3);border-radius:6px;background:rgba(187,134,252,0.2);color:var(--primary);cursor:pointer;font-family:var(--font-sans)">24h</button>
            <button onclick="loadFloodEvents(604800)" data-timespan="604800" style="padding:4px 10px;font-size:11px;border:1px solid rgba(255,255,255,0.12);border-radius:6px;background:transparent;color:rgba(255,255,255,0.6);cursor:pointer;font-family:var(--font-sans)">7d</button>
            <button onclick="loadFloodEvents(2592000)" data-timespan="2592000" style="padding:4px 10px;font-size:11px;border:1px solid rgba(255,255,255,0.12);border-radius:6px;background:transparent;color:rgba(255,255,255,0.6);cursor:pointer;font-family:var(--font-sans)">30d</button>
          </div>
        </div>
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

    <div style="margin:32px 0 24px;padding:20px 24px;background:linear-gradient(135deg,rgba(3,218,197,0.15),rgba(187,134,252,0.15));border:1px solid rgba(3,218,197,0.3);border-radius:12px;display:flex;align-items:center;gap:16px">
      <div style="width:48px;height:48px;background:linear-gradient(135deg,var(--secondary),var(--primary));border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0">
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="rgba(0,0,0,0.87)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>
      </div>
      <div>
        <h2 style="margin:0;font-size:1.25rem;font-weight:600;color:var(--foreground)">ExtremeCloud IQ Insights</h2>
        <div style="font-size:0.875rem;color:var(--foreground-muted);margin-top:4px">Network devices, sites, and client connectivity</div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card" style="margin:0">
        <div class="section-title">
          <span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg></span>
          <h2>ExtremeCloud IQ Devices</h2>
        </div>
        <div class="muted">Connected XIQ devices:</div>
        <div id="xiq-devices-container" style="margin-top:12px">
          <div class="muted">Loading...</div>
        </div>
      </div>

      <div class="card" style="margin:0">
        <div class="section-title">
          <span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="10" r="3"/><path d="M12 21.7C17.3 17 20 13 20 10a8 8 0 1 0-16 0c0 3 2.7 7 8 11.7z"/></svg></span>
          <h2>ExtremeCloud IQ Sites</h2>
        </div>
        <div class="muted">XIQ site locations:</div>
        <div id="xiq-sites-container" style="margin-top:12px">
          <div class="muted">Loading...</div>
        </div>
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
        </div>
      </div>
    </div>

    <!-- Clients View (Placeholder) -->
    <div id="view-clients" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">Connected Clients</h1>
          <div class="page-subtitle">Monitor connected wireless and wired clients</div>
        </div>
      </div>
      <div class="page-content">
        <div style="padding:60px;text-align:center;color:var(--foreground-muted)">
          <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.4;margin-bottom:16px"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          <div style="font-size:16px;margin-bottom:8px">Client monitoring available through RCA</div>
          <div style="font-size:13px">Use the Root Cause Analysis section for client insights</div>
        </div>
      </div>
    </div>

    <!-- Switches View (Placeholder) -->
    <div id="view-switches" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">Switches</h1>
          <div class="page-subtitle">Monitor switch port telemetry and status</div>
        </div>
      </div>
      <div class="page-content">
        <div style="padding:60px;text-align:center;color:var(--foreground-muted)">
          <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.4;margin-bottom:16px"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
          <div style="font-size:16px;margin-bottom:8px">Switch telemetry available in Network Intelligence</div>
          <div style="font-size:13px">Navigate to Network Intelligence > Telemetry tab</div>
        </div>
      </div>
    </div>

    <!-- Topology Map View -->
    <div id="view-topology" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">Network Topology Map</h1>
          <div class="page-subtitle">Visualize device connections and network hierarchy</div>
        </div>
        <div class="header-actions">
          <select id="topology-network-select" style="padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--foreground);margin-right:8px">
            <option value="">All Networks</option>
          </select>
          <label style="display:flex;align-items:center;gap:6px;margin-right:12px;cursor:pointer">
            <input type="checkbox" id="topology-include-clients" style="width:16px;height:16px;accent-color:var(--primary)">
            <span style="font-size:13px;color:var(--foreground-muted)">Show Clients</span>
          </label>
          <button class="header-btn" onclick="resetTopologyLayout()" style="margin-right:8px">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
            Reset Layout
          </button>
          <button id="topology-lock-btn" class="header-btn" onclick="toggleTopologyLock()" style="margin-right:8px">
            <svg id="topology-lock-icon" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2z"/><path d="M17 11V7a5 5 0 0 0-9.58-2"/></svg>
            <span id="topology-lock-text">Unlocked</span>
          </button>
          <button class="header-btn" onclick="loadTopologyMap()">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
            Refresh
          </button>
        </div>
      </div>
      <div class="page-content">
        <div style="background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.3);border-radius:8px;padding:12px 16px;margin-bottom:16px;display:flex;align-items:center;gap:10px">
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2"><path d="M18 11V6a2 2 0 0 0-2-2h-5m-3 3v10a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2v-5"/><path d="m3 3 18 18"/><path d="m9 9 6 6"/></svg>
          <span style="color:#93c5fd;font-size:13px"><strong>Tip:</strong> Drag devices to rearrange the topology. Click "Lock" to prevent accidental moves. Use "Reset Layout" to restore defaults.</span>
        </div>
        <!-- Topology Stats -->
        <div class="stat-cards" id="topology-stats">
          <div class="stat-card">
            <div class="stat-card-label">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="5" r="3"/><circle cx="5" cy="19" r="3"/><circle cx="19" cy="19" r="3"/></svg>
              Total Nodes
            </div>
            <div class="stat-card-value" id="topo-total-nodes">--</div>
            <div class="stat-card-sub">Network devices</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-label">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><polyline points="5 12 12 19 19 12"/></svg>
              Connections
            </div>
            <div class="stat-card-value" id="topo-connections">--</div>
            <div class="stat-card-sub">LLDP/CDP links</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-label">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
              Networks
            </div>
            <div class="stat-card-value" id="topo-networks">--</div>
            <div class="stat-card-sub">Meraki networks</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-label">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
              Online
            </div>
            <div class="stat-card-value" id="topo-online" style="color:var(--success)">--</div>
            <div class="stat-card-sub">Active devices</div>
          </div>
        </div>

        <!-- Topology Legend -->
        <div style="display:flex;gap:24px;margin-bottom:20px;padding:16px;background:var(--surface);border-radius:12px;flex-wrap:wrap">
          <div style="display:flex;align-items:center;gap:8px">
            <div style="width:16px;height:16px;background:linear-gradient(135deg,#6366f1,#8b5cf6);border-radius:4px"></div>
            <span style="font-size:13px;color:var(--foreground-muted)">MX (Appliance)</span>
          </div>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="width:16px;height:16px;background:linear-gradient(135deg,#3b82f6,#0ea5e9);border-radius:4px"></div>
            <span style="font-size:13px;color:var(--foreground-muted)">MS (Switch)</span>
          </div>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="width:16px;height:16px;background:linear-gradient(135deg,#22c55e,#10b981);border-radius:4px"></div>
            <span style="font-size:13px;color:var(--foreground-muted)">MR (Access Point)</span>
          </div>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="width:16px;height:16px;background:linear-gradient(135deg,#f59e0b,#f97316);border-radius:4px"></div>
            <span style="font-size:13px;color:var(--foreground-muted)">MV (Camera)</span>
          </div>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="width:16px;height:16px;background:linear-gradient(135deg,#ec4899,#d946ef);border-radius:4px"></div>
            <span style="font-size:13px;color:var(--foreground-muted)">Other</span>
          </div>
          <div style="display:flex;align-items:center;gap:8px;margin-left:auto">
            <div style="width:24px;height:3px;background:#22c55e;border-radius:2px"></div>
            <span style="font-size:13px;color:var(--foreground-muted)">LLDP Link</span>
          </div>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="width:24px;height:3px;background:#3b82f6;border-radius:2px"></div>
            <span style="font-size:13px;color:var(--foreground-muted)">CDP Link</span>
          </div>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="width:24px;height:3px;background:#22c55e;border-radius:2px;border:1px dashed #22c55e"></div>
            <span style="font-size:13px;color:var(--foreground-muted)">Wireless</span>
          </div>
        </div>

        <!-- Topology Canvas -->
        <div id="topology-canvas" style="background:#0f172a;border-radius:12px;border:1px solid var(--border);min-height:600px;position:relative;overflow:auto">
          <div id="topology-loading" style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;color:var(--foreground-muted)">
            <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.4;margin-bottom:16px"><circle cx="12" cy="5" r="3"/><circle cx="5" cy="19" r="3"/><circle cx="19" cy="19" r="3"/><line x1="12" y1="8" x2="5" y2="16"/><line x1="12" y1="8" x2="19" y2="16"/></svg>
            <div style="font-size:14px">Click Refresh to load topology</div>
          </div>
          <svg id="topology-svg" width="100%" height="600" style="display:none;background:#0f172a"></svg>
        </div>

        <!-- Link Details Panel -->
        <div id="topology-links" style="margin-top:20px;background:var(--surface);border-radius:12px;padding:20px;border:1px solid var(--border);display:none">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
            <h3 style="margin:0;font-size:16px;font-weight:600">
              <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:8px"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
              Network Links (LLDP/CDP)
            </h3>
            <span id="topology-link-count" style="background:var(--primary);color:white;padding:4px 10px;border-radius:12px;font-size:12px;font-weight:600">0 links</span>
          </div>
          <div id="topology-links-table" style="overflow-x:auto">
            <table style="width:100%;border-collapse:collapse;font-size:13px">
              <thead>
                <tr style="border-bottom:1px solid var(--border)">
                  <th style="text-align:left;padding:10px 8px;color:var(--foreground-muted);font-weight:500">Protocol</th>
                  <th style="text-align:left;padding:10px 8px;color:var(--foreground-muted);font-weight:500">Source Device</th>
                  <th style="text-align:left;padding:10px 8px;color:var(--foreground-muted);font-weight:500">Port</th>
                  <th style="text-align:left;padding:10px 8px;color:var(--foreground-muted);font-weight:500">Target Device</th>
                  <th style="text-align:left;padding:10px 8px;color:var(--foreground-muted);font-weight:500">Port</th>
                  <th style="text-align:left;padding:10px 8px;color:var(--foreground-muted);font-weight:500">IP</th>
                </tr>
              </thead>
              <tbody id="topology-links-body"></tbody>
            </table>
          </div>
        </div>

        <!-- Device Details Panel -->
        <div id="topology-details" style="display:none;margin-top:20px;background:var(--surface);border-radius:12px;padding:20px;border:1px solid var(--border)">
          <h3 style="margin:0 0 16px 0;font-size:16px;font-weight:600">Device Details</h3>
          <div id="topology-device-info" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px"></div>
        </div>
      </div>
    </div>

    <!-- Network Intelligence View (links to RCA tabs) -->
    <div id="view-intelligence" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">Network Intelligence</h1>
          <div class="page-subtitle">AI-powered roaming, telemetry, and health analysis</div>
        </div>
      </div>
      <div class="page-content">
        <div style="padding:60px;text-align:center;color:var(--foreground-muted)">
          <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="1.5" style="opacity:0.6;margin-bottom:16px"><path d="M12 2a10 10 0 1 0 10 10H12V2z"/><path d="M12 2a10 10 0 0 1 10 10"/></svg>
          <div style="font-size:16px;margin-bottom:8px">Network Intelligence features are in the RCA section</div>
          <div style="font-size:13px;margin-bottom:20px">Roaming Analysis, Switch Telemetry, Health Radar, and Predictive Detection</div>
          <button onclick="showView('rca')" style="padding:12px 24px;background:var(--primary);border:none;border-radius:8px;color:white;font-weight:600;cursor:pointer">Go to Root Cause Analysis</button>
        </div>
      </div>
    </div>

    <!-- Predictive View (links to RCA predictive tab) -->
    <div id="view-predictive" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">Predictive Alerts</h1>
          <div class="page-subtitle">AI-powered failure detection and risk forecasting</div>
        </div>
      </div>
      <div class="page-content">
        <div style="padding:60px;text-align:center;color:var(--foreground-muted)">
          <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#FF5722" stroke-width="1.5" style="opacity:0.6;margin-bottom:16px"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          <div style="font-size:16px;margin-bottom:8px">Predictive Detection in AI Network Intelligence</div>
          <div style="font-size:13px;margin-bottom:20px">Forecasts risk of device outage or flapping within 30-120 minutes</div>
          <button onclick="showView('rca');setTimeout(()=>switchAnalysisTab('predictive'),100)" style="padding:12px 24px;background:linear-gradient(135deg,#FF5722,#E64A19);border:none;border-radius:8px;color:white;font-weight:600;cursor:pointer">Run Predictive Analysis</button>
        </div>
      </div>
    </div>

    <!-- Events View (Placeholder) -->
    <div id="view-events" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">Network Events</h1>
          <div class="page-subtitle">DFS radar events, WIPS alerts, and network activity</div>
        </div>
      </div>
      <div class="page-content">
        <div style="padding:60px;text-align:center;color:var(--foreground-muted)">
          <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.4;margin-bottom:16px"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          <div style="font-size:16px;margin-bottom:8px">Event monitoring available in RCA section</div>
          <div style="font-size:13px">Network health, DFS events, and WIPS alerts</div>
        </div>
      </div>
    </div>

    <!-- Roaming View (Placeholder) -->
    <div id="view-roaming" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">Client Roaming</h1>
          <div class="page-subtitle">Track client movement and roaming patterns</div>
        </div>
      </div>
      <div class="page-content">
        <div style="padding:60px;text-align:center;color:var(--foreground-muted)">
          <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#00BCD4" stroke-width="1.5" style="opacity:0.6;margin-bottom:16px"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>
          <div style="font-size:16px;margin-bottom:8px">Roaming Analysis in AI Network Intelligence</div>
          <div style="font-size:13px;margin-bottom:20px">Track client movement, detect failures, identify sticky clients</div>
          <button onclick="showView('rca');setTimeout(()=>switchAnalysisTab('roaming'),100)" style="padding:12px 24px;background:linear-gradient(135deg,#00BCD4,#009688);border:none;border-radius:8px;color:rgba(0,0,0,0.87);font-weight:600;cursor:pointer">Run Roaming Analysis</button>
        </div>
      </div>
    </div>

    <!-- XIQ View (Placeholder) -->
    <div id="view-xiq" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">ExtremeCloud IQ</h1>
          <div class="page-subtitle">XIQ devices, sites, and client connectivity</div>
        </div>
      </div>
      <div class="page-content">
        <div style="padding:60px;text-align:center;color:var(--foreground-muted)">
          <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--secondary)" stroke-width="1.5" style="opacity:0.6;margin-bottom:16px"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
          <div style="font-size:16px;margin-bottom:8px">XIQ insights available in RCA section</div>
          <div style="font-size:13px">ExtremeCloud IQ devices, sites, and active clients</div>
        </div>
      </div>
    </div>

    <!-- Evidence Collection View -->
    <div id="view-evidence" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">Autonomous Evidence Collection</h1>
          <div class="page-subtitle">Collect diagnostic data for incident investigation and SIEM integration</div>
        </div>
        <div class="header-actions">
          <button class="header-btn" onclick="checkForAnomalies()">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
            Check Anomalies
          </button>
        </div>
      </div>
      <div class="page-content">
        <!-- Anomaly Alert Banner -->
        <div id="evidence-anomaly-banner" style="display:none;padding:16px 20px;background:linear-gradient(135deg,rgba(239,68,68,0.2),rgba(234,88,12,0.1));border:1px solid rgba(239,68,68,0.3);border-radius:10px;margin-bottom:20px">
          <div style="display:flex;align-items:center;gap:12px">
            <div style="width:40px;height:40px;background:rgba(239,68,68,0.2);border-radius:8px;display:flex;align-items:center;justify-content:center">
              <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            </div>
            <div style="flex:1">
              <div style="font-weight:600;color:#EF4444;margin-bottom:4px">Anomalies Detected</div>
              <div id="evidence-anomaly-summary" style="font-size:13px;color:rgba(255,255,255,0.7)">--</div>
            </div>
            <button onclick="autoCollectEvidence()" style="padding:10px 20px;background:linear-gradient(135deg,#EF4444,#DC2626);border:none;border-radius:8px;color:white;font-weight:600;cursor:pointer;font-size:13px">Auto-Collect Evidence</button>
          </div>
        </div>

        <div class="card" style="border-left:3px solid #06B6D4;background:linear-gradient(135deg,rgba(6,182,212,0.08),rgba(59,130,246,0.05))">
          <div class="section-title">
            <span class="icon" style="color:#06B6D4"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg></span>
            <h2>Evidence Collection</h2>
            <span style="margin-left:auto;padding:4px 10px;background:linear-gradient(135deg,#06B6D4,#3B82F6);border-radius:12px;font-size:10px;font-weight:600;color:white;text-transform:uppercase">Autonomous</span>
          </div>
          <div class="muted">Collects packet captures, client logs, DHCP/DNS traces, auth logs, and RF snapshots</div>

          <div style="margin-top:20px;display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px">
            <!-- Target Network -->
            <div>
              <label style="display:block;font-size:12px;color:rgba(255,255,255,0.6);margin-bottom:6px">Target Network</label>
              <select id="evidence-network-select" style="width:100%;padding:12px;background:#0b1220;color:#e8eefc;border:1px solid rgba(6,182,212,0.3);border-radius:8px;font-size:13px">
                <option value="">All Networks</option>
              </select>
            </div>

            <!-- Target Device -->
            <div>
              <label style="display:block;font-size:12px;color:rgba(255,255,255,0.6);margin-bottom:6px">Target Device (Optional)</label>
              <select id="evidence-device-select" style="width:100%;padding:12px;background:#0b1220;color:#e8eefc;border:1px solid rgba(6,182,212,0.3);border-radius:8px;font-size:13px">
                <option value="">All Devices</option>
              </select>
            </div>

            <!-- Client MAC -->
            <div>
              <label style="display:block;font-size:12px;color:rgba(255,255,255,0.6);margin-bottom:6px">Client MAC (Optional)</label>
              <input type="text" id="evidence-client-mac" placeholder="e.g., 00:11:22:33:44:55" style="width:100%;padding:12px;background:#0b1220;color:#e8eefc;border:1px solid rgba(6,182,212,0.3);border-radius:8px;font-size:13px;box-sizing:border-box" />
            </div>

            <!-- Timespan -->
            <div>
              <label style="display:block;font-size:12px;color:rgba(255,255,255,0.6);margin-bottom:6px">Timespan</label>
              <select id="evidence-timespan" style="width:100%;padding:12px;background:#0b1220;color:#e8eefc;border:1px solid rgba(6,182,212,0.3);border-radius:8px;font-size:13px">
                <option value="1800">30 minutes</option>
                <option value="3600" selected>1 hour</option>
                <option value="7200">2 hours</option>
                <option value="14400">4 hours</option>
                <option value="86400">24 hours</option>
              </select>
            </div>
          </div>

          <!-- Evidence Types -->
          <div style="margin-top:20px">
            <label style="display:block;font-size:12px;color:rgba(255,255,255,0.6);margin-bottom:10px">Evidence Types to Collect</label>
            <div style="display:flex;flex-wrap:wrap;gap:10px">
              <label style="display:flex;align-items:center;gap:8px;padding:8px 14px;background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.3);border-radius:8px;cursor:pointer;font-size:13px">
                <input type="checkbox" id="ev-client-logs" checked style="accent-color:#06B6D4" /> Client Event Logs
              </label>
              <label style="display:flex;align-items:center;gap:8px;padding:8px 14px;background:rgba(34,197,94,0.15);border:1px solid rgba(34,197,94,0.3);border-radius:8px;cursor:pointer;font-size:13px">
                <input type="checkbox" id="ev-dhcp-dns" checked style="accent-color:#22C55E" /> DHCP + DNS Trace
              </label>
              <label style="display:flex;align-items:center;gap:8px;padding:8px 14px;background:rgba(168,85,247,0.15);border:1px solid rgba(168,85,247,0.3);border-radius:8px;cursor:pointer;font-size:13px">
                <input type="checkbox" id="ev-auth-logs" checked style="accent-color:#A855F7" /> Auth Logs (802.1x/WPA)
              </label>
              <label style="display:flex;align-items:center;gap:8px;padding:8px 14px;background:rgba(249,115,22,0.15);border:1px solid rgba(249,115,22,0.3);border-radius:8px;cursor:pointer;font-size:13px">
                <input type="checkbox" id="ev-rf-snapshot" checked style="accent-color:#F97316" /> RF Snapshot
              </label>
              <label style="display:flex;align-items:center;gap:8px;padding:8px 14px;background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.3);border-radius:8px;cursor:pointer;font-size:13px">
                <input type="checkbox" id="ev-security" checked style="accent-color:#EF4444" /> Security Events
              </label>
              <label style="display:flex;align-items:center;gap:8px;padding:8px 14px;background:rgba(59,130,246,0.15);border:1px solid rgba(59,130,246,0.3);border-radius:8px;cursor:pointer;font-size:13px">
                <input type="checkbox" id="ev-config" checked style="accent-color:#3B82F6" /> Config Snapshot
              </label>
              <label style="display:flex;align-items:center;gap:8px;padding:8px 14px;background:rgba(156,163,175,0.15);border:1px solid rgba(156,163,175,0.3);border-radius:8px;cursor:pointer;font-size:13px">
                <input type="checkbox" id="ev-packet-capture" style="accent-color:#9CA3AF" /> Packet Capture Info
              </label>
            </div>
          </div>

          <div style="margin-top:24px;display:flex;gap:12px;flex-wrap:wrap">
            <button onclick="collectEvidence()" id="evidence-collect-button" style="padding:12px 24px;background:linear-gradient(135deg,#06B6D4,#3B82F6);border:none;border-radius:8px;color:white;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:14px">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              Collect Evidence
            </button>
            <button onclick="loadEvidenceNetworks();loadEvidenceDevices()" style="padding:12px 20px;background:transparent;border:1px solid rgba(6,182,212,0.3);border-radius:8px;color:#06B6D4;font-weight:500;cursor:pointer;font-size:13px">
              Refresh Targets
            </button>
          </div>

          <!-- Results Section -->
          <div id="evidence-results" style="margin-top:24px;display:none">
            <div id="evidence-loading" style="display:none;padding:40px;text-align:center">
              <div style="width:40px;height:40px;border:3px solid rgba(6,182,212,0.3);border-top-color:#06B6D4;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto"></div>
              <div style="margin-top:12px;color:var(--foreground-muted)">Collecting evidence from network devices...</div>
              <div style="margin-top:8px;font-size:12px;color:rgba(255,255,255,0.4)">This may take 30-60 seconds</div>
            </div>

            <div id="evidence-content" style="display:none">
              <!-- Collection Summary Banner -->
              <div id="evidence-summary-banner" style="padding:20px;border-radius:12px;margin-bottom:20px;background:linear-gradient(135deg,rgba(6,182,212,0.2),rgba(59,130,246,0.1))">
                <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px">
                  <div>
                    <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,0.6)">Collection ID</div>
                    <div id="evidence-collection-id" style="font-size:18px;font-weight:600;color:#06B6D4;font-family:var(--font-mono)">--</div>
                  </div>
                  <div style="text-align:center;padding:0 20px;border-left:1px solid rgba(255,255,255,0.1);border-right:1px solid rgba(255,255,255,0.1)">
                    <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,0.6)">Total Events</div>
                    <div id="evidence-total-events" style="font-size:28px;font-weight:700;color:var(--foreground)">--</div>
                  </div>
                  <div style="text-align:center;padding:0 20px;border-right:1px solid rgba(255,255,255,0.1)">
                    <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,0.6)">Critical</div>
                    <div id="evidence-critical" style="font-size:28px;font-weight:700;color:#EF4444">--</div>
                  </div>
                  <div style="text-align:center">
                    <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,0.6)">Warnings</div>
                    <div id="evidence-warnings" style="font-size:28px;font-weight:700;color:var(--warning)">--</div>
                  </div>
                  <div>
                    <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,0.6)">Duration</div>
                    <div id="evidence-duration" style="font-size:18px;font-weight:600;color:var(--success)">--</div>
                  </div>
                </div>
              </div>

              <!-- Timeline -->
              <div style="margin-bottom:20px">
                <div style="font-weight:600;font-size:14px;color:rgba(255,255,255,0.87);margin-bottom:12px;display:flex;align-items:center;gap:8px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#06B6D4" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                  Event Timeline
                </div>
                <div id="evidence-timeline" style="max-height:300px;overflow-y:auto;background:rgba(255,255,255,0.03);border-radius:8px;padding:12px">
                  <div class="muted">No events</div>
                </div>
              </div>

              <!-- Data Sections Grid -->
              <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-bottom:20px">
                <!-- Device Status -->
                <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:16px">
                  <div style="font-weight:600;font-size:13px;color:rgba(255,255,255,0.87);margin-bottom:10px;display:flex;align-items:center;gap:8px">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#06B6D4" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/></svg>
                    Device Status
                    <span id="evidence-device-count" style="margin-left:auto;padding:2px 8px;background:rgba(6,182,212,0.2);border-radius:10px;font-size:11px;color:#06B6D4">0</span>
                  </div>
                  <div id="evidence-devices-list" style="max-height:150px;overflow-y:auto;font-size:12px"><div class="muted">No data</div></div>
                </div>

                <!-- Client Events -->
                <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:16px">
                  <div style="font-weight:600;font-size:13px;color:rgba(255,255,255,0.87);margin-bottom:10px;display:flex;align-items:center;gap:8px">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22C55E" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    Client Events
                    <span id="evidence-client-count" style="margin-left:auto;padding:2px 8px;background:rgba(34,197,94,0.2);border-radius:10px;font-size:11px;color:#22C55E">0</span>
                  </div>
                  <div id="evidence-clients-list" style="max-height:150px;overflow-y:auto;font-size:12px"><div class="muted">No data</div></div>
                </div>

                <!-- Auth Events -->
                <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:16px">
                  <div style="font-weight:600;font-size:13px;color:rgba(255,255,255,0.87);margin-bottom:10px;display:flex;align-items:center;gap:8px">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#A855F7" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    Auth Events
                    <span id="evidence-auth-count" style="margin-left:auto;padding:2px 8px;background:rgba(168,85,247,0.2);border-radius:10px;font-size:11px;color:#A855F7">0</span>
                  </div>
                  <div id="evidence-auth-list" style="max-height:150px;overflow-y:auto;font-size:12px"><div class="muted">No data</div></div>
                </div>

                <!-- Security Events -->
                <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:16px">
                  <div style="font-weight:600;font-size:13px;color:rgba(255,255,255,0.87);margin-bottom:10px;display:flex;align-items:center;gap:8px">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    Security Events
                    <span id="evidence-security-count" style="margin-left:auto;padding:2px 8px;background:rgba(239,68,68,0.2);border-radius:10px;font-size:11px;color:#EF4444">0</span>
                  </div>
                  <div id="evidence-security-list" style="max-height:150px;overflow-y:auto;font-size:12px"><div class="muted">No data</div></div>
                </div>
              </div>

              <!-- RF Snapshot -->
              <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:16px;margin-bottom:20px">
                <div style="font-weight:600;font-size:13px;color:rgba(255,255,255,0.87);margin-bottom:10px;display:flex;align-items:center;gap:8px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#F97316" stroke-width="2"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>
                  RF Snapshot
                </div>
                <div id="evidence-rf-data" style="font-size:12px"><div class="muted">No data</div></div>
              </div>

              <!-- Export Actions -->
              <div style="display:flex;gap:12px;flex-wrap:wrap;padding-top:16px;border-top:1px solid rgba(255,255,255,0.1)">
                <button onclick="downloadEvidence()" style="padding:10px 20px;background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.3);border-radius:8px;color:#06B6D4;font-weight:500;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:13px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                  Download JSON Bundle
                </button>
                <button onclick="copySiemFormat()" style="padding:10px 20px;background:rgba(168,85,247,0.15);border:1px solid rgba(168,85,247,0.3);border-radius:8px;color:#A855F7;font-weight:500;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:13px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                  Copy SIEM Format
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Change Risk Prediction View -->
    <div id="view-change-risk" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">AI Change Risk Prediction</h1>
          <div class="page-subtitle">Simulate configuration impact before pushing changes</div>
        </div>
      </div>
      <div class="page-content">
        <div class="card" style="border-left:3px solid #E91E63;background:linear-gradient(135deg,rgba(233,30,99,0.08),rgba(156,39,176,0.05))">
          <div class="section-title">
            <span class="icon" style="color:#E91E63"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg></span>
            <h2>Change Risk Analysis</h2>
            <span style="margin-left:auto;padding:4px 10px;background:linear-gradient(135deg,#E91E63,#9C27B0);border-radius:12px;font-size:10px;font-weight:600;color:rgba(255,255,255,0.95);text-transform:uppercase">AI-Powered</span>
          </div>
          <div class="muted">Analyze risk before pushing configuration changes to your network</div>

          <div style="margin-top:20px;display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px">
            <!-- Change Type Selector -->
            <div>
              <label style="display:block;font-size:12px;color:rgba(255,255,255,0.6);margin-bottom:6px">Change Type</label>
              <select id="change-type-select" style="width:100%;padding:12px;background:#0b1220;color:#e8eefc;border:1px solid rgba(233,30,99,0.3);border-radius:8px;font-size:13px">
                <option value="ssid_update">SSID Update</option>
                <option value="security_policy">Security Policy Change</option>
                <option value="vlan_change">VLAN Configuration</option>
                <option value="rf_profile">RF Profile Change</option>
                <option value="qos_rules">QoS Rules Update</option>
                <option value="firmware_upgrade">Firmware Upgrade</option>
                <option value="switching_config">Switching Configuration</option>
                <option value="wan_config">WAN/Uplink Configuration</option>
                <option value="network_settings">Network Settings</option>
              </select>
            </div>

            <!-- Target Network -->
            <div>
              <label style="display:block;font-size:12px;color:rgba(255,255,255,0.6);margin-bottom:6px">Target Network (Optional)</label>
              <select id="change-network-select" style="width:100%;padding:12px;background:#0b1220;color:#e8eefc;border:1px solid rgba(233,30,99,0.3);border-radius:8px;font-size:13px">
                <option value="">All Networks</option>
              </select>
            </div>

            <!-- Description -->
            <div style="grid-column:span 2">
              <label style="display:block;font-size:12px;color:rgba(255,255,255,0.6);margin-bottom:6px">Change Description (Optional)</label>
              <input type="text" id="change-description" placeholder="e.g., Updating guest SSID password..." style="width:100%;padding:12px;background:#0b1220;color:#e8eefc;border:1px solid rgba(233,30,99,0.3);border-radius:8px;font-size:13px;box-sizing:border-box" />
            </div>
          </div>

          <div style="margin-top:20px;display:flex;gap:12px;flex-wrap:wrap">
            <button onclick="analyzeChangeRisk()" id="change-risk-button" style="padding:12px 24px;background:linear-gradient(135deg,#E91E63,#9C27B0);border:none;border-radius:8px;color:white;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:14px">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              Analyze Risk
            </button>
            <button onclick="loadChangeNetworks()" style="padding:12px 20px;background:transparent;border:1px solid rgba(233,30,99,0.3);border-radius:8px;color:#E91E63;font-weight:500;cursor:pointer;font-size:13px">
              Refresh Networks
            </button>
          </div>

          <!-- Results Section -->
          <div id="change-risk-results" style="margin-top:24px;display:none">
            <div id="change-risk-loading" style="display:none;padding:40px;text-align:center">
              <div style="width:40px;height:40px;border:3px solid rgba(233,30,99,0.3);border-top-color:#E91E63;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto"></div>
              <div style="margin-top:12px;color:var(--foreground-muted)">Analyzing historical data, client patterns, RF density...</div>
            </div>

            <div id="change-risk-content" style="display:none">
              <!-- Risk Score Banner -->
              <div id="change-risk-banner" style="padding:24px;border-radius:12px;margin-bottom:20px;background:linear-gradient(135deg,rgba(233,30,99,0.2),rgba(156,39,176,0.1))">
                <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:20px">
                  <div style="text-align:center">
                    <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,0.6);margin-bottom:4px">Risk Score</div>
                    <div style="display:flex;align-items:baseline;gap:4px;justify-content:center">
                      <span id="change-risk-score" style="font-size:56px;font-weight:700;color:#E91E63">--</span>
                    </div>
                    <div id="change-risk-level" style="display:inline-block;padding:4px 16px;border-radius:20px;font-size:12px;font-weight:600;text-transform:uppercase;background:rgba(233,30,99,0.3);color:#E91E63;margin-top:8px">--</div>
                  </div>
                  <div style="flex:1;min-width:200px;max-width:300px;text-align:center;padding:0 20px;border-left:1px solid rgba(255,255,255,0.1);border-right:1px solid rgba(255,255,255,0.1)">
                    <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,0.6);margin-bottom:8px">Blast Radius</div>
                    <div id="change-blast-radius" style="font-size:32px;font-weight:700;color:var(--warning)">-- APs</div>
                    <div id="change-blast-detail" style="font-size:12px;color:rgba(255,255,255,0.5);margin-top:4px">-- clients affected</div>
                  </div>
                  <div style="text-align:center">
                    <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,0.6);margin-bottom:8px">Suggested Window</div>
                    <div id="change-suggested-window" style="font-size:24px;font-weight:600;color:var(--success)">--</div>
                    <div id="change-window-reason" style="font-size:11px;color:rgba(255,255,255,0.5);margin-top:4px">Based on usage patterns</div>
                  </div>
                </div>
              </div>

              <!-- Risk Factors -->
              <div style="margin-bottom:20px">
                <div style="font-weight:600;font-size:14px;color:rgba(255,255,255,0.87);margin-bottom:12px;display:flex;align-items:center;gap:8px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#E91E63" stroke-width="2"><path d="M12 2a10 10 0 1 0 10 10H12V2z"/></svg>
                  Risk Factors
                </div>
                <div id="change-risk-factors" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px">
                  <!-- Factors will be inserted here -->
                </div>
              </div>

              <!-- Recommendations -->
              <div style="margin-bottom:20px">
                <div style="font-weight:600;font-size:14px;color:rgba(255,255,255,0.87);margin-bottom:12px;display:flex;align-items:center;gap:8px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                  Recommendations
                </div>
                <div id="change-risk-recommendations" style="display:flex;flex-direction:column;gap:8px">
                  <!-- Recommendations will be inserted here -->
                </div>
              </div>

              <!-- Historical Failures -->
              <div id="change-historical-section" style="display:none">
                <div style="font-weight:600;font-size:14px;color:rgba(255,255,255,0.87);margin-bottom:12px;display:flex;align-items:center;gap:8px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--warning)" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                  Recent Historical Incidents
                </div>
                <div id="change-historical-failures" style="max-height:200px;overflow-y:auto;background:rgba(255,255,255,0.03);border-radius:8px;padding:12px">
                  <!-- Historical failures will be inserted here -->
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

  </main>

  <script>
    // View Navigation Functions
    function showView(viewId) {
      // Hide all view panels
      document.querySelectorAll('.view-panel').forEach(panel => {
        panel.classList.remove('active');
      });

      // Remove active from all nav items
      document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
      });

      // Show selected view panel
      const targetPanel = document.getElementById('view-' + viewId);
      if (targetPanel) {
        targetPanel.classList.add('active');
      }

      // Set active nav item
      document.querySelectorAll('.nav-item').forEach(item => {
        if (item.getAttribute('onclick') && item.getAttribute('onclick').includes("'" + viewId + "'")) {
          item.classList.add('active');
        }
      });

      // Trigger data load for specific views
      if (viewId === 'dashboard') {
        loadDashboardData();
      } else if (viewId === 'devices') {
        loadDevicesView();
      }
    }

    // Dashboard data loading
    async function loadDashboardData() {
      try {
        // Fetch organizations
        const orgsRes = await fetch('/api/organizations');
        const orgs = await orgsRes.json();

        // Update org stats
        document.getElementById('stat-orgs').textContent = orgs.length;
        const orgNames = orgs.map(o => o.name).slice(0, 3).join(', ');
        document.getElementById('orgs-container').textContent = orgNames + (orgs.length > 3 ? '...' : '');

        // Fetch devices for each org and aggregate
        let totalDevices = 0;
        let onlineDevices = 0;
        let offlineDevices = 0;
        let totalClients = 0;

        for (const org of orgs) {
          try {
            const devRes = await fetch('/api/organizations/' + org.id + '/devices');
            const devices = await devRes.json();
            totalDevices += devices.length;
            onlineDevices += devices.filter(d => d.status === 'online').length;
            offlineDevices += devices.filter(d => d.status === 'offline').length;
          } catch (e) {
            console.warn('Error fetching devices for org', org.name, e);
          }
        }

        document.getElementById('stat-total-devices').textContent = totalDevices;
        document.getElementById('stat-online').textContent = onlineDevices;
        document.getElementById('stat-offline').textContent = offlineDevices;
        document.getElementById('stat-clients').textContent = '--'; // Would need client API call

      } catch (err) {
        console.error('Error loading dashboard data:', err);
      }
    }

    // Devices view data loading
    let allDevices = [];
    async function loadDevicesView() {
      const tbody = document.getElementById('ap-table-body');
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--foreground-muted)"><div style="animation:spin 1s linear infinite;display:inline-block;width:20px;height:20px;border:2px solid var(--primary);border-top-color:transparent;border-radius:50%"></div> Loading...</td></tr>';

      try {
        const orgsRes = await fetch('/api/organizations');
        const orgs = await orgsRes.json();

        allDevices = [];
        let totalClients = 0;

        for (const org of orgs) {
          try {
            const netsRes = await fetch('/api/organizations/' + org.id + '/networks');
            const networks = await netsRes.json();
            const networkMap = {};
            networks.forEach(n => networkMap[n.id] = n.name);

            const devRes = await fetch('/api/organizations/' + org.id + '/devices');
            const devices = await devRes.json();

            // Filter for APs only
            const aps = devices.filter(d => d.productType === 'wireless');

            for (const ap of aps) {
              allDevices.push({
                ...ap,
                networkName: networkMap[ap.networkId] || ap.networkId,
                orgName: org.name
              });
            }
          } catch (e) {
            console.warn('Error fetching devices for org', org.name, e);
          }
        }

        // Update stats
        const online = allDevices.filter(d => d.status === 'online').length;
        const offline = allDevices.filter(d => d.status !== 'online').length;
        const models = new Set(allDevices.map(d => d.model)).size;

        document.getElementById('ap-total').textContent = allDevices.length;
        document.getElementById('ap-online').textContent = online;
        document.getElementById('ap-offline').textContent = offline;
        document.getElementById('ap-models').textContent = models;
        document.getElementById('ap-clients').textContent = '--';

        // Render table
        renderAPTable(allDevices);

      } catch (err) {
        console.error('Error loading devices:', err);
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--destructive)">Error loading devices: ' + err.message + '</td></tr>';
      }
    }

    function renderAPTable(devices) {
      const tbody = document.getElementById('ap-table-body');
      if (devices.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--foreground-muted)">No access points found</td></tr>';
        return;
      }

      tbody.innerHTML = devices.map(ap => {
        const statusClass = ap.status === 'online' ? 'online' : (ap.status === 'alerting' ? 'alerting' : 'offline');
        const statusText = ap.status === 'online' ? 'Online' : (ap.status === 'alerting' ? 'Alerting' : 'Offline');
        return '<tr>' +
          '<td><span class="status-badge ' + statusClass + '"><span style="width:6px;height:6px;border-radius:50%;background:currentColor"></span> ' + statusText + '</span></td>' +
          '<td>' + (ap.name || ap.serial) + '</td>' +
          '<td style="font-family:var(--font-mono);font-size:12px">' + ap.serial + '</td>' +
          '<td>' + (ap.networkName || '--') + '</td>' +
          '<td>' + (ap.model || '--') + '</td>' +
          '<td style="font-family:var(--font-mono);font-size:12px">' + (ap.lanIp || '--') + '</td>' +
          '<td><span class="client-count">' + (ap.clients || '--') + '</span></td>' +
          '</tr>';
      }).join('');
    }

    function filterAPTable() {
      const search = document.getElementById('ap-search').value.toLowerCase();
      if (!search) {
        renderAPTable(allDevices);
        return;
      }
      const filtered = allDevices.filter(ap =>
        (ap.name && ap.name.toLowerCase().includes(search)) ||
        (ap.serial && ap.serial.toLowerCase().includes(search)) ||
        (ap.model && ap.model.toLowerCase().includes(search)) ||
        (ap.lanIp && ap.lanIp.includes(search)) ||
        (ap.networkName && ap.networkName.toLowerCase().includes(search))
      );
      renderAPTable(filtered);
    }

    // Auto-load dashboard on page load
    document.addEventListener('DOMContentLoaded', function() {
      loadDashboardData();
      loadChangeNetworks(); // Pre-load networks for change risk dropdown
      loadEvidenceNetworks(); // Pre-load networks for evidence collection
      loadEvidenceDevices(); // Pre-load devices for evidence collection
    });

    // Evidence Collection Functions
    let lastEvidenceData = null;
    let detectedAnomalies = [];

    async function loadEvidenceNetworks() {
      try {
        const res = await fetch('/api/change-risk/networks');
        const networks = await res.json();
        const select = document.getElementById('evidence-network-select');
        if (select) {
          select.innerHTML = '<option value="">All Networks</option>';
          networks.forEach(net => {
            const opt = document.createElement('option');
            opt.value = net.id;
            opt.textContent = net.name + ' (' + net.org + ')';
            select.appendChild(opt);
          });
        }
      } catch (err) {
        console.error('Error loading networks:', err);
      }
    }

    async function loadEvidenceDevices() {
      try {
        const res = await fetch('/api/evidence/devices');
        const devices = await res.json();
        const select = document.getElementById('evidence-device-select');
        if (select) {
          select.innerHTML = '<option value="">All Devices</option>';
          devices.forEach(dev => {
            const opt = document.createElement('option');
            opt.value = dev.serial;
            opt.textContent = dev.name + ' (' + dev.type + ' - ' + dev.status + ')';
            select.appendChild(opt);
          });
        }
      } catch (err) {
        console.error('Error loading devices:', err);
      }
    }

    async function checkForAnomalies() {
      try {
        const res = await fetch('/api/evidence/anomaly-check');
        const data = await res.json();
        detectedAnomalies = data.anomalies || [];

        const banner = document.getElementById('evidence-anomaly-banner');
        const summary = document.getElementById('evidence-anomaly-summary');

        if (data.anomaliesDetected && data.anomalyCount > 0) {
          banner.style.display = 'block';
          const criticalCount = detectedAnomalies.filter(a => a.severity === 'critical').length;
          const highCount = detectedAnomalies.filter(a => a.severity === 'high').length;
          summary.textContent = data.anomalyCount + ' anomalies detected: ' +
            (criticalCount > 0 ? criticalCount + ' critical, ' : '') +
            (highCount > 0 ? highCount + ' high priority' : '') +
            ' - ' + detectedAnomalies[0].recommendation;
        } else {
          banner.style.display = 'none';
          alert('No anomalies detected. Network is healthy.');
        }
      } catch (err) {
        console.error('Anomaly check error:', err);
        alert('Error checking for anomalies: ' + err.message);
      }
    }

    async function autoCollectEvidence() {
      if (detectedAnomalies.length === 0) {
        alert('No anomalies to investigate. Run anomaly check first.');
        return;
      }

      // Set trigger type to anomaly and collect
      await collectEvidence('anomaly', detectedAnomalies);
    }

    async function collectEvidence(triggerType = 'manual', anomalyDetails = null) {
      const networkId = document.getElementById('evidence-network-select').value;
      const deviceSerial = document.getElementById('evidence-device-select').value;
      const clientMac = document.getElementById('evidence-client-mac').value.trim();
      const timespan = parseInt(document.getElementById('evidence-timespan').value);

      const includeClientLogs = document.getElementById('ev-client-logs').checked;
      const includeDhcpDns = document.getElementById('ev-dhcp-dns').checked;
      const includeAuthLogs = document.getElementById('ev-auth-logs').checked;
      const includeRfSnapshot = document.getElementById('ev-rf-snapshot').checked;
      const includeSecurityEvents = document.getElementById('ev-security').checked;
      const includeConfigSnapshot = document.getElementById('ev-config').checked;
      const includePacketCapture = document.getElementById('ev-packet-capture').checked;

      const resultsDiv = document.getElementById('evidence-results');
      const loadingDiv = document.getElementById('evidence-loading');
      const contentDiv = document.getElementById('evidence-content');
      const button = document.getElementById('evidence-collect-button');

      // Show loading
      resultsDiv.style.display = 'block';
      loadingDiv.style.display = 'block';
      contentDiv.style.display = 'none';
      button.disabled = true;
      button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 1s linear infinite"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Collecting...';

      try {
        const res = await fetch('/api/evidence/collect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            networkId: networkId || null,
            deviceSerial: deviceSerial || null,
            clientMac: clientMac || null,
            timespan,
            includeClientLogs,
            includeDhcpDns,
            includeAuthLogs,
            includeRfSnapshot,
            includeSecurityEvents,
            includeConfigSnapshot,
            includePacketCapture,
            triggerType,
            anomalyDetails
          })
        });

        const data = await res.json();
        if (data.error) throw new Error(data.error);

        lastEvidenceData = data;

        // Hide loading, show content
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';

        // Update summary
        document.getElementById('evidence-collection-id').textContent = data.collectionId;
        document.getElementById('evidence-total-events').textContent = data.summary.totalEvents;
        document.getElementById('evidence-critical').textContent = data.summary.criticalFindings;
        document.getElementById('evidence-warnings').textContent = data.summary.warnings;
        document.getElementById('evidence-duration').textContent = data.collectionDuration;

        // Update timeline
        const timelineDiv = document.getElementById('evidence-timeline');
        if (data.timeline && data.timeline.length > 0) {
          timelineDiv.innerHTML = data.timeline.slice(0, 50).map(t => {
            const severityColors = {
              critical: '#EF4444',
              high: '#F97316',
              medium: '#FBBF24',
              low: '#22C55E'
            };
            const color = severityColors[t.severity] || '#9CA3AF';
            return '<div style="padding:8px 12px;border-left:3px solid ' + color + ';margin-bottom:6px;background:rgba(255,255,255,0.02)">' +
              '<div style="display:flex;justify-content:space-between;gap:12px">' +
              '<span style="color:' + color + ';font-weight:500">' + t.type.toUpperCase() + '</span>' +
              '<span style="color:rgba(255,255,255,0.4);font-size:11px">' + new Date(t.time).toLocaleString() + '</span>' +
              '</div>' +
              '<div style="color:rgba(255,255,255,0.7);margin-top:4px">' + t.message + '</div>' +
              '</div>';
          }).join('');
        } else {
          timelineDiv.innerHTML = '<div class="muted">No significant events in timeline</div>';
        }

        // Update device status
        const deviceCount = (data.data.deviceStatus || []).length;
        document.getElementById('evidence-device-count').textContent = deviceCount;
        const devicesDiv = document.getElementById('evidence-devices-list');
        if (deviceCount > 0) {
          devicesDiv.innerHTML = data.data.deviceStatus.slice(0, 20).map(d => {
            const statusColor = d.status === 'online' ? '#22C55E' : d.status === 'alerting' ? '#FBBF24' : '#EF4444';
            return '<div style="padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.05)">' +
              '<span style="color:' + statusColor + '">\u25CF</span> ' + d.name + ' <span style="color:rgba(255,255,255,0.4)">(' + d.model + ')</span>' +
              '</div>';
          }).join('');
        } else {
          devicesDiv.innerHTML = '<div class="muted">No devices</div>';
        }

        // Update client events
        const clientCount = (data.data.clientEvents || []).length;
        document.getElementById('evidence-client-count').textContent = clientCount;
        const clientsDiv = document.getElementById('evidence-clients-list');
        if (clientCount > 0) {
          const eventTypes = {};
          data.data.clientEvents.forEach(e => {
            eventTypes[e.type] = (eventTypes[e.type] || 0) + 1;
          });
          clientsDiv.innerHTML = Object.entries(eventTypes).map(([type, count]) =>
            '<div style="padding:4px 0;display:flex;justify-content:space-between">' +
            '<span style="color:rgba(255,255,255,0.7)">' + type + '</span>' +
            '<span style="color:#22C55E">' + count + '</span></div>'
          ).join('');
        } else {
          clientsDiv.innerHTML = '<div class="muted">No client events</div>';
        }

        // Update auth events
        const authCount = (data.data.authEvents || []).length;
        document.getElementById('evidence-auth-count').textContent = authCount;
        const authDiv = document.getElementById('evidence-auth-list');
        if (authCount > 0) {
          const authTypes = {};
          data.data.authEvents.forEach(e => {
            authTypes[e.type] = (authTypes[e.type] || 0) + 1;
          });
          authDiv.innerHTML = Object.entries(authTypes).map(([type, count]) =>
            '<div style="padding:4px 0;display:flex;justify-content:space-between">' +
            '<span style="color:rgba(255,255,255,0.7)">' + type + '</span>' +
            '<span style="color:#A855F7">' + count + '</span></div>'
          ).join('');
        } else {
          authDiv.innerHTML = '<div class="muted">No auth events</div>';
        }

        // Update security events
        const secCount = (data.data.securityEvents || []).length;
        document.getElementById('evidence-security-count').textContent = secCount;
        const secDiv = document.getElementById('evidence-security-list');
        if (secCount > 0) {
          secDiv.innerHTML = data.data.securityEvents.slice(0, 10).map(e =>
            '<div style="padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.05)">' +
            '<span style="color:#EF4444">' + e.type + '</span><br/>' +
            '<span style="color:rgba(255,255,255,0.5);font-size:11px">' + e.description + '</span>' +
            '</div>'
          ).join('');
        } else {
          secDiv.innerHTML = '<div class="muted">No security events</div>';
        }

        // Update RF data
        const rfDiv = document.getElementById('evidence-rf-data');
        if (data.data.rfSnapshot && data.data.rfSnapshot.channelUtilization.length > 0) {
          rfDiv.innerHTML = data.data.rfSnapshot.channelUtilization.map(cu =>
            '<div style="padding:8px;background:rgba(249,115,22,0.1);border-radius:6px;margin-bottom:8px">' +
            '<div style="font-weight:500;color:#F97316">' + cu.networkName + '</div>' +
            '<div style="display:flex;gap:16px;margin-top:6px;color:rgba(255,255,255,0.7)">' +
            '<span>Avg Utilization: <b>' + Math.round(cu.avgUtilization) + '%</b></span>' +
            '<span>Interference: <b>' + Math.round(cu.avgInterference) + '%</b></span>' +
            '</div></div>'
          ).join('');
        } else {
          rfDiv.innerHTML = '<div class="muted">No RF data collected</div>';
        }

      } catch (err) {
        console.error('Evidence collection error:', err);
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';
        document.getElementById('evidence-collection-id').textContent = 'ERROR';
        document.getElementById('evidence-timeline').innerHTML = '<div style="color:var(--destructive)">Error: ' + err.message + '</div>';
      } finally {
        button.disabled = false;
        button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> Collect Evidence';
      }
    }

    function downloadEvidence() {
      if (!lastEvidenceData) {
        alert('No evidence data to download. Run collection first.');
        return;
      }
      const blob = new Blob([JSON.stringify(lastEvidenceData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = lastEvidenceData.collectionId + '.json';
      a.click();
      URL.revokeObjectURL(url);
    }

    function copySiemFormat() {
      if (!lastEvidenceData || !lastEvidenceData.siemFormat) {
        alert('No SIEM data available. Run collection first.');
        return;
      }
      navigator.clipboard.writeText(JSON.stringify(lastEvidenceData.siemFormat, null, 2))
        .then(() => alert('SIEM format copied to clipboard'))
        .catch(err => alert('Failed to copy: ' + err.message));
    }

    // Topology Map Functions
    let topologyData = null;
    let customPositions = {}; // Store user-dragged positions
    let topologyLocked = false; // Lock state to prevent dragging
    let dragState = {
      isDragging: false,
      nodeId: null,
      startX: 0,
      startY: 0,
      offsetX: 0,
      offsetY: 0
    };

    function toggleTopologyLock() {
      topologyLocked = !topologyLocked;
      const lockBtn = document.getElementById('topology-lock-btn');
      const lockIcon = document.getElementById('topology-lock-icon');
      const lockText = document.getElementById('topology-lock-text');
      const svg = document.getElementById('topology-svg');

      if (topologyLocked) {
        lockBtn.style.background = 'rgba(34, 197, 94, 0.2)';
        lockBtn.style.borderColor = '#22c55e';
        lockBtn.style.color = '#22c55e';
        lockIcon.innerHTML = '<path d="M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2z"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>';
        lockText.textContent = 'Locked';
        // Update all node cursors
        document.querySelectorAll('[id^="topo-node-"]').forEach(node => {
          node.style.cursor = 'pointer';
        });
      } else {
        lockBtn.style.background = '';
        lockBtn.style.borderColor = '';
        lockBtn.style.color = '';
        lockIcon.innerHTML = '<path d="M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2z"/><path d="M17 11V7a5 5 0 0 0-9.58-2"/>';
        lockText.textContent = 'Unlocked';
        // Update all node cursors
        document.querySelectorAll('[id^="topo-node-"]').forEach(node => {
          node.style.cursor = 'grab';
        });
      }
    }

    // Initialize drag handlers on the SVG
    function initTopologyDrag() {
      const svg = document.getElementById('topology-svg');
      if (!svg) return;

      svg.addEventListener('mousemove', handleTopologyDrag);
      svg.addEventListener('mouseup', handleTopologyDragEnd);
      svg.addEventListener('mouseleave', handleTopologyDragEnd);

      // Touch support
      svg.addEventListener('touchmove', (e) => {
        if (dragState.isDragging) {
          e.preventDefault();
          const touch = e.touches[0];
          handleTopologyDrag({ clientX: touch.clientX, clientY: touch.clientY });
        }
      }, { passive: false });
      svg.addEventListener('touchend', handleTopologyDragEnd);
    }

    function handleTopologyDragStart(e, nodeId) {
      // Don't allow dragging if topology is locked
      if (topologyLocked) return;

      e.stopPropagation();
      const svg = document.getElementById('topology-svg');
      const pt = svg.createSVGPoint();
      pt.x = e.clientX || (e.touches && e.touches[0].clientX);
      pt.y = e.clientY || (e.touches && e.touches[0].clientY);
      const svgP = pt.matrixTransform(svg.getScreenCTM().inverse());

      dragState.isDragging = true;
      dragState.nodeId = nodeId;
      dragState.startX = svgP.x;
      dragState.startY = svgP.y;

      const pos = window.topoNodePositions[nodeId];
      if (pos) {
        dragState.offsetX = svgP.x - pos.x;
        dragState.offsetY = svgP.y - pos.y;
      }

      document.body.style.cursor = 'grabbing';
    }

    function handleTopologyDrag(e) {
      if (!dragState.isDragging || !dragState.nodeId) return;

      const svg = document.getElementById('topology-svg');
      const pt = svg.createSVGPoint();
      pt.x = e.clientX;
      pt.y = e.clientY;
      const svgP = pt.matrixTransform(svg.getScreenCTM().inverse());

      const newX = svgP.x - dragState.offsetX;
      const newY = svgP.y - dragState.offsetY;

      // Update position
      if (window.topoNodePositions[dragState.nodeId]) {
        window.topoNodePositions[dragState.nodeId].x = newX;
        window.topoNodePositions[dragState.nodeId].y = newY;
        customPositions[dragState.nodeId] = { x: newX, y: newY };
      }

      // Update node visual position
      const nodeGroup = document.getElementById('topo-node-' + dragState.nodeId.replace(/[^a-zA-Z0-9]/g, '_'));
      if (nodeGroup) {
        nodeGroup.setAttribute('transform', 'translate(' + newX + ',' + newY + ')');
      }

      // Update connected edges
      updateTopologyEdges();
    }

    function handleTopologyDragEnd() {
      if (dragState.isDragging) {
        dragState.isDragging = false;
        dragState.nodeId = null;
        document.body.style.cursor = '';
      }
    }

    function updateTopologyEdges() {
      const edgesGroup = document.getElementById('topo-edges-group');
      if (!edgesGroup || !window.topoEdgesData) return;

      // Clear existing edges
      edgesGroup.innerHTML = '';

      // Redraw all edges with current positions
      window.topoEdgesData.forEach(edge => {
        if (edge.type === 'network-device') return;

        const source = window.topoNodePositions[edge.from];
        const target = window.topoNodePositions[edge.to];
        if (!source || !target) return;

        // Curved bezier path
        const dx = target.x - source.x;
        const cx1 = source.x + dx * 0.4;
        const cy1 = source.y;
        const cx2 = source.x + dx * 0.6;
        const cy2 = target.y;

        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', 'M ' + source.x + ' ' + source.y + ' C ' + cx1 + ' ' + cy1 + ', ' + cx2 + ' ' + cy2 + ', ' + target.x + ' ' + target.y);
        path.setAttribute('fill', 'none');

        let strokeColor = '#475569';
        if (edge.type === 'lldp' || edge.protocol === 'LLDP') strokeColor = '#22c55e';
        else if (edge.type === 'cdp' || edge.protocol === 'CDP') strokeColor = '#3b82f6';
        if (edge.isWireless) {
          path.setAttribute('stroke-dasharray', '6,4');
        }

        path.setAttribute('stroke', strokeColor);
        path.setAttribute('stroke-width', '2');
        edgesGroup.appendChild(path);

        // Port label
        if (edge.fromPort || edge.toPort) {
          const midX = (source.x + target.x) / 2;
          const midY = (source.y + target.y) / 2;

          const labelBg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
          labelBg.setAttribute('x', midX - 25);
          labelBg.setAttribute('y', midY - 8);
          labelBg.setAttribute('width', '50');
          labelBg.setAttribute('height', '16');
          labelBg.setAttribute('rx', '3');
          labelBg.setAttribute('fill', '#0f172a');
          labelBg.setAttribute('opacity', '0.9');
          edgesGroup.appendChild(labelBg);

          const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
          label.setAttribute('x', midX);
          label.setAttribute('y', midY + 4);
          label.setAttribute('text-anchor', 'middle');
          label.setAttribute('fill', strokeColor);
          label.setAttribute('font-size', '9');
          label.textContent = (edge.fromPort || '') + '↔' + (edge.toPort || '');
          edgesGroup.appendChild(label);
        }
      });

      // Draw wireless client connections
      Object.entries(window.topoNodePositions).forEach(([id, pos]) => {
        if (!pos.isClient) return;

        const client = pos.node;
        const apPos = Object.values(window.topoNodePositions).find(p =>
          p.node && (p.node.serial === client.apSerial || p.node.id === client.apSerial)
        );

        if (apPos) {
          const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
          const dx = pos.x - apPos.x;
          const cx1 = apPos.x + dx * 0.5;
          const cy1 = apPos.y;
          const cx2 = apPos.x + dx * 0.5;
          const cy2 = pos.y;

          path.setAttribute('d', 'M ' + apPos.x + ' ' + apPos.y + ' C ' + cx1 + ' ' + cy1 + ', ' + cx2 + ' ' + cy2 + ', ' + pos.x + ' ' + pos.y);
          path.setAttribute('fill', 'none');
          path.setAttribute('stroke', '#22c55e');
          path.setAttribute('stroke-width', '2');
          path.setAttribute('stroke-dasharray', '6,4');
          edgesGroup.appendChild(path);
        }
      });
    }

    function resetTopologyLayout() {
      customPositions = {};
      // Unlock if locked
      if (topologyLocked) {
        toggleTopologyLock();
      }
      if (topologyData) {
        renderTopology(topologyData);
      }
    }

    async function loadTopologyMap() {
      const loadingDiv = document.getElementById('topology-loading');
      const svgElement = document.getElementById('topology-svg');
      const networkSelect = document.getElementById('topology-network-select');

      loadingDiv.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2" style="animation:spin 1s linear infinite;margin-bottom:16px"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg><div style="font-size:14px">Loading topology...</div>';
      loadingDiv.style.display = 'flex';
      svgElement.style.display = 'none';

      try {
        const selectedNetwork = networkSelect.value;
        const includeClientsCheckbox = document.getElementById('topology-include-clients');
        const includeClients = includeClientsCheckbox ? includeClientsCheckbox.checked : false;

        let url = '/api/topology/map';
        if (selectedNetwork) {
          url = '/api/topology/network/' + selectedNetwork;
        }
        if (includeClients) {
          url += (url.includes('?') ? '&' : '?') + 'includeClients=true';
        }

        const res = await fetch(url);
        const data = await res.json();

        if (data.error) throw new Error(data.error);

        topologyData = data;

        // Update stats
        document.getElementById('topo-total-nodes').textContent = data.nodes ? data.nodes.length : 0;
        document.getElementById('topo-connections').textContent = data.edges ? data.edges.length : 0;
        document.getElementById('topo-networks').textContent = data.networks ? data.networks.length : (selectedNetwork ? 1 : 0);
        const onlineCount = data.nodes ? data.nodes.filter(n => n.status === 'online').length : 0;
        document.getElementById('topo-online').textContent = onlineCount;

        // Populate network dropdown if not already done
        if (networkSelect.options.length <= 1 && data.networks) {
          data.networks.forEach(net => {
            const opt = document.createElement('option');
            opt.value = net.id;
            opt.textContent = net.name;
            networkSelect.appendChild(opt);
          });
        }

        // Render topology
        renderTopology(data);

        loadingDiv.style.display = 'none';
        svgElement.style.display = 'block';

      } catch (err) {
        console.error('Topology load error:', err);
        loadingDiv.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--destructive)" stroke-width="1.5" style="opacity:0.6;margin-bottom:16px"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg><div style="font-size:14px;color:var(--destructive)">Error: ' + err.message + '</div>';
      }
    }

    function renderTopology(data) {
      const svg = document.getElementById('topology-svg');
      const container = document.getElementById('topology-canvas');
      const width = container.clientWidth || 900;
      const height = 600;

      svg.setAttribute('width', width);
      svg.setAttribute('height', height);
      svg.innerHTML = '';

      // Add defs for gradients and filters
      const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
      defs.innerHTML = '<filter id="glow"><feGaussianBlur stdDeviation="2" result="coloredBlur"/><feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>';
      svg.appendChild(defs);

      // Filter out network container nodes, only show devices
      const deviceNodes = data.nodes ? data.nodes.filter(n => n.type !== 'network') : [];

      if (deviceNodes.length === 0) {
        svg.innerHTML = '<text x="' + (width/2) + '" y="' + (height/2) + '" text-anchor="middle" fill="var(--foreground-muted)" font-size="14">No devices found</text>';
        return;
      }

      // Device icon SVG paths
      const deviceIcons = {
        switch: '<rect x="-30" y="-10" width="60" height="20" rx="3" fill="#1e293b" stroke="#475569" stroke-width="1"/><rect x="-26" y="-6" width="4" height="4" rx="1" fill="#22c55e"/><rect x="-18" y="-6" width="4" height="4" rx="1" fill="#22c55e"/><rect x="-10" y="-6" width="4" height="4" rx="1" fill="#22c55e"/><rect x="-2" y="-6" width="4" height="4" rx="1" fill="#22c55e"/><rect x="6" y="-6" width="4" height="4" rx="1" fill="#475569"/><rect x="14" y="-6" width="4" height="4" rx="1" fill="#475569"/><rect x="22" y="-6" width="4" height="4" rx="1" fill="#475569"/>',
        router: '<rect x="-25" y="-18" width="50" height="36" rx="4" fill="#1e293b" stroke="#475569" stroke-width="1"/><rect x="-20" y="-13" width="40" height="8" rx="2" fill="#0f172a"/><circle cx="-14" cy="-9" r="2" fill="#22c55e"/><circle cx="-6" cy="-9" r="2" fill="#22c55e"/><rect x="-20" y="0" width="40" height="8" rx="2" fill="#0f172a"/><circle cx="-14" cy="4" r="2" fill="#3b82f6"/><circle cx="-6" cy="4" r="2" fill="#475569"/>',
        ap: '<circle cx="0" cy="0" r="22" fill="#1e293b" stroke="#475569" stroke-width="2"/><circle cx="0" cy="0" r="14" fill="none" stroke="#3b82f6" stroke-width="1" opacity="0.5"/><circle cx="0" cy="0" r="8" fill="none" stroke="#3b82f6" stroke-width="1" opacity="0.3"/><circle cx="0" cy="0" r="5" fill="#3b82f6"/>',
        laptop: '<rect x="-22" y="-14" width="44" height="28" rx="2" fill="#1e293b" stroke="#475569" stroke-width="1"/><rect x="-18" y="-10" width="36" height="20" rx="1" fill="#0ea5e9" opacity="0.3"/><path d="M-28 14 L-22 14 L-22 16 L22 16 L22 14 L28 14 L28 18 L-28 18 Z" fill="#334155"/>',
        phone: '<rect x="-12" y="-20" width="24" height="40" rx="3" fill="#1e293b" stroke="#475569" stroke-width="1"/><rect x="-9" y="-16" width="18" height="28" rx="1" fill="#0ea5e9" opacity="0.3"/><circle cx="0" cy="16" r="3" fill="#334155"/>',
        camera: '<rect x="-20" y="-12" width="40" height="24" rx="4" fill="#1e293b" stroke="#475569" stroke-width="1"/><circle cx="-5" cy="0" r="8" fill="#0f172a" stroke="#f59e0b" stroke-width="2"/><circle cx="-5" cy="0" r="4" fill="#f59e0b" opacity="0.5"/><rect x="8" y="-6" width="8" height="4" rx="1" fill="#334155"/>',
        wireless: '<path d="M-8 8 Q0 -4 8 8" fill="none" stroke="#22c55e" stroke-width="2" stroke-linecap="round"/><path d="M-12 4 Q0 -10 12 4" fill="none" stroke="#22c55e" stroke-width="2" stroke-linecap="round" opacity="0.7"/><path d="M-16 0 Q0 -16 16 0" fill="none" stroke="#22c55e" stroke-width="2" stroke-linecap="round" opacity="0.4"/>'
      };

      // Build hierarchy: Switches -> connected devices -> wireless clients
      const switches = deviceNodes.filter(n => n.type === 'switch' || (n.model && n.model.startsWith('MS')));
      const routers = deviceNodes.filter(n => n.type === 'appliance' || (n.model && (n.model.startsWith('MX') || n.model.startsWith('Z'))));
      const aps = deviceNodes.filter(n => n.type === 'ap' || n.type === 'wireless' || (n.model && (n.model.startsWith('MR') || n.model.startsWith('CW'))));
      const cameras = deviceNodes.filter(n => (n.model && n.model.startsWith('MV')));
      const others = deviceNodes.filter(n => !switches.includes(n) && !routers.includes(n) && !aps.includes(n) && !cameras.includes(n));

      // Position calculation - horizontal tree layout
      const nodePositions = {};
      const startX = 80;
      const tierSpacing = 180;
      let currentY = 60;
      const verticalSpacing = 90;

      // Build connection map from edges
      const connectionMap = {};
      if (data.edges) {
        data.edges.forEach(edge => {
          if (edge.type === 'network-device') return;
          if (!connectionMap[edge.from]) connectionMap[edge.from] = [];
          if (!connectionMap[edge.to]) connectionMap[edge.to] = [];
          connectionMap[edge.from].push({ target: edge.to, edge });
          connectionMap[edge.to].push({ target: edge.from, edge });
        });
      }

      // Position switches (leftmost)
      switches.forEach((sw, i) => {
        nodePositions[sw.id] = {
          x: startX,
          y: currentY + (i * verticalSpacing * 2),
          node: sw,
          deviceType: 'switch'
        };
      });

      // Position routers and APs connected to switches
      let tier2Y = 40;
      const tier2Devices = [...routers, ...aps, ...cameras, ...others];

      tier2Devices.forEach((device, i) => {
        // Find if connected to a switch
        let connectedSwitch = null;
        const connections = connectionMap[device.id] || connectionMap[device.serial] || [];
        for (const conn of connections) {
          const sw = switches.find(s => s.id === conn.target || s.serial === conn.target);
          if (sw) {
            connectedSwitch = sw;
            break;
          }
        }

        const baseY = connectedSwitch && nodePositions[connectedSwitch.id]
          ? nodePositions[connectedSwitch.id].y
          : tier2Y;

        let deviceType = 'router';
        if (device.type === 'ap' || device.type === 'wireless' || (device.model && (device.model.startsWith('MR') || device.model.startsWith('CW')))) {
          deviceType = 'ap';
        } else if (device.model && device.model.startsWith('MV')) {
          deviceType = 'camera';
        } else if (device.type === 'appliance' || (device.model && (device.model.startsWith('MX') || device.model.startsWith('Z')))) {
          deviceType = 'router';
        } else {
          deviceType = 'laptop';
        }

        nodePositions[device.id] = {
          x: startX + tierSpacing,
          y: baseY + (i * verticalSpacing) - ((tier2Devices.length - 1) * verticalSpacing / 2),
          node: device,
          deviceType: deviceType
        };
        tier2Y += verticalSpacing;
      });

      // If no switches, arrange all devices horizontally
      if (switches.length === 0) {
        let yPos = 100;
        tier2Devices.forEach((device, i) => {
          let deviceType = 'router';
          if (device.type === 'ap' || device.type === 'wireless' || (device.model && (device.model.startsWith('MR') || device.model.startsWith('CW')))) {
            deviceType = 'ap';
          } else if (device.model && device.model.startsWith('MV')) {
            deviceType = 'camera';
          }
          nodePositions[device.id] = {
            x: startX + (i % 3) * tierSpacing,
            y: yPos + Math.floor(i / 3) * verticalSpacing,
            node: device,
            deviceType: deviceType
          };
        });
      }

      // Add wireless clients if available
      const wirelessClients = data.clients || [];
      wirelessClients.forEach((client, i) => {
        // Find connected AP
        const connectedAp = aps.find(ap => ap.serial === client.apSerial || ap.id === client.apSerial);
        const basePos = connectedAp && nodePositions[connectedAp.id]
          ? nodePositions[connectedAp.id]
          : { x: startX + tierSpacing, y: 200 };

        nodePositions['client-' + client.id] = {
          x: basePos.x + tierSpacing,
          y: basePos.y + (i * 70) - 35,
          node: client,
          deviceType: client.deviceType === 'Phone' ? 'phone' : 'laptop',
          isClient: true,
          signalStrength: client.rssi ? Math.min(100, Math.max(0, 100 + client.rssi)) : null
        };
      });

      // Calculate required height
      const allYPositions = Object.values(nodePositions).map(p => p.y);
      const minY = Math.min(...allYPositions, 50);
      const maxY = Math.max(...allYPositions, 100);
      const requiredHeight = Math.max(500, maxY - minY + 150);
      svg.setAttribute('height', requiredHeight);

      // Offset all positions if needed
      const yOffset = minY < 50 ? 50 - minY : 0;
      Object.values(nodePositions).forEach(pos => pos.y += yOffset);

      // Apply custom positions from user dragging
      Object.keys(customPositions).forEach(nodeId => {
        if (nodePositions[nodeId]) {
          nodePositions[nodeId].x = customPositions[nodeId].x;
          nodePositions[nodeId].y = customPositions[nodeId].y;
        }
      });

      // Store positions globally for drag updates
      window.topoNodePositions = nodePositions;
      window.topoEdgesData = data.edges || [];

      // Draw curved connections
      const edgesGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      edgesGroup.setAttribute('id', 'topo-edges-group');
      const lldpEdges = [];

      if (data.edges) {
        data.edges.forEach(edge => {
          if (edge.type === 'network-device') return;

          if (edge.type === 'lldp' || edge.type === 'cdp') {
            lldpEdges.push(edge);
          }

          const source = nodePositions[edge.from] || nodePositions[edge.to.replace ? edge.to : ''];
          const target = nodePositions[edge.to] || nodePositions[edge.from.replace ? edge.from : ''];
          if (!source || !target) return;

          // Curved bezier path
          const dx = target.x - source.x;
          const dy = target.y - source.y;
          const cx1 = source.x + dx * 0.4;
          const cy1 = source.y;
          const cx2 = source.x + dx * 0.6;
          const cy2 = target.y;

          const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
          path.setAttribute('d', 'M ' + source.x + ' ' + source.y + ' C ' + cx1 + ' ' + cy1 + ', ' + cx2 + ' ' + cy2 + ', ' + target.x + ' ' + target.y);
          path.setAttribute('fill', 'none');

          // Color based on protocol
          let strokeColor = '#475569';
          if (edge.type === 'lldp' || edge.protocol === 'LLDP') {
            strokeColor = '#22c55e';
          } else if (edge.type === 'cdp' || edge.protocol === 'CDP') {
            strokeColor = '#3b82f6';
          }

          path.setAttribute('stroke', strokeColor);
          path.setAttribute('stroke-width', '2');
          path.style.cursor = 'pointer';
          path.onclick = () => showLinkDetails(edge);
          edgesGroup.appendChild(path);

          // Port label at midpoint
          if (edge.fromPort || edge.toPort) {
            const midX = (source.x + target.x) / 2;
            const midY = (source.y + target.y) / 2;

            const labelBg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
            labelBg.setAttribute('x', midX - 25);
            labelBg.setAttribute('y', midY - 8);
            labelBg.setAttribute('width', '50');
            labelBg.setAttribute('height', '16');
            labelBg.setAttribute('rx', '3');
            labelBg.setAttribute('fill', '#0f172a');
            labelBg.setAttribute('opacity', '0.9');
            edgesGroup.appendChild(labelBg);

            const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            label.setAttribute('x', midX);
            label.setAttribute('y', midY + 4);
            label.setAttribute('text-anchor', 'middle');
            label.setAttribute('fill', strokeColor);
            label.setAttribute('font-size', '9');
            label.textContent = (edge.fromPort || '') + '↔' + (edge.toPort || '');
            edgesGroup.appendChild(label);
          }
        });
      }

      // Draw wireless client connections (dashed)
      Object.entries(nodePositions).forEach(([id, pos]) => {
        if (!pos.isClient) return;

        // Find connected AP
        const client = pos.node;
        const apPos = Object.values(nodePositions).find(p =>
          p.node && (p.node.serial === client.apSerial || p.node.id === client.apSerial)
        );

        if (apPos) {
          const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
          const dx = pos.x - apPos.x;
          const cx1 = apPos.x + dx * 0.5;
          const cy1 = apPos.y;
          const cx2 = apPos.x + dx * 0.5;
          const cy2 = pos.y;

          path.setAttribute('d', 'M ' + apPos.x + ' ' + apPos.y + ' C ' + cx1 + ' ' + cy1 + ', ' + cx2 + ' ' + cy2 + ', ' + pos.x + ' ' + pos.y);
          path.setAttribute('fill', 'none');
          path.setAttribute('stroke', '#22c55e');
          path.setAttribute('stroke-width', '2');
          path.setAttribute('stroke-dasharray', '6,4');
          edgesGroup.appendChild(path);
        }
      });

      svg.appendChild(edgesGroup);

      // Populate links table
      populateLinksTable(lldpEdges);

      // Draw device nodes
      const nodesGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');

      Object.entries(nodePositions).forEach(([id, pos]) => {
        const node = pos.node;
        const nodeId = id.replace(/[^a-zA-Z0-9]/g, '_');
        const group = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        group.setAttribute('id', 'topo-node-' + nodeId);
        group.setAttribute('transform', 'translate(' + pos.x + ',' + pos.y + ')');
        group.style.cursor = topologyLocked ? 'pointer' : 'grab';

        // Add drag handlers
        group.onmousedown = (e) => {
          e.preventDefault();
          handleTopologyDragStart(e, id);
        };
        group.ontouchstart = (e) => {
          handleTopologyDragStart(e, id);
        };
        group.onclick = (e) => {
          // Only show details if not dragging
          if (!dragState.isDragging) {
            showDeviceDetails(node);
          }
        };

        // Draw device icon based on type
        const iconType = pos.deviceType || 'router';
        const iconG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        iconG.innerHTML = deviceIcons[iconType] || deviceIcons.router;
        group.appendChild(iconG);

        // Status glow for online devices
        if (node.status === 'online') {
          const glow = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
          glow.setAttribute('r', '4');
          glow.setAttribute('cx', iconType === 'switch' ? '26' : '20');
          glow.setAttribute('cy', iconType === 'switch' ? '-6' : '-15');
          glow.setAttribute('fill', '#22c55e');
          glow.setAttribute('filter', 'url(#glow)');
          group.appendChild(glow);
        }

        // Device name label
        const nameLabel = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        nameLabel.setAttribute('y', iconType === 'switch' ? '30' : '35');
        nameLabel.setAttribute('text-anchor', 'middle');
        nameLabel.setAttribute('fill', '#e2e8f0');
        nameLabel.setAttribute('font-size', '11');
        nameLabel.textContent = (node.label || node.name || node.description || node.serial || 'Unknown').substring(0, 18);
        group.appendChild(nameLabel);

        // For APs, show channel info if available
        if (iconType === 'ap' && node.channel) {
          const channelLabel = document.createElementNS('http://www.w3.org/2000/svg', 'text');
          channelLabel.setAttribute('y', '-30');
          channelLabel.setAttribute('text-anchor', 'middle');
          channelLabel.setAttribute('fill', '#94a3b8');
          channelLabel.setAttribute('font-size', '10');
          channelLabel.textContent = node.channel;
          group.appendChild(channelLabel);
        }

        // For wireless clients, show signal strength
        if (pos.isClient && pos.signalStrength !== null) {
          // Wireless signal icon
          const signalG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
          signalG.setAttribute('transform', 'translate(30, -10)');
          signalG.innerHTML = deviceIcons.wireless;
          group.appendChild(signalG);

          // Signal strength percentage
          const signalLabel = document.createElementNS('http://www.w3.org/2000/svg', 'text');
          signalLabel.setAttribute('x', '55');
          signalLabel.setAttribute('y', '-5');
          signalLabel.setAttribute('fill', '#22c55e');
          signalLabel.setAttribute('font-size', '12');
          signalLabel.setAttribute('font-weight', 'bold');
          signalLabel.textContent = pos.signalStrength + '%';
          group.appendChild(signalLabel);
        }

        nodesGroup.appendChild(group);
      });

      svg.appendChild(nodesGroup);

      // Initialize drag handlers
      initTopologyDrag();
    }

    function showDeviceDetails(node) {
      const detailsPanel = document.getElementById('topology-details');
      const infoDiv = document.getElementById('topology-device-info');

      detailsPanel.style.display = 'block';

      const statusColor = node.status === 'online' ? 'var(--success)' : node.status === 'alerting' ? '#f59e0b' : 'var(--destructive)';
      const displayName = node.label || node.name || node.serial || 'Unnamed';

      infoDiv.innerHTML =
        '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">Device Name</div>' +
          '<div style="font-weight:600">' + displayName + '</div>' +
        '</div>' +
        '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">Model</div>' +
          '<div style="font-weight:600">' + (node.model || 'Unknown') + '</div>' +
        '</div>' +
        '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">Serial</div>' +
          '<div style="font-weight:600;font-family:monospace">' + (node.serial || node.id || 'N/A') + '</div>' +
        '</div>' +
        '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">Status</div>' +
          '<div style="font-weight:600;color:' + statusColor + '">' + (node.status || 'Unknown').toUpperCase() + '</div>' +
        '</div>' +
        '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">Tier</div>' +
          '<div style="font-weight:600">' + ({1:'Core',2:'Distribution',3:'Access',4:'Endpoint'}[node.tier] || 'Unknown') + '</div>' +
        '</div>' +
        '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">IP Address</div>' +
          '<div style="font-weight:600;font-family:monospace">' + (node.lanIp || node.ip || 'N/A') + '</div>' +
        '</div>';
    }

    function populateLinksTable(edges) {
      const linksPanel = document.getElementById('topology-links');
      const linksBody = document.getElementById('topology-links-body');
      const linkCount = document.getElementById('topology-link-count');

      if (!edges || edges.length === 0) {
        linksPanel.style.display = 'none';
        return;
      }

      linksPanel.style.display = 'block';
      linkCount.textContent = edges.length + ' link' + (edges.length !== 1 ? 's' : '');

      linksBody.innerHTML = edges.map(edge => {
        const protocolColor = edge.type === 'lldp' || edge.protocol === 'LLDP' ? '#22c55e' : '#3b82f6';
        const protocol = edge.protocol || (edge.type === 'lldp' ? 'LLDP' : edge.type === 'cdp' ? 'CDP' : 'Unknown');

        return '<tr style="border-bottom:1px solid var(--border);cursor:pointer" onclick="showLinkDetails(' + JSON.stringify(edge).replace(/"/g, "'") + ')">' +
          '<td style="padding:10px 8px"><span style="background:' + protocolColor + ';color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">' + protocol + '</span></td>' +
          '<td style="padding:10px 8px">' + (edge.fromDevice || edge.from || 'Unknown') + '</td>' +
          '<td style="padding:10px 8px;font-family:monospace;color:var(--primary)">' + (edge.fromPort || '-') + '</td>' +
          '<td style="padding:10px 8px">' + (edge.toDevice || edge.to || 'Unknown') + '</td>' +
          '<td style="padding:10px 8px;font-family:monospace;color:var(--primary)">' + (edge.toPort || '-') + '</td>' +
          '<td style="padding:10px 8px;font-family:monospace;color:var(--foreground-muted)">' + (edge.toIp || '-') + '</td>' +
          '</tr>';
      }).join('');
    }

    function showLinkDetails(edge) {
      const detailsPanel = document.getElementById('topology-details');
      const infoDiv = document.getElementById('topology-device-info');

      detailsPanel.style.display = 'block';

      const protocolColor = edge.type === 'lldp' || edge.protocol === 'LLDP' ? '#22c55e' : '#3b82f6';
      const protocol = edge.protocol || (edge.type === 'lldp' ? 'LLDP' : edge.type === 'cdp' ? 'CDP' : 'Unknown');

      infoDiv.innerHTML =
        '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">Protocol</div>' +
          '<div style="font-weight:600;color:' + protocolColor + '">' + protocol + '</div>' +
        '</div>' +
        '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">Source Device</div>' +
          '<div style="font-weight:600">' + (edge.fromDevice || edge.from || 'Unknown') + '</div>' +
        '</div>' +
        '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">Source Port</div>' +
          '<div style="font-weight:600;font-family:monospace">' + (edge.fromPort || 'N/A') + '</div>' +
        '</div>' +
        '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">Target Device</div>' +
          '<div style="font-weight:600">' + (edge.toDevice || edge.to || 'Unknown') + '</div>' +
        '</div>' +
        '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">Target Port</div>' +
          '<div style="font-weight:600;font-family:monospace">' + (edge.toPort || 'N/A') + '</div>' +
        '</div>' +
        '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">Target IP</div>' +
          '<div style="font-weight:600;font-family:monospace">' + (edge.toIp || 'N/A') + '</div>' +
        '</div>' +
        (edge.toPlatform ? '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">Platform</div>' +
          '<div style="font-weight:600">' + edge.toPlatform + '</div>' +
        '</div>' : '') +
        (edge.toModel ? '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">Model/Description</div>' +
          '<div style="font-weight:600">' + edge.toModel + '</div>' +
        '</div>' : '') +
        (edge.capabilities ? '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">Capabilities</div>' +
          '<div style="font-weight:600">' + edge.capabilities + '</div>' +
        '</div>' : '') +
        (edge.nativeVlan ? '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">Native VLAN</div>' +
          '<div style="font-weight:600">' + edge.nativeVlan + '</div>' +
        '</div>' : '') +
        (edge.toMac ? '<div style="background:rgba(255,255,255,0.02);padding:12px;border-radius:8px">' +
          '<div style="color:var(--foreground-muted);font-size:11px;margin-bottom:4px">Chassis ID (MAC)</div>' +
          '<div style="font-weight:600;font-family:monospace">' + edge.toMac + '</div>' +
        '</div>' : '');
    }

    // Change Risk Prediction Functions
    async function loadChangeNetworks() {
      try {
        const res = await fetch('/api/change-risk/networks');
        const networks = await res.json();
        const select = document.getElementById('change-network-select');
        select.innerHTML = '<option value="">All Networks</option>';
        networks.forEach(net => {
          const opt = document.createElement('option');
          opt.value = net.id;
          opt.textContent = net.name + ' (' + net.org + ')';
          select.appendChild(opt);
        });
      } catch (err) {
        console.error('Error loading networks:', err);
      }
    }

    async function analyzeChangeRisk() {
      const changeType = document.getElementById('change-type-select').value;
      const targetNetwork = document.getElementById('change-network-select').value;
      const description = document.getElementById('change-description').value;

      const resultsDiv = document.getElementById('change-risk-results');
      const loadingDiv = document.getElementById('change-risk-loading');
      const contentDiv = document.getElementById('change-risk-content');
      const button = document.getElementById('change-risk-button');

      // Show loading
      resultsDiv.style.display = 'block';
      loadingDiv.style.display = 'block';
      contentDiv.style.display = 'none';
      button.disabled = true;
      button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 1s linear infinite"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Analyzing...';

      try {
        const res = await fetch('/api/change-risk/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ changeType, targetNetwork, changeDescription: description })
        });

        const data = await res.json();

        if (data.error) {
          throw new Error(data.error);
        }

        // Hide loading, show content
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';

        // Update risk score
        const riskScore = parseFloat(data.riskScore);
        document.getElementById('change-risk-score').textContent = data.riskScore;

        // Update risk level with color
        const levelEl = document.getElementById('change-risk-level');
        levelEl.textContent = data.riskLevel;
        const levelColors = {
          low: { bg: 'rgba(74,222,128,0.3)', color: 'var(--success)' },
          medium: { bg: 'rgba(251,191,36,0.3)', color: 'var(--warning)' },
          high: { bg: 'rgba(248,113,113,0.3)', color: 'var(--destructive)' },
          critical: { bg: 'rgba(220,38,38,0.4)', color: '#DC2626' }
        };
        const lc = levelColors[data.riskLevel] || levelColors.medium;
        levelEl.style.background = lc.bg;
        levelEl.style.color = lc.color;

        // Update score color
        const scoreEl = document.getElementById('change-risk-score');
        scoreEl.style.color = lc.color;

        // Update banner background
        const banner = document.getElementById('change-risk-banner');
        if (data.riskLevel === 'critical') {
          banner.style.background = 'linear-gradient(135deg,rgba(220,38,38,0.2),rgba(248,113,113,0.1))';
        } else if (data.riskLevel === 'high') {
          banner.style.background = 'linear-gradient(135deg,rgba(248,113,113,0.2),rgba(251,191,36,0.1))';
        } else if (data.riskLevel === 'medium') {
          banner.style.background = 'linear-gradient(135deg,rgba(251,191,36,0.2),rgba(74,222,128,0.1))';
        } else {
          banner.style.background = 'linear-gradient(135deg,rgba(74,222,128,0.2),rgba(59,130,246,0.1))';
        }

        // Update blast radius
        document.getElementById('change-blast-radius').textContent = data.blastRadius.aps + ' APs';
        document.getElementById('change-blast-detail').textContent = data.blastRadius.clients + ' clients affected';

        // Update suggested window
        document.getElementById('change-suggested-window').textContent = data.suggestedWindow.recommended;
        document.getElementById('change-window-reason').textContent = data.suggestedWindow.reason;

        // Update risk factors
        const factorsDiv = document.getElementById('change-risk-factors');
        factorsDiv.innerHTML = Object.entries(data.factors).map(([key, factor]) => {
          const factorColor = factor.score >= 70 ? 'var(--destructive)' :
                             factor.score >= 40 ? 'var(--warning)' : 'var(--success)';
          return '<div style="padding:14px;background:rgba(255,255,255,0.05);border-radius:8px;border-left:3px solid ' + factorColor + '">' +
            '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">' +
            '<span style="font-size:12px;font-weight:600;color:rgba(255,255,255,0.8);text-transform:capitalize">' + key.replace(/([A-Z])/g, ' $1').trim() + '</span>' +
            '<span style="font-size:14px;font-weight:700;color:' + factorColor + '">' + factor.score + '</span>' +
            '</div>' +
            '<div style="font-size:11px;color:rgba(255,255,255,0.5)">' + factor.detail + '</div>' +
            '</div>';
        }).join('');

        // Update recommendations
        const recsDiv = document.getElementById('change-risk-recommendations');
        const priorityColors = {
          critical: { bg: 'rgba(220,38,38,0.15)', border: '#DC2626', icon: '#DC2626' },
          high: { bg: 'rgba(248,113,113,0.15)', border: 'var(--destructive)', icon: 'var(--destructive)' },
          medium: { bg: 'rgba(251,191,36,0.15)', border: 'var(--warning)', icon: 'var(--warning)' },
          info: { bg: 'rgba(59,130,246,0.15)', border: '#3B82F6', icon: '#3B82F6' }
        };
        recsDiv.innerHTML = data.recommendations.map(rec => {
          const pc = priorityColors[rec.priority] || priorityColors.info;
          return '<div style="padding:12px 16px;background:' + pc.bg + ';border-left:3px solid ' + pc.border + ';border-radius:6px">' +
            '<div style="font-weight:600;font-size:13px;color:' + pc.icon + ';margin-bottom:4px">' + rec.title + '</div>' +
            '<div style="font-size:12px;color:rgba(255,255,255,0.7)">' + rec.detail + '</div>' +
            '</div>';
        }).join('');

        // Update historical failures
        const histSection = document.getElementById('change-historical-section');
        const histDiv = document.getElementById('change-historical-failures');
        if (data.historicalFailures && data.historicalFailures.length > 0) {
          histSection.style.display = 'block';
          histDiv.innerHTML = data.historicalFailures.map(f =>
            '<div style="padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.05);font-size:12px">' +
            '<div style="display:flex;justify-content:space-between;gap:12px">' +
            '<span style="color:var(--warning)">' + f.type + '</span>' +
            '<span style="color:rgba(255,255,255,0.4)">' + new Date(f.time).toLocaleString() + '</span>' +
            '</div>' +
            '<div style="color:rgba(255,255,255,0.6);margin-top:4px">' + (f.device || 'Unknown device') + '</div>' +
            '</div>'
          ).join('');
        } else {
          histSection.style.display = 'none';
        }

      } catch (err) {
        console.error('Change risk analysis error:', err);
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';
        document.getElementById('change-risk-score').textContent = 'ERR';
        document.getElementById('change-risk-level').textContent = 'Error';
        document.getElementById('change-risk-factors').innerHTML = '<div style="color:var(--destructive)">Error: ' + err.message + '</div>';
      } finally {
        button.disabled = false;
        button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Analyze Risk';
      }
    }

    // RCA Functions
    function setRcaQuestion(question) {
      document.getElementById('rca-question').value = question;
    }

    async function analyzeRca() {
      const question = document.getElementById('rca-question').value.trim();
      if (!question) {
        alert('Please enter a question');
        return;
      }

      const resultsDiv = document.getElementById('rca-results');
      const loadingDiv = document.getElementById('rca-loading');
      const contentDiv = document.getElementById('rca-content');
      const button = document.getElementById('rca-button');

      // Show loading state
      resultsDiv.style.display = 'block';
      loadingDiv.style.display = 'block';
      contentDiv.style.display = 'none';
      button.disabled = true;
      button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="animation:spin 1s linear infinite"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Analyzing...';

      try {
        const res = await fetch('/api/rca/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ question })
        });

        const data = await res.json();

        if (data.error) {
          throw new Error(data.error);
        }

        // Hide loading, show content
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';

        // Update summary
        const summaryDiv = document.getElementById('rca-summary');
        const summaryColor = data.findings.some(f => f.severity === 'critical') ? 'var(--destructive)' :
                           data.findings.some(f => f.severity === 'high') ? 'var(--warning)' :
                           data.findings.length > 0 ? 'var(--secondary)' : 'var(--success)';
        summaryDiv.style.borderLeftColor = summaryColor;
        summaryDiv.innerHTML = '<div style="font-weight:600;color:' + summaryColor + ';margin-bottom:8px">Analysis Summary</div>' +
                              '<div style="color:rgba(255,255,255,0.87)">' + data.summary + '</div>';

        // Update confidence
        document.getElementById('rca-confidence-bar').style.width = data.confidence + '%';
        document.getElementById('rca-confidence-value').textContent = data.confidence + '%';

        // Update findings
        const findingsDiv = document.getElementById('rca-findings');
        if (data.findings && data.findings.length > 0) {
          findingsDiv.innerHTML = '<div style="font-weight:600;color:rgba(255,255,255,0.87);margin-bottom:12px">Findings</div>' +
            data.findings.map(f => {
              const severityColors = {
                critical: { bg: 'rgba(207,102,121,0.15)', border: 'var(--destructive)', text: 'var(--destructive)' },
                high: { bg: 'rgba(255,183,77,0.15)', border: 'var(--warning)', text: 'var(--warning)' },
                medium: { bg: 'rgba(187,134,252,0.15)', border: 'var(--primary)', text: 'var(--primary)' },
                low: { bg: 'rgba(255,255,255,0.05)', border: 'rgba(255,255,255,0.3)', text: 'rgba(255,255,255,0.6)' }
              };
              const colors = severityColors[f.severity] || severityColors.low;
              return '<div style="padding:12px;background:' + colors.bg + ';border-left:3px solid ' + colors.border + ';border-radius:6px;margin-bottom:8px">' +
                '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">' +
                '<span style="font-weight:600;color:' + colors.text + '">' + f.title + '</span>' +
                '<span style="padding:2px 8px;background:' + colors.border + ';border-radius:10px;font-size:10px;color:rgba(0,0,0,0.87);text-transform:uppercase">' + f.severity + '</span>' +
                '</div>' +
                '<div style="font-size:13px;color:rgba(255,255,255,0.7)">' + f.detail + '</div>' +
                (f.devices ? '<div style="margin-top:8px;font-size:11px;color:rgba(255,255,255,0.5)">Affected: ' + f.devices.slice(0, 5).join(', ') + (f.devices.length > 5 ? '...' : '') + '</div>' : '') +
                '</div>';
            }).join('');
        } else {
          findingsDiv.innerHTML = '';
        }

        // Update recommendations
        const recsDiv = document.getElementById('rca-recommendations');
        if (data.recommendations && data.recommendations.length > 0) {
          recsDiv.innerHTML = '<div style="font-weight:600;color:rgba(255,255,255,0.87);margin-bottom:12px">Recommendations</div>' +
            data.recommendations.map(r =>
              '<div style="padding:12px;background:rgba(129,199,132,0.1);border-left:3px solid var(--success);border-radius:6px;margin-bottom:8px">' +
              '<div style="font-weight:500;color:var(--success);margin-bottom:4px">' + r.title + '</div>' +
              '<div style="font-size:13px;color:rgba(255,255,255,0.7)">' + r.detail + '</div>' +
              '</div>'
            ).join('');
        } else {
          recsDiv.innerHTML = '';
        }

        // Update metrics
        const metricsDiv = document.getElementById('rca-metrics');
        if (data.metrics) {
          const metricItems = [];
          if (data.metrics.totalEvents !== undefined) {
            metricItems.push('<div style="padding:8px 12px;background:rgba(255,255,255,0.05);border-radius:6px;font-size:12px"><span style="color:var(--primary);font-weight:600">' + data.metrics.totalEvents + '</span> Events Analyzed</div>');
          }
          if (data.metrics.totalDevices !== undefined) {
            metricItems.push('<div style="padding:8px 12px;background:rgba(255,255,255,0.05);border-radius:6px;font-size:12px"><span style="color:var(--secondary);font-weight:600">' + data.metrics.totalDevices + '</span> Devices</div>');
          }
          if (data.metrics.offlineDevices !== undefined && data.metrics.offlineDevices > 0) {
            metricItems.push('<div style="padding:8px 12px;background:rgba(207,102,121,0.15);border-radius:6px;font-size:12px"><span style="color:var(--destructive);font-weight:600">' + data.metrics.offlineDevices + '</span> Offline</div>');
          }
          if (data.metrics.eventBreakdown) {
            const topEvents = Object.entries(data.metrics.eventBreakdown).sort((a, b) => b[1] - a[1]).slice(0, 3);
            for (const [event, count] of topEvents) {
              metricItems.push('<div style="padding:8px 12px;background:rgba(255,255,255,0.05);border-radius:6px;font-size:11px"><span style="color:rgba(255,255,255,0.6)">' + event + ':</span> <span style="font-weight:600">' + count + '</span></div>');
            }
          }
          metricsDiv.innerHTML = metricItems.join('');
        }

      } catch (err) {
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';
        document.getElementById('rca-summary').innerHTML = '<div style="color:var(--destructive)">Error: ' + err.message + '</div>';
        document.getElementById('rca-findings').innerHTML = '';
        document.getElementById('rca-recommendations').innerHTML = '';
        document.getElementById('rca-metrics').innerHTML = '';
      }

      // Reset button
      button.disabled = false;
      button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg> Analyze';
    }

    // Allow Enter key to trigger analysis
    document.addEventListener('DOMContentLoaded', function() {
      const rcaInput = document.getElementById('rca-question');
      if (rcaInput) {
        rcaInput.addEventListener('keypress', function(e) {
          if (e.key === 'Enter') {
            analyzeRca();
          }
        });
      }
    });

    // AI Network Intelligence Tab Switching
    function switchAnalysisTab(tab) {
      // Update tab buttons
      const tabs = ['roaming', 'telemetry', 'radar', 'predictive'];
      const colors = {
        roaming: { active: 'linear-gradient(135deg,#00BCD4,#009688)', inactive: 'rgba(0,188,212,0.15)', border: 'rgba(0,188,212,0.3)', text: '#00BCD4', activeText: 'rgba(0,0,0,0.87)' },
        telemetry: { active: 'linear-gradient(135deg,#2196F3,#03A9F4)', inactive: 'rgba(33,150,243,0.15)', border: 'rgba(33,150,243,0.3)', text: '#2196F3', activeText: 'rgba(255,255,255,0.95)' },
        radar: { active: 'linear-gradient(135deg,#4CAF50,#8BC34A)', inactive: 'rgba(76,175,80,0.15)', border: 'rgba(76,175,80,0.3)', text: '#4CAF50', activeText: 'rgba(0,0,0,0.87)' },
        predictive: { active: 'linear-gradient(135deg,#FF5722,#E64A19)', inactive: 'rgba(255,87,34,0.15)', border: 'rgba(255,87,34,0.3)', text: '#FF5722', activeText: 'rgba(255,255,255,0.95)' }
      };

      tabs.forEach(t => {
        const tabBtn = document.getElementById('tab-' + t);
        const panel = document.getElementById('panel-' + t);
        const c = colors[t];

        if (t === tab) {
          tabBtn.style.background = c.active;
          tabBtn.style.border = 'none';
          tabBtn.style.color = c.activeText;
          tabBtn.style.fontWeight = '600';
          panel.style.display = 'block';
        } else {
          tabBtn.style.background = c.inactive;
          tabBtn.style.border = '1px solid ' + c.border;
          tabBtn.style.color = c.text;
          tabBtn.style.fontWeight = '500';
          panel.style.display = 'none';
        }
      });

      // Load networks when radar tab is activated
      if (tab === 'radar') {
        const select = document.getElementById('radar-network-select');
        if (select && select.options.length <= 1) {
          loadRadarNetworks();
        }
      }
    }

    // Roaming Path Tracking Functions
    let roamingTimespan = 86400; // Default 24 hours

    function setRoamingTimespan(seconds) {
      roamingTimespan = seconds;
      const buttons = document.querySelectorAll('#roaming-timespan-selector button');
      buttons.forEach(btn => {
        if (parseInt(btn.dataset.timespan) === seconds) {
          btn.style.background = 'rgba(0,188,212,0.2)';
          btn.style.borderColor = 'rgba(255,255,255,0.2)';
          btn.style.color = '#00BCD4';
        } else {
          btn.style.background = 'transparent';
          btn.style.borderColor = 'rgba(255,255,255,0.12)';
          btn.style.color = 'rgba(255,255,255,0.6)';
        }
      });
    }

    async function runRoamingAnalysis() {
      const resultsDiv = document.getElementById('roaming-results');
      const loadingDiv = document.getElementById('roaming-loading');
      const contentDiv = document.getElementById('roaming-content');
      const button = document.getElementById('roaming-button');

      // Show loading state
      resultsDiv.style.display = 'block';
      loadingDiv.style.display = 'block';
      contentDiv.style.display = 'none';
      button.disabled = true;
      button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="animation:spin 1s linear infinite"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Analyzing...';

      try {
        const res = await fetchWithTimeout('/api/roaming/analysis?timespan=' + roamingTimespan, {}, 30000);
        const data = await res.json();

        if (data.error) {
          throw new Error(data.error);
        }

        // Hide loading, show content
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';

        // Update optimization score
        const score = data.optimization?.score || 0;
        const grade = data.optimization?.grade || '-';
        document.getElementById('roaming-score').textContent = score;
        document.getElementById('roaming-score').style.color = score >= 80 ? 'var(--success)' : score >= 60 ? 'var(--warning)' : 'var(--destructive)';
        document.getElementById('roaming-grade').textContent = grade;
        document.getElementById('roaming-grade').style.background = score >= 80 ? 'rgba(129,199,132,0.3)' : score >= 60 ? 'rgba(255,183,77,0.3)' : 'rgba(207,102,121,0.3)';
        document.getElementById('roaming-summary').textContent = data.optimization?.summary || '';

        // Update metrics - show roaming clients, or unique clients with events if no roams
        const roamingClients = data.clientMovements?.length || 0;
        const uniqueClients = data.metrics?.uniqueClients || 0;
        document.getElementById('roaming-metric-clients').textContent = roamingClients > 0 ? roamingClients : uniqueClients;
        document.getElementById('roaming-metric-roams').textContent = data.metrics?.totalRoams || 0;
        document.getElementById('roaming-metric-failures').textContent = data.metrics?.totalFailures || 0;
        document.getElementById('roaming-metric-sticky').textContent = data.stickyClients?.length || 0;

        // Render recommendations
        const recsDiv = document.getElementById('roaming-recommendations');
        const recs = data.optimization?.recommendations || [];
        if (recs.length > 0) {
          recsDiv.innerHTML = '<div style="font-weight:600;color:rgba(255,255,255,0.87);margin-bottom:12px">AI Recommendations</div>' +
            recs.map(r => {
              const priorityColors = {
                critical: { bg: 'rgba(207,102,121,0.15)', border: 'var(--destructive)', text: 'var(--destructive)' },
                high: { bg: 'rgba(255,183,77,0.15)', border: 'var(--warning)', text: 'var(--warning)' },
                medium: { bg: 'rgba(187,134,252,0.15)', border: 'var(--primary)', text: 'var(--primary)' },
                low: { bg: 'rgba(129,199,132,0.15)', border: 'var(--success)', text: 'var(--success)' }
              };
              const colors = priorityColors[r.priority] || priorityColors.medium;
              return '<div style="padding:12px;background:' + colors.bg + ';border-left:3px solid ' + colors.border + ';border-radius:6px;margin-bottom:8px">' +
                '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">' +
                '<span style="font-weight:600;color:' + colors.text + '">' + r.title + '</span>' +
                '<span style="padding:2px 8px;background:' + colors.border + ';border-radius:10px;font-size:10px;color:rgba(0,0,0,0.87);text-transform:uppercase">' + r.priority + '</span>' +
                '</div>' +
                '<div style="font-size:13px;color:rgba(255,255,255,0.7);margin-bottom:6px">' + (r.issue || '') + '</div>' +
                '<div style="font-size:12px;color:rgba(255,255,255,0.6);padding:8px;background:rgba(0,0,0,0.2);border-radius:4px"><strong>Action:</strong> ' + (r.action || '') + '</div>' +
                (r.details ? '<div style="margin-top:8px;font-size:11px;color:rgba(255,255,255,0.5)">' + r.details.join(' | ') + '</div>' : '') +
                '</div>';
            }).join('');
        } else {
          recsDiv.innerHTML = '';
        }

        // Render top roaming clients
        const clientsList = document.getElementById('roaming-clients-list');
        if (data.clientMovements && data.clientMovements.length > 0) {
          clientsList.innerHTML = data.clientMovements.slice(0, 10).map(c =>
            '<div style="padding:8px 10px;margin:4px 0;background:linear-gradient(rgba(255,255,255,0.03),rgba(255,255,255,0.03)),#121212;border-radius:6px">' +
            '<div style="display:flex;justify-content:space-between;align-items:center">' +
            '<span style="font-size:12px;color:rgba(255,255,255,0.87)">' + (c.clientName || 'Unknown') + '</span>' +
            '<span style="font-size:11px;padding:2px 6px;border-radius:4px;background:#00BCD4;color:#000">' + c.totalRoams + ' roams</span>' +
            '</div>' +
            '<div style="font-size:11px;color:rgba(255,255,255,0.5);margin-top:2px;font-family:var(--font-mono)">' + c.clientMac + '</div>' +
            '<div style="font-size:10px;color:rgba(255,255,255,0.4);margin-top:2px">' + (c.manufacturer || '') + ' · ' + c.uniqueAPs + ' APs visited</div>' +
            '</div>'
          ).join('');
        } else {
          const totalEvents = data.metrics?.totalEvents || 0;
          const uniqueClients = data.metrics?.uniqueClients || 0;
          if (totalEvents > 0) {
            clientsList.innerHTML = '<div class="muted" style="padding:12px;text-align:center">' + uniqueClients + ' clients with ' + totalEvents + ' events<br><span style="font-size:11px">No AP-to-AP transitions detected</span></div>';
          } else {
            clientsList.innerHTML = '<div class="muted" style="padding:12px;text-align:center">No roaming activity detected</div>';
          }
        }

        // Render roaming failures
        const failuresList = document.getElementById('roaming-failures-list');
        if (data.roamingFailures && data.roamingFailures.length > 0) {
          failuresList.innerHTML = data.roamingFailures.slice(0, 10).map(f =>
            '<div style="padding:8px 10px;margin:4px 0;background:linear-gradient(rgba(207,102,121,0.1),rgba(207,102,121,0.05)),#121212;border-radius:6px">' +
            '<div style="display:flex;justify-content:space-between;align-items:center">' +
            '<span style="font-size:12px;color:rgba(255,255,255,0.87)">' + (f.clientName || 'Unknown') + '</span>' +
            '<span style="font-size:11px;padding:2px 6px;border-radius:4px;background:var(--destructive);color:#000">' + f.failureCount + ' fails</span>' +
            '</div>' +
            '<div style="font-size:11px;color:rgba(255,255,255,0.5);margin-top:2px;font-family:var(--font-mono)">' + f.clientMac + '</div>' +
            '<div style="font-size:10px;color:rgba(255,255,255,0.4);margin-top:2px">' + (f.manufacturer || '') + ' · ' + f.failureRate + '% failure rate</div>' +
            '</div>'
          ).join('');
        } else {
          failuresList.innerHTML = '<div style="padding:12px;text-align:center;color:var(--success)"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;vertical-align:middle"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>No roaming failures</div>';
        }

        // Render sticky clients
        const stickyList = document.getElementById('roaming-sticky-list');
        if (data.stickyClients && data.stickyClients.length > 0) {
          stickyList.innerHTML = data.stickyClients.slice(0, 10).map(s =>
            '<div style="padding:8px 10px;margin:4px 0;background:linear-gradient(rgba(255,183,77,0.1),rgba(255,183,77,0.05)),#121212;border-radius:6px">' +
            '<div style="display:flex;justify-content:space-between;align-items:center">' +
            '<span style="font-size:12px;color:rgba(255,255,255,0.87)">' + (s.clientName || 'Unknown') + '</span>' +
            '<span style="font-size:11px;padding:2px 6px;border-radius:4px;background:var(--warning);color:#000">' + s.avgRssi + ' dBm</span>' +
            '</div>' +
            '<div style="font-size:11px;color:rgba(255,255,255,0.5);margin-top:2px;font-family:var(--font-mono)">' + s.clientMac + '</div>' +
            '<div style="font-size:10px;color:rgba(255,255,255,0.4);margin-top:2px">Stuck on: ' + (s.currentAP || 'Unknown') + '</div>' +
            '<div style="font-size:10px;color:var(--warning);margin-top:4px">' + (s.recommendation || '') + '</div>' +
            '</div>'
          ).join('');
        } else {
          stickyList.innerHTML = '<div style="padding:12px;text-align:center;color:var(--success)"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;vertical-align:middle"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>No sticky clients</div>';
        }

        // Render AP transitions
        const transitionsList = document.getElementById('roaming-transitions-list');
        const transitions = Object.entries(data.apTransitions || {}).sort((a, b) => b[1] - a[1]).slice(0, 10);
        if (transitions.length > 0) {
          transitionsList.innerHTML = transitions.map(([path, count]) =>
            '<div style="padding:8px 12px;background:rgba(187,134,252,0.1);border-radius:6px;font-size:12px;display:flex;align-items:center;gap:8px">' +
            '<span style="color:rgba(255,255,255,0.7)">' + path + '</span>' +
            '<span style="padding:2px 6px;background:var(--primary);border-radius:4px;color:#000;font-weight:600;font-size:10px">' + count + '</span>' +
            '</div>'
          ).join('');
        } else {
          transitionsList.innerHTML = '<div class="muted">No transition data</div>';
        }

        // Render insights
        const insightsDiv = document.getElementById('roaming-insights');
        const insights = data.optimization?.insights || [];
        if (insights.length > 0) {
          insightsDiv.innerHTML = '<div style="font-weight:600;color:rgba(255,255,255,0.87);margin-bottom:12px">AI Insights</div>' +
            '<div style="display:grid;gap:8px">' +
            insights.map(i => {
              const typeIcons = {
                success: '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
                traffic_flow: '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
                device_issue: '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--warning)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
                coverage: '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#00BCD4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>'
              };
              return '<div style="padding:10px 12px;background:rgba(255,255,255,0.03);border-radius:6px;display:flex;gap:10px;align-items:flex-start">' +
                '<div style="flex-shrink:0;margin-top:2px">' + (typeIcons[i.type] || typeIcons.coverage) + '</div>' +
                '<div>' +
                '<div style="font-size:13px;font-weight:500;color:rgba(255,255,255,0.87)">' + (i.title || '') + '</div>' +
                (i.detail ? '<div style="font-size:12px;color:rgba(255,255,255,0.6);margin-top:2px">' + i.detail + '</div>' : '') +
                (i.recommendation ? '<div style="font-size:11px;color:rgba(255,255,255,0.5);margin-top:4px;font-style:italic">' + i.recommendation + '</div>' : '') +
                (i.data ? '<div style="font-size:11px;color:rgba(255,255,255,0.5);margin-top:4px">' + i.data.map(d => d.path + ': ' + d.count).join(' | ') + '</div>' : '') +
                '</div></div>';
            }).join('') +
            '</div>';
        } else {
          insightsDiv.innerHTML = '';
        }

      } catch (err) {
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';
        document.getElementById('roaming-optimization').innerHTML = '<div style="color:var(--destructive)">Error: ' + err.message + '</div>';
        document.getElementById('roaming-recommendations').innerHTML = '';
        document.getElementById('roaming-clients-list').innerHTML = '';
        document.getElementById('roaming-failures-list').innerHTML = '';
        document.getElementById('roaming-sticky-list').innerHTML = '';
        document.getElementById('roaming-transitions-list').innerHTML = '';
        document.getElementById('roaming-insights').innerHTML = '';
      }

      // Reset button
      button.disabled = false;
      button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49"/></svg> Analyze';
    }

    // Switch Port Telemetry Functions
    async function loadSwitchTelemetry() {
      const resultsDiv = document.getElementById('switch-telemetry-results');
      const loadingDiv = document.getElementById('switch-telemetry-loading');
      const contentDiv = document.getElementById('switch-telemetry-content');
      const button = document.getElementById('switch-telemetry-button');

      // Show loading state
      resultsDiv.style.display = 'block';
      loadingDiv.style.display = 'block';
      contentDiv.style.display = 'none';
      button.disabled = true;
      button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="animation:spin 1s linear infinite"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Scanning...';

      try {
        const res = await fetchWithTimeout('/api/switch/telemetry', {}, 45000);
        const data = await res.json();

        if (data.error) {
          throw new Error(data.error);
        }

        // Hide loading, show content
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';

        // Update summary metrics
        document.getElementById('telemetry-total-switches').textContent = data.summary?.totalSwitches || 0;
        document.getElementById('telemetry-total-ports').textContent = data.summary?.totalPorts || 0;
        document.getElementById('telemetry-errors').textContent = data.summary?.portsWithErrors || 0;
        document.getElementById('telemetry-crc').textContent = data.summary?.portsWithCRC || 0;
        document.getElementById('telemetry-drops').textContent = data.summary?.portsWithDrops || 0;
        document.getElementById('telemetry-poe').textContent = data.summary?.poeIssues || 0;
        document.getElementById('telemetry-negotiation').textContent = data.summary?.negotiationIssues || 0;
        document.getElementById('telemetry-offline').textContent = data.summary?.offlineSwitches || 0;

        // Render port issues
        const issuesList = document.getElementById('telemetry-issues-list');
        if (data.portIssues && data.portIssues.length > 0) {
          issuesList.innerHTML = data.portIssues.slice(0, 20).map(issue => {
            const typeColors = {
              error: { bg: 'rgba(207,102,121,0.15)', border: 'var(--destructive)', icon: '⚠️' },
              crc: { bg: 'rgba(255,152,0,0.15)', border: '#FF9800', icon: '🔄' },
              drops: { bg: 'rgba(156,39,176,0.15)', border: '#9C27B0', icon: '📉' },
              poe: { bg: 'rgba(255,183,77,0.15)', border: 'var(--warning)', icon: '⚡' },
              negotiation: { bg: 'rgba(121,85,72,0.15)', border: '#795548', icon: '🔗' }
            };
            const colors = typeColors[issue.type] || typeColors.error;
            const severityBadge = issue.severity === 'high' ? 'var(--destructive)' :
                                 issue.severity === 'medium' ? 'var(--warning)' : 'var(--success)';

            return '<div style="padding:10px 12px;margin:6px 0;background:' + colors.bg + ';border-left:3px solid ' + colors.border + ';border-radius:6px">' +
              '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">' +
              '<span style="font-size:13px;font-weight:500;color:rgba(255,255,255,0.87)">' + colors.icon + ' ' + issue.switch + ' - Port ' + issue.port + '</span>' +
              '<div style="display:flex;gap:6px">' +
              '<span style="padding:2px 6px;background:rgba(255,255,255,0.1);border-radius:4px;font-size:10px;color:rgba(255,255,255,0.6);text-transform:uppercase">' + issue.type + '</span>' +
              '<span style="padding:2px 6px;background:' + severityBadge + ';border-radius:4px;font-size:10px;color:rgba(0,0,0,0.87);text-transform:uppercase">' + issue.severity + '</span>' +
              '</div></div>' +
              '<div style="font-size:12px;color:rgba(255,255,255,0.7)">' + issue.detail + '</div>' +
              '<div style="font-size:11px;color:rgba(255,255,255,0.5);margin-top:4px">Organization: ' + issue.organization + '</div>' +
              '</div>';
          }).join('');

          if (data.portIssues.length > 20) {
            issuesList.innerHTML += '<div style="padding:10px;text-align:center;color:rgba(255,255,255,0.5);font-size:12px">...and ' + (data.portIssues.length - 20) + ' more issues</div>';
          }
        } else {
          issuesList.innerHTML = '<div style="padding:20px;text-align:center;background:rgba(129,199,132,0.1);border-radius:8px;color:var(--success)"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:8px;vertical-align:middle"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>No port issues detected - All switches healthy!</div>';
        }

        // Render switches by organization
        const switchesList = document.getElementById('telemetry-switches-list');
        if (data.organizations && data.organizations.length > 0) {
          switchesList.innerHTML = data.organizations.map(org => {
            if (org.switches.length === 0) return '';

            return '<div style="margin-bottom:16px">' +
              '<div style="font-size:13px;font-weight:600;color:rgba(255,255,255,0.87);margin-bottom:8px;padding:8px 12px;background:rgba(33,150,243,0.1);border-radius:6px;display:flex;justify-content:space-between;align-items:center">' +
              '<span>' + org.name + '</span>' +
              '<span style="font-size:11px;color:rgba(255,255,255,0.5)">' + org.switches.length + ' switch(es)' + (org.issueCount > 0 ? ' · <span style="color:var(--warning)">' + org.issueCount + ' issues</span>' : '') + '</span>' +
              '</div>' +
              '<div style="display:grid;gap:8px">' +
              org.switches.map(sw => {
                const totalIssues = Object.values(sw.issues).reduce((a, b) => a + b, 0);
                const statusColor = sw.status === 'online' ? 'var(--success)' :
                                   sw.status === 'alerting' ? 'var(--warning)' : 'var(--destructive)';

                return '<div style="padding:10px 12px;background:linear-gradient(rgba(255,255,255,0.03),rgba(255,255,255,0.03)),#121212;border-radius:6px;border:1px solid rgba(255,255,255,0.08)">' +
                  '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">' +
                  '<div style="display:flex;align-items:center;gap:8px">' +
                  '<span style="width:8px;height:8px;border-radius:50%;background:' + statusColor + '"></span>' +
                  '<span style="font-size:13px;font-weight:500;color:rgba(255,255,255,0.87)">' + sw.name + '</span>' +
                  '</div>' +
                  '<span style="font-size:11px;color:rgba(255,255,255,0.5);font-family:var(--font-mono)">' + sw.model + '</span>' +
                  '</div>' +
                  '<div style="display:flex;gap:12px;flex-wrap:wrap;font-size:11px;color:rgba(255,255,255,0.6)">' +
                  '<span>Ports: <strong>' + sw.activePorts + '/' + sw.totalPorts + '</strong> active</span>' +
                  '<span>IP: ' + sw.lanIp + '</span>' +
                  (totalIssues > 0 ? '<span style="color:var(--warning)">Issues: ' + totalIssues + '</span>' : '<span style="color:var(--success)">No issues</span>') +
                  '</div>' +
                  (totalIssues > 0 ? '<div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">' +
                    (sw.issues.errors > 0 ? '<span style="padding:2px 6px;background:rgba(207,102,121,0.2);border-radius:4px;font-size:10px;color:var(--destructive)">Errors: ' + sw.issues.errors + '</span>' : '') +
                    (sw.issues.crc > 0 ? '<span style="padding:2px 6px;background:rgba(255,152,0,0.2);border-radius:4px;font-size:10px;color:#FF9800">CRC: ' + sw.issues.crc + '</span>' : '') +
                    (sw.issues.drops > 0 ? '<span style="padding:2px 6px;background:rgba(156,39,176,0.2);border-radius:4px;font-size:10px;color:#9C27B0">Drops: ' + sw.issues.drops + '</span>' : '') +
                    (sw.issues.poe > 0 ? '<span style="padding:2px 6px;background:rgba(255,183,77,0.2);border-radius:4px;font-size:10px;color:var(--warning)">PoE: ' + sw.issues.poe + '</span>' : '') +
                    (sw.issues.negotiation > 0 ? '<span style="padding:2px 6px;background:rgba(121,85,72,0.2);border-radius:4px;font-size:10px;color:#795548">Negotiation: ' + sw.issues.negotiation + '</span>' : '') +
                  '</div>' : '') +
                  '</div>';
              }).join('') +
              '</div></div>';
          }).join('');
        } else {
          switchesList.innerHTML = '<div class="muted" style="padding:20px;text-align:center">No switches found in any organization</div>';
        }

      } catch (err) {
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';
        document.getElementById('telemetry-issues-list').innerHTML = '<div style="color:var(--destructive);padding:12px">Error: ' + err.message + '</div>';
        document.getElementById('telemetry-switches-list').innerHTML = '';
      }

      // Reset button
      button.disabled = false;
      button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg> Load Telemetry';
    }

    // ===========================================
    // HEALTH RADAR FUNCTIONS
    // ===========================================
    let healthRadarChart = null;

    async function loadRadarNetworks() {
      const select = document.getElementById('radar-network-select');
      try {
        const res = await fetchWithTimeout('/api/networks', {}, 10000);
        if (!res.ok) throw new Error('Failed to fetch networks');
        const data = await res.json();

        select.innerHTML = '<option value="">Select Network...</option>';
        const networks = data.networks || data;
        if (Array.isArray(networks)) {
          networks.forEach(n => {
            const opt = document.createElement('option');
            opt.value = n.id;
            opt.textContent = n.name;
            select.appendChild(opt);
          });
        }
      } catch (err) {
        console.error('Error loading networks for radar:', err);
      }
    }

    function initHealthRadarChart() {
      const ctx = document.getElementById('health-radar-chart');
      if (!ctx) return;

      if (healthRadarChart) {
        healthRadarChart.destroy();
      }

      healthRadarChart = new Chart(ctx, {
        type: 'radar',
        data: {
          labels: ['Wi-Fi', 'WAN', 'Switching', 'Availability'],
          datasets: [{
            label: 'Health Score',
            data: [0, 0, 0, 0],
            fill: true,
            backgroundColor: 'rgba(76, 175, 80, 0.2)',
            borderColor: '#4CAF50',
            borderWidth: 2,
            pointBackgroundColor: '#4CAF50',
            pointBorderColor: '#fff',
            pointHoverBackgroundColor: '#fff',
            pointHoverBorderColor: '#4CAF50'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            r: {
              suggestedMin: 0,
              suggestedMax: 100,
              ticks: {
                stepSize: 20,
                color: 'rgba(255,255,255,0.5)',
                backdropColor: 'transparent'
              },
              grid: {
                color: 'rgba(255,255,255,0.1)'
              },
              angleLines: {
                color: 'rgba(255,255,255,0.1)'
              },
              pointLabels: {
                color: 'rgba(255,255,255,0.8)',
                font: { size: 12, weight: '500' }
              }
            }
          },
          plugins: {
            legend: { display: false }
          }
        }
      });
    }

    async function runHealthRadar() {
      const resultsDiv = document.getElementById('radar-results');
      const loadingDiv = document.getElementById('radar-loading');
      const contentDiv = document.getElementById('radar-content');
      const button = document.getElementById('radar-button');
      const networkId = document.getElementById('radar-network-select').value;

      if (!networkId) {
        alert('Please select a network first');
        return;
      }

      // Show loading state
      resultsDiv.style.display = 'block';
      loadingDiv.style.display = 'block';
      contentDiv.style.display = 'none';
      button.disabled = true;
      button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="animation:spin 1s linear infinite"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Analyzing...';

      try {
        const res = await fetchWithTimeout('/api/network/health-radar?networkId=' + encodeURIComponent(networkId), {}, 30000);
        const data = await res.json();

        if (data.error) {
          throw new Error(data.error);
        }

        // Hide loading, show content
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';

        // Initialize chart if needed
        if (!healthRadarChart) {
          initHealthRadarChart();
        }

        // Update chart
        if (healthRadarChart) {
          healthRadarChart.data.datasets[0].data = data.radar.values;
          healthRadarChart.update();
        }

        // Update network info
        document.getElementById('radar-network-name').textContent = data.network?.name || networkId;
        document.getElementById('radar-timestamp').textContent = new Date(data.ts).toLocaleString();

        // Update overall score
        const overall = data.overallScore || 0;
        document.getElementById('radar-overall-score').textContent = overall;
        document.getElementById('radar-overall-score').style.color = overall >= 80 ? '#4CAF50' : overall >= 60 ? '#FF9800' : '#F44336';

        const grade = overall >= 90 ? 'A' : overall >= 80 ? 'B' : overall >= 70 ? 'C' : overall >= 60 ? 'D' : 'F';
        const gradeEl = document.getElementById('radar-overall-grade');
        gradeEl.textContent = grade;
        gradeEl.style.background = overall >= 80 ? 'rgba(76,175,80,0.3)' : overall >= 60 ? 'rgba(255,152,0,0.3)' : 'rgba(244,67,54,0.3)';
        gradeEl.style.color = overall >= 80 ? '#4CAF50' : overall >= 60 ? '#FF9800' : '#F44336';

        // Update individual scores
        const scores = data.scores || {};
        document.getElementById('radar-score-wifi').textContent = scores.wifi ?? '--';
        document.getElementById('radar-score-wan').textContent = scores.wan ?? '--';
        document.getElementById('radar-score-switching').textContent = scores.switching ?? '--';
        document.getElementById('radar-score-availability').textContent = scores.availability ?? '--';

        // Color individual scores
        ['wifi', 'wan', 'switching', 'availability'].forEach(key => {
          const el = document.getElementById('radar-score-' + key);
          const val = scores[key] || 0;
          if (val < 60) el.style.opacity = '0.6';
          else el.style.opacity = '1';
        });

        // Update device counts
        const counts = data.counts || {};
        document.getElementById('radar-device-counts').innerHTML =
          'Total: <strong>' + (counts.totalDevices || 0) + '</strong> · ' +
          'Online: <strong style="color:#4CAF50">' + (counts.online || 0) + '</strong><br>' +
          'MR (Wireless): <strong>' + (counts.mr || 0) + '</strong> · ' +
          'MS (Switch): <strong>' + (counts.ms || 0) + '</strong> · ' +
          'MX (Appliance): <strong>' + (counts.mx || 0) + '</strong>';

        // Update KPI details
        const kpis = data.kpis || {};
        const wan = data.wan || {};
        const failed = data.failed || {};
        const chan = data.chan || {};

        let kpiHtml = '';
        if (counts.mr > 0) {
          kpiHtml += '<div>Wi-Fi: Channel Util <strong>' + (chan.utilPct || 0).toFixed(1) + '%</strong> · Failed Conn <strong>' + (failed.perMin || 0).toFixed(2) + '/min</strong> · MR Online <strong>' + (kpis.mrOnlinePct || 0) + '%</strong></div>';
        }
        if (counts.mx > 0) {
          kpiHtml += '<div>WAN: Loss <strong>' + (wan.lossPct || 0) + '%</strong> · Latency <strong>' + (wan.latencyMs || 0) + 'ms</strong>' + (wan.jitterMs ? ' · Jitter <strong>' + wan.jitterMs + 'ms</strong>' : '') + '</div>';
        }
        if (counts.ms > 0) {
          kpiHtml += '<div>Switching: MS Online <strong>' + (kpis.msOnlinePct || 0) + '%</strong></div>';
        }
        kpiHtml += '<div>Availability: All Devices Online <strong>' + (kpis.onlinePct || 0) + '%</strong></div>';

        document.getElementById('radar-kpi-details').innerHTML = kpiHtml || '--';

      } catch (err) {
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';
        document.getElementById('radar-kpi-details').innerHTML = '<div style="color:var(--destructive)">Error: ' + err.message + '</div>';
      }

      // Reset button
      button.disabled = false;
      button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg> Analyze';
    }

    // ===========================================
    // PREDICTIVE FAILURE DETECTION FUNCTIONS
    // ===========================================
    async function runPredictiveAnalysis() {
      const resultsDiv = document.getElementById('predictive-results');
      const loadingDiv = document.getElementById('predictive-loading');
      const contentDiv = document.getElementById('predictive-content');
      const button = document.getElementById('predictive-button');

      // Show loading state
      resultsDiv.style.display = 'block';
      loadingDiv.style.display = 'block';
      contentDiv.style.display = 'none';
      button.disabled = true;
      button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="animation:spin 1s linear infinite"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Analyzing...';

      try {
        const res = await fetchWithTimeout('/api/predictive/failure-detection', {}, 60000);
        const data = await res.json();

        if (data.error) {
          throw new Error(data.error);
        }

        // Hide loading, show content
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';

        // Update risk score
        const riskScore = data.riskScore || 0;
        const riskLevel = data.riskLevel || 'low';
        document.getElementById('predictive-score').textContent = riskScore;
        document.getElementById('predictive-score').style.color = riskScore >= 75 ? '#F44336' : riskScore >= 50 ? '#FF9800' : riskScore >= 25 ? '#FFC107' : '#4CAF50';

        const levelEl = document.getElementById('predictive-level');
        levelEl.textContent = riskLevel;
        levelEl.style.background = riskLevel === 'critical' ? 'rgba(244,67,54,0.3)' :
                                   riskLevel === 'high' ? 'rgba(255,152,0,0.3)' :
                                   riskLevel === 'medium' ? 'rgba(255,193,7,0.3)' : 'rgba(76,175,80,0.3)';
        levelEl.style.color = riskLevel === 'critical' ? '#F44336' :
                              riskLevel === 'high' ? '#FF9800' :
                              riskLevel === 'medium' ? '#FFC107' : '#4CAF50';

        // Update score container color
        const scoreContainer = document.getElementById('predictive-score-container');
        scoreContainer.style.background = riskLevel === 'critical' ? 'linear-gradient(135deg,rgba(244,67,54,0.2),rgba(211,47,47,0.1))' :
                                          riskLevel === 'high' ? 'linear-gradient(135deg,rgba(255,152,0,0.2),rgba(245,124,0,0.1))' :
                                          riskLevel === 'medium' ? 'linear-gradient(135deg,rgba(255,193,7,0.2),rgba(255,160,0,0.1))' :
                                          'linear-gradient(135deg,rgba(76,175,80,0.2),rgba(56,142,60,0.1))';

        // Update summary
        const summary = data.summary || {};
        const summaryText = document.getElementById('predictive-summary-text');
        if (summary.totalRisks === 0) {
          summaryText.textContent = 'No failure risks detected. All monitored devices are operating normally.';
        } else {
          summaryText.textContent = summary.totalRisks + ' potential risk' + (summary.totalRisks > 1 ? 's' : '') + ' detected: ' +
            (summary.critical > 0 ? summary.critical + ' critical, ' : '') +
            (summary.high > 0 ? summary.high + ' high, ' : '') +
            (summary.medium > 0 ? summary.medium + ' medium' : '') +
            '. AI predicts possible outages within 30-120 minutes if unaddressed.';
        }

        // Update signal metrics
        const signals = data.signals || {};
        document.getElementById('predictive-reboots').textContent = signals.reboots || 0;
        document.getElementById('predictive-bursts').textContent = signals.eventBursts || 0;
        document.getElementById('predictive-uplink').textContent = signals.uplinkIssues || 0;
        document.getElementById('predictive-auth').textContent = signals.authFailures || 0;
        document.getElementById('predictive-dhcp').textContent = signals.dhcpFailures || 0;
        document.getElementById('predictive-wireless').textContent = signals.wirelessIssues || 0;
        document.getElementById('predictive-offline').textContent = signals.offlineDevices || 0;
        document.getElementById('predictive-alerting').textContent = signals.alertingDevices || 0;

        // Render risk items
        const risksList = document.getElementById('predictive-risks-list');
        const risks = data.risks || [];
        if (risks.length > 0) {
          risksList.innerHTML = risks.slice(0, 20).map(risk => {
            const severityColors = {
              critical: { bg: 'rgba(244,67,54,0.15)', border: '#F44336', text: '#F44336' },
              high: { bg: 'rgba(255,152,0,0.15)', border: '#FF9800', text: '#FF9800' },
              medium: { bg: 'rgba(255,193,7,0.15)', border: '#FFC107', text: '#FFC107' },
              low: { bg: 'rgba(76,175,80,0.15)', border: '#4CAF50', text: '#4CAF50' }
            };
            const colors = severityColors[risk.severity] || severityColors.medium;

            const typeIcons = {
              device_rebooting: '🔄',
              device_alerting: '⚠️',
              device_offline: '🔴',
              event_burst: '📊',
              uplink_instability: '📡',
              uplink_latency: '⏱️',
              auth_failures: '🔐',
              dhcp_failures: '🌐',
              wireless_instability: '📶'
            };
            const icon = typeIcons[risk.type] || '⚡';

            return '<div style="padding:12px 14px;margin:8px 0;background:' + colors.bg + ';border-left:3px solid ' + colors.border + ';border-radius:8px">' +
              '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px">' +
              '<div style="display:flex;align-items:center;gap:8px">' +
              '<span style="font-size:16px">' + icon + '</span>' +
              '<div>' +
              '<div style="font-size:13px;font-weight:600;color:rgba(255,255,255,0.87)">' + (risk.device || 'Unknown Device') + '</div>' +
              '<div style="font-size:11px;color:rgba(255,255,255,0.5)">' + (risk.org || '') + (risk.network ? ' · ' + risk.network : '') + '</div>' +
              '</div></div>' +
              '<div style="display:flex;gap:6px;flex-wrap:wrap">' +
              '<span style="padding:2px 8px;background:' + colors.border + ';border-radius:10px;font-size:10px;color:rgba(0,0,0,0.87);text-transform:uppercase;font-weight:600">' + risk.severity + '</span>' +
              '<span style="padding:2px 8px;background:rgba(255,255,255,0.1);border-radius:10px;font-size:10px;color:rgba(255,255,255,0.7)">' + (risk.probability || 0) + '% probability</span>' +
              '</div></div>' +
              '<div style="font-size:12px;color:' + colors.text + ';font-weight:500;margin-bottom:4px">' + (risk.signal || '') + '</div>' +
              '<div style="font-size:12px;color:rgba(255,255,255,0.7);margin-bottom:8px">' + (risk.detail || '') + '</div>' +
              '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">' +
              '<div style="font-size:11px;color:rgba(255,255,255,0.5)">Timeframe: <strong>' + (risk.timeframe || 'Unknown') + '</strong></div>' +
              '<div style="font-size:11px;padding:6px 10px;background:rgba(0,0,0,0.2);border-radius:6px;color:rgba(255,255,255,0.8)"><strong>Action:</strong> ' + (risk.recommendation || 'Monitor closely') + '</div>' +
              '</div></div>';
          }).join('');

          if (risks.length > 20) {
            risksList.innerHTML += '<div style="padding:12px;text-align:center;color:rgba(255,255,255,0.5);font-size:12px">...and ' + (risks.length - 20) + ' more risks</div>';
          }
        } else {
          risksList.innerHTML = '<div style="padding:30px;text-align:center;background:rgba(76,175,80,0.1);border-radius:8px;color:#4CAF50">' +
            '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:12px"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>' +
            '<div style="font-size:14px;font-weight:600">All Clear!</div>' +
            '<div style="font-size:12px;margin-top:4px">No failure risks detected across all monitored devices</div></div>';
        }

        // Update device type summaries
        const apRisks = risks.filter(r => r.deviceType === 'wireless');
        const switchRisks = risks.filter(r => r.deviceType === 'switch');
        const mxRisks = risks.filter(r => r.deviceType === 'appliance');

        document.getElementById('predictive-ap-risks').innerHTML = apRisks.length > 0 ?
          apRisks.slice(0, 3).map(r => '<div style="margin:4px 0;padding:6px 8px;background:rgba(255,255,255,0.05);border-radius:4px"><span style="color:rgba(255,255,255,0.8)">' + r.device + '</span> - <span style="color:' + (r.severity === 'critical' ? '#F44336' : r.severity === 'high' ? '#FF9800' : '#FFC107') + '">' + r.signal + '</span></div>').join('') +
          (apRisks.length > 3 ? '<div style="color:rgba(255,255,255,0.4);font-size:11px;margin-top:4px">+' + (apRisks.length - 3) + ' more</div>' : '') :
          '<div style="color:#4CAF50">No AP risks detected</div>';

        document.getElementById('predictive-switch-risks').innerHTML = switchRisks.length > 0 ?
          switchRisks.slice(0, 3).map(r => '<div style="margin:4px 0;padding:6px 8px;background:rgba(255,255,255,0.05);border-radius:4px"><span style="color:rgba(255,255,255,0.8)">' + r.device + '</span> - <span style="color:' + (r.severity === 'critical' ? '#F44336' : r.severity === 'high' ? '#FF9800' : '#FFC107') + '">' + r.signal + '</span></div>').join('') +
          (switchRisks.length > 3 ? '<div style="color:rgba(255,255,255,0.4);font-size:11px;margin-top:4px">+' + (switchRisks.length - 3) + ' more</div>' : '') :
          '<div style="color:#4CAF50">No switch risks detected</div>';

        document.getElementById('predictive-mx-risks').innerHTML = mxRisks.length > 0 ?
          mxRisks.slice(0, 3).map(r => '<div style="margin:4px 0;padding:6px 8px;background:rgba(255,255,255,0.05);border-radius:4px"><span style="color:rgba(255,255,255,0.8)">' + r.device + '</span> - <span style="color:' + (r.severity === 'critical' ? '#F44336' : r.severity === 'high' ? '#FF9800' : '#FFC107') + '">' + r.signal + '</span></div>').join('') +
          (mxRisks.length > 3 ? '<div style="color:rgba(255,255,255,0.4);font-size:11px;margin-top:4px">+' + (mxRisks.length - 3) + ' more</div>' : '') :
          '<div style="color:#4CAF50">No appliance risks detected</div>';

      } catch (err) {
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';
        document.getElementById('predictive-risks-list').innerHTML = '<div style="color:var(--destructive);padding:12px">Error: ' + err.message + '</div>';
      }

      // Reset button
      button.disabled = false;
      button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> Analyze Risks';
    }

    // Load networks for radar on tab switch
    document.getElementById('tab-radar')?.addEventListener('click', () => {
      if (document.getElementById('radar-network-select').options.length <= 1) {
        loadRadarNetworks();
      }
    });

    async function loadOrganizations() {
      const container = document.getElementById('orgs-container');
      try {
        const res = await fetchWithTimeout('/api/organizations', {}, 10000);
        if (!res.ok) throw new Error('Failed to fetch');
        const orgs = await res.json();
        if (orgs.error) {
          container.innerHTML = '<div class="warn" style="font-size:12px">' + orgs.error + '</div>';
          return;
        }
        if (orgs.length === 0) {
          container.innerHTML = '<div class="muted" style="font-size:12px">No organizations</div>';
          return;
        }
        container.innerHTML = orgs.map(org =>
          '<div style="padding:10px 14px;background:rgba(0,0,0,0.3);border:1px solid rgba(157,190,64,0.3);border-radius:8px;min-width:140px">' +
          '<div style="font-size:13px;font-weight:600;color:rgba(255,255,255,0.9);margin-bottom:4px">' + org.name + '</div>' +
          '<a href="' + (org.url || 'https://dashboard.meraki.com') + '" target="_blank" style="font-size:11px;color:#9dbe40;text-decoration:none;display:inline-flex;align-items:center;gap:4px">' +
          'Dashboard <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>' +
          '</a>' +
          '</div>'
        ).join('');
      } catch (err) {
        container.innerHTML = '<div class="warn" style="font-size:12px">Error loading orgs</div>';
      }
    }

    async function loadXiqDevices() {
      const container = document.getElementById('xiq-devices-container');
      try {
        const res = await fetchWithTimeout('/api/xiq/devices?limit=10', {}, 10000);
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
        const res = await fetchWithTimeout('/api/xiq/sites?limit=10', {}, 10000);
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
        const res = await fetchWithTimeout('/api/xiq/clients?limit=10', {}, 10000);
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

    // Fetch with timeout helper
    async function fetchWithTimeout(url, options = {}, timeoutMs = 15000) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetch(url, { ...options, signal: controller.signal });
        clearTimeout(timeoutId);
        return res;
      } catch (err) {
        clearTimeout(timeoutId);
        throw err;
      }
    }

    // Initialize all sections in parallel with proper error handling
    Promise.allSettled([
      loadOrganizations().catch(e => { console.error('loadOrganizations failed:', e); document.getElementById('orgs-container').innerHTML = '<div class="warn">Error loading organizations</div>'; }),
      loadXiqDevices().catch(e => { console.error('loadXiqDevices failed:', e); document.getElementById('xiq-devices-container').innerHTML = '<div class="warn">Error loading XIQ devices</div>'; }),
      loadXiqSites().catch(e => { console.error('loadXiqSites failed:', e); document.getElementById('xiq-sites-container').innerHTML = '<div class="warn">Error loading XIQ sites</div>'; }),
      loadXiqClients().catch(e => { console.error('loadXiqClients failed:', e); document.getElementById('xiq-clients-container').innerHTML = '<div class="warn">Error loading XIQ clients</div>'; }),
      loadBobStats().catch(e => { console.error('loadBobStats failed:', e); document.getElementById('bob-stats-container').innerHTML = '<div class="warn">Error loading BOB stats</div>'; }),
      loadNetworkHealth().catch(e => { console.error('loadNetworkHealth failed:', e); document.getElementById('network-health-container').innerHTML = '<div class="warn">Error loading network health</div>'; }),
      loadPeplinkLocations().catch(e => { console.error('loadPeplinkLocations failed:', e); document.getElementById('peplink-summary-container').innerHTML = '<div class="warn">Error loading PepLink data</div>'; })
    ]).then(() => console.log('Dashboard initialized'));

    let peplinkMap = null;

    // Static locations (always shown)
    const staticLocations = [
      {
        device: 'Dr_BOB',
        organization: 'Extreme Networks',
        group: 'Mobile Lab',
        model: 'Peplink MAX BR1 Mini',
        serial: '1934-28F6-1183',
        status: 'online',
        latitude: 25.792326,
        longitude: -80.14033,
        address: 'Miami, FL',
        lastUpdate: '2025-12-11 13:11:58',
        tag: 'Dr_BOB',
        firmware: '8.5.2 build 5243',
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
        const res = await fetchWithTimeout('/api/peplink/locations', {}, 30000);
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
        const res = await fetchWithTimeout('/api/assets/stats', {}, 10000);
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
          const res = await fetchWithTimeout('/api/assets?search=' + encodeURIComponent(query) + '&limit=25', {}, 10000);
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
          const res = await fetchWithTimeout('/api/networks/' + net.id + '/wireless-health', {}, 15000);
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

      // Flood Events - handled by loadFloodEvents() with timespan selector

      // Load roaming events with default 1 day
      loadRoamingEvents(1);
      // Load flood events with default 24h
      loadFloodEvents(86400);
    }

    // WIPS/Flood events loader with timespan selector
    async function loadFloodEvents(timespan) {
      const floodContainer = document.getElementById('flood-events-container');

      // Update button styles
      const buttons = document.querySelectorAll('#wips-timespan-selector button');
      buttons.forEach(btn => {
        if (parseInt(btn.dataset.timespan) === timespan) {
          btn.style.background = 'rgba(187,134,252,0.2)';
          btn.style.borderColor = 'rgba(187,134,252,0.3)';
          btn.style.color = 'var(--primary)';
        } else {
          btn.style.background = 'transparent';
          btn.style.borderColor = 'rgba(255,255,255,0.12)';
          btn.style.color = 'rgba(255,255,255,0.6)';
        }
      });

      // Format timespan for display
      const timespanLabel = timespan === 3600 ? '1 hour' : timespan === 86400 ? '24 hours' : timespan === 604800 ? '7 days' : '30 days';

      // Show loading state
      floodContainer.innerHTML = '<div class="muted">Loading ' + timespanLabel + ' of WIPS events...</div>';

      const networks = [
        { id: 'L_636133447366083359', name: 'Freehold, NJ' },
        { id: 'L_636133447366083398', name: 'Suffolk, VA' }
      ];

      let allFloods = [];

      for (const net of networks) {
        try {
          const res = await fetchWithTimeout('/api/networks/' + net.id + '/wireless-health?timespan=' + timespan, {}, 15000);
          if (res.ok) {
            const data = await res.json();
            allFloods = allFloods.concat((data.floods?.events || []).map(e => ({...e, network: net.name})));
          }
        } catch (err) {
          console.error('Error loading flood events for', net.name, err);
        }
      }

      // Render flood events
      if (allFloods.length === 0) {
        floodContainer.innerHTML = '<div class="success" style="font-size:13px">No intrusion alerts in the last ' + timespanLabel + '</div>';
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
        '<strong>Analysis:</strong> ' + allFloods.length + ' packet flood events detected in the last ' + timespanLabel + '.</div>';
      }
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
          const res = await fetchWithTimeout('/api/networks/' + net.id + '/wireless-health?timespan=' + timespan, {}, 15000);
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
            if (!merged[c.mac]) merged[c.mac] = { count: 0, aps: new Set(), hostname: null, lpi: false };
            merged[c.mac].count += c.count;
            c.aps.forEach(ap => merged[c.mac].aps.add(ap));
            if (c.hostname && !merged[c.mac].hostname) merged[c.mac].hostname = c.hostname;
            if (c.lpi) merged[c.mac].lpi = true;
          });

          const topClients = Object.entries(merged)
            .sort((a, b) => b[1].count - a[1].count)
            .slice(0, 8);

          roamingContainer.innerHTML =
            '<div style="font-size:12px;font-weight:500;color:rgba(255,255,255,0.7);margin-bottom:8px">Top Roaming Clients</div>' +
            topClients.map(([mac, info]) =>
              '<div style="padding:8px 10px;margin:4px 0;background:linear-gradient(rgba(255,255,255,0.03),rgba(255,255,255,0.03)),#121212;border-radius:6px">' +
              '<div style="display:flex;justify-content:space-between;align-items:center">' +
              '<div>' +
              (info.hostname ? '<div style="font-size:13px;font-weight:500;color:rgba(255,255,255,0.95)">' + info.hostname + (info.lpi ? ' <span style="font-size:9px;padding:1px 4px;border-radius:3px;background:linear-gradient(135deg,#7c3aed,#2563eb);color:#fff;font-weight:600;vertical-align:middle">6E</span>' : '') + '</div>' : '') +
              '<div style="display:flex;align-items:center;gap:6px"><span style="font-size:11px;font-family:var(--font-mono);color:rgba(255,255,255,0.6)">' + mac + '</span>' + (!info.hostname && info.lpi ? '<span style="font-size:9px;padding:1px 4px;border-radius:3px;background:linear-gradient(135deg,#7c3aed,#2563eb);color:#fff;font-weight:600">6E</span>' : '') + '</div>' +
              '</div>' +
              '<span style="font-size:11px;padding:2px 6px;border-radius:4px;background:var(--success);color:#000">' + info.count + ' events</span></div>' +
              '<div style="font-size:11px;color:rgba(255,255,255,0.5);margin-top:4px">Seen on: ' + [...info.aps].join(', ') + '</div></div>'
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
  logLevel: "debug",
  pathRewrite: { '^/': '/mcp' },  // Express strips /mcp mount path, so re-add it for upstream
  onProxyReq: (proxyReq, req) => {
    // Optionally strip Authorization header (some users want to avoid passing tokens through proxy)
    if (!FORWARD_AUTH_HEADER) {
      proxyReq.removeHeader("authorization");
    }
    // Preserve original host if needed (some MCP servers care)
    proxyReq.setHeader("x-original-host", req.headers.host || "");
    console.log(`[Proxy] ${req.method} ${req.url} -> ${UPSTREAM}`);
  },
  onError: (err, req, res) => {
    console.error(`[Proxy Error] ${err.message}`);
    res.status(502).json({ error: "Proxy error", message: err.message, upstream: UPSTREAM });
  }
});

app.use(PROXY_ROUTE, proxy);

app.listen(PORT, () => {
  console.log(`Meraki MCP Proxy running on :${PORT}`);
  console.log(`Upstream: ${UPSTREAM}`);
  console.log(`Proxy: http://localhost:${PORT}${PROXY_ROUTE} -> ${UPSTREAM}`);
});

