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

// =============================================================================
// PREDICTIVE OUTAGE DETECTION ENGINE
// =============================================================================

// Predictive API: Analyze for potential outages
app.get("/api/predictive/analyze", async (req, res) => {
  try {
    const orgs = await merakiFetch("/organizations");
    if (!orgs || orgs.length === 0) {
      return res.status(500).json({ error: "No organizations found" });
    }

    const orgId = orgs[0].id;
    const predictions = {
      timestamp: new Date().toISOString(),
      riskLevel: 'low',
      riskScore: 0,
      predictions: [],
      metrics: {},
      recommendations: []
    };

    // Get devices and their statuses
    const [devices, statuses, networks] = await Promise.all([
      merakiFetch(`/organizations/${orgId}/devices`),
      merakiFetch(`/organizations/${orgId}/devices/statuses`),
      merakiFetch(`/organizations/${orgId}/networks`)
    ]);

    const statusMap = {};
    for (const s of statuses) {
      statusMap[s.serial] = s;
    }

    predictions.metrics.totalDevices = devices.length;
    predictions.metrics.networks = networks.length;

    // ===========================================
    // 1. UPLINK DEGRADATION DETECTION
    // ===========================================
    const uplinkIssues = [];
    const mxDevices = devices.filter(d => d.model?.startsWith('MX') || d.model?.startsWith('Z'));

    for (const device of mxDevices) {
      const status = statusMap[device.serial];
      if (status) {
        // Check for WAN status issues
        if (status.wan1Ip && !status.wan2Ip && device.model?.includes('MX')) {
          uplinkIssues.push({
            device: device.name || device.serial,
            model: device.model,
            issue: 'Single WAN active - no redundancy',
            severity: 'medium'
          });
        }

        // Check for high latency indicators (if device is alerting)
        if (status.status === 'alerting') {
          uplinkIssues.push({
            device: device.name || device.serial,
            model: device.model,
            issue: 'Device in alerting state - possible uplink issues',
            severity: 'high'
          });
        }
      }
    }

    // Try to get uplink status for appliances
    for (const network of networks) {
      if (network.productTypes?.includes('appliance')) {
        try {
          const uplinkStatus = await merakiFetch(`/networks/${network.id}/appliance/uplinks/statuses`);
          if (uplinkStatus && Array.isArray(uplinkStatus)) {
            for (const uplink of uplinkStatus) {
              if (uplink.highAvailability?.enabled === false) {
                uplinkIssues.push({
                  device: uplink.serial,
                  network: network.name,
                  issue: 'High availability not configured',
                  severity: 'low'
                });
              }
              // Check each WAN interface
              for (const iface of (uplink.uplinks || [])) {
                if (iface.status === 'failed') {
                  uplinkIssues.push({
                    device: uplink.serial,
                    network: network.name,
                    interface: iface.interface,
                    issue: `WAN interface ${iface.interface} has failed`,
                    severity: 'critical'
                  });
                } else if (iface.status === 'not connected') {
                  uplinkIssues.push({
                    device: uplink.serial,
                    network: network.name,
                    interface: iface.interface,
                    issue: `WAN interface ${iface.interface} not connected`,
                    severity: 'medium'
                  });
                }
              }
            }
          }
        } catch (e) {
          // Uplink API may not be available for all networks
        }
      }
    }

    if (uplinkIssues.length > 0) {
      const criticalUplink = uplinkIssues.filter(i => i.severity === 'critical');
      predictions.predictions.push({
        category: 'uplink_degradation',
        title: 'Uplink Degradation Risk',
        severity: criticalUplink.length > 0 ? 'critical' : 'medium',
        probability: criticalUplink.length > 0 ? 85 : 45,
        timeframe: criticalUplink.length > 0 ? 'Immediate' : '24-48 hours',
        details: `${uplinkIssues.length} uplink concern(s) detected across your network infrastructure.`,
        issues: uplinkIssues.slice(0, 5),
        impact: 'Internet connectivity loss, site isolation, business disruption'
      });
      predictions.riskScore += criticalUplink.length > 0 ? 40 : 15;
    }

    predictions.metrics.uplinkIssues = uplinkIssues.length;

    // ===========================================
    // 2. RF CONGESTION TRENDS
    // ===========================================
    const rfIssues = [];
    const wirelessDevices = devices.filter(d => d.model?.startsWith('MR') || d.model?.startsWith('CW'));

    // Get wireless events to analyze RF trends
    for (const network of networks) {
      if (network.productTypes?.includes('wireless')) {
        try {
          const events = await merakiFetch(`/networks/${network.id}/events?productType=wireless&perPage=500&timespan=86400`);
          const wirelessEvents = events.events || [];

          // Count RF-related events
          const dfsEvents = wirelessEvents.filter(e => e.type === 'dfs_event');
          const channelChanges = wirelessEvents.filter(e =>
            e.type?.includes('channel') || e.type?.includes('rf') || e.type === 'sunray_auto_rf_channel_change'
          );
          const interferenceEvents = wirelessEvents.filter(e =>
            e.type?.includes('interference') || e.type?.includes('noise')
          );

          predictions.metrics.dfsEvents = (predictions.metrics.dfsEvents || 0) + dfsEvents.length;
          predictions.metrics.channelChanges = (predictions.metrics.channelChanges || 0) + channelChanges.length;

          // DFS events indicate radar detection - potential channel availability issues
          if (dfsEvents.length > 10) {
            rfIssues.push({
              network: network.name,
              issue: `High DFS radar events (${dfsEvents.length})`,
              detail: 'Frequent radar detection causing channel switches on 5GHz',
              severity: 'medium'
            });
          }

          // Excessive channel changes indicate instability
          if (channelChanges.length > 100) {
            rfIssues.push({
              network: network.name,
              issue: `Excessive RF channel changes (${channelChanges.length})`,
              detail: 'RF environment is unstable, causing frequent channel optimization',
              severity: 'high'
            });
          }

          // Check for co-channel interference patterns
          if (interferenceEvents.length > 20) {
            rfIssues.push({
              network: network.name,
              issue: `RF interference detected (${interferenceEvents.length} events)`,
              detail: 'External interference affecting wireless performance',
              severity: 'high'
            });
          }
        } catch (e) {
          // Events may not be available
        }
      }
    }

    // Check AP density and potential congestion
    const apCount = wirelessDevices.length;
    const networkCount = networks.filter(n => n.productTypes?.includes('wireless')).length;
    if (networkCount > 0 && apCount / networkCount > 50) {
      rfIssues.push({
        issue: 'High AP density detected',
        detail: `${apCount} APs across ${networkCount} wireless networks may cause co-channel interference`,
        severity: 'medium'
      });
    }

    if (rfIssues.length > 0) {
      const highSeverity = rfIssues.filter(i => i.severity === 'high' || i.severity === 'critical');
      predictions.predictions.push({
        category: 'rf_congestion',
        title: 'RF Congestion Trend',
        severity: highSeverity.length > 0 ? 'high' : 'medium',
        probability: highSeverity.length > 0 ? 70 : 40,
        timeframe: '1-7 days',
        details: `RF environment showing signs of degradation with ${rfIssues.length} concern(s).`,
        issues: rfIssues.slice(0, 5),
        impact: 'Wireless performance degradation, client disconnections, poor video/voice quality'
      });
      predictions.riskScore += highSeverity.length > 0 ? 25 : 10;

      predictions.recommendations.push({
        title: 'RF Optimization',
        priority: 'medium',
        detail: 'Review channel planning, consider reducing AP power levels, and enable band steering to balance 2.4/5GHz load.'
      });
    }

    predictions.metrics.wirelessAPs = apCount;

    // ===========================================
    // 3. POE DEGRADATION DETECTION
    // ===========================================
    const poeIssues = [];
    const switchDevices = devices.filter(d => d.model?.startsWith('MS') || d.model?.startsWith('C9'));

    for (const sw of switchDevices) {
      const status = statusMap[sw.serial];

      // Check if switch is alerting (could indicate PoE issues)
      if (status?.status === 'alerting') {
        poeIssues.push({
          device: sw.name || sw.serial,
          model: sw.model,
          issue: 'Switch in alerting state - check PoE budget',
          severity: 'medium'
        });
      }

      // Try to get switch port statuses for PoE analysis
      try {
        const ports = await merakiFetch(`/devices/${sw.serial}/switch/ports/statuses`);
        if (ports && Array.isArray(ports)) {
          let poeEnabledPorts = 0;
          let poeDrawingPorts = 0;
          let totalPoePower = 0;

          for (const port of ports) {
            if (port.powerUsageInWh !== undefined || port.enabled) {
              poeEnabledPorts++;
              if (port.powerUsageInWh > 0) {
                poeDrawingPorts++;
                totalPoePower += port.powerUsageInWh || 0;
              }
            }

            // Check for ports with errors
            if (port.errors && port.errors.length > 0) {
              poeIssues.push({
                device: sw.name || sw.serial,
                port: port.portId,
                issue: `Port errors: ${port.errors.join(', ')}`,
                severity: 'medium'
              });
            }
          }

          // High PoE utilization warning
          if (poeDrawingPorts > poeEnabledPorts * 0.8) {
            poeIssues.push({
              device: sw.name || sw.serial,
              model: sw.model,
              issue: `High PoE port utilization (${poeDrawingPorts}/${poeEnabledPorts} ports drawing power)`,
              severity: 'medium'
            });
          }
        }
      } catch (e) {
        // Port status may not be available
      }
    }

    if (poeIssues.length > 0) {
      predictions.predictions.push({
        category: 'poe_degradation',
        title: 'PoE Budget Risk',
        severity: poeIssues.some(i => i.severity === 'high') ? 'high' : 'medium',
        probability: 55,
        timeframe: '1-14 days',
        details: `${poeIssues.length} PoE-related concern(s) detected on switches.`,
        issues: poeIssues.slice(0, 5),
        impact: 'AP power loss, phone outages, camera failures'
      });
      predictions.riskScore += 15;

      predictions.recommendations.push({
        title: 'PoE Capacity Planning',
        priority: 'medium',
        detail: 'Review PoE budget allocation, consider upgrading to higher wattage switches, or implement PoE scheduling for non-critical devices.'
      });
    }

    predictions.metrics.switches = switchDevices.length;
    predictions.metrics.poeIssues = poeIssues.length;

    // ===========================================
    // 4. HARDWARE AGING DETECTION
    // ===========================================
    const agingIssues = [];

    // Known end-of-life/aging models
    const agingModels = {
      'MR18': { eol: true, replacement: 'MR36' },
      'MR26': { eol: true, replacement: 'MR36' },
      'MR32': { eol: true, replacement: 'MR36' },
      'MR33': { aging: true, replacement: 'MR36' },
      'MR42': { aging: true, replacement: 'MR46' },
      'MR52': { aging: true, replacement: 'MR56' },
      'MR62': { eol: true, replacement: 'MR46' },
      'MR66': { eol: true, replacement: 'MR46' },
      'MS220': { aging: true, replacement: 'MS130' },
      'MS320': { aging: true, replacement: 'MS350' },
      'MS350-24': { aging: true, replacement: 'MS355' },
      'MX60': { eol: true, replacement: 'MX68' },
      'MX64': { aging: true, replacement: 'MX68' },
      'MX80': { eol: true, replacement: 'MX85' },
      'MX84': { aging: true, replacement: 'MX85' },
      'MX100': { aging: true, replacement: 'MX105' },
      'Z1': { eol: true, replacement: 'Z4' },
    };

    for (const device of devices) {
      // Check model against aging list
      for (const [model, info] of Object.entries(agingModels)) {
        if (device.model?.includes(model)) {
          agingIssues.push({
            device: device.name || device.serial,
            model: device.model,
            issue: info.eol ? 'End-of-Life hardware' : 'Aging hardware',
            replacement: info.replacement,
            severity: info.eol ? 'high' : 'medium'
          });
          break;
        }
      }

      // Check for devices with frequent status changes (sign of hardware issues)
      const status = statusMap[device.serial];
      if (status?.status === 'alerting' || status?.status === 'dormant') {
        // Check if already flagged
        const alreadyFlagged = agingIssues.some(i => i.device === (device.name || device.serial));
        if (!alreadyFlagged) {
          agingIssues.push({
            device: device.name || device.serial,
            model: device.model,
            issue: `Device in ${status.status} state - potential hardware degradation`,
            severity: 'medium'
          });
        }
      }
    }

    // Check for devices offline for extended periods
    const offlineDevices = statuses.filter(s => s.status === 'offline');
    predictions.metrics.offlineDevices = offlineDevices.length;

    if (offlineDevices.length > 0) {
      for (const offline of offlineDevices.slice(0, 3)) {
        const device = devices.find(d => d.serial === offline.serial);
        agingIssues.push({
          device: device?.name || offline.serial,
          model: device?.model || 'Unknown',
          issue: 'Device offline - possible hardware failure',
          severity: 'critical'
        });
      }
    }

    if (agingIssues.length > 0) {
      const eolCount = agingIssues.filter(i => i.issue === 'End-of-Life hardware').length;
      const criticalCount = agingIssues.filter(i => i.severity === 'critical').length;

      predictions.predictions.push({
        category: 'hardware_aging',
        title: 'Hardware Lifecycle Risk',
        severity: criticalCount > 0 ? 'critical' : (eolCount > 0 ? 'high' : 'medium'),
        probability: criticalCount > 0 ? 90 : (eolCount > 0 ? 75 : 50),
        timeframe: criticalCount > 0 ? 'Immediate' : '30-90 days',
        details: `${agingIssues.length} device(s) identified with hardware concerns. ${eolCount} at end-of-life.`,
        issues: agingIssues.slice(0, 5),
        impact: 'Device failures, security vulnerabilities, loss of support'
      });
      predictions.riskScore += criticalCount > 0 ? 35 : (eolCount > 0 ? 25 : 10);

      if (eolCount > 0) {
        predictions.recommendations.push({
          title: 'Hardware Refresh Planning',
          priority: 'high',
          detail: `${eolCount} end-of-life device(s) should be replaced. Consider a phased hardware refresh to maintain security and support coverage.`
        });
      }
    }

    predictions.metrics.agingDevices = agingIssues.length;

    // ===========================================
    // CALCULATE OVERALL RISK
    // ===========================================
    if (predictions.riskScore >= 60) {
      predictions.riskLevel = 'critical';
    } else if (predictions.riskScore >= 40) {
      predictions.riskLevel = 'high';
    } else if (predictions.riskScore >= 20) {
      predictions.riskLevel = 'medium';
    } else {
      predictions.riskLevel = 'low';
    }

    // Sort predictions by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    predictions.predictions.sort((a, b) =>
      (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4)
    );

    // Add general recommendations if no issues
    if (predictions.predictions.length === 0) {
      predictions.recommendations.push({
        title: 'Continue Monitoring',
        priority: 'low',
        detail: 'No immediate risks detected. Continue regular monitoring and maintain firmware updates.'
      });
    }

    res.json(predictions);

  } catch (err) {
    console.error("Predictive analysis error:", err);
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
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
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
  <div class="wrap">
    <div class="header" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px">
      <div style="display:flex;align-items:center;gap:16px">
        <div class="logo">E</div>
        <div class="brand">
          <div class="brand-name">Extreme Networks MCP Exchange</div>
          <div class="brand-sub">Meraki MCP Server (RDU)</div>
        </div>
      </div>
      <div style="display:flex;flex-direction:column;align-items:flex-end;gap:8px">
        <div style="display:flex;align-items:center;gap:8px">
          <span class="status-dot"></span>
          <span style="font-weight:600;color:var(--secondary)">Service Active</span>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <span class="pill" style="font-size:12px">Upstream: <b>${UPSTREAM}</b></span>
          <span class="pill" style="font-size:12px">Route: <b>${PROXY_ROUTE}</b></span>
        </div>
      </div>
    </div>

    <div style="margin:0 0 24px;padding:20px 24px;background:linear-gradient(135deg,rgba(108,179,63,0.15),rgba(129,199,132,0.1));border:1px solid rgba(108,179,63,0.3);border-radius:12px;display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap">
      <div style="display:flex;align-items:center;gap:16px">
        <div style="flex-shrink:0">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 56" width="64" height="45">
            <path fill="#9dbe40" d="M40,4 C23,4 16,12 14,18 C6,20 0,28 0,36 C0,46 8,52 18,52 L62,52 C72,52 80,46 80,36 C80,28 74,20 66,18 C64,12 57,4 40,4 Z"/>
            <text x="40" y="38" text-anchor="middle" fill="white" font-family="Arial,sans-serif" font-size="28" font-weight="bold">M</text>
          </svg>
        </div>
        <div>
          <h2 style="margin:0;font-size:1.25rem;font-weight:600;color:var(--foreground)">Meraki Dynamic Troubleshooting</h2>
          <div style="font-size:0.875rem;color:var(--foreground-muted);margin-top:4px">Real-time wireless diagnostics and event analysis</div>
        </div>
      </div>
      <div style="text-align:center">
        <div style="font-size:11px;font-weight:600;color:rgba(157,190,64,0.8);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">Meraki Organizations</div>
        <div id="orgs-container" style="display:flex;flex-direction:column;gap:8px;align-items:center">
          <div class="muted" style="font-size:12px">Loading...</div>
        </div>
      </div>
    </div>

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
      <div class="muted">Predictive analysis, roaming optimization, and switch telemetry in one unified view</div>

      <!-- Tab Navigation -->
      <div id="ai-analysis-tabs" style="display:flex;gap:8px;margin-top:16px;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:12px">
        <button onclick="switchAnalysisTab('predictive')" id="tab-predictive" class="ai-tab active" style="padding:10px 20px;background:linear-gradient(135deg,#FF6B35,#FFB74D);border:none;border-radius:8px;color:rgba(0,0,0,0.87);font-weight:600;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:13px">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          Predictive
        </button>
        <button onclick="switchAnalysisTab('roaming')" id="tab-roaming" class="ai-tab" style="padding:10px 20px;background:rgba(0,188,212,0.15);border:1px solid rgba(0,188,212,0.3);border-radius:8px;color:#00BCD4;font-weight:500;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:13px">
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
      </div>

      <!-- Predictive Tab Content -->
      <div id="panel-predictive" class="ai-panel" style="margin-top:20px">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:16px">
          <div>
            <div style="font-size:16px;font-weight:600;color:rgba(255,255,255,0.87)">Predictive Outage Detection</div>
            <div style="font-size:12px;color:rgba(255,255,255,0.5)">AI-powered analysis to predict potential network outages</div>
          </div>
          <button onclick="runPredictiveAnalysis()" id="predictive-button" style="padding:10px 20px;background:linear-gradient(135deg,#FF6B35,#FFB74D);border:none;border-radius:8px;color:rgba(0,0,0,0.87);font-weight:600;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:13px">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
            Run Analysis
          </button>
        </div>

        <div id="predictive-results" style="display:none">
          <div id="predictive-loading" style="display:none;padding:40px;text-align:center">
            <div style="width:40px;height:40px;border:3px solid rgba(255,107,53,0.3);border-top-color:#FF6B35;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto"></div>
            <div style="margin-top:12px;color:var(--foreground-muted)">Analyzing network trends...</div>
          </div>

          <div id="predictive-content" style="display:none">
            <div id="predictive-risk" style="padding:20px;border-radius:12px;margin-bottom:20px;text-align:center">
              <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,0.6);margin-bottom:8px">Overall Risk Level</div>
              <div id="predictive-risk-level" style="font-size:32px;font-weight:700">--</div>
              <div id="predictive-risk-score" style="font-size:14px;color:rgba(255,255,255,0.6);margin-top:4px">Risk Score: --</div>
            </div>

            <div id="predictive-categories" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:20px">
              <div class="pred-category" data-category="uplink" style="padding:14px;background:rgba(255,255,255,0.05);border-radius:8px;border-left:3px solid rgba(255,255,255,0.2)">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v10"/><path d="m4.93 10.93 1.41 1.41"/><path d="M2 18h2"/><path d="M20 18h2"/><path d="m19.07 10.93-1.41 1.41"/><path d="M22 22H2"/><path d="m8 22 4-10 4 10"/></svg>
                  <span style="font-weight:600;font-size:12px">Uplink Health</span>
                </div>
                <div id="pred-uplink-status" style="font-size:11px;color:rgba(255,255,255,0.6)">Checking...</div>
              </div>
              <div class="pred-category" data-category="rf" style="padding:14px;background:rgba(255,255,255,0.05);border-radius:8px;border-left:3px solid rgba(255,255,255,0.2)">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>
                  <span style="font-weight:600;font-size:12px">RF Congestion</span>
                </div>
                <div id="pred-rf-status" style="font-size:11px;color:rgba(255,255,255,0.6)">Checking...</div>
              </div>
              <div class="pred-category" data-category="poe" style="padding:14px;background:rgba(255,255,255,0.05);border-radius:8px;border-left:3px solid rgba(255,255,255,0.2)">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
                  <span style="font-weight:600;font-size:12px">PoE Budget</span>
                </div>
                <div id="pred-poe-status" style="font-size:11px;color:rgba(255,255,255,0.6)">Checking...</div>
              </div>
              <div class="pred-category" data-category="hardware" style="padding:14px;background:rgba(255,255,255,0.05);border-radius:8px;border-left:3px solid rgba(255,255,255,0.2)">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>
                  <span style="font-weight:600;font-size:12px">Hardware Aging</span>
                </div>
                <div id="pred-hardware-status" style="font-size:11px;color:rgba(255,255,255,0.6)">Checking...</div>
              </div>
            </div>

            <div id="predictive-predictions" style="margin-bottom:20px"></div>
            <div id="predictive-recommendations" style="margin-bottom:16px"></div>
            <div id="predictive-metrics" style="display:flex;gap:12px;flex-wrap:wrap"></div>
          </div>
        </div>
      </div>

      <!-- Roaming Tab Content -->
      <div id="panel-roaming" class="ai-panel" style="margin-top:20px;display:none">
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

  <script>
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
      const tabs = ['predictive', 'roaming', 'telemetry', 'radar'];
      const colors = {
        predictive: { active: 'linear-gradient(135deg,#FF6B35,#FFB74D)', inactive: 'rgba(255,107,53,0.15)', border: 'rgba(255,107,53,0.3)', text: '#FF6B35', activeText: 'rgba(0,0,0,0.87)' },
        roaming: { active: 'linear-gradient(135deg,#00BCD4,#009688)', inactive: 'rgba(0,188,212,0.15)', border: 'rgba(0,188,212,0.3)', text: '#00BCD4', activeText: 'rgba(0,0,0,0.87)' },
        telemetry: { active: 'linear-gradient(135deg,#2196F3,#03A9F4)', inactive: 'rgba(33,150,243,0.15)', border: 'rgba(33,150,243,0.3)', text: '#2196F3', activeText: 'rgba(255,255,255,0.95)' },
        radar: { active: 'linear-gradient(135deg,#4CAF50,#8BC34A)', inactive: 'rgba(76,175,80,0.15)', border: 'rgba(76,175,80,0.3)', text: '#4CAF50', activeText: 'rgba(0,0,0,0.87)' }
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

    // Predictive Outage Detection Functions
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
        const res = await fetchWithTimeout('/api/predictive/analyze', {}, 30000);
        const data = await res.json();

        if (data.error) {
          throw new Error(data.error);
        }

        // Hide loading, show content
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';

        // Update overall risk level (API uses riskLevel)
        const riskDiv = document.getElementById('predictive-risk');
        const riskColors = {
          critical: { bg: 'linear-gradient(135deg,rgba(207,102,121,0.3),rgba(207,102,121,0.1))', text: 'var(--destructive)' },
          high: { bg: 'linear-gradient(135deg,rgba(255,183,77,0.3),rgba(255,183,77,0.1))', text: 'var(--warning)' },
          medium: { bg: 'linear-gradient(135deg,rgba(187,134,252,0.3),rgba(187,134,252,0.1))', text: 'var(--primary)' },
          low: { bg: 'linear-gradient(135deg,rgba(129,199,132,0.3),rgba(129,199,132,0.1))', text: 'var(--success)' }
        };
        const riskStyle = riskColors[data.riskLevel] || riskColors.low;
        riskDiv.style.background = riskStyle.bg;
        document.getElementById('predictive-risk-level').textContent = (data.riskLevel || 'low').toUpperCase();
        document.getElementById('predictive-risk-level').style.color = riskStyle.text;
        document.getElementById('predictive-risk-score').textContent = 'Risk Score: ' + (data.riskScore || 0) + '/100';

        // Update category cards based on predictions
        const categoryStyles = {
          critical: { border: 'var(--destructive)', text: 'At Risk' },
          high: { border: 'var(--warning)', text: 'Warning' },
          medium: { border: 'var(--primary)', text: 'Monitor' },
          low: { border: 'var(--success)', text: 'Healthy' }
        };

        // Extract category status from predictions
        const uplinkPred = data.predictions?.find(p => p.category === 'uplink_degradation');
        const rfPred = data.predictions?.find(p => p.category === 'rf_congestion');
        const poePred = data.predictions?.find(p => p.category === 'poe_degradation');
        const hwPred = data.predictions?.find(p => p.category === 'hardware_aging');

        // Uplink
        const uplinkCard = document.querySelector('[data-category="uplink"]');
        const uplinkSeverity = uplinkPred?.severity || 'low';
        const uplinkStyle = categoryStyles[uplinkSeverity] || categoryStyles.low;
        uplinkCard.style.borderLeftColor = uplinkStyle.border;
        document.getElementById('pred-uplink-status').innerHTML = '<span style="color:' + uplinkStyle.border + '">' + uplinkStyle.text + '</span>' + (uplinkPred ? ' - ' + (uplinkPred.issues?.length || 0) + ' issue(s)' : '');

        // RF
        const rfCard = document.querySelector('[data-category="rf"]');
        const rfSeverity = rfPred?.severity || 'low';
        const rfStyle = categoryStyles[rfSeverity] || categoryStyles.low;
        rfCard.style.borderLeftColor = rfStyle.border;
        document.getElementById('pred-rf-status').innerHTML = '<span style="color:' + rfStyle.border + '">' + rfStyle.text + '</span>' + (rfPred ? ' - ' + (rfPred.issues?.length || 0) + ' issue(s)' : '');

        // PoE
        const poeCard = document.querySelector('[data-category="poe"]');
        const poeSeverity = poePred?.severity || 'low';
        const poeStyle = categoryStyles[poeSeverity] || categoryStyles.low;
        poeCard.style.borderLeftColor = poeStyle.border;
        document.getElementById('pred-poe-status').innerHTML = '<span style="color:' + poeStyle.border + '">' + poeStyle.text + '</span>' + (poePred ? ' - ' + (poePred.issues?.length || 0) + ' issue(s)' : '');

        // Hardware
        const hwCard = document.querySelector('[data-category="hardware"]');
        const hwSeverity = hwPred?.severity || 'low';
        const hwStyle = categoryStyles[hwSeverity] || categoryStyles.low;
        hwCard.style.borderLeftColor = hwStyle.border;
        document.getElementById('pred-hardware-status').innerHTML = '<span style="color:' + hwStyle.border + '">' + hwStyle.text + '</span>' + (hwPred ? ' - ' + (hwPred.issues?.length || 0) + ' issue(s)' : '');

        // Render predictions
        const predictionsDiv = document.getElementById('predictive-predictions');
        if (data.predictions && data.predictions.length > 0) {
          predictionsDiv.innerHTML = '<div style="font-weight:600;color:rgba(255,255,255,0.87);margin-bottom:12px">Predicted Outage Risks</div>' +
            data.predictions.map(p => {
              const predColors = {
                critical: { bg: 'rgba(207,102,121,0.15)', border: 'var(--destructive)', text: 'var(--destructive)' },
                high: { bg: 'rgba(255,183,77,0.15)', border: 'var(--warning)', text: 'var(--warning)' },
                medium: { bg: 'rgba(187,134,252,0.15)', border: 'var(--primary)', text: 'var(--primary)' },
                low: { bg: 'rgba(129,199,132,0.15)', border: 'var(--success)', text: 'var(--success)' }
              };
              const colors = predColors[p.severity] || predColors.low;
              const categoryNames = {
                'uplink_degradation': 'Uplink Health',
                'rf_congestion': 'RF Congestion',
                'poe_degradation': 'PoE Budget',
                'hardware_aging': 'Hardware Aging'
              };
              return '<div style="padding:12px;background:' + colors.bg + ';border-left:3px solid ' + colors.border + ';border-radius:6px;margin-bottom:8px">' +
                '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">' +
                '<span style="font-weight:600;color:' + colors.text + '">' + p.title + '</span>' +
                '<div style="display:flex;gap:6px">' +
                '<span style="padding:2px 8px;background:rgba(255,255,255,0.1);border-radius:10px;font-size:10px;color:rgba(255,255,255,0.7)">' + (p.timeframe || 'Unknown') + '</span>' +
                '<span style="padding:2px 8px;background:' + colors.border + ';border-radius:10px;font-size:10px;color:rgba(0,0,0,0.87);text-transform:uppercase">' + p.severity + '</span>' +
                '</div></div>' +
                '<div style="font-size:13px;color:rgba(255,255,255,0.7)">' + (p.details || '') + '</div>' +
                (p.impact ? '<div style="margin-top:6px;font-size:12px;color:rgba(255,183,77,0.9)">Impact: ' + p.impact + '</div>' : '') +
                '<div style="margin-top:8px;font-size:11px;color:rgba(255,255,255,0.5)">Category: ' + (categoryNames[p.category] || p.category) + '</div>' +
                '</div>';
            }).join('');
        } else {
          predictionsDiv.innerHTML = '<div style="padding:20px;text-align:center;background:rgba(129,199,132,0.1);border-radius:8px;color:var(--success)"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:8px"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg><div>No outage risks predicted - Network health is good!</div></div>';
        }

        // Render recommendations (API uses 'detail' not 'action')
        const recsDiv = document.getElementById('predictive-recommendations');
        if (data.recommendations && data.recommendations.length > 0) {
          recsDiv.innerHTML = '<div style="font-weight:600;color:rgba(255,255,255,0.87);margin-bottom:12px">Preventive Actions</div>' +
            data.recommendations.map(r =>
              '<div style="padding:12px;background:rgba(129,199,132,0.1);border-left:3px solid var(--success);border-radius:6px;margin-bottom:8px">' +
              '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">' +
              '<span style="font-weight:500;color:var(--success)">' + r.title + '</span>' +
              '<span style="padding:2px 8px;background:rgba(255,255,255,0.1);border-radius:10px;font-size:10px;color:rgba(255,255,255,0.5);text-transform:uppercase">' + (r.priority || 'medium') + '</span>' +
              '</div>' +
              '<div style="font-size:13px;color:rgba(255,255,255,0.7)">' + (r.detail || '') + '</div>' +
              '</div>'
            ).join('');
        } else {
          recsDiv.innerHTML = '';
        }

        // Render metrics (API uses totalDevices, networks, etc.)
        const metricsDiv = document.getElementById('predictive-metrics');
        const metricItems = [];
        if (data.metrics) {
          if (data.metrics.totalDevices) {
            metricItems.push('<div style="padding:8px 12px;background:rgba(255,255,255,0.05);border-radius:6px;font-size:12px"><span style="color:var(--primary);font-weight:600">' + data.metrics.totalDevices + '</span> Devices</div>');
          }
          if (data.metrics.networks) {
            metricItems.push('<div style="padding:8px 12px;background:rgba(255,255,255,0.05);border-radius:6px;font-size:12px"><span style="color:var(--secondary);font-weight:600">' + data.metrics.networks + '</span> Networks</div>');
          }
          if (data.metrics.wirelessAPs) {
            metricItems.push('<div style="padding:8px 12px;background:rgba(255,255,255,0.05);border-radius:6px;font-size:12px"><span style="color:var(--primary);font-weight:600">' + data.metrics.wirelessAPs + '</span> APs</div>');
          }
          if (data.metrics.switches) {
            metricItems.push('<div style="padding:8px 12px;background:rgba(255,255,255,0.05);border-radius:6px;font-size:12px"><span style="color:var(--primary);font-weight:600">' + data.metrics.switches + '</span> Switches</div>');
          }
          if (data.metrics.offlineDevices > 0) {
            metricItems.push('<div style="padding:8px 12px;background:rgba(207,102,121,0.15);border-radius:6px;font-size:12px"><span style="color:var(--destructive);font-weight:600">' + data.metrics.offlineDevices + '</span> Offline</div>');
          }
          if (data.metrics.dfsEvents > 0) {
            metricItems.push('<div style="padding:8px 12px;background:rgba(255,183,77,0.15);border-radius:6px;font-size:12px"><span style="color:var(--warning);font-weight:600">' + data.metrics.dfsEvents + '</span> DFS Events</div>');
          }
        }
        metricsDiv.innerHTML = metricItems.join('');

      } catch (err) {
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';
        document.getElementById('predictive-risk').innerHTML = '<div style="color:var(--destructive)">Error: ' + err.message + '</div>';
        document.getElementById('predictive-predictions').innerHTML = '';
        document.getElementById('predictive-recommendations').innerHTML = '';
        document.getElementById('predictive-metrics').innerHTML = '';
      }

      // Reset button
      button.disabled = false;
      button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg> Run Analysis';
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

