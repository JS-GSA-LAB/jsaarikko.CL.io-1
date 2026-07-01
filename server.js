import express from "express";
import helmet from "helmet";
import { createProxyMiddleware } from "http-proxy-middleware";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import bcrypt from "bcryptjs";
import session from "express-session";
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { isoUint8Array } from "@simplewebauthn/server/helpers";

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

// ── In-memory user store (seeded from env vars on each start) ───────
const users = new Map();

{
  const adminUser = process.env.ADMIN_USER || "admin";
  const adminPass = process.env.ADMIN_PASS;
  if (adminPass) {
    const hash = bcrypt.hashSync(adminPass, 10);
    const adminRecord = {
      id: 1,
      username: adminUser,
      password_hash: hash,
      display_name: "Administrator",
      role: "admin",
    };

    // Load persisted WebAuthn credential from env var
    if (process.env.WEBAUTHN_CREDENTIAL) {
      try {
        adminRecord.webauthn_credential = JSON.parse(process.env.WEBAUTHN_CREDENTIAL);
        console.log("Loaded WebAuthn passkey for admin user");
      } catch (e) {
        console.warn("Failed to parse WEBAUTHN_CREDENTIAL:", e.message);
      }
    }

    users.set(adminUser.toLowerCase(), adminRecord);
    console.log(`Seeded admin user "${adminUser}"`);
  } else {
    console.warn("No ADMIN_PASS set — no admin user seeded. Login will be unavailable.");
  }
}

// ── Seed additional users from PORTAL_USERS env var ──────────────────
let nextUserId = 2;
{
  const portalUsersEnv = process.env.PORTAL_USERS;
  if (portalUsersEnv) {
    try {
      const extraUsers = JSON.parse(portalUsersEnv);
      for (const u of extraUsers) {
        if (!u.username) continue;
        if (!u.password && !u.password_hash) continue;
        const key = u.username.toLowerCase();
        if (users.has(key)) continue; // don't overwrite admin
        const hash = u.password_hash || bcrypt.hashSync(u.password, 10);
        users.set(key, {
          id: nextUserId++,
          username: u.username,
          password_hash: hash,
          display_name: u.display_name || u.username,
          role: u.role || "viewer",
        });
      }
      console.log(`Seeded ${extraUsers.length} additional portal user(s) from PORTAL_USERS`);
    } catch (e) {
      console.warn("Failed to parse PORTAL_USERS:", e.message);
    }
  }
}

// ── Sync portal users to Railway env var for persistence ─────────────
const RAILWAY_API_TOKEN = process.env.RAILWAY_API_TOKEN || "";
const RAILWAY_PROJECT_ID = process.env.RAILWAY_PROJECT_ID || "";
const RAILWAY_ENVIRONMENT_ID = process.env.RAILWAY_ENVIRONMENT_ID || "";
const RAILWAY_SERVICE_ID = process.env.RAILWAY_SERVICE_ID || "";

console.log("[Railway sync diagnostics]",
  "API_TOKEN:", RAILWAY_API_TOKEN ? "set" : "MISSING",
  "| PROJECT_ID:", RAILWAY_PROJECT_ID || "MISSING",
  "| ENV_ID:", RAILWAY_ENVIRONMENT_ID || "MISSING",
  "| SERVICE_ID:", RAILWAY_SERVICE_ID || "MISSING",
  "| PORTAL_USERS env:", process.env.PORTAL_USERS ? `loaded (${process.env.PORTAL_USERS.length} chars)` : "empty"
);

async function syncPortalUsersToRailway() {
  if (!RAILWAY_API_TOKEN) {
    console.warn("PORTAL_USERS sync skipped: RAILWAY_API_TOKEN not set. Generate one at Railway → Account Settings → Tokens.");
    return;
  }
  if (!RAILWAY_PROJECT_ID || !RAILWAY_ENVIRONMENT_ID || !RAILWAY_SERVICE_ID) {
    console.warn("PORTAL_USERS sync skipped: missing RAILWAY_PROJECT_ID, RAILWAY_ENVIRONMENT_ID, or RAILWAY_SERVICE_ID (these are auto-injected by Railway at runtime).");
    return;
  }
  const adminUser = (process.env.ADMIN_USER || "admin").toLowerCase();
  const portalUsers = [];
  for (const u of users.values()) {
    if (u.username.toLowerCase() === adminUser) continue; // admin is managed by ADMIN_USER/ADMIN_PASS
    portalUsers.push({
      username: u.username,
      password_hash: u.password_hash,
      display_name: u.display_name,
      role: u.role,
    });
  }
  const value = JSON.stringify(portalUsers);
  try {
    const res = await fetch("https://backboard.railway.app/graphql/v2", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${RAILWAY_API_TOKEN}` },
      body: JSON.stringify({
        query: `mutation($input: VariableUpsertInput!) { variableUpsert(input: $input) }`,
        variables: { input: { projectId: RAILWAY_PROJECT_ID, environmentId: RAILWAY_ENVIRONMENT_ID, serviceId: RAILWAY_SERVICE_ID, name: "PORTAL_USERS", value } },
      }),
    });
    const body = await res.json();
    if (body.errors) console.warn("Railway env sync warning:", body.errors[0].message);
    else console.log("Synced PORTAL_USERS to Railway env var");
  } catch (e) {
    console.warn("Failed to sync PORTAL_USERS to Railway:", e.message);
  }
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
 * - ADMIN_USER              (optional) default "admin" — username seeded on first run
 * - ADMIN_PASS              (required on first deploy) password for seeded admin account
 * - SESSION_SECRET           (required) random string for cookie signing
 * - DATA_DIR                (unused, reserved for future persistent storage)
 * - ANTHROPIC_API_KEY       (optional) Anthropic API key for Claude chat integration
 * - FORWARD_AUTH_HEADER     (optional) default "true" => forward Authorization header to upstream
 * - RP_ID                   (optional) WebAuthn relying party ID — defaults to RAILWAY_PUBLIC_DOMAIN or "localhost"
 * - WEBAUTHN_CREDENTIAL     (optional) JSON-stringified WebAuthn credential for passkey login
 * - PORTAL_USERS            (optional) JSON array of additional users (supports password or password_hash)
 * - RAILWAY_API_TOKEN       (optional) Railway API token — enables auto-sync of portal users across deploys
 *
 * Notes:
 * - This app provides a simple web UI and a reverse-proxy endpoint.
 * - Your Claude/clients can point to: https://<your-railway-domain>/mcp
 * - Your existing Meraki MCP server remains where it is; Railway just fronts it with a UI + stable URL.
 */

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || "";

const MERAKI_API_BASE = "https://api.meraki.com/api/v1";
const MERAKI_API_KEY = process.env.MERAKI_API_KEY || "";

// ── WebAuthn / Passkey configuration ────────────────────────────────
const RP_ID = process.env.RP_ID || process.env.RAILWAY_PUBLIC_DOMAIN || "localhost";
const RP_ORIGIN = RP_ID === "localhost" ? `http://localhost:${process.env.PORT || 3000}` : `https://${RP_ID}`;
const RP_NAME = "GSA VC Portal";
const challenges = new Map(); // temporary challenge storage with TTL

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
    console.error('[meraki]', res.status, text?.slice(0, 300));
    throw new Error('Meraki API error: ' + res.status);
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
    console.error('[xiq]', res.status, text?.slice(0, 300));
    throw new Error('XIQ API error: ' + res.status);
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
    console.error('[peplink]', res.status, text?.slice(0, 300));
    throw new Error('PepLink API error: ' + res.status);
  }
  const text = await res.text();
  return text ? JSON.parse(text) : { success: true };
}

const app = express();

const PORT = Number(process.env.PORT || 3000);
const UPSTREAM = (process.env.UPSTREAM_MCP_URL || "").replace(/\/+$/, "");
const PROXY_ROUTE = process.env.PROXY_ROUTE || "/mcp";
const UI_ROUTE = process.env.UI_ROUTE || "/";
const FORWARD_AUTH_HEADER = (process.env.FORWARD_AUTH_HEADER ?? "false").toLowerCase() === "true";

if (!UPSTREAM) {
  console.error("Missing required env var UPSTREAM_MCP_URL");
  process.exit(1);
}

app.disable("x-powered-by");
if (process.env.RAILWAY_ENVIRONMENT) app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));

// ── Session auth ────────────────────────────────────────────────────
app.use(express.urlencoded({ extended: false }));

// Fail-closed: refuse to run with the insecure default session secret in production.
// A predictable secret lets an attacker forge session cookies and bypass auth entirely.
if (process.env.RAILWAY_ENVIRONMENT && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === "dev-secret-change-me")) {
  console.error("Refusing to start in production without a strong SESSION_SECRET. Set SESSION_SECRET.");
  process.exit(1);
}
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret-change-me";
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    secure: !!process.env.RAILWAY_ENVIRONMENT,
    httpOnly: true,
    sameSite: "lax",
  },
}));

function requireAuth(req, res, next) {
  if (req.path === "/login" || req.path === "/healthz") return next();
  if (req.path === "/webauthn/auth/options" || req.path === "/webauthn/auth/verify") return next();
  if (req.session && req.session.userId) return next();
  const accept = req.headers.accept || "";
  if (accept.includes("text/html")) return res.redirect("/login");
  return res.status(401).json({ error: "Authentication required" });
}
app.use(requireAuth);

// Health
app.get("/healthz", (_req, res) => res.json({ ok: true }));

// ── Auth routes ─────────────────────────────────────────────────────
app.get("/login", (req, res) => {
  if (req.session && req.session.userId) return res.redirect("/");
  const error = req.query.error ? "Invalid username or password." : "";
  res.send(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign In — GSA VC Portal</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    background:#0d1117;color:#e6edf3;display:flex;align-items:center;justify-content:center;min-height:100vh}
  .card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:40px;width:100%;max-width:380px}
  .logo{width:48px;height:48px;background:linear-gradient(135deg,#7c3aed,#6d28d9);border-radius:10px;
    display:flex;align-items:center;justify-content:center;font-weight:700;font-size:22px;color:#fff;margin:0 auto 16px}
  h1{text-align:center;font-size:20px;margin-bottom:4px}
  .sub{text-align:center;font-size:13px;color:#8b949e;margin-bottom:24px}
  label{display:block;font-size:13px;color:#8b949e;margin-bottom:6px}
  input{width:100%;padding:10px 12px;background:#0d1117;border:1px solid #30363d;border-radius:6px;
    color:#e6edf3;font-size:14px;margin-bottom:16px;outline:none}
  input:focus{border-color:#7c3aed}
  button{width:100%;padding:10px;background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;
    border:none;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer}
  button:hover{opacity:0.9}
  .error{background:rgba(248,81,73,0.1);border:1px solid rgba(248,81,73,0.4);color:#f85149;
    border-radius:6px;padding:8px 12px;font-size:13px;margin-bottom:16px;text-align:center}
  .divider{display:flex;align-items:center;margin:20px 0;color:#8b949e;font-size:12px}
  .divider::before,.divider::after{content:'';flex:1;border-top:1px solid #30363d}
  .divider span{padding:0 12px}
  .passkey-btn{width:100%;padding:10px;background:transparent;color:#e6edf3;
    border:1px solid #30363d;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;
    display:flex;align-items:center;justify-content:center;gap:8px;transition:border-color 0.2s}
  .passkey-btn:hover{border-color:#7c3aed}
  .passkey-btn svg{width:18px;height:18px}
</style></head><body>
<div class="card">
  <div class="logo">E</div>
  <h1>GSA VC Portal</h1>
  <p class="sub">Sign in to continue</p>
  ${error ? '<div class="error">' + error + '</div>' : ''}
  <form method="POST" action="/login">
    <label for="username">Username</label>
    <input id="username" name="username" type="text" required autofocus>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" required>
    <button type="submit">Sign In</button>
  </form>
  <div id="passkey-section">
    <div class="divider"><span>or</span></div>
    <button type="button" class="passkey-btn" id="passkey-login-btn" onclick="loginWithPasskey()">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 11c0-2.21 1.79-4 4-4s4 1.79 4 4-1.79 4-4 4"/>
        <path d="M16 15v6l-2-1-2 1v-6"/>
        <circle cx="16" cy="11" r="1"/>
        <path d="M2 18c0-3.31 2.69-6 6-6s6 2.69 6 6"/>
        <circle cx="8" cy="8" r="3"/>
      </svg>
      Sign in with Passkey
    </button>
    <div id="passkey-error" class="error" style="display:none;margin-top:12px"></div>
  </div>
</div>
<script>
async function loadWebAuthnBrowser() {
  if (typeof SimpleWebAuthnBrowser !== 'undefined') return;
  await new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = 'https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js';
    s.onload = resolve;
    s.onerror = () => reject(new Error('Failed to load WebAuthn library'));
    document.head.appendChild(s);
  });
}
async function loginWithPasskey() {
  const errEl = document.getElementById('passkey-error');
  errEl.style.display = 'none';
  try {
    await loadWebAuthnBrowser();
    const optRes = await fetch('/webauthn/auth/options');
    if (!optRes.ok) {
      const body = await optRes.json().catch(() => ({}));
      throw new Error(body.error || 'No passkeys registered yet. Log in with password first, then register a passkey from the sidebar.');
    }
    const opts = await optRes.json();
    const authResp = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: opts });
    const verRes = await fetch('/webauthn/auth/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(authResp),
    });
    const result = await verRes.json();
    if (result.verified) {
      window.location.href = result.redirect || '/';
    } else {
      errEl.textContent = 'Passkey verification failed.';
      errEl.style.display = 'block';
    }
  } catch (e) {
    if (e.name === 'NotAllowedError') return;
    errEl.textContent = e.message || 'Passkey authentication failed.';
    errEl.style.display = 'block';
  }
}
</script>
</body></html>`);
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.redirect("/login?error=1");

  const user = users.get(username.toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.redirect("/login?error=1");
  }

  req.session.regenerate((err) => {
    if (err) return res.redirect("/login?error=1");
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.displayName = user.display_name;
    req.session.role = user.role;
    res.redirect("/");
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.redirect("/login");
  });
});

// ── WebAuthn / Passkey routes ───────────────────────────────────────

// Registration: generate options (requires active session)
app.get("/webauthn/register/options", async (req, res) => {
  try {
    const user = users.get(req.session.username.toLowerCase());
    if (!user) return res.status(400).json({ error: "User not found" });

    const opts = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: isoUint8Array.fromUTF8String(String(user.id)),
      userName: user.username,
      userDisplayName: user.display_name,
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
      excludeCredentials: user.webauthn_credential
        ? [{ id: user.webauthn_credential.credentialID, type: "public-key" }]
        : [],
    });

    challenges.set(req.session.userId, { challenge: opts.challenge, expires: Date.now() + 5 * 60 * 1000 });
    res.json(opts);
  } catch (e) {
    console.error("WebAuthn register options error:", e);
    res.status(500).json({ error: e.message });
  }
});

// Registration: verify response (requires active session)
app.post("/webauthn/register/verify", express.json(), async (req, res) => {
  try {
    const stored = challenges.get(req.session.userId);
    if (!stored || Date.now() > stored.expires) {
      return res.status(400).json({ error: "Challenge expired" });
    }

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: stored.challenge,
      expectedOrigin: RP_ORIGIN,
      expectedRPID: RP_ID,
    });

    challenges.delete(req.session.userId);

    if (verification.verified && verification.registrationInfo) {
      const { credential } = verification.registrationInfo;
      const credentialJSON = {
        credentialID: credential.id,
        credentialPublicKey: Array.from(credential.publicKey),
        counter: credential.counter,
        transports: req.body.response?.transports || [],
      };

      // Attach to in-memory user
      const user = users.get(req.session.username.toLowerCase());
      if (user) user.webauthn_credential = credentialJSON;

      const credentialStr = JSON.stringify(credentialJSON);
      console.log("\n╔══════════════════════════════════════════════════════════════╗");
      console.log("║  WEBAUTHN CREDENTIAL — Copy this to Railway env var:       ║");
      console.log("╠══════════════════════════════════════════════════════════════╣");
      console.log("║  WEBAUTHN_CREDENTIAL=" + credentialStr);
      console.log("╚══════════════════════════════════════════════════════════════╝\n");

      res.json({ verified: true, credential: credentialStr });
    } else {
      res.json({ verified: false });
    }
  } catch (e) {
    console.error("WebAuthn register verify error:", e);
    res.status(500).json({ error: e.message });
  }
});

// Authentication: generate options (public — no session required)
app.get("/webauthn/auth/options", async (req, res) => {
  try {
    // Find the admin user with a registered credential
    let allowCredentials = [];
    for (const [, user] of users) {
      if (user.webauthn_credential) {
        allowCredentials.push({
          id: user.webauthn_credential.credentialID,
          type: "public-key",
          transports: user.webauthn_credential.transports || [],
        });
      }
    }

    if (allowCredentials.length === 0) {
      return res.status(404).json({ error: "No passkeys registered" });
    }

    const opts = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials,
      userVerification: "preferred",
    });

    // Store challenge keyed by the challenge itself (no session available)
    challenges.set("auth:" + opts.challenge, { challenge: opts.challenge, expires: Date.now() + 5 * 60 * 1000 });
    res.json(opts);
  } catch (e) {
    console.error("WebAuthn auth options error:", e);
    res.status(500).json({ error: e.message });
  }
});

// Authentication: verify response (public — no session required)
app.post("/webauthn/auth/verify", express.json(), async (req, res) => {
  try {
    const { id: credentialID } = req.body;

    // Find user with matching credential
    let matchedUser = null;
    for (const [, user] of users) {
      if (user.webauthn_credential && user.webauthn_credential.credentialID === credentialID) {
        matchedUser = user;
        break;
      }
    }

    if (!matchedUser) {
      return res.status(400).json({ error: "Credential not recognized" });
    }

    // Find the stored challenge from clientDataJSON
    const clientData = JSON.parse(Buffer.from(req.body.response.clientDataJSON, "base64url").toString());
    const storedKey = "auth:" + clientData.challenge;
    const stored = challenges.get(storedKey);
    if (!stored || Date.now() > stored.expires) {
      return res.status(400).json({ error: "Challenge expired or not found" });
    }

    const cred = matchedUser.webauthn_credential;
    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: stored.challenge,
      expectedOrigin: RP_ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: cred.credentialID,
        publicKey: new Uint8Array(cred.credentialPublicKey),
        counter: cred.counter,
      },
    });

    challenges.delete(storedKey);

    if (verification.verified) {
      // Update counter
      cred.counter = verification.authenticationInfo.newCounter;

      // Create session
      req.session.regenerate((err) => {
        if (err) return res.status(500).json({ error: "Session error" });
        req.session.userId = matchedUser.id;
        req.session.username = matchedUser.username;
        req.session.displayName = matchedUser.display_name;
        req.session.role = matchedUser.role;
        res.json({ verified: true, redirect: "/" });
      });
    } else {
      res.json({ verified: false });
    }
  } catch (e) {
    console.error("WebAuthn auth verify error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ── Portal Users CRUD API ────────────────────────────────────────────
app.get("/api/portal-users", (req, res) => {
  if (req.session.role !== "admin") return res.status(403).json({ error: "Admin access required" });
  const list = [];
  for (const u of users.values()) {
    list.push({
      id: u.id,
      username: u.username,
      display_name: u.display_name,
      role: u.role,
      has_passkey: !!u.webauthn_credential,
    });
  }
  res.json(list);
});

app.post("/api/portal-users", express.json(), (req, res) => {
  if (req.session.role !== "admin") return res.status(403).json({ error: "Admin access required" });
  const { username, password, display_name, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password are required" });
  const key = username.toLowerCase();
  if (users.has(key)) return res.status(409).json({ error: "Username already exists" });
  const hash = bcrypt.hashSync(password, 10);
  const newUser = { id: nextUserId++, username, password_hash: hash, display_name: display_name || username, role: role || "viewer" };
  users.set(key, newUser);
  syncPortalUsersToRailway();
  res.status(201).json({ id: newUser.id, username: newUser.username, display_name: newUser.display_name, role: newUser.role });
});

app.put("/api/portal-users/:id", express.json(), (req, res) => {
  if (req.session.role !== "admin") return res.status(403).json({ error: "Admin access required" });
  const targetId = Number(req.params.id);
  let target = null;
  for (const u of users.values()) { if (u.id === targetId) { target = u; break; } }
  if (!target) return res.status(404).json({ error: "User not found" });
  const { display_name, role, password } = req.body;
  if (display_name !== undefined) target.display_name = display_name;
  if (role !== undefined) target.role = role;
  if (password) target.password_hash = bcrypt.hashSync(password, 10);
  syncPortalUsersToRailway();
  res.json({ id: target.id, username: target.username, display_name: target.display_name, role: target.role });
});

app.delete("/api/portal-users/:id", (req, res) => {
  if (req.session.role !== "admin") return res.status(403).json({ error: "Admin access required" });
  const targetId = Number(req.params.id);
  if (targetId === req.session.userId) return res.status(400).json({ error: "Cannot delete your own account" });
  let targetKey = null;
  for (const [key, u] of users.entries()) { if (u.id === targetId) { targetKey = key; break; } }
  if (!targetKey) return res.status(404).json({ error: "User not found" });
  users.delete(targetKey);
  syncPortalUsersToRailway();
  res.json({ ok: true });
});

// Build dynamic system prompt with MCP server awareness
function buildChatSystemPrompt() {
  const connections = [];
  if (UPSTREAM)
    connections.push('Platform ONE APIs MCP Server (Extreme Networks) — Connected, URL: ' + UPSTREAM + PROXY_ROUTE);
  if (MERAKI_API_KEY)
    connections.push('Meraki APIs MCP Server (Cisco) — Connected, Endpoint: ' + MERAKI_API_BASE);
  if (XIQ_USERNAME && XIQ_PASSWORD)
    connections.push('ExtremeCloud IQ (Extreme Networks) — Connected, Endpoint: ' + XIQ_API_BASE);
  if (PEPLINK_CLIENT_ID && PEPLINK_CLIENT_SECRET)
    connections.push('PepLink InControl2 (PepLink) — Connected, Endpoint: ' + PEPLINK_API_BASE);

  let mcpSection = '';
  if (connections.length > 0) {
    mcpSection = '\n\nYou have the following MCP server connections and API integrations configured and active:\n'
      + connections.map(c => '- ' + c).join('\n')
      + '\n\nWhen users ask about MCP connections, integrations, or server status, report these active connections and their status.';
  }

  return 'You are a helpful network operations AI assistant integrated into the Extreme Exchange platform. '
    + 'Help users with network management, troubleshooting, and automation tasks. Keep responses concise.'
    + mcpSection;
}

// Claude Chat API
app.post("/api/claude-chat", express.json(), async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: "ANTHROPIC_API_KEY not configured" });
  }
  try {
    const { messages } = req.body;
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-5-20250929",
        max_tokens: 1024,
        system: buildChatSystemPrompt(),
        messages: messages,
      }),
    });
    if (!response.ok) {
      const errBody = await response.text();
      return res.status(response.status).json({ error: errBody });
    }
    const data = await response.json();
    const text = data.content && data.content[0] ? data.content[0].text : "No response";
    res.json({ reply: text });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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
    const org = await merakiFetch(`/organizations/${encodeURIComponent(req.params.orgId)}`);
    res.json(org);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Delete Organization
app.delete("/api/organizations/:orgId", async (req, res) => {
  try {
    const result = await merakiFetch(`/organizations/${encodeURIComponent(req.params.orgId)}`, { method: "DELETE" });
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
    const networks = await merakiFetch(`/organizations/${encodeURIComponent(req.params.orgId)}/networks`);
    res.json(networks);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: List Devices for an Organization
app.get("/api/organizations/:orgId/devices", async (req, res) => {
  try {
    const devices = await merakiFetch(`/organizations/${encodeURIComponent(req.params.orgId)}/devices`);
    res.json(devices);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Get Device Statuses for an Organization
app.get("/api/organizations/:orgId/devices/statuses", async (req, res) => {
  try {
    const statuses = await merakiFetch(`/organizations/${encodeURIComponent(req.params.orgId)}/devices/statuses`);
    res.json(statuses);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Get Network Events
app.get("/api/networks/:networkId/events", async (req, res) => {
  try {
    const { productType, includedEventTypes, startingAfter } = req.query;
    let endpoint = `/networks/${encodeURIComponent(req.params.networkId)}/events?perPage=100`;
    if (productType) endpoint += `&productType=${productType}`;
    if (includedEventTypes) endpoint += `&includedEventTypes[]=${includedEventTypes}`;
    if (startingAfter) endpoint += `&startingAfter=${startingAfter}`;
    const events = await merakiFetch(endpoint);
    res.json(events);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Get Network Traffic Analysis
app.get("/api/networks/:networkId/traffic", async (req, res) => {
  try {
    const timespan = req.query.timespan || 86400;
    const traffic = await merakiFetch(`/networks/${encodeURIComponent(req.params.networkId)}/traffic?timespan=${encodeURIComponent(timespan)}`);
    res.json(traffic);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Get Device Events by Serial
app.get("/api/devices/:serial/events", async (req, res) => {
  try {
    const events = await merakiFetch(`/devices/${encodeURIComponent(req.params.serial)}/lossAndLatencyHistory?timespan=604800&ip=8.8.8.8`);
    res.json(events);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Get DFS Events for a Network
app.get("/api/networks/:networkId/dfs-events", async (req, res) => {
  try {
    const events = await merakiFetch(`/networks/${encodeURIComponent(req.params.networkId)}/events?productType=wireless&perPage=100`);
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
    const events = await merakiFetch(`/networks/${encodeURIComponent(req.params.networkId)}/events?productType=wireless&perPage=1000&timespan=${timespan}`);
    const allEvents = events.events || [];

    // Fetch Air Marshal/WIPS events separately (they're rare and get lost in general events)
    const wipsEventTypes = ['packet_flood', 'device_packet_flood', 'bcast_deauth', 'bcast_disassoc', 'rogue_ap_association'].join('&includedEventTypes[]=');
    let wipsEvents = [];
    try {
      const wipsResponse = await merakiFetch(`/networks/${encodeURIComponent(req.params.networkId)}/events?productType=wireless&perPage=500&timespan=${timespan}&includedEventTypes[]=${wipsEventTypes}`);
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
      const sixGhzStats = await merakiFetch(`/networks/${encodeURIComponent(req.params.networkId)}/wireless/clients/connectionStats?band=6&timespan=${Math.min(timespan, 604800)}`);
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
    const data = await merakiFetch(`/networks/${encodeURIComponent(req.params.networkId)}/wireless/settings`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Update Network Wireless Settings
app.put("/api/networks/:networkId/wireless/settings", express.json(), async (req, res) => {
  try {
    const data = await merakiFetch(`/networks/${encodeURIComponent(req.params.networkId)}/wireless/settings`, {
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
    const data = await merakiFetch(`/networks/${encodeURIComponent(req.params.networkId)}/settings`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Meraki API: Update Network Settings
app.put("/api/networks/:networkId/settings", express.json(), async (req, res) => {
  try {
    const data = await merakiFetch(`/networks/${encodeURIComponent(req.params.networkId)}/settings`, {
      method: "PUT",
      body: req.body
    });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =============================================================================
// LOCAL STATUS PAGE APIs
// =============================================================================

// Get device details by serial
app.get("/api/devices/:serial", async (req, res) => {
  try {
    const device = await merakiFetch(`/devices/${encodeURIComponent(req.params.serial)}`);
    res.json(device);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get device wireless status (radio settings, channel, power)
app.get("/api/devices/:serial/wireless/status", async (req, res) => {
  try {
    const serial = req.params.serial;

    // Get device basic info
    const device = await merakiFetch(`/devices/${serial}`);

    // Get organization ID from device network
    const network = await merakiFetch(`/networks/${device.networkId}`);
    const orgId = network.organizationId;

    // Get device status
    let status = {};
    try {
      const statuses = await merakiFetch(`/organizations/${orgId}/devices/statuses?serials[]=${serial}`);
      status = statuses && statuses[0] ? statuses[0] : {};
    } catch (e) {}

    // Get wireless radio settings
    let radioSettings = {};
    try {
      radioSettings = await merakiFetch(`/devices/${serial}/wireless/radio/settings`);
    } catch (e) {}

    // Get device clients
    let clients = [];
    try {
      clients = await merakiFetch(`/devices/${serial}/clients?timespan=300`);
    } catch (e) {}

    // Get LLDP/CDP neighbors
    let neighbors = {};
    try {
      neighbors = await merakiFetch(`/devices/${serial}/lldpCdp`);
    } catch (e) {}

    // Get device uplink info
    let uplinks = [];
    try {
      const uplinkData = await merakiFetch(`/organizations/${orgId}/devices/uplinks/addresses/byDevice?serials[]=${serial}`);
      uplinks = uplinkData && uplinkData[0] ? uplinkData[0].uplinks : [];
    } catch (e) {}

    res.json({
      device: {
        ...device,
        status: status.status || 'unknown',
        publicIp: status.publicIp,
        gateway: status.gateway,
        primaryDns: status.primaryDns,
        secondaryDns: status.secondaryDns,
        lastReportedAt: status.lastReportedAt
      },
      radioSettings,
      clients: clients || [],
      clientCount: clients ? clients.length : 0,
      neighbors,
      uplinks
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all APs in a network with status
app.get("/api/networks/:networkId/wireless/accessPoints", async (req, res) => {
  try {
    const networkId = req.params.networkId;
    const network = await merakiFetch(`/networks/${networkId}`);
    const orgId = network.organizationId;

    // Get all devices in network
    const devices = await merakiFetch(`/networks/${networkId}/devices`);

    // Filter to APs only
    const aps = devices.filter(d => d.model && (d.model.startsWith('MR') || d.model.startsWith('CW')));

    // Get statuses for all APs
    let statusMap = {};
    try {
      const serials = aps.map(ap => ap.serial).join('&serials[]=');
      if (serials) {
        const statuses = await merakiFetch(`/organizations/${orgId}/devices/statuses?serials[]=${serials}`);
        for (const s of (statuses || [])) {
          statusMap[s.serial] = s;
        }
      }
    } catch (e) {}

    // Enhance APs with status
    const enhancedAps = aps.map(ap => ({
      ...ap,
      status: statusMap[ap.serial]?.status || 'unknown',
      publicIp: statusMap[ap.serial]?.publicIp,
      gateway: statusMap[ap.serial]?.gateway,
      clientCount: statusMap[ap.serial]?.clientCount,
      lastReportedAt: statusMap[ap.serial]?.lastReportedAt
    }));

    res.json(enhancedAps);
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
        const fc = await merakiFetch(`/networks/${encodeURIComponent(networkId)}/wireless/failedConnections?t0=${encodeURIComponent(t0)}&t1=${encodeURIComponent(t1)}&perPage=1000`);
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
        const cu = await merakiFetch(`/networks/${encodeURIComponent(networkId)}/wireless/channelUtilizationHistory?t0=${encodeURIComponent(t0)}&t1=${encodeURIComponent(t1)}&resolution=600`);
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
    const data = await xiqFetch(`/devices/${encodeURIComponent(req.params.deviceId)}`);
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
    const data = await xiqFetch(`/locations/site/${encodeURIComponent(req.params.siteId)}`);
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
    const data = await peplinkFetch(`/rest/o/${encodeURIComponent(req.params.orgId)}/g`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PepLink API: List Devices in Group
app.get("/api/peplink/organizations/:orgId/groups/:groupId/devices", async (req, res) => {
  try {
    const data = await peplinkFetch(`/rest/o/${encodeURIComponent(req.params.orgId)}/g/${encodeURIComponent(req.params.groupId)}/d`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PepLink API: Get Device Location
app.get("/api/peplink/organizations/:orgId/groups/:groupId/devices/:deviceId/location", async (req, res) => {
  try {
    const data = await peplinkFetch(`/rest/o/${encodeURIComponent(req.params.orgId)}/g/${encodeURIComponent(req.params.groupId)}/d/${encodeURIComponent(req.params.deviceId)}/loc`);
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
  const { owner, type, region, search, page = 1 } = req.query;
  // Clamp limit to a sane max to prevent full-dump in one request
  const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 500);
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
app.get(UI_ROUTE, (req, res) => {
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

    /* 9-dot App Launcher */
    .app-launcher {
      position: relative;
      display: inline-block;
    }
    .app-launcher-btn {
      width: 36px;
      height: 36px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--surface);
      color: var(--foreground-muted);
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.15s ease;
    }
    .app-launcher-btn:hover {
      background: var(--surface-hover);
      color: var(--foreground);
      border-color: var(--primary);
    }
    .app-launcher-dots {
      display: grid;
      grid-template-columns: repeat(3, 5px);
      gap: 3px;
    }
    .app-launcher-dots span {
      width: 5px;
      height: 5px;
      background: currentColor;
      border-radius: 50%;
    }
    .app-launcher-menu {
      position: absolute;
      top: 40px;
      right: 0;
      width: 280px;
      background: #1c2028;
      border: 1px solid rgba(124,58,237,0.3);
      border-radius: 12px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.7), 0 0 0 1px rgba(0,0,0,0.3);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      padding: 12px;
      display: none;
      z-index: 1000;
    }
    .app-launcher-menu.show {
      display: block;
    }
    .app-launcher-title {
      font-size: 10px;
      font-weight: 600;
      color: rgba(255,255,255,0.5);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 10px;
      padding: 0 4px;
    }
    .app-launcher-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 4px;
    }
    .app-launcher-item {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 6px;
      padding: 10px 6px;
      border-radius: 8px;
      cursor: pointer;
      transition: background 0.15s ease;
      text-decoration: none;
      color: var(--foreground);
    }
    .app-launcher-item:hover {
      background: rgba(255,255,255,0.08);
    }
    .app-launcher-icon {
      width: 36px;
      height: 36px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .app-launcher-label {
      font-size: 10px;
      text-align: center;
      color: rgba(255,255,255,0.8);
      font-weight: 500;
    }
    .app-launcher-divider {
      height: 1px;
      background: var(--border);
      margin: 10px 0;
    }
    /* Portal User Modal */
    .portal-user-overlay {
      display: none; position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0,0,0,0.6); z-index: 10001;
      justify-content: center; align-items: center;
    }
    .portal-user-overlay.active { display: flex; }
    .portal-user-modal {
      background: #1a1f2e; border-radius: 12px; width: 440px;
      border: 1px solid rgba(255,255,255,0.1); padding: 24px;
    }
    .portal-user-modal-header {
      display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;
    }
    .portal-user-modal-header h3 {
      font-size: 16px; font-weight: 600; color: #fff; margin: 0;
    }
    .portal-user-modal-close {
      background: none; border: none; color: rgba(255,255,255,0.4);
      font-size: 20px; cursor: pointer; padding: 0;
    }
    .portal-user-modal-close:hover { color: rgba(255,255,255,0.8); }
    .portal-user-field { margin-bottom: 16px; }
    .portal-user-label {
      display: block; font-size: 11px; color: rgba(255,255,255,0.4); margin-bottom: 6px;
      text-transform: uppercase; letter-spacing: 0.5px;
    }
    .portal-user-input {
      width: 100%; padding: 10px 12px; border-radius: 6px;
      background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.12);
      color: rgba(255,255,255,0.9); font-size: 13px; font-family: inherit;
      box-sizing: border-box;
    }
    .portal-user-input:focus { outline: none; border-color: var(--primary); }
    .portal-user-modal-actions {
      display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px;
    }
    .portal-user-btn {
      padding: 8px 18px; border-radius: 6px; font-size: 13px; font-weight: 500;
      cursor: pointer; font-family: inherit; border: 1px solid rgba(255,255,255,0.15);
      background: rgba(255,255,255,0.05); color: rgba(255,255,255,0.7);
    }
    .portal-user-btn:hover { background: rgba(255,255,255,0.1); }
    .portal-user-btn.primary {
      background: var(--primary); color: white; border-color: var(--primary);
    }
    .portal-user-btn.primary:hover { opacity: 0.9; }
    .pu-action-btn {
      background: none; border: 1px solid rgba(255,255,255,0.12); color: rgba(255,255,255,0.6);
      padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 11px; font-family: inherit;
    }
    .pu-action-btn:hover { border-color: var(--primary); color: var(--primary); }
    .pu-action-btn.danger:hover { border-color: #f85149; color: #f85149; }
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
        <button class="nav-item" onclick="showView('app-traffic')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20V10"/><path d="M18 20V4"/><path d="M6 20v-4"/></svg>
          App Traffic
        </button>
        <button class="nav-item" onclick="showView('local-status')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
          Local Status
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
        <button class="nav-item" onclick="showView('xiq-troubleshoot')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
          XIQ Troubleshoot
        </button>
      </div>
      <div class="nav-section">
        <div class="nav-section-title">Security</div>
        <button class="nav-item" onclick="showView('psirt')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          PSIRT Advisories
        </button>
      </div>
      <div class="nav-section">
        <div class="nav-section-title">RF Planning</div>
        <button class="nav-item" onclick="showView('rf-visualizer')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>
          RF Visualizer
        </button>
      </div>
      <div class="nav-section">
        <div class="nav-section-title">AI Exchange</div>
        <button class="nav-item" onclick="showView('ai-agents')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v4m0 14v4M4.22 4.22l2.83 2.83m9.9 9.9l2.83 2.83M1 12h4m14 0h4M4.22 19.78l2.83-2.83m9.9-9.9l2.83-2.83"/></svg>
          AI Agents
        </button>
      </div>
      ${req.session.role === "admin" ? `<div class="nav-section">
        <div class="nav-section-title">Administration</div>
        <button class="nav-item" onclick="showView('portal-users')">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
          Portal Users
        </button>
      </div>` : ""}
    </div>
    <div class="sidebar-footer">
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
        <span style="width:8px;height:8px;background:var(--success);border-radius:50%"></span>
        <span style="color:var(--success)">Service Active</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span>Route: ${PROXY_ROUTE}</span>
        <div style="display:flex;gap:8px;align-items:center">
          <button onclick="registerPasskey()" style="background:none;border:1px solid rgba(255,255,255,0.15);color:rgba(255,255,255,0.5);font-size:11px;padding:2px 8px;border-radius:4px;cursor:pointer;display:flex;align-items:center;gap:4px" onmouseover="this.style.borderColor='#7c3aed';this.style.color='#a78bfa'" onmouseout="this.style.borderColor='rgba(255,255,255,0.15)';this.style.color='rgba(255,255,255,0.5)'" title="Register a passkey for biometric login">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 11c0-2.21 1.79-4 4-4s4 1.79 4 4-1.79 4-4 4"/><path d="M16 15v6l-2-1-2 1v-6"/><circle cx="16" cy="11" r="1"/><path d="M2 18c0-3.31 2.69-6 6-6s6 2.69 6 6"/><circle cx="8" cy="8" r="3"/></svg>
            Passkey
          </button>
          <a href="/logout" style="color:rgba(255,255,255,0.4);text-decoration:none;font-size:11px" onmouseover="this.style.color='#f85149'" onmouseout="this.style.color='rgba(255,255,255,0.4)'">Sign Out</a>
        </div>
      </div>
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
          <div class="app-launcher">
            <button class="app-launcher-btn" onclick="toggleAppLauncher(event)" title="Apps & Integrations">
              <div class="app-launcher-dots">
                <span></span><span></span><span></span>
                <span></span><span></span><span></span>
                <span></span><span></span><span></span>
              </div>
            </button>
            <div class="app-launcher-menu" id="app-launcher-menu">
              <div class="app-launcher-title">Integrations</div>
              <div class="app-launcher-grid">
                <a class="app-launcher-item" onclick="openIntegration('teams')">
                  <div class="app-launcher-icon" style="background:#5059c9">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="white"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>
                  </div>
                  <span class="app-launcher-label">Teams</span>
                </a>
                <a class="app-launcher-item" onclick="openIntegration('slack')">
                  <div class="app-launcher-icon" style="background:#4a154b">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="white"><path d="M6 15a2 2 0 0 1-2 2 2 2 0 0 1-2-2 2 2 0 0 1 2-2h2v2zm1 0a2 2 0 0 1 2-2 2 2 0 0 1 2 2v5a2 2 0 1 1-4 0v-5z"/></svg>
                  </div>
                  <span class="app-launcher-label">Slack</span>
                </a>
                <a class="app-launcher-item" onclick="openIntegration('webhook')">
                  <div class="app-launcher-icon" style="background:#10b981">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                  </div>
                  <span class="app-launcher-label">Webhook</span>
                </a>
              </div>
              <div class="app-launcher-divider"></div>
              <div class="app-launcher-title">Tools</div>
              <div class="app-launcher-grid">
                <a class="app-launcher-item" href="https://xiq-migration.up.railway.app/" target="_blank" onclick="closeAppLauncher()">
                  <div class="app-launcher-icon" style="background:linear-gradient(135deg,#7c3aed,#2dd4bf)">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M17 1l4 4-4 4"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><path d="M7 23l-4-4 4-4"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>
                  </div>
                  <span class="app-launcher-label">XIQ Migration</span>
                </a>
                <a class="app-launcher-item" onclick="showView('topology');closeAppLauncher()">
                  <div class="app-launcher-icon" style="background:#3b82f6">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><circle cx="12" cy="5" r="3"/><circle cx="5" cy="19" r="3"/><circle cx="19" cy="19" r="3"/><line x1="12" y1="8" x2="5" y2="16"/><line x1="12" y1="8" x2="19" y2="16"/></svg>
                  </div>
                  <span class="app-launcher-label">Topology</span>
                </a>
                <a class="app-launcher-item" onclick="showView('rca');closeAppLauncher()">
                  <div class="app-launcher-icon" style="background:#8b5cf6">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                  </div>
                  <span class="app-launcher-label">RCA</span>
                </a>
                <a class="app-launcher-item" href="https://bobkit-production.up.railway.app/" target="_blank" onclick="closeAppLauncher()">
                  <div class="app-launcher-icon" style="background:linear-gradient(135deg,#f59e0b,#ef4444)">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                  </div>
                  <span class="app-launcher-label">BOBKit</span>
                </a>
              </div>
            </div>
          </div>
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

    <!-- Application Traffic Engine View -->
    <div id="view-app-traffic" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">Application Traffic Engine</h1>
          <div class="page-subtitle">Real-time application visibility and traffic analysis</div>
        </div>
        <div class="header-actions">
          <select id="app-traffic-network-select" onchange="loadAppTraffic()" style="padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--foreground);margin-right:8px">
            <option value="">Select Network</option>
          </select>
          <button class="header-btn" onclick="loadAppTraffic()">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
            Refresh
          </button>
        </div>
      </div>
      <div class="page-content">
        <div class="stat-cards">
          <div class="stat-card" style="border-left:3px solid #3b82f6">
            <div class="stat-card-label">Total Applications</div>
            <div class="stat-card-value" id="app-traffic-total">--</div>
            <div class="stat-card-sub">Detected apps</div>
          </div>
          <div class="stat-card" style="border-left:3px solid #10b981">
            <div class="stat-card-label">Upload</div>
            <div class="stat-card-value" id="app-traffic-upload">--</div>
            <div class="stat-card-sub">Sent data</div>
          </div>
          <div class="stat-card" style="border-left:3px solid #8b5cf6">
            <div class="stat-card-label">Download</div>
            <div class="stat-card-value" id="app-traffic-download">--</div>
            <div class="stat-card-sub">Received data</div>
          </div>
          <div class="stat-card" style="border-left:3px solid #f59e0b">
            <div class="stat-card-label">Active Clients</div>
            <div class="stat-card-value" id="app-traffic-clients">--</div>
            <div class="stat-card-sub">Using apps</div>
          </div>
        </div>
        <div class="card" style="margin-top:20px;border-left:3px solid #3b82f6">
          <div style="font-weight:600;font-size:16px;margin-bottom:16px">Top Applications by Bandwidth</div>
          <div id="app-traffic-list">
            <div style="text-align:center;padding:40px;color:var(--foreground-muted)">Select a network to view application traffic</div>
          </div>
        </div>
        <div class="card" style="margin-top:20px;border-left:3px solid #f59e0b">
          <div style="font-weight:600;font-size:16px;margin-bottom:16px">Traffic Shaping Rules</div>
          <div style="display:flex;flex-direction:column;gap:10px">
            <div style="padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:8px;display:flex;justify-content:space-between;align-items:center">
              <span>BitTorrent / P2P</span>
              <span style="padding:4px 10px;background:rgba(239,68,68,0.15);color:#ef4444;border-radius:4px;font-size:11px">Blocked</span>
            </div>
            <div style="padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:8px;display:flex;justify-content:space-between;align-items:center">
              <span>Video Streaming</span>
              <span style="padding:4px 10px;background:rgba(245,158,11,0.15);color:#f59e0b;border-radius:4px;font-size:11px">Limited</span>
            </div>
            <div style="padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:8px;display:flex;justify-content:space-between;align-items:center">
              <span>VoIP / Conferencing</span>
              <span style="padding:4px 10px;background:rgba(16,185,129,0.15);color:#10b981;border-radius:4px;font-size:11px">High Priority</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Local Status Page View -->
    <div id="view-local-status" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">Meraki Local Status Page</h1>
          <div class="page-subtitle">Access Point status, radio settings, and network connectivity</div>
        </div>
        <div class="header-actions">
          <select id="local-status-network-select" onchange="loadLocalStatusAPs()" style="padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--foreground);margin-right:8px">
            <option value="">Select Network</option>
          </select>
          <select id="local-status-ap-select" onchange="loadAPStatus()" style="padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--foreground);margin-right:8px">
            <option value="">All APs Overview</option>
          </select>
          <button class="header-btn" onclick="refreshLocalStatus()">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2v6h-6"/><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M3 22v-6h6"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/></svg>
            Refresh
          </button>
        </div>
      </div>
      <div class="page-content">
        <!-- Stats Overview -->
        <div class="stats-grid" id="local-status-stats">
          <div class="stat-card">
            <div class="stat-card-label">Total APs</div>
            <div class="stat-card-value" id="local-status-total">--</div>
            <div class="stat-card-sub">In selected network</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-label">Online</div>
            <div class="stat-card-value" id="local-status-online" style="color:var(--success)">--</div>
            <div class="stat-card-sub">Connected</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-label">Alerting</div>
            <div class="stat-card-value" id="local-status-alerting" style="color:#f59e0b">--</div>
            <div class="stat-card-sub">Needs attention</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-label">Total Clients</div>
            <div class="stat-card-value" id="local-status-clients">--</div>
            <div class="stat-card-sub">Connected to APs</div>
          </div>
        </div>

        <!-- AP Overview / Detail Content -->
        <div id="local-status-content">
          <div style="text-align:center;padding:60px;color:var(--foreground-muted)">
            <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.4;margin-bottom:16px"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>
            <div style="font-size:14px">Select a network to view Access Points</div>
          </div>
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

    <!-- PSIRT Advisories View -->
    <div id="view-psirt" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">PSIRT Security Advisories</h1>
          <div class="page-subtitle">Product Security Incident Response Team notifications</div>
        </div>
        <div class="header-actions">
          <a href="https://www.extremenetworks.com/support/psirt" target="_blank" class="header-btn">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
            Extreme PSIRT Portal
          </a>
          <button class="header-btn" onclick="refreshPsirtAdvisories()">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2v6h-6"/><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M3 22v-6h6"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/></svg>
            Refresh
          </button>
        </div>
      </div>
      <div class="page-content">
        <!-- Quick Links -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-bottom:24px">
          <a href="https://extreme-networks.my.site.com/ExtrSearch#q=cve&t=Knowledge&sort=relevancy&f:@sfrecordtypename=[Security_Advisory]" target="_blank" class="card" style="text-decoration:none;border-left:3px solid #7c3aed;cursor:pointer;transition:all 0.2s">
            <div style="display:flex;align-items:center;gap:16px">
              <div style="width:48px;height:48px;background:linear-gradient(135deg,#7c3aed,#5b21b6);border-radius:10px;display:flex;align-items:center;justify-content:center">
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
              </div>
              <div>
                <div style="font-weight:600;color:var(--foreground);margin-bottom:4px">Security Advisories Database</div>
                <div style="font-size:13px;color:var(--foreground-muted)">Browse all CVEs and security bulletins</div>
              </div>
            </div>
          </a>
          <a href="https://www.extremenetworks.com/support/psirt/customer-product-vulnerability-inquiry" target="_blank" class="card" style="text-decoration:none;border-left:3px solid #06b6d4;cursor:pointer;transition:all 0.2s">
            <div style="display:flex;align-items:center;gap:16px">
              <div style="width:48px;height:48px;background:linear-gradient(135deg,#06b6d4,#0891b2);border-radius:10px;display:flex;align-items:center;justify-content:center">
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
              </div>
              <div>
                <div style="font-weight:600;color:var(--foreground);margin-bottom:4px">Vulnerability Inquiry</div>
                <div style="font-size:13px;color:var(--foreground-muted)">Submit product security questions</div>
              </div>
            </div>
          </a>
          <a href="https://teams.microsoft.com/l/message/19:meeting_ZGFlZGIzMGQtNWI0Ny00MjNkLTk3NWItNDEyMTczYWY4MmM1@thread.v2/1770312280790?context=%7B%22contextType%22%3A%22chat%22%7D" target="_blank" class="card" style="text-decoration:none;border-left:3px solid #5059c9;cursor:pointer;transition:all 0.2s">
            <div style="display:flex;align-items:center;gap:16px">
              <div style="width:48px;height:48px;background:linear-gradient(135deg,#5059c9,#4338ca);border-radius:10px;display:flex;align-items:center;justify-content:center">
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="white"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>
              </div>
              <div>
                <div style="font-weight:600;color:var(--foreground);margin-bottom:4px">Teams Security Channel</div>
                <div style="font-size:13px;color:var(--foreground-muted)">Open company security discussion</div>
              </div>
            </div>
          </a>
        </div>

        <!-- Inventory Scan Results -->
        <div id="psirt-scan-results" style="margin-bottom:24px">
          <div style="padding:20px;background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.3);border-radius:8px">
            <div style="display:flex;align-items:center;gap:12px">
              <div class="loading-spinner"></div>
              <div>
                <div style="font-weight:600;color:#3b82f6">Scanning Inventory...</div>
                <div style="font-size:12px;color:var(--foreground-muted)">Checking your devices against known vulnerabilities</div>
              </div>
            </div>
          </div>
        </div>

        <!-- Active Advisories Section -->
        <div class="card" style="border-left:3px solid #ef4444">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
            <div style="display:flex;align-items:center;gap:12px">
              <div style="width:40px;height:40px;background:rgba(239,68,68,0.15);border-radius:8px;display:flex;align-items:center;justify-content:center">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
              </div>
              <div>
                <div style="font-weight:600;font-size:16px">Active Security Advisories</div>
                <div style="font-size:12px;color:var(--foreground-muted)">Recent vulnerabilities affecting Extreme products</div>
              </div>
            </div>
            <div id="psirt-count-badge" style="padding:6px 12px;background:rgba(239,68,68,0.15);color:#ef4444;border-radius:20px;font-size:12px;font-weight:600">Loading...</div>
          </div>
          <div id="psirt-advisories-list" style="display:flex;flex-direction:column;gap:12px">
            <!-- Advisories will be loaded here -->
            <div style="text-align:center;padding:40px;color:var(--foreground-muted)">
              <div class="loading-spinner" style="margin:0 auto 16px"></div>
              <div>Loading advisories...</div>
            </div>
          </div>
        </div>

        <!-- Vulnerability Disclosure Policy -->
        <div class="card" style="margin-top:20px;border-left:3px solid #10b981">
          <div style="display:flex;align-items:flex-start;gap:16px">
            <div style="width:48px;height:48px;background:rgba(16,185,129,0.15);border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
            </div>
            <div style="flex:1">
              <div style="font-weight:600;font-size:16px;margin-bottom:8px">Vulnerability Disclosure Policy</div>
              <div style="font-size:13px;color:var(--foreground-muted);line-height:1.6;margin-bottom:12px">
                Extreme Networks prioritizes the security of our products. We encourage responsible disclosure and are committed to maintaining the highest standards of security. Report vulnerabilities to <a href="mailto:psirt@extremenetworks.com" style="color:#7c3aed">psirt@extremenetworks.com</a>.
              </div>
              <div style="display:flex;gap:12px;flex-wrap:wrap">
                <div style="padding:8px 16px;background:rgba(124,58,237,0.1);border-radius:6px;font-size:12px;color:#a78bfa">
                  <strong>Response:</strong> 72 hours acknowledgment
                </div>
                <div style="padding:8px 16px;background:rgba(16,185,129,0.1);border-radius:6px;font-size:12px;color:#34d399">
                  <strong>Disclosure:</strong> Coordinated timeline
                </div>
                <div style="padding:8px 16px;background:rgba(6,182,212,0.1);border-radius:6px;font-size:12px;color:#22d3ee">
                  <strong>Credit:</strong> Optional recognition
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- RF Visualizer View -->
    <div id="view-rf-visualizer" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">Wireless RF Visualizer</h1>
          <div class="page-subtitle">Visualize AP coverage, channel planning, and RF interference</div>
        </div>
        <div class="header-actions">
          <button class="header-btn" onclick="clearRfCanvas()">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
            Clear All
          </button>
          <button class="header-btn" onclick="exportRfPlan()">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            Export
          </button>
        </div>
      </div>
      <div class="page-content">
        <div style="display:grid;grid-template-columns:1fr 320px;gap:20px;height:calc(100vh - 180px)">
          <!-- RF Canvas -->
          <div class="card" style="padding:0;overflow:hidden;position:relative">
            <div style="position:absolute;top:12px;left:12px;z-index:10;display:flex;gap:8px">
              <button id="rf-tool-add" onclick="setRfTool('add')" class="rf-tool-btn active" style="padding:8px 12px;background:var(--primary);border:none;border-radius:6px;color:white;cursor:pointer;font-size:12px;display:flex;align-items:center;gap:6px">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                Add AP
              </button>
              <button id="rf-tool-move" onclick="setRfTool('move')" class="rf-tool-btn" style="padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--foreground);cursor:pointer;font-size:12px;display:flex;align-items:center;gap:6px">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="5 9 2 12 5 15"/><polyline points="9 5 12 2 15 5"/><polyline points="15 19 12 22 9 19"/><polyline points="19 9 22 12 19 15"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="12" y1="2" x2="12" y2="22"/></svg>
                Move
              </button>
              <button id="rf-tool-delete" onclick="setRfTool('delete')" class="rf-tool-btn" style="padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--foreground);cursor:pointer;font-size:12px;display:flex;align-items:center;gap:6px">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                Delete
              </button>
            </div>
            <div style="position:absolute;top:12px;right:12px;z-index:10;display:flex;gap:8px">
              <select id="rf-band-filter" onchange="updateRfVisualization()" style="padding:6px 10px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--foreground);font-size:12px">
                <option value="all">All Bands</option>
                <option value="2.4">2.4 GHz</option>
                <option value="5">5 GHz</option>
                <option value="6">6 GHz</option>
              </select>
              <label style="display:flex;align-items:center;gap:6px;padding:6px 10px;background:var(--surface);border:1px solid var(--border);border-radius:6px;font-size:12px;cursor:pointer">
                <input type="checkbox" id="rf-show-interference" onchange="updateRfVisualization()" checked style="accent-color:var(--primary)">
                Show Interference
              </label>
            </div>
            <svg id="rf-canvas" width="100%" height="100%" style="background:linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px),linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px);background-size:20px 20px;cursor:crosshair" onclick="handleRfCanvasClick(event)">
              <!-- Grid reference -->
              <defs>
                <pattern id="rf-grid" width="50" height="50" patternUnits="userSpaceOnUse">
                  <path d="M 50 0 L 0 0 0 50" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="1"/>
                </pattern>
                <!-- Gradient for interference zones -->
                <radialGradient id="rf-gradient-interference">
                  <stop offset="0%" stop-color="rgba(239,68,68,0.4)"/>
                  <stop offset="100%" stop-color="rgba(239,68,68,0)"/>
                </radialGradient>
              </defs>
              <rect width="100%" height="100%" fill="url(#rf-grid)"/>
              <g id="rf-coverage-layer"></g>
              <g id="rf-interference-layer"></g>
              <g id="rf-ap-layer"></g>
            </svg>
            <!-- Scale indicator -->
            <div style="position:absolute;bottom:12px;left:12px;padding:6px 10px;background:rgba(0,0,0,0.7);border-radius:4px;font-size:10px;color:rgba(255,255,255,0.7)">
              <div style="display:flex;align-items:center;gap:8px">
                <div style="width:50px;height:2px;background:var(--foreground)"></div>
                <span>~10m / 33ft</span>
              </div>
            </div>
            <!-- Stats overlay -->
            <div style="position:absolute;bottom:12px;right:12px;padding:10px;background:rgba(0,0,0,0.7);border-radius:6px;font-size:11px">
              <div style="display:grid;grid-template-columns:auto auto;gap:4px 12px">
                <span style="color:rgba(255,255,255,0.6)">APs:</span>
                <span id="rf-stat-aps" style="font-weight:600">0</span>
                <span style="color:rgba(255,255,255,0.6)">Coverage:</span>
                <span id="rf-stat-coverage" style="font-weight:600">0%</span>
                <span style="color:rgba(255,255,255,0.6)">Interference:</span>
                <span id="rf-stat-interference" style="font-weight:600;color:#22c55e">None</span>
              </div>
            </div>
          </div>

          <!-- AP Configuration Panel -->
          <div style="display:flex;flex-direction:column;gap:16px">
            <!-- Channel Legend -->
            <div class="card">
              <div style="font-size:13px;font-weight:600;margin-bottom:12px">Channel Color Legend</div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:11px">
                <div style="display:flex;align-items:center;gap:8px">
                  <div style="width:16px;height:16px;background:#ef4444;border-radius:4px;opacity:0.7"></div>
                  <span>2.4GHz Ch 1</span>
                </div>
                <div style="display:flex;align-items:center;gap:8px">
                  <div style="width:16px;height:16px;background:#f59e0b;border-radius:4px;opacity:0.7"></div>
                  <span>2.4GHz Ch 6</span>
                </div>
                <div style="display:flex;align-items:center;gap:8px">
                  <div style="width:16px;height:16px;background:#22c55e;border-radius:4px;opacity:0.7"></div>
                  <span>2.4GHz Ch 11</span>
                </div>
                <div style="display:flex;align-items:center;gap:8px">
                  <div style="width:16px;height:16px;background:#3b82f6;border-radius:4px;opacity:0.7"></div>
                  <span>5GHz (36-48)</span>
                </div>
                <div style="display:flex;align-items:center;gap:8px">
                  <div style="width:16px;height:16px;background:#8b5cf6;border-radius:4px;opacity:0.7"></div>
                  <span>5GHz (149-165)</span>
                </div>
                <div style="display:flex;align-items:center;gap:8px">
                  <div style="width:16px;height:16px;background:#ec4899;border-radius:4px;opacity:0.7"></div>
                  <span>6GHz</span>
                </div>
              </div>
            </div>

            <!-- Selected AP Properties -->
            <div class="card" id="rf-ap-properties" style="display:none">
              <div style="font-size:13px;font-weight:600;margin-bottom:12px;display:flex;align-items:center;justify-content:space-between">
                <span>AP Properties</span>
                <button onclick="deleteSelectedAp()" style="padding:4px 8px;background:rgba(239,68,68,0.2);border:none;border-radius:4px;color:#ef4444;cursor:pointer;font-size:10px">Delete</button>
              </div>
              <div style="display:flex;flex-direction:column;gap:12px">
                <div>
                  <label style="font-size:11px;color:var(--foreground-muted);display:block;margin-bottom:4px">AP Name</label>
                  <input type="text" id="rf-ap-name" onchange="updateSelectedAp()" style="width:100%;padding:8px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--foreground);font-size:12px">
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
                  <div>
                    <label style="font-size:11px;color:var(--foreground-muted);display:block;margin-bottom:4px">Band</label>
                    <select id="rf-ap-band" onchange="updateApChannelOptions();updateSelectedAp()" style="width:100%;padding:8px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--foreground);font-size:12px">
                      <option value="2.4">2.4 GHz</option>
                      <option value="5">5 GHz</option>
                      <option value="6">6 GHz</option>
                    </select>
                  </div>
                  <div>
                    <label style="font-size:11px;color:var(--foreground-muted);display:block;margin-bottom:4px">Channel</label>
                    <select id="rf-ap-channel" onchange="updateSelectedAp()" style="width:100%;padding:8px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--foreground);font-size:12px">
                      <option value="1">1</option>
                      <option value="6">6</option>
                      <option value="11">11</option>
                    </select>
                  </div>
                </div>
                <div>
                  <label style="font-size:11px;color:var(--foreground-muted);display:block;margin-bottom:4px">Tx Power: <span id="rf-ap-power-val">17</span> dBm</label>
                  <input type="range" id="rf-ap-power" min="5" max="23" value="17" onchange="document.getElementById('rf-ap-power-val').textContent=this.value;updateSelectedAp()" style="width:100%;accent-color:var(--primary)">
                </div>
                <div>
                  <label style="font-size:11px;color:var(--foreground-muted);display:block;margin-bottom:4px">Coverage Radius</label>
                  <div style="display:flex;gap:8px">
                    <button onclick="setApCoverage('small')" class="coverage-btn" data-size="small" style="flex:1;padding:6px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--foreground);cursor:pointer;font-size:11px">Small</button>
                    <button onclick="setApCoverage('medium')" class="coverage-btn active" data-size="medium" style="flex:1;padding:6px;background:var(--primary);border:none;border-radius:4px;color:white;cursor:pointer;font-size:11px">Medium</button>
                    <button onclick="setApCoverage('large')" class="coverage-btn" data-size="large" style="flex:1;padding:6px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--foreground);cursor:pointer;font-size:11px">Large</button>
                  </div>
                </div>
              </div>
            </div>

            <!-- AP List -->
            <div class="card" style="flex:1;overflow:auto">
              <div style="font-size:13px;font-weight:600;margin-bottom:12px">Placed APs</div>
              <div id="rf-ap-list" style="display:flex;flex-direction:column;gap:8px">
                <div style="text-align:center;padding:30px;color:var(--foreground-muted);font-size:12px">
                  Click on the canvas to place APs
                </div>
              </div>
            </div>

            <!-- Quick Tips -->
            <div class="card" style="background:rgba(139,92,246,0.1);border:1px solid rgba(139,92,246,0.3)">
              <div style="font-size:12px;font-weight:600;color:#a78bfa;margin-bottom:8px">RF Planning Tips</div>
              <ul style="font-size:11px;color:var(--foreground-muted);margin:0;padding-left:16px;line-height:1.6">
                <li>Use non-overlapping 2.4GHz channels: 1, 6, 11</li>
                <li>5GHz has more channels, less interference</li>
                <li>Aim for 15-20% coverage overlap for roaming</li>
                <li>Adjacent APs should use different channels</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- XIQ Troubleshooting View -->
    <div id="view-xiq-troubleshoot" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">XIQ Troubleshooting Center</h1>
          <div class="page-subtitle">Diagnose wireless and switching issues with CLI commands and best practices</div>
        </div>
        <div class="header-actions">
          <select id="xiq-ts-device-select" onchange="loadXiqDeviceInfo()" style="padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--foreground);min-width:200px">
            <option value="">Select Device</option>
          </select>
          <button class="header-btn" onclick="refreshXiqTroubleshoot()">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2v6h-6"/><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M3 22v-6h6"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/></svg>
            Refresh
          </button>
        </div>
      </div>
      <div class="page-content">
        <!-- Stats -->
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-card-label">Total Devices</div>
            <div class="stat-card-value" id="xiq-ts-total">--</div>
            <div class="stat-card-sub">APs + Switches</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-label">Online</div>
            <div class="stat-card-value" id="xiq-ts-online" style="color:var(--success)">--</div>
            <div class="stat-card-sub">Connected</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-label">Config Mismatch</div>
            <div class="stat-card-value" id="xiq-ts-mismatch" style="color:#f59e0b">--</div>
            <div class="stat-card-sub">Needs sync</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-label">Best Practices</div>
            <div class="stat-card-value" id="xiq-ts-bp-score">--</div>
            <div class="stat-card-sub">Compliance score</div>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:20px">
          <!-- Left Column: Device Info & SSH -->
          <div style="display:flex;flex-direction:column;gap:20px">
            <!-- Device Information -->
            <div class="card" id="xiq-ts-device-info">
              <div style="font-size:14px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                Device Information
              </div>
              <div style="text-align:center;padding:40px;color:var(--foreground-muted)">
                <div>Select a device to view details</div>
              </div>
            </div>

            <!-- SSH Connection -->
            <div class="card">
              <div style="font-size:14px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                SSH Connection
              </div>
              <div id="xiq-ts-ssh-info">
                <div style="background:rgba(0,0,0,0.3);border-radius:8px;padding:16px;font-family:monospace">
                  <div style="color:var(--foreground-muted);font-size:11px;margin-bottom:8px">SSH Command:</div>
                  <div style="display:flex;align-items:center;gap:8px">
                    <code id="xiq-ts-ssh-cmd" style="flex:1;color:#22c55e;font-size:13px">ssh admin@&lt;select-device&gt;</code>
                    <button onclick="copyToClipboard('xiq-ts-ssh-cmd')" style="padding:6px 10px;background:var(--primary);border:none;border-radius:4px;color:white;cursor:pointer;font-size:11px">Copy</button>
                  </div>
                </div>
                <div style="margin-top:12px;padding:12px;background:rgba(59,130,246,0.1);border-radius:8px;border-left:3px solid #3b82f6">
                  <div style="font-size:12px;color:#3b82f6;font-weight:600;margin-bottom:4px">Default Credentials</div>
                  <div style="font-size:11px;color:var(--foreground-muted)">Username: <code>admin</code> | Password: <code>aerohive</code> (or your configured password)</div>
                </div>
              </div>
            </div>

            <!-- Common Troubleshooting Challenges -->
            <div class="card">
              <div style="font-size:14px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
                Common Troubleshooting Scenarios
              </div>
              <div style="display:flex;flex-direction:column;gap:8px" id="xiq-ts-scenarios">
                <div class="ts-scenario" onclick="loadTsScenario('wifi-connectivity')" style="padding:12px;background:var(--surface);border:1px solid var(--border);border-radius:8px;cursor:pointer;transition:all 0.2s" onmouseover="this.style.borderColor='var(--primary)'" onmouseout="this.style.borderColor='var(--border)'">
                  <div style="font-weight:500;font-size:13px">WiFi Connectivity Issues</div>
                  <div style="font-size:11px;color:var(--foreground-muted);margin-top:2px">Client can't connect or drops frequently</div>
                </div>
                <div class="ts-scenario" onclick="loadTsScenario('slow-wifi')" style="padding:12px;background:var(--surface);border:1px solid var(--border);border-radius:8px;cursor:pointer;transition:all 0.2s" onmouseover="this.style.borderColor='var(--primary)'" onmouseout="this.style.borderColor='var(--border)'">
                  <div style="font-weight:500;font-size:13px">Slow WiFi Performance</div>
                  <div style="font-size:11px;color:var(--foreground-muted);margin-top:2px">Low throughput, high latency</div>
                </div>
                <div class="ts-scenario" onclick="loadTsScenario('roaming')" style="padding:12px;background:var(--surface);border:1px solid var(--border);border-radius:8px;cursor:pointer;transition:all 0.2s" onmouseover="this.style.borderColor='var(--primary)'" onmouseout="this.style.borderColor='var(--border)'">
                  <div style="font-weight:500;font-size:13px">Roaming Problems</div>
                  <div style="font-size:11px;color:var(--foreground-muted);margin-top:2px">Clients not roaming or sticky clients</div>
                </div>
                <div class="ts-scenario" onclick="loadTsScenario('vlan-issues')" style="padding:12px;background:var(--surface);border:1px solid var(--border);border-radius:8px;cursor:pointer;transition:all 0.2s" onmouseover="this.style.borderColor='var(--primary)'" onmouseout="this.style.borderColor='var(--border)'">
                  <div style="font-weight:500;font-size:13px">VLAN/Network Segmentation</div>
                  <div style="font-size:11px;color:var(--foreground-muted);margin-top:2px">Traffic not reaching correct VLAN</div>
                </div>
                <div class="ts-scenario" onclick="loadTsScenario('switch-port')" style="padding:12px;background:var(--surface);border:1px solid var(--border);border-radius:8px;cursor:pointer;transition:all 0.2s" onmouseover="this.style.borderColor='var(--primary)'" onmouseout="this.style.borderColor='var(--border)'">
                  <div style="font-weight:500;font-size:13px">Switch Port Issues</div>
                  <div style="font-size:11px;color:var(--foreground-muted);margin-top:2px">Port down, errors, or speed mismatch</div>
                </div>
                <div class="ts-scenario" onclick="loadTsScenario('auth-issues')" style="padding:12px;background:var(--surface);border:1px solid var(--border);border-radius:8px;cursor:pointer;transition:all 0.2s" onmouseover="this.style.borderColor='var(--primary)'" onmouseout="this.style.borderColor='var(--border)'">
                  <div style="font-weight:500;font-size:13px">Authentication Failures</div>
                  <div style="font-size:11px;color:var(--foreground-muted);margin-top:2px">RADIUS, 802.1X, or PSK issues</div>
                </div>
              </div>
            </div>
          </div>

          <!-- Right Column: CLI Commands & Best Practices -->
          <div style="display:flex;flex-direction:column;gap:20px">
            <!-- CLI Command Library -->
            <div class="card">
              <div style="font-size:14px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;justify-content:space-between">
                <div style="display:flex;align-items:center;gap:8px">
                  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><polyline points="9 11 12 14 22 4"/></svg>
                  CLI Commands
                </div>
                <select id="xiq-ts-cmd-category" onchange="filterCliCommands()" style="padding:6px 10px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--foreground);font-size:12px">
                  <option value="all">All Commands</option>
                  <option value="ap">AP Commands</option>
                  <option value="switch">Switch Commands</option>
                  <option value="wireless">Wireless</option>
                  <option value="network">Network</option>
                  <option value="diagnostics">Diagnostics</option>
                </select>
              </div>
              <div id="xiq-ts-cli-commands" style="max-height:400px;overflow-y:auto;display:flex;flex-direction:column;gap:8px">
                <!-- Commands will be populated here -->
              </div>
            </div>

            <!-- Best Practices Check -->
            <div class="card">
              <div style="font-size:14px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                Best Practices Check
              </div>
              <div id="xiq-ts-best-practices">
                <div style="text-align:center;padding:20px;color:var(--foreground-muted)">
                  <div>Select a device to run best practices analysis</div>
                </div>
              </div>
              <button onclick="runBestPracticesCheck()" style="width:100%;margin-top:16px;padding:12px;background:linear-gradient(135deg,#22c55e,#16a34a);border:none;border-radius:8px;color:white;font-weight:600;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                Run Best Practices Analysis
              </button>
            </div>
          </div>
        </div>

        <!-- Scenario Details Panel -->
        <div id="xiq-ts-scenario-detail" class="card" style="margin-top:20px;display:none">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px">
            <div>
              <div id="xiq-ts-scenario-title" style="font-size:16px;font-weight:600"></div>
              <div id="xiq-ts-scenario-desc" style="font-size:12px;color:var(--foreground-muted);margin-top:4px"></div>
            </div>
            <button onclick="document.getElementById('xiq-ts-scenario-detail').style.display='none'" style="background:none;border:none;color:var(--foreground-muted);cursor:pointer;padding:4px">
              <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>
          <div id="xiq-ts-scenario-content"></div>
        </div>

        <!-- Configuration Analyzer -->
        <div class="card" style="margin-top:20px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
            <div style="display:flex;align-items:center;gap:8px">
              <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
              <div>
                <div style="font-size:16px;font-weight:600">IQEngine Configuration Analyzer</div>
                <div style="font-size:12px;color:var(--foreground-muted)">Paste AP config to analyze against industry best practices</div>
              </div>
            </div>
            <div style="display:flex;gap:8px">
              <button onclick="loadSampleConfig()" style="padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--foreground);cursor:pointer;font-size:12px">
                Load Sample
              </button>
              <button onclick="clearConfigAnalyzer()" style="padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--foreground);cursor:pointer;font-size:12px">
                Clear
              </button>
            </div>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
            <!-- Config Input -->
            <div>
              <div style="font-size:12px;color:var(--foreground-muted);margin-bottom:8px">Paste your AP configuration here (from "show running-config" or XIQ export):</div>
              <textarea id="xiq-config-input" placeholder="# Paste IQEngine/HiveOS AP configuration here...
# Example:
# interface wifi0
#   radio profile auto-channel
#   ssid MyNetwork
#     security wpa2
#     vlan 100
# ..." style="width:100%;height:350px;background:rgba(0,0,0,0.3);border:1px solid var(--border);border-radius:8px;padding:12px;color:#22c55e;font-family:monospace;font-size:12px;resize:vertical"></textarea>
              <button onclick="analyzeConfig()" style="width:100%;margin-top:12px;padding:12px;background:linear-gradient(135deg,var(--primary),#7c3aed);border:none;border-radius:8px;color:white;font-weight:600;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                Analyze Configuration
              </button>
            </div>

            <!-- Analysis Results -->
            <div>
              <div style="font-size:12px;color:var(--foreground-muted);margin-bottom:8px">Analysis Results:</div>
              <div id="xiq-config-results" style="background:rgba(0,0,0,0.2);border:1px solid var(--border);border-radius:8px;padding:16px;min-height:350px;overflow-y:auto">
                <div style="text-align:center;padding:60px 20px;color:var(--foreground-muted)">
                  <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" style="opacity:0.3;margin-bottom:16px"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                  <div style="font-size:14px">Paste configuration and click "Analyze" to see results</div>
                  <div style="font-size:12px;margin-top:8px;opacity:0.7">Supports IQEngine AP, HiveOS, and ExtremeCloud IQ configs</div>
                </div>
              </div>
            </div>
          </div>

          <!-- Best Practices Reference -->
          <div style="margin-top:20px;padding:16px;background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.3);border-radius:8px">
            <div style="font-weight:600;font-size:13px;margin-bottom:12px;color:#3b82f6">Industry Best Practices Checklist</div>
            <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;font-size:12px">
              <div>
                <div style="font-weight:500;margin-bottom:6px;color:var(--foreground)">Wireless Security</div>
                <div style="color:var(--foreground-muted);line-height:1.6">
                  • WPA3 or WPA2-Enterprise<br>
                  • 802.1X with RADIUS<br>
                  • PMF (Protected Management Frames)<br>
                  • Disable legacy protocols (WEP, WPA)
                </div>
              </div>
              <div>
                <div style="font-weight:500;margin-bottom:6px;color:var(--foreground)">RF Optimization</div>
                <div style="color:var(--foreground-muted);line-height:1.6">
                  • Auto channel selection<br>
                  • Band steering enabled<br>
                  • Appropriate power levels<br>
                  • 5GHz preferred for density
                </div>
              </div>
              <div>
                <div style="font-weight:500;margin-bottom:6px;color:var(--foreground)">Client Experience</div>
                <div style="color:var(--foreground-muted);line-height:1.6">
                  • 802.11r/k/v enabled<br>
                  • Load balancing active<br>
                  • Minimum RSSI threshold<br>
                  • Airtime fairness
                </div>
              </div>
            </div>
          </div>
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

    <!-- AI Agents Marketplace View -->
    <div id="view-ai-agents" class="view-panel">
      <style>
        .ai-agents-banner {
          background: linear-gradient(135deg, #1a0a2e 0%, #2d1b4e 50%, #0d1421 100%);
          padding: 40px 35px;
          text-align: center;
          margin: -24px -24px 24px -24px;
          position: relative;
          overflow: hidden;
        }
        .ai-agents-banner::before {
          content: '';
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          height: 3px;
          background: linear-gradient(90deg, #8b5cf6, #06b6d4, #8b5cf6);
        }
        .ai-agents-banner h1 {
          font-size: 26px;
          font-weight: 700;
          color: #fff;
          margin: 0 0 9px 0;
        }
        .ai-agents-banner p {
          color: rgba(255,255,255,0.6);
          font-size: 14px;
          margin: 0;
        }
        .ai-agents-section {
          margin-bottom: 32px;
        }
        .ai-agents-section-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 16px;
        }
        .ai-agents-section-title {
          font-size: 16px;
          font-weight: 600;
          color: rgba(255,255,255,0.9);
        }
        .ai-agents-see-all {
          font-size: 13px;
          color: rgba(255,255,255,0.5);
          text-decoration: none;
          display: flex;
          align-items: center;
          gap: 4px;
          cursor: pointer;
        }
        .ai-agents-see-all:hover {
          color: var(--primary);
        }
        .ai-agents-grid {
          display: grid;
          grid-template-columns: repeat(5, 1fr);
          gap: 16px;
        }
        @media (max-width: 1400px) {
          .ai-agents-grid { grid-template-columns: repeat(4, 1fr); }
        }
        @media (max-width: 1100px) {
          .ai-agents-grid { grid-template-columns: repeat(3, 1fr); }
        }
        @media (max-width: 800px) {
          .ai-agents-grid { grid-template-columns: repeat(2, 1fr); }
        }
        .ai-agent-card {
          background: #1e2330;
          border-radius: 12px;
          padding: 20px;
          cursor: pointer;
          transition: all 0.2s ease;
          border: 1px solid transparent;
          min-height: 140px;
          display: flex;
          flex-direction: column;
        }
        .ai-agent-card { position: relative; }
        .ai-agent-card:hover {
          background: #252b3b;
          border-color: rgba(139, 92, 246, 0.3);
          transform: translateY(-2px);
        }
        .ai-agent-delete {
          position: absolute; top: 0; right: 0; width: 40px; height: 40px;
          display: flex; align-items: center; justify-content: center;
          background: none; border: none; cursor: pointer;
          opacity: 0; transition: opacity 0.15s ease; z-index: 2;
          border-radius: 0 12px 0 8px;
        }
        .ai-agent-delete svg {
          width: 18px; height: 18px; stroke: rgba(255,255,255,0.4); fill: none; stroke-width: 2;
        }
        .ai-agent-delete:hover svg { stroke: #f87171; }
        .ai-agent-card:hover .ai-agent-delete { opacity: 1; }
        .ai-agent-card-header {
          display: flex;
          align-items: flex-start;
          gap: 12px;
          margin-bottom: 8px;
        }
        .ai-agent-icon {
          width: 32px;
          height: 32px;
          border-radius: 8px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-weight: 700;
          font-size: 14px;
          flex-shrink: 0;
          background: linear-gradient(135deg, #8b5cf6, #7c3aed);
          color: white;
        }
        .ai-agent-icon.chevron {
          font-size: 12px;
          letter-spacing: -2px;
        }
        .ai-agent-icon.cyan {
          background: linear-gradient(135deg, #06b6d4, #0891b2);
        }
        .ai-agent-card-info {
          min-width: 0;
          overflow: hidden;
        }
        .ai-agent-title {
          font-size: 14px;
          font-weight: 600;
          color: rgba(255,255,255,0.95);
          margin-bottom: 4px;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }
        .ai-agent-subtitle {
          font-size: 12px;
          color: rgba(255,255,255,0.5);
        }
        .ai-agent-tags {
          display: flex;
          gap: 6px;
          margin-top: 12px;
          flex-wrap: wrap;
        }
        .ai-agent-tag {
          font-size: 11px;
          padding: 4px 10px;
          border-radius: 12px;
          background: rgba(255,255,255,0.08);
          color: rgba(255,255,255,0.7);
          border: 1px solid rgba(255,255,255,0.1);
        }
        .ai-agent-status {
          margin-top: auto;
          padding-top: 12px;
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 12px;
          color: var(--success);
        }
        .ai-agent-status-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: var(--success);
        }
        .ai-agent-description {
          font-size: 12px;
          color: rgba(255,255,255,0.5);
          margin-top: 8px;
          line-height: 1.5;
          flex-grow: 1;
          display: -webkit-box;
          -webkit-line-clamp: 3;
          -webkit-box-orient: vertical;
          overflow: hidden;
        }
        .ai-promo-card {
          background: linear-gradient(135deg, #2d1b69 0%, #1e3a5f 100%);
          border-radius: 12px;
          padding: 24px;
          display: flex;
          flex-direction: column;
          justify-content: center;
          min-height: 140px;
        }
        .ai-promo-card h3 {
          font-size: 16px;
          font-weight: 700;
          color: white;
          margin: 0 0 8px 0;
        }
        .ai-promo-card p {
          font-size: 13px;
          color: rgba(255,255,255,0.7);
          margin: 0 0 16px 0;
          line-height: 1.5;
        }
        .ai-promo-btn {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 10px 16px;
          background: rgba(255,255,255,0.15);
          border: 1px solid rgba(255,255,255,0.2);
          border-radius: 6px;
          color: white;
          font-size: 13px;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.2s;
          width: fit-content;
        }
        .ai-promo-btn:hover {
          background: rgba(255,255,255,0.25);
        }

        /* MCP Detail Page */
        .mcp-detail-overlay {
          display: none;
          position: fixed;
          top: 0; left: 0; right: 0; bottom: 0;
          background: #0d1117;
          z-index: 9999;
          overflow-y: auto;
        }
        .mcp-detail-overlay.active { display: block; }
        .mcp-detail-topbar {
          display: flex;
          align-items: center;
          padding: 12px 24px;
          border-bottom: 1px solid rgba(255,255,255,0.08);
          background: rgba(255,255,255,0.02);
        }
        .mcp-detail-topbar-logo {
          display: flex;
          align-items: center;
          gap: 10px;
          font-size: 15px;
          font-weight: 600;
          color: rgba(255,255,255,0.95);
        }
        .mcp-detail-topbar-logo-icon {
          width: 26px; height: 26px;
          border-radius: 6px;
          background: linear-gradient(135deg, #8b5cf6, #7c3aed);
          display: flex; align-items: center; justify-content: center;
          color: white; font-weight: 700; font-size: 13px;
        }
        .mcp-detail-tabs {
          display: flex; gap: 4px; margin-left: 24px;
        }
        .mcp-detail-tab {
          padding: 5px 14px; border-radius: 20px; font-size: 12px; font-weight: 500;
          color: rgba(255,255,255,0.6); background: transparent; border: none;
          cursor: pointer; font-family: inherit;
        }
        .mcp-detail-tab.active {
          background: var(--primary); color: white;
        }
        .mcp-detail-content {
          max-width: 960px; margin: 0 auto; padding: 24px 32px;
        }
        .mcp-detail-backlink {
          display: inline-flex; align-items: center; gap: 4px;
          font-size: 13px; color: rgba(255,255,255,0.5); cursor: pointer;
          background: none; border: none; padding: 0; font-family: inherit;
          margin-bottom: 20px;
        }
        .mcp-detail-backlink:hover { color: var(--primary); }
        .mcp-detail-header {
          display: flex; align-items: flex-start; gap: 16px; margin-bottom: 16px;
        }
        .mcp-detail-header-icon {
          width: 40px; height: 40px; border-radius: 10px;
          background: linear-gradient(135deg, #8b5cf6, #7c3aed);
          display: flex; align-items: center; justify-content: center;
          color: white; font-weight: 700; font-size: 18px; flex-shrink: 0;
        }
        .mcp-detail-topbar-logo-icon.cyan,
        .mcp-detail-header-icon.cyan {
          background: linear-gradient(135deg, #06b6d4, #0891b2);
        }
        .mcp-detail-header h1 {
          font-size: 24px; font-weight: 700; color: #fff; margin: 0 0 4px 0;
        }
        .mcp-detail-source {
          font-size: 13px; color: rgba(255,255,255,0.5); margin-bottom: 8px;
        }
        .mcp-detail-tag {
          display: inline-block; font-size: 11px; padding: 3px 10px;
          border-radius: 12px; background: rgba(255,255,255,0.08);
          color: rgba(255,255,255,0.7); border: 1px solid rgba(255,255,255,0.1);
          margin-bottom: 12px;
        }
        .mcp-detail-desc {
          font-size: 13px; color: rgba(255,255,255,0.6); line-height: 1.6; margin-bottom: 20px;
        }
        .mcp-detail-actions {
          display: flex; align-items: center; gap: 12px; margin-bottom: 28px;
        }
        .mcp-detail-status-badge {
          display: inline-flex; align-items: center; gap: 6px;
          font-size: 12px; color: var(--success);
          padding: 5px 12px; border-radius: 20px;
          background: rgba(74, 222, 128, 0.1); border: 1px solid rgba(74, 222, 128, 0.2);
        }
        .mcp-detail-status-dot {
          width: 7px; height: 7px; border-radius: 50%; background: var(--success);
        }
        .mcp-detail-btn {
          display: inline-flex; align-items: center; gap: 6px;
          padding: 7px 16px; border-radius: 6px; font-size: 12px; font-weight: 500;
          border: 1px solid rgba(255,255,255,0.15); background: rgba(255,255,255,0.05);
          color: rgba(255,255,255,0.8); cursor: pointer; font-family: inherit;
        }
        .mcp-detail-btn:hover { background: rgba(255,255,255,0.1); }
        .mcp-detail-btn svg { width: 14px; height: 14px; }
        .mcp-detail-pills {
          display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 24px;
          border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 16px;
        }
        .mcp-detail-pill {
          padding: 5px 14px; border-radius: 6px; font-size: 11px; font-weight: 500;
          background: rgba(255,255,255,0.06); color: rgba(255,255,255,0.5);
          border: 1px solid rgba(255,255,255,0.08); cursor: pointer; font-family: inherit;
        }
        .mcp-detail-pill:hover { background: rgba(255,255,255,0.1); color: rgba(255,255,255,0.7); }
        .mcp-detail-pill.active {
          background: rgba(139,92,246,0.15); color: #a78bfa;
          border-color: rgba(139,92,246,0.3);
        }
        .mcp-detail-meta {
          display: flex; gap: 32px; margin-bottom: 28px;
          font-size: 12px; color: rgba(255,255,255,0.4);
        }
        .mcp-detail-meta strong { color: rgba(255,255,255,0.6); }
        .mcp-detail-section h2 {
          font-size: 18px; font-weight: 600; color: rgba(255,255,255,0.9); margin: 0 0 12px 0;
        }
        .mcp-detail-section p {
          font-size: 13px; color: rgba(255,255,255,0.55); line-height: 1.7; margin: 0 0 20px 0;
        }
        .mcp-detail-section h3 {
          font-size: 15px; font-weight: 600; color: rgba(255,255,255,0.85); margin: 0 0 14px 0;
        }
        .mcp-use-case {
          margin-bottom: 16px; padding-left: 8px;
        }
        .mcp-use-case-title {
          font-size: 13px; font-weight: 600; color: rgba(255,255,255,0.8); margin-bottom: 4px;
        }
        .mcp-use-case-title span { margin-right: 6px; }
        .mcp-use-case-desc {
          font-size: 12px; color: rgba(255,255,255,0.45); line-height: 1.5;
        }

        /* Manage MCP Modal */
        .mcp-manage-overlay {
          display: none; position: fixed;
          top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(0,0,0,0.6); z-index: 10001;
          justify-content: center; align-items: center;
        }
        .mcp-manage-overlay.active { display: flex; }
        .mcp-manage-modal {
          background: #1a1f2e; border-radius: 12px; width: 480px;
          border: 1px solid rgba(255,255,255,0.1); padding: 24px;
        }
        .mcp-manage-header {
          display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;
        }
        .mcp-manage-header h3 {
          font-size: 16px; font-weight: 600; color: #fff; margin: 0;
        }
        .mcp-manage-close {
          background: none; border: none; color: rgba(255,255,255,0.4);
          font-size: 20px; cursor: pointer; padding: 0;
        }
        .mcp-manage-close:hover { color: rgba(255,255,255,0.8); }
        .mcp-manage-field {
          margin-bottom: 16px;
        }
        .mcp-manage-label {
          font-size: 11px; color: rgba(255,255,255,0.4); margin-bottom: 4px;
          text-transform: uppercase; letter-spacing: 0.5px;
        }
        .mcp-manage-value {
          font-size: 13px; color: rgba(255,255,255,0.8);
        }
        .mcp-manage-input {
          width: 100%; padding: 10px 12px; border-radius: 6px;
          background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.12);
          color: rgba(255,255,255,0.9); font-size: 13px; font-family: inherit;
          box-sizing: border-box;
        }
        .mcp-manage-input:focus {
          outline: none; border-color: var(--primary);
        }
        .mcp-manage-actions {
          display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px;
        }
        .mcp-manage-btn {
          padding: 8px 18px; border-radius: 6px; font-size: 13px; font-weight: 500;
          cursor: pointer; font-family: inherit; border: 1px solid rgba(255,255,255,0.15);
          background: rgba(255,255,255,0.05); color: rgba(255,255,255,0.7);
        }
        .mcp-manage-btn:hover { background: rgba(255,255,255,0.1); }
        .mcp-manage-btn.primary {
          background: var(--primary); color: white; border-color: var(--primary);
        }
        .mcp-manage-btn.primary:hover { opacity: 0.9; }
        .mcp-manage-btn.test {
          background: rgba(255,255,255,0.08); color: rgba(255,255,255,0.8);
        }

        /* Catalog Tool Detail Page */
        .tool-detail-overlay {
          display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0;
          background: #0d1117; z-index: 9999; overflow-y: auto;
        }
        .tool-detail-overlay.active { display: block; }
        .tool-detail-content {
          max-width: 1050px; margin: 0 auto; padding: 40px 32px;
        }
        .tool-detail-top {
          display: flex; justify-content: space-between; align-items: flex-start; gap: 40px;
        }
        .tool-detail-left { flex: 1; }
        .tool-detail-right { flex-shrink: 0; width: 340px; }
        .tool-detail-title-row {
          display: flex; align-items: center; gap: 14px; margin-bottom: 14px;
        }
        .tool-detail-icon {
          width: 40px; height: 40px; border-radius: 10px;
          background: linear-gradient(135deg, #8b5cf6, #7c3aed);
          display: flex; align-items: center; justify-content: center;
          color: white; font-weight: 700; font-size: 18px; flex-shrink: 0;
        }
        .tool-detail-title-row h1 {
          font-size: 28px; font-weight: 700; color: #fff; margin: 0;
        }
        .tool-detail-source {
          font-size: 14px; color: rgba(255,255,255,0.5); margin-bottom: 10px;
        }
        .tool-detail-tag {
          display: inline-block; font-size: 12px; padding: 4px 14px;
          border-radius: 6px; background: rgba(255,255,255,0.08);
          color: rgba(255,255,255,0.7); border: 1px solid rgba(255,255,255,0.12);
          margin-bottom: 20px;
        }
        .tool-detail-desc {
          font-size: 14px; color: rgba(255,255,255,0.6); line-height: 1.6; margin-bottom: 20px;
        }
        .tool-detail-activate {
          display: inline-flex; align-items: center; gap: 8px;
          padding: 10px 20px; border-radius: 8px; background: #8b5cf6;
          border: none; color: white; font-size: 14px; font-weight: 500;
          cursor: pointer; font-family: inherit;
        }
        .tool-detail-activate:hover { background: #7c3aed; }
        .tool-detail-activate svg { width: 16px; height: 16px; }
        .tool-detail-meta-label {
          font-size: 13px; font-weight: 600; color: rgba(255,255,255,0.6);
          min-width: 110px; flex-shrink: 0;
        }
        .tool-detail-meta-row {
          display: flex; align-items: flex-start; gap: 16px; margin-bottom: 16px;
        }
        .tool-detail-pills {
          display: flex; flex-wrap: wrap; gap: 8px;
        }
        .tool-detail-pill {
          padding: 5px 14px; border-radius: 20px; font-size: 12px;
          border: 1px solid rgba(255,255,255,0.2); background: transparent;
          color: rgba(255,255,255,0.7); font-family: inherit;
        }
        .tool-detail-req {
          font-size: 13px; color: rgba(255,255,255,0.6);
        }
        .tool-detail-divider {
          border: none; border-top: 1px solid rgba(255,255,255,0.08);
          margin: 32px 0;
        }
        .tool-detail-section h2 {
          font-size: 20px; font-weight: 700; color: rgba(255,255,255,0.9); margin: 0 0 12px 0;
        }
        .tool-detail-section p {
          font-size: 14px; color: rgba(255,255,255,0.55); line-height: 1.7; margin: 0 0 24px 0;
        }
        .tool-detail-section h3 {
          font-size: 17px; font-weight: 700; color: rgba(255,255,255,0.85); margin: 0 0 16px 0;
        }
        .tool-detail-usecase {
          margin-bottom: 18px;
        }
        .tool-detail-usecase-title {
          font-size: 14px; font-weight: 600; color: rgba(255,255,255,0.8); margin-bottom: 4px;
        }
        .tool-detail-usecase-title span { color: #8b5cf6; margin-right: 6px; }
        .tool-detail-usecase-desc {
          font-size: 13px; color: rgba(255,255,255,0.45); line-height: 1.5;
        }
        .tool-detail-back {
          display: inline-flex; align-items: center; gap: 4px;
          font-size: 13px; color: rgba(255,255,255,0.5); cursor: pointer;
          background: none; border: none; padding: 0; font-family: inherit;
          margin-bottom: 24px;
        }
        .tool-detail-back:hover { color: var(--primary); }

        /* Outlook Activate Modal */
        .outlook-activate-overlay {
          display: none; position: fixed;
          top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(0,0,0,0.6); z-index: 10002;
          justify-content: center; align-items: center;
        }
        .outlook-activate-overlay.active { display: flex; }
        .outlook-activate-modal {
          background: #1e2235; border-radius: 12px; width: 620px;
          border: 1px solid rgba(255,255,255,0.1); padding: 28px 32px;
        }
        .outlook-activate-header {
          display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;
        }
        .outlook-activate-header h3 {
          font-size: 18px; font-weight: 600; color: #fff; margin: 0;
        }
        .outlook-activate-close {
          background: none; border: none; color: rgba(255,255,255,0.4);
          font-size: 22px; cursor: pointer; padding: 0; line-height: 1;
        }
        .outlook-activate-close:hover { color: rgba(255,255,255,0.8); }
        .outlook-activate-meta {
          display: flex; gap: 0; flex-direction: column; margin-bottom: 20px;
        }
        .outlook-activate-meta-row {
          display: flex; align-items: center; padding: 6px 0;
        }
        .outlook-activate-meta-label {
          font-size: 14px; font-weight: 600; color: rgba(255,255,255,0.9); width: 120px;
        }
        .outlook-activate-meta-value {
          font-size: 14px; color: rgba(255,255,255,0.6);
        }
        .outlook-activate-field {
          position: relative; margin-bottom: 18px;
        }
        .outlook-activate-field label {
          position: absolute; top: -9px; left: 12px;
          background: #1e2235; padding: 0 6px;
          font-size: 11px; color: rgba(255,255,255,0.45);
          pointer-events: none;
        }
        .outlook-activate-field input {
          width: 100%; padding: 14px 14px; border-radius: 8px;
          background: transparent; border: 1px solid rgba(255,255,255,0.2);
          color: rgba(255,255,255,0.85); font-size: 13px; font-family: inherit;
          box-sizing: border-box;
        }
        .outlook-activate-field input:focus {
          outline: none; border-color: var(--primary);
        }
        .outlook-activate-field input::placeholder {
          color: rgba(255,255,255,0.3);
        }
        .outlook-activate-footer {
          display: flex; align-items: center; justify-content: space-between; margin-top: 28px;
        }
        .outlook-activate-cancel {
          background: none; border: none; color: var(--primary);
          font-size: 14px; font-weight: 500; cursor: pointer; font-family: inherit;
          padding: 0;
        }
        .outlook-activate-cancel:hover { opacity: 0.8; }
        .outlook-activate-footer-right {
          display: flex; gap: 10px;
        }
        .outlook-activate-btn-test {
          padding: 10px 20px; border-radius: 8px; font-size: 13px; font-weight: 500;
          cursor: pointer; font-family: inherit; border: 1px solid rgba(255,255,255,0.2);
          background: transparent; color: rgba(255,255,255,0.7);
        }
        .outlook-activate-btn-test:hover { background: rgba(255,255,255,0.06); }
        .outlook-activate-btn-activate {
          padding: 10px 24px; border-radius: 8px; font-size: 13px; font-weight: 500;
          cursor: pointer; font-family: inherit; border: none;
          background: var(--primary); color: white;
        }
        .outlook-activate-btn-activate:hover { opacity: 0.9; }

        /* Teams Activate Modal */
        .teams-activate-overlay {
          display: none; position: fixed;
          top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(0,0,0,0.6); z-index: 10002;
          justify-content: center; align-items: center;
        }
        .teams-activate-overlay.active { display: flex; }
        .teams-activate-modal {
          background: #1e2235; border-radius: 12px; width: 620px;
          border: 1px solid rgba(255,255,255,0.1); padding: 28px 32px;
        }
        .teams-activate-header {
          display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;
        }
        .teams-activate-header h3 {
          font-size: 18px; font-weight: 600; color: #fff; margin: 0;
        }
        .teams-activate-close {
          background: none; border: none; color: rgba(255,255,255,0.4);
          font-size: 22px; cursor: pointer; padding: 0; line-height: 1;
        }
        .teams-activate-close:hover { color: rgba(255,255,255,0.8); }
        .teams-activate-meta {
          display: flex; gap: 0; flex-direction: column; margin-bottom: 20px;
        }
        .teams-activate-meta-row {
          display: flex; align-items: center; padding: 6px 0;
        }
        .teams-activate-meta-label {
          font-size: 14px; font-weight: 600; color: rgba(255,255,255,0.9); width: 120px;
        }
        .teams-activate-meta-value {
          font-size: 14px; color: rgba(255,255,255,0.6);
        }
        .teams-activate-field {
          position: relative; margin-bottom: 18px;
        }
        .teams-activate-field label {
          position: absolute; top: -9px; left: 12px;
          background: #1e2235; padding: 0 6px;
          font-size: 11px; color: rgba(255,255,255,0.45);
          pointer-events: none;
        }
        .teams-activate-field input {
          width: 100%; padding: 14px 14px; border-radius: 8px;
          background: transparent; border: 1px solid rgba(255,255,255,0.2);
          color: rgba(255,255,255,0.85); font-size: 13px; font-family: inherit;
          box-sizing: border-box;
        }
        .teams-activate-field input:focus {
          outline: none; border-color: var(--primary);
        }
        .teams-activate-field input::placeholder {
          color: rgba(255,255,255,0.3);
        }
        .teams-activate-footer {
          display: flex; align-items: center; justify-content: space-between; margin-top: 28px;
        }
        .teams-activate-cancel {
          background: none; border: none; color: var(--primary);
          font-size: 14px; font-weight: 500; cursor: pointer; font-family: inherit;
          padding: 0;
        }
        .teams-activate-cancel:hover { opacity: 0.8; }
        .teams-activate-footer-right {
          display: flex; gap: 10px;
        }
        .teams-activate-btn-test {
          padding: 10px 20px; border-radius: 8px; font-size: 13px; font-weight: 500;
          cursor: pointer; font-family: inherit; border: 1px solid rgba(255,255,255,0.2);
          background: transparent; color: rgba(255,255,255,0.7);
        }
        .teams-activate-btn-test:hover { background: rgba(255,255,255,0.06); }
        .teams-activate-btn-activate {
          padding: 10px 24px; border-radius: 8px; font-size: 13px; font-weight: 500;
          cursor: pointer; font-family: inherit; border: none;
          background: var(--primary); color: white;
        }
        .teams-activate-btn-activate:hover { opacity: 0.9; }

        /* Create Agent Flow Modal */
        .create-flow-overlay {
          display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(0,0,0,0.6); z-index: 10001;
          justify-content: center; align-items: center;
        }
        .create-flow-overlay.active { display: flex; }
        .create-flow-modal {
          background: #1a1f2e; border-radius: 12px; width: 540px;
          border: 1px solid rgba(255,255,255,0.1); padding: 32px;
        }
        .create-flow-header {
          display: flex; justify-content: space-between; align-items: center; margin-bottom: 28px;
        }
        .create-flow-header h2 {
          font-size: 22px; font-weight: 600; color: rgba(255,255,255,0.9); margin: 0;
        }
        .create-flow-close {
          background: none; border: none; color: rgba(255,255,255,0.4);
          font-size: 22px; cursor: pointer;
        }
        .create-flow-close:hover { color: rgba(255,255,255,0.8); }
        .create-flow-field { margin-bottom: 8px; }
        .create-flow-input {
          width: 100%; padding: 14px 16px; border-radius: 8px;
          background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.15);
          color: rgba(255,255,255,0.9); font-size: 15px; font-family: inherit;
          box-sizing: border-box;
        }
        .create-flow-input::placeholder { color: rgba(255,255,255,0.3); }
        .create-flow-input:focus { outline: none; border-color: rgba(139,92,246,0.5); }
        .create-flow-textarea {
          width: 100%; padding: 14px 16px; border-radius: 8px; min-height: 120px; resize: vertical;
          background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.15);
          color: rgba(255,255,255,0.9); font-size: 15px; font-family: inherit;
          box-sizing: border-box;
        }
        .create-flow-textarea::placeholder { color: rgba(255,255,255,0.3); }
        .create-flow-textarea:focus { outline: none; border-color: rgba(139,92,246,0.5); }
        .create-flow-hint {
          font-size: 12px; color: rgba(255,255,255,0.35); margin-top: 8px; line-height: 1.5;
        }
        .create-flow-hint-row {
          display: flex; justify-content: space-between; align-items: flex-start;
        }
        .create-flow-counter {
          font-size: 12px; color: rgba(255,255,255,0.35); white-space: nowrap; margin-left: 12px; margin-top: 8px;
        }
        .create-flow-actions {
          display: flex; justify-content: flex-end; gap: 12px; margin-top: 28px;
        }
        .create-flow-btn {
          padding: 10px 24px; border-radius: 8px; font-size: 14px; font-weight: 500;
          cursor: pointer; font-family: inherit;
          border: 1px solid rgba(255,255,255,0.2); background: transparent;
          color: rgba(255,255,255,0.8);
        }
        .create-flow-btn:hover { background: rgba(255,255,255,0.05); }
        .create-flow-btn.save {
          background: #8b5cf6; color: white; border-color: #8b5cf6;
        }
        .create-flow-btn.save:hover { background: #7c3aed; }

        /* Workflow Builder Modal */
        .workflow-modal-overlay {
          display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(0,0,0,0.7); z-index: 10000;
          justify-content: center; align-items: center;
        }
        .workflow-modal-overlay.active { display: flex; }
        .workflow-modal {
          background: #0f1219; border-radius: 12px; width: 92vw; height: 75vh;
          max-width: 1400px; display: flex; flex-direction: column;
          border: 1px solid rgba(255,255,255,0.08); overflow: hidden; position: relative;
        }
        .workflow-modal-header {
          display: flex; align-items: center; justify-content: space-between;
          padding: 14px 20px; border-bottom: 1px solid rgba(255,255,255,0.08); flex-shrink: 0;
        }
        .workflow-modal-header-left { display: flex; align-items: center; gap: 8px; }
        .workflow-modal-title { font-size: 14px; font-weight: 600; color: rgba(255,255,255,0.9); }
        .workflow-modal-preview-btn {
          padding: 6px 16px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.15);
          background: rgba(255,255,255,0.05); color: rgba(255,255,255,0.8);
          font-size: 12px; font-weight: 500; cursor: pointer; font-family: inherit;
        }
        .workflow-modal-preview-btn:hover { background: rgba(255,255,255,0.1); }
        .workflow-modal-body {
          flex: 1; position: relative; overflow: hidden;
          background: radial-gradient(circle at 1px 1px, rgba(255,255,255,0.03) 1px, transparent 0);
          background-size: 24px 24px;
        }
        .wf-add-btn {
          position: absolute; top: 16px; left: 16px; width: 32px; height: 32px;
          border-radius: 6px; background: var(--primary); border: none; color: white;
          font-size: 18px; cursor: pointer; display: flex; align-items: center;
          justify-content: center; z-index: 3;
        }
        .wf-add-btn:hover { opacity: 0.85; }
        .wf-dropdown {
          display: none; position: absolute; top: 54px; left: 16px; z-index: 4;
          background: #1a1f2e; border: 1px solid rgba(255,255,255,0.12);
          border-radius: 8px; min-width: 240px; padding: 4px 0;
          box-shadow: 0 8px 24px rgba(0,0,0,0.4);
        }
        .wf-dropdown.active { display: block; }
        .wf-dropdown-item {
          display: flex; align-items: center; gap: 10px; padding: 10px 14px;
          font-size: 13px; color: rgba(255,255,255,0.75); cursor: pointer;
          border: none; background: none; width: 100%; text-align: left; font-family: inherit;
        }
        .wf-dropdown-item:hover { background: rgba(255,255,255,0.06); }
        .wf-dropdown-item svg {
          width: 16px; height: 16px; stroke: rgba(255,255,255,0.5);
          fill: none; stroke-width: 2; flex-shrink: 0;
        }
        .wf-canvas { position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 1; }
        .wf-node {
          position: absolute; display: flex; align-items: center; gap: 8px;
          cursor: grab; white-space: nowrap; z-index: 2; user-select: none;
        }
        .wf-node:active { cursor: grabbing; }
        .wf-node-port {
          width: 10px; height: 10px; border-radius: 50%;
          border: 2px solid rgba(255,255,255,0.3); background: #0f1219;
          flex-shrink: 0; cursor: crosshair;
        }
        .wf-node-port:hover { border-color: var(--primary); background: rgba(139,92,246,0.2); }
        .wf-node-icon {
          width: 28px; height: 28px; border-radius: 6px;
          background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.12);
          display: flex; align-items: center; justify-content: center; flex-shrink: 0;
        }
        .wf-node-icon svg {
          width: 14px; height: 14px; stroke: rgba(255,255,255,0.6); fill: none; stroke-width: 2;
        }
        .wf-node-label { font-size: 12px; color: rgba(255,255,255,0.7); font-weight: 500; }
        .wf-node.start-node { cursor: pointer; }
        .wf-node.start-node .wf-node-icon {
          background: rgba(139,92,246,0.15); border-color: rgba(139,92,246,0.3);
        }

        /* Chat Input Panel */
        .wf-chat-overlay {
          display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(0,0,0,0.5); z-index: 10002;
          justify-content: center; align-items: center;
        }
        .wf-chat-overlay.active { display: flex; }
        .wf-chat-panel {
          background: #151922; border-radius: 12px; width: 420px; height: 520px;
          border: 1px solid rgba(255,255,255,0.1); overflow: hidden;
          display: flex; flex-direction: column;
          min-width: 320px; min-height: 300px; max-width: 90vw; max-height: 90vh;
          position: relative;
        }
        .wf-chat-resize-handle {
          position: absolute; bottom: 0; right: 0; width: 18px; height: 18px;
          cursor: nwse-resize; z-index: 10;
          background: linear-gradient(135deg, transparent 50%, rgba(139,92,246,0.4) 50%);
          border-radius: 0 0 12px 0;
        }
        .wf-chat-resize-handle:hover {
          background: linear-gradient(135deg, transparent 50%, rgba(139,92,246,0.7) 50%);
        }
        .wf-chat-header {
          display: flex; align-items: center; justify-content: space-between;
          padding: 14px 16px; border-bottom: 1px solid rgba(255,255,255,0.08);
        }
        .wf-chat-header-left { display: flex; align-items: center; gap: 8px; }
        .wf-chat-header-title { font-size: 14px; font-weight: 600; color: rgba(255,255,255,0.9); }
        .wf-chat-header-icon {
          width: 24px; height: 24px; border-radius: 6px;
          background: rgba(139,92,246,0.15); border: 1px solid rgba(139,92,246,0.3);
          display: flex; align-items: center; justify-content: center;
        }
        .wf-chat-header-icon svg { width: 12px; height: 12px; stroke: #a78bfa; fill: none; stroke-width: 2; }
        .wf-chat-close {
          background: none; border: none; color: rgba(255,255,255,0.4);
          font-size: 18px; cursor: pointer;
        }
        .wf-chat-close:hover { color: rgba(255,255,255,0.8); }
        .wf-chat-type-row {
          padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.06);
        }
        .wf-chat-type-label {
          font-size: 11px; color: rgba(255,255,255,0.4); margin-bottom: 6px;
          text-transform: uppercase; letter-spacing: 0.5px;
        }
        .wf-chat-type-select {
          width: 100%; padding: 8px 10px; border-radius: 6px;
          background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.12);
          color: rgba(255,255,255,0.8); font-size: 13px; font-family: inherit;
          appearance: auto;
        }
        .wf-chat-messages {
          flex: 1; padding: 16px; overflow-y: auto; min-height: 200px;
          display: flex; flex-direction: column; gap: 12px;
        }
        .wf-chat-msg {
          font-size: 13px; line-height: 1.5; max-width: 85%; padding: 10px 14px;
          border-radius: 10px;
        }
        .wf-chat-msg.user {
          background: var(--primary); color: white; align-self: flex-end;
          border-bottom-right-radius: 4px;
        }
        .wf-chat-msg.assistant {
          background: rgba(255,255,255,0.08); color: rgba(255,255,255,0.85);
          align-self: flex-start; border-bottom-left-radius: 4px;
        }
        .wf-chat-input-row {
          display: flex; gap: 8px; padding: 12px 16px;
          border-top: 1px solid rgba(255,255,255,0.08);
        }
        .wf-chat-input {
          flex: 1; padding: 10px 12px; border-radius: 8px;
          background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.12);
          color: rgba(255,255,255,0.9); font-size: 13px; font-family: inherit;
        }
        .wf-chat-input:focus { outline: none; border-color: var(--primary); }
        .wf-chat-send {
          padding: 8px 14px; border-radius: 8px; background: var(--primary);
          border: none; color: white; cursor: pointer; font-family: inherit;
          font-size: 13px; font-weight: 500;
        }
        .wf-chat-send:hover { opacity: 0.9; }
      </style>

      <!-- Banner -->
      <div class="ai-agents-banner">
        <h1>Extreme Exchange's AI Agents Supercharge Your Team</h1>
        <p>Get AI-powered assistants to accelerate your team's efficiency and maximize your network's performance.</p>
      </div>

      <!-- Active Agents Section -->
      <div class="ai-agents-section">
        <div class="ai-agents-section-header">
          <div class="ai-agents-section-title">Active</div>
          <a class="ai-agents-see-all" id="ai-agents-see-all">See All Active (<span id="ai-active-count">0</span>) &rarr;</a>
        </div>
        <div class="ai-agents-grid" id="ai-active-agents"></div>
      </div>

      <!-- Catalog Section -->
      <div class="ai-agents-section">
        <div class="ai-agents-section-header">
          <div class="ai-agents-section-title">Catalog</div>
        </div>
        <div class="ai-agents-grid" id="ai-catalog-agents"></div>
      </div>

      <!-- MCP Detail Page -->
      <div class="mcp-detail-overlay" id="mcp-detail-overlay">
        <div class="mcp-detail-topbar">
          <div class="mcp-detail-topbar-logo">
            <div class="mcp-detail-topbar-logo-icon">E</div>
            Extreme Exchange
          </div>
          <div class="mcp-detail-tabs">
            <button class="mcp-detail-tab active">Catalog</button>
            <button class="mcp-detail-tab">Dashboard</button>
            <button class="mcp-detail-tab">Agent Flow Builder</button>
          </div>
        </div>
        <div class="mcp-detail-content">
          <button class="mcp-detail-backlink" onclick="closeMcpDetail()">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
            Catalog
          </button>

          <div class="mcp-detail-header">
            <div class="mcp-detail-header-icon">E</div>
            <div>
              <h1>Platform ONE APIs MCP Server</h1>
            </div>
          </div>

          <div class="mcp-detail-source">Extreme Networks</div>
          <div class="mcp-detail-tag">Tool</div>
          <div class="mcp-detail-desc">Enables integration with Extreme Platform ONE APIs for enhanced network management and automation.</div>

          <div class="mcp-detail-actions">
            <div class="mcp-detail-status-badge"><span class="mcp-detail-status-dot"></span>Active</div>
            <button class="mcp-detail-btn" onclick="openMcpManageModal()">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
              Manage
            </button>
            <button class="mcp-detail-btn">Deactivate</button>
          </div>

          <div class="mcp-detail-pills">
            <button class="mcp-detail-pill">Supported Agents</button>
            <button class="mcp-detail-pill">General Model</button>
            <button class="mcp-detail-pill">Service Agent</button>
            <button class="mcp-detail-pill active">MCP</button>
            <button class="mcp-detail-pill">Purpose</button>
            <button class="mcp-detail-pill">Agent Configuration</button>
            <button class="mcp-detail-pill">Agent Execution</button>
            <button class="mcp-detail-pill">Standardization</button>
          </div>

          <div class="mcp-detail-meta">
            <div><strong>Services:</strong> 1 API</div>
            <div><strong>Last Updated:</strong> 2025.01.30</div>
          </div>

          <div class="mcp-detail-section">
            <h2>Overview</h2>
            <p>The Platform ONE APIs serve as a unified configuration and exposure layer for multiple operational agents such as Device Health, Service, and MCP agents. It provides a consistent interface to register, configure, and onboard agents while standardizing how their capabilities, use cases, and metadata are defined and discovered.</p>

            <h3>Use Cases</h3>
            <div class="mcp-use-case">
              <div class="mcp-use-case-title"><span>1.</span> Unified agent exposure</div>
              <div class="mcp-use-case-desc">Expose multiple agents through a single MCP entry point, enabling consistent discovery and configuration across the platform.</div>
            </div>
            <div class="mcp-use-case">
              <div class="mcp-use-case-title"><span>2.</span> Centralized agent configuration</div>
              <div class="mcp-use-case-desc">Define and manage agent configurations, actions, responses, and metadata in a standardized format.</div>
            </div>
            <div class="mcp-use-case">
              <div class="mcp-use-case-title"><span>3.</span> Scalable agent onboarding</div>
              <div class="mcp-use-case-desc">Easily onboard new agent types such as Device Health, Service, or MCP by reusing the same configuration schema.</div>
            </div>
            <div class="mcp-use-case">
              <div class="mcp-use-case-title"><span>4.</span> Consistent UI and consumer integration</div>
              <div class="mcp-use-case-desc">Ensure downstream consumers and UIs can fetch and interact with different agents in a uniform way.</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Meraki MCP Detail Page -->
      <div class="mcp-detail-overlay" id="meraki-detail-overlay">
        <div class="mcp-detail-topbar">
          <div class="mcp-detail-topbar-logo">
            <div class="mcp-detail-topbar-logo-icon cyan">M</div>
            Cisco Meraki
          </div>
          <div class="mcp-detail-tabs">
            <button class="mcp-detail-tab active">Catalog</button>
            <button class="mcp-detail-tab">Dashboard</button>
            <button class="mcp-detail-tab">Agent Flow Builder</button>
          </div>
        </div>
        <div class="mcp-detail-content">
          <button class="mcp-detail-backlink" onclick="closeMerakiDetail()">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
            Catalog
          </button>

          <div class="mcp-detail-header">
            <div class="mcp-detail-header-icon cyan">M</div>
            <div>
              <h1>Meraki APIs MCP Server</h1>
            </div>
          </div>

          <div class="mcp-detail-source">Cisco</div>
          <div class="mcp-detail-tag">Tool</div>
          <div class="mcp-detail-desc">Enables integration with Cisco Meraki APIs for cloud-managed network monitoring and automation.</div>

          <div class="mcp-detail-actions">
            <div class="mcp-detail-status-badge"><span class="mcp-detail-status-dot"></span>Active</div>
            <button class="mcp-detail-btn" onclick="openMerakiManageModal()">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
              Manage
            </button>
            <button class="mcp-detail-btn">Deactivate</button>
          </div>

          <div class="mcp-detail-pills">
            <button class="mcp-detail-pill">Supported Agents</button>
            <button class="mcp-detail-pill">General Model</button>
            <button class="mcp-detail-pill">Service Agent</button>
            <button class="mcp-detail-pill active">MCP</button>
            <button class="mcp-detail-pill">Purpose</button>
            <button class="mcp-detail-pill">Agent Configuration</button>
            <button class="mcp-detail-pill">Agent Execution</button>
            <button class="mcp-detail-pill">Standardization</button>
          </div>

          <div class="mcp-detail-meta">
            <div><strong>Services:</strong> 1 API</div>
            <div><strong>Last Updated:</strong> 2025.06.15</div>
          </div>

          <div class="mcp-detail-section">
            <h2>Overview</h2>
            <p>The Meraki APIs MCP Server provides a streamlined interface for interacting with the Cisco Meraki Dashboard API. It enables cloud-managed network monitoring, device management, and automation across Meraki organizations and networks, giving agents direct access to network infrastructure insights and controls.</p>

            <h3>Use Cases</h3>
            <div class="mcp-use-case">
              <div class="mcp-use-case-title"><span>1.</span> Network monitoring</div>
              <div class="mcp-use-case-desc">Monitor device status, uptime, connectivity, and performance across Meraki networks.</div>
            </div>
            <div class="mcp-use-case">
              <div class="mcp-use-case-title"><span>2.</span> Device management</div>
              <div class="mcp-use-case-desc">List, configure, and manage Meraki devices including APs, switches, and security appliances.</div>
            </div>
            <div class="mcp-use-case">
              <div class="mcp-use-case-title"><span>3.</span> Organization and network administration</div>
              <div class="mcp-use-case-desc">Manage organizations, networks, and administrators through the Meraki Dashboard API.</div>
            </div>
            <div class="mcp-use-case">
              <div class="mcp-use-case-title"><span>4.</span> Client and traffic analysis</div>
              <div class="mcp-use-case-desc">Track connected clients, bandwidth usage, and application traffic across the network.</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Manage MCP Modal -->
      <div class="mcp-manage-overlay" id="mcp-manage-overlay" onclick="if(event.target===this)closeMcpManageModal()">
        <div class="mcp-manage-modal">
          <div class="mcp-manage-header">
            <h3>Manage Platform ONE APIs MCP Server</h3>
            <button class="mcp-manage-close" onclick="closeMcpManageModal()">&times;</button>
          </div>
          <div class="mcp-manage-field">
            <div class="mcp-manage-label">Type</div>
            <div class="mcp-manage-value">MCP Server</div>
          </div>
          <div class="mcp-manage-field">
            <div class="mcp-manage-label">Name</div>
            <div class="mcp-manage-value">Platform ONE APIs MCP Server</div>
          </div>
          <div class="mcp-manage-field">
            <div class="mcp-manage-label">Server URL</div>
            <input class="mcp-manage-input" type="text" value="https://mcp-server.sandbox.alore.team/mcp" readonly>
          </div>
          <div class="mcp-manage-field">
            <div class="mcp-manage-label">API Key</div>
            <input class="mcp-manage-input" type="password" value="sk-xxxxxxxxxxxx" readonly>
          </div>
          <div class="mcp-manage-actions">
            <button class="mcp-manage-btn" onclick="closeMcpManageModal()">Cancel</button>
            <button class="mcp-manage-btn test">Test Connection</button>
            <button class="mcp-manage-btn primary">Save Changes</button>
          </div>
        </div>
      </div>

      <!-- Manage Meraki MCP Modal -->
      <div class="mcp-manage-overlay" id="meraki-manage-overlay" onclick="if(event.target===this)closeMerakiManageModal()">
        <div class="mcp-manage-modal">
          <div class="mcp-manage-header">
            <h3>Manage Meraki APIs MCP Server</h3>
            <button class="mcp-manage-close" onclick="closeMerakiManageModal()">&times;</button>
          </div>
          <div class="mcp-manage-field">
            <div class="mcp-manage-label">Type</div>
            <div class="mcp-manage-value">MCP Server</div>
          </div>
          <div class="mcp-manage-field">
            <div class="mcp-manage-label">Name</div>
            <div class="mcp-manage-value">Meraki APIs MCP Server</div>
          </div>
          <div class="mcp-manage-field">
            <div class="mcp-manage-label">Server URL</div>
            <input class="mcp-manage-input" type="text" value="https://meraki-mcp.example.com/mcp" readonly>
          </div>
          <div class="mcp-manage-field">
            <div class="mcp-manage-label">API Key</div>
            <input class="mcp-manage-input" type="password" value="sk-xxxxxxxxxxxx" readonly>
          </div>
          <div class="mcp-manage-actions">
            <button class="mcp-manage-btn" onclick="closeMerakiManageModal()">Cancel</button>
            <button class="mcp-manage-btn test">Test Connection</button>
            <button class="mcp-manage-btn primary">Save Changes</button>
          </div>
        </div>
      </div>

      <!-- Catalog Tool Detail Page -->
      <div class="tool-detail-overlay" id="tool-detail-overlay">
        <div class="tool-detail-content">
          <button class="tool-detail-back" onclick="closeToolDetail()">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
            Back
          </button>

          <div class="tool-detail-top">
            <div class="tool-detail-left">
              <div class="tool-detail-title-row">
                <div class="tool-detail-icon" id="tool-detail-icon">O</div>
                <h1 id="tool-detail-title">Microsoft Outlook</h1>
              </div>
              <div class="tool-detail-source" id="tool-detail-source">Third Party</div>
              <div class="tool-detail-tag" id="tool-detail-tag">Tool</div>
              <div class="tool-detail-desc" id="tool-detail-desc">Microsoft Outlook APIs to manage Messages, Channels and Chats</div>
              <button class="tool-detail-activate" id="tool-detail-activate-btn" onclick="openOutlookActivate()">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                Activate
              </button>
            </div>
            <div class="tool-detail-right" id="tool-detail-right">
              <div class="tool-detail-meta-row">
                <div class="tool-detail-meta-label">Industry</div>
                <div class="tool-detail-pills">
                  <span class="tool-detail-pill">Enterprise</span>
                  <span class="tool-detail-pill">Manufacturing</span>
                  <span class="tool-detail-pill">Hospitality</span>
                  <span class="tool-detail-pill">Federal</span>
                  <span class="tool-detail-pill">State</span>
                  <span class="tool-detail-pill">Local</span>
                  <span class="tool-detail-pill">Education</span>
                </div>
              </div>
              <div class="tool-detail-meta-row">
                <div class="tool-detail-meta-label">Job Function</div>
                <div class="tool-detail-pills">
                  <span class="tool-detail-pill">Network Ops</span>
                  <span class="tool-detail-pill">Security Ops</span>
                  <span class="tool-detail-pill">NetSecOps</span>
                </div>
              </div>
              <div class="tool-detail-meta-row">
                <div class="tool-detail-meta-label">Requirements</div>
                <div class="tool-detail-req">Valid Platform ONE subscription.</div>
              </div>
            </div>
          </div>

          <hr class="tool-detail-divider">

          <div class="tool-detail-section" id="tool-detail-overview">
            <h2>Overview</h2>
            <p id="tool-detail-overview-text">Use these tools to perform Create/Read/Update/Delete operations on your Microsoft Outlook Messages, Events and Calendar.</p>

            <h3>Use Cases</h3>
            <div id="tool-detail-usecases">
              <div class="tool-detail-usecase">
                <div class="tool-detail-usecase-title"><span>&#10023;</span> Email Messages</div>
                <div class="tool-detail-usecase-desc">List Messages, Get Message, Create Draft Message, Send Message, Update Message, Delete Message, Copy Message, Move Message, Reply to Message, Forward Message.</div>
              </div>
              <div class="tool-detail-usecase">
                <div class="tool-detail-usecase-title"><span>&#10023;</span> Events</div>
                <div class="tool-detail-usecase-desc">List Events, Get Event, Create Event, Update Event, Delete Event</div>
              </div>
              <div class="tool-detail-usecase">
                <div class="tool-detail-usecase-title"><span>&#10023;</span> Calendar</div>
                <div class="tool-detail-usecase-desc">List Events, Get Event, Create Event. Update Event, Delete Event</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Outlook Activate Modal -->
      <div class="outlook-activate-overlay" id="outlook-activate-overlay" onclick="if(event.target===this)closeOutlookActivate()">
        <div class="outlook-activate-modal">
          <div class="outlook-activate-header">
            <h3>Activate Microsoft Outlook</h3>
            <button class="outlook-activate-close" onclick="closeOutlookActivate()">&times;</button>
          </div>
          <div class="outlook-activate-meta">
            <div class="outlook-activate-meta-row">
              <div class="outlook-activate-meta-label">Type</div>
              <div class="outlook-activate-meta-value">Tool</div>
            </div>
            <div class="outlook-activate-meta-row">
              <div class="outlook-activate-meta-label">Name</div>
              <div class="outlook-activate-meta-value">Microsoft Outlook</div>
            </div>
          </div>
          <div class="outlook-activate-field">
            <label>Access Token URL</label>
            <input type="text" id="outlook-token-url" value="https://login.microsoftonline.com/<tenantId>/oauth2/v2.0/token">
          </div>
          <div class="outlook-activate-field">
            <label>Authorization URL</label>
            <input type="text" id="outlook-auth-url" value="https://login.microsoftonline.com/<tenantId>/oauth2/v2.0/authorize">
          </div>
          <div class="outlook-activate-field">
            <input type="text" id="outlook-client-id" placeholder="Client ID">
          </div>
          <div class="outlook-activate-field">
            <input type="password" id="outlook-client-secret" placeholder="Client Secret">
          </div>
          <div class="outlook-activate-footer">
            <button class="outlook-activate-cancel" onclick="closeOutlookActivate()">Cancel</button>
            <div class="outlook-activate-footer-right">
              <button class="outlook-activate-btn-test" onclick="testOutlookConnection()">Test Connection</button>
              <button class="outlook-activate-btn-activate" onclick="activateOutlookConnection()">Activate</button>
            </div>
          </div>
        </div>
      </div>

      <!-- Teams Activate Modal -->
      <div class="teams-activate-overlay" id="teams-activate-overlay" onclick="if(event.target===this)closeTeamsActivate()">
        <div class="teams-activate-modal">
          <div class="teams-activate-header">
            <h3>Activate Microsoft Teams</h3>
            <button class="teams-activate-close" onclick="closeTeamsActivate()">&times;</button>
          </div>
          <div class="teams-activate-meta">
            <div class="teams-activate-meta-row">
              <div class="teams-activate-meta-label">Type</div>
              <div class="teams-activate-meta-value">Tool</div>
            </div>
            <div class="teams-activate-meta-row">
              <div class="teams-activate-meta-label">Name</div>
              <div class="teams-activate-meta-value">Microsoft Teams</div>
            </div>
          </div>
          <div class="teams-activate-field">
            <label>Access Token URL</label>
            <input type="text" id="teams-token-url" value="https://login.microsoftonline.com/<tenantId>/oauth2/v2.0/token">
          </div>
          <div class="teams-activate-field">
            <label>Authorization URL</label>
            <input type="text" id="teams-auth-url" value="https://login.microsoftonline.com/<tenantId>/oauth2/v2.0/authorize">
          </div>
          <div class="teams-activate-field">
            <input type="text" id="teams-client-id" placeholder="Client ID">
          </div>
          <div class="teams-activate-field">
            <input type="password" id="teams-client-secret" placeholder="Client Secret">
          </div>
          <div class="teams-activate-footer">
            <button class="teams-activate-cancel" onclick="closeTeamsActivate()">Cancel</button>
            <div class="teams-activate-footer-right">
              <button class="teams-activate-btn-test" onclick="testTeamsConnection()">Test Connection</button>
              <button class="teams-activate-btn-activate" onclick="activateTeamsConnection()">Activate</button>
            </div>
          </div>
        </div>
      </div>

      <!-- Create Agent Flow Modal -->
      <div class="create-flow-overlay" id="create-flow-overlay" onclick="if(event.target===this)closeCreateFlow()">
        <div class="create-flow-modal">
          <div class="create-flow-header">
            <h2>Create Agent Flow</h2>
            <button class="create-flow-close" onclick="closeCreateFlow()">&times;</button>
          </div>
          <div class="create-flow-field">
            <input class="create-flow-input" id="create-flow-name" type="text" placeholder="Name" maxlength="100">
          </div>
          <div class="create-flow-hint">Give your flow a name that is intuitive and easy to understand.</div>
          <div class="create-flow-field" style="margin-top:20px">
            <textarea class="create-flow-textarea" id="create-flow-desc" placeholder="Description" maxlength="250" oninput="updateFlowCounter()"></textarea>
          </div>
          <div class="create-flow-hint-row">
            <div class="create-flow-hint">Provide a description of your flow that includes the purpose of the flow, the context it will be used in, and any other relevant information..</div>
            <div class="create-flow-counter" id="create-flow-counter">0/250</div>
          </div>
          <div class="create-flow-actions">
            <button class="create-flow-btn" onclick="closeCreateFlow()">Cancel</button>
            <button class="create-flow-btn save" onclick="saveCreateFlow()">Save</button>
          </div>
        </div>
      </div>

      <!-- Workflow Builder Modal -->
      <div class="workflow-modal-overlay" id="workflow-modal-overlay" onclick="if(event.target===this)closeWorkflowModal()">
        <div class="workflow-modal">
          <div class="workflow-modal-header">
            <div class="workflow-modal-header-left">
              <span style="color:#8b5cf6;font-size:14px;">&#9671;</span>
              <span class="workflow-modal-title" id="workflow-modal-title">Testing workflow</span>
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.4)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="cursor:pointer"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
            </div>
            <div style="display:flex;align-items:center;gap:12px;">
              <button class="workflow-modal-preview-btn">Preview</button>
              <button style="background:none;border:none;color:rgba(255,255,255,0.4);font-size:20px;cursor:pointer" onclick="closeWorkflowModal()">&times;</button>
            </div>
          </div>
          <div class="workflow-modal-body" id="workflow-modal-body">
            <button class="wf-add-btn" onclick="toggleWfDropdown()">+</button>
            <div class="wf-dropdown" id="wf-dropdown">
              <button class="wf-dropdown-item" onclick="addWfNode('condition')">
                <svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 4-7 8-7s8 3 8 7"/></svg>
                New Condition Agent Node
              </button>
              <button class="wf-dropdown-item" onclick="addWfNode('mcp')">
                <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 1v4m0 14v4M4.22 4.22l2.83 2.83m9.9 9.9l2.83 2.83M1 12h4m14 0h4M4.22 19.78l2.83-2.83m9.9-9.9l2.83-2.83"/></svg>
                New AI Agents MCP Node
              </button>
              <button class="wf-dropdown-item" onclick="addWfNode('reply')">
                <svg viewBox="0 0 24 24"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
                New Direct Reply Node
              </button>
            </div>
            <svg class="wf-canvas" id="wf-canvas"></svg>
          </div>
        </div>
      </div>

      <!-- Chat Input Panel -->
      <div class="wf-chat-overlay" id="wf-chat-overlay" onclick="if(event.target===this)closeWfChat()">
        <div class="wf-chat-panel" id="wf-chat-panel">
          <div class="wf-chat-header">
            <div class="wf-chat-header-left">
              <div class="wf-chat-header-icon">
                <svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="3"/></svg>
              </div>
              <span class="wf-chat-header-title">Start</span>
            </div>
            <button class="wf-chat-close" onclick="closeWfChat()">&times;</button>
          </div>
          <div class="wf-chat-type-row">
            <div class="wf-chat-type-label">Chat Input</div>
            <select class="wf-chat-type-select">
              <option>Chat Input</option>
            </select>
          </div>
          <div class="wf-chat-messages" id="wf-chat-messages"></div>
          <div class="wf-chat-input-row">
            <input class="wf-chat-input" id="wf-chat-input" type="text" placeholder="Chat Input" onkeydown="if(event.key==='Enter')sendWfChat()">
            <button class="wf-chat-send" onclick="sendWfChat()">Send</button>
          </div>
          <div class="wf-chat-resize-handle" id="wf-chat-resize-handle"></div>
        </div>
      </div>
    </div>

    <!-- Portal Users View -->
    <div id="view-portal-users" class="view-panel">
      <div class="page-header">
        <div>
          <h1 class="page-title">Portal Users</h1>
          <div class="page-subtitle">Manage user accounts for the GSA VC Portal</div>
        </div>
        <div class="header-actions">
          <button class="header-btn" style="background:var(--primary);color:white" onclick="openAddUser()">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            Add User
          </button>
        </div>
      </div>
      <div class="page-content">
        <div class="data-table-container">
          <table class="data-table" id="portal-users-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Username</th>
                <th>Display Name</th>
                <th>Role</th>
                <th>Passkey</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="portal-users-tbody">
              <tr><td colspan="6" style="text-align:center;color:var(--foreground-muted);padding:40px">Loading...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Portal User Add/Edit Modal -->
    <div class="portal-user-overlay" id="portal-user-overlay" onclick="if(event.target===this)closeUserModal()">
      <div class="portal-user-modal">
        <div class="portal-user-modal-header">
          <h3 id="portal-user-modal-title">Add User</h3>
          <button class="portal-user-modal-close" onclick="closeUserModal()">&times;</button>
        </div>
        <div class="portal-user-modal-body">
          <input type="hidden" id="pu-edit-id" value="">
          <div class="portal-user-field">
            <label class="portal-user-label">Username</label>
            <input class="portal-user-input" type="text" id="pu-username" placeholder="Enter username" autocomplete="off">
          </div>
          <div class="portal-user-field">
            <label class="portal-user-label">Password <span id="pu-password-hint" style="display:none;color:rgba(255,255,255,0.3)">(leave blank to keep current)</span></label>
            <input class="portal-user-input" type="password" id="pu-password" placeholder="Enter password" autocomplete="new-password">
          </div>
          <div class="portal-user-field">
            <label class="portal-user-label">Display Name</label>
            <input class="portal-user-input" type="text" id="pu-display-name" placeholder="Enter display name" autocomplete="off">
          </div>
          <div class="portal-user-field">
            <label class="portal-user-label">Role</label>
            <select class="portal-user-input" id="pu-role">
              <option value="admin">Admin</option>
              <option value="viewer" selected>Viewer</option>
            </select>
          </div>
        </div>
        <div class="portal-user-modal-actions">
          <button class="portal-user-btn" onclick="closeUserModal()">Cancel</button>
          <button class="portal-user-btn primary" onclick="saveUser()">Save</button>
        </div>
      </div>
    </div>

  </main>

  <script>
    // HTML-escape helper to prevent stored XSS from attacker-controlled client fields
    function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
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
      } else if (viewId === 'psirt') {
        loadPsirtAdvisories();
      } else if (viewId === 'app-traffic') {
        initAppTrafficView();
      } else if (viewId === 'local-status') {
        initLocalStatusView();
      } else if (viewId === 'xiq-troubleshoot') {
        initXiqTroubleshoot();
      } else if (viewId === 'rf-visualizer') {
        initRfVisualizer();
      } else if (viewId === 'ai-agents') {
        initAiAgentsView();
      } else if (viewId === 'portal-users') {
        loadPortalUsers();
      }
    }

    // ── Portal Users Management ──────────────────────────────────────
    var portalUserEditMode = null; // 'add' or 'edit'

    async function loadPortalUsers() {
      try {
        const res = await fetch('/api/portal-users');
        const users = await res.json();
        const tbody = document.getElementById('portal-users-tbody');
        if (!users.length) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--foreground-muted);padding:40px">No users found</td></tr>';
          return;
        }
        tbody.innerHTML = users.map(function(u) {
          var roleBadge = u.role === 'admin'
            ? '<span class="status-badge" style="background:rgba(139,92,246,0.15);color:#a78bfa">Admin</span>'
            : '<span class="status-badge" style="background:rgba(34,197,94,0.15);color:#22c55e">Viewer</span>';
          var passkeyIcon = u.has_passkey
            ? '<span style="color:#22c55e" title="Passkey registered">&#10003;</span>'
            : '<span style="color:rgba(255,255,255,0.2)">—</span>';
          return '<tr>'
            + '<td>' + roleBadge + '</td>'
            + '<td>' + u.username + '</td>'
            + '<td>' + (u.display_name || '') + '</td>'
            + '<td>' + u.role + '</td>'
            + '<td>' + passkeyIcon + '</td>'
            + '<td>'
            + '<button class="pu-action-btn" style="margin-right:6px" onclick="openEditUser(' + u.id + ')">Edit</button>'
            + '<button class="pu-action-btn danger" onclick="deleteUser(' + u.id + ')">Delete</button>'
            + '</td></tr>';
        }).join('');
      } catch (e) {
        document.getElementById('portal-users-tbody').innerHTML = '<tr><td colspan="6" style="text-align:center;color:#f85149;padding:40px">Error loading users: ' + e.message + '</td></tr>';
      }
    }

    function openAddUser() {
      portalUserEditMode = 'add';
      document.getElementById('portal-user-modal-title').textContent = 'Add User';
      document.getElementById('pu-edit-id').value = '';
      document.getElementById('pu-username').value = '';
      document.getElementById('pu-username').readOnly = false;
      document.getElementById('pu-password').value = '';
      document.getElementById('pu-password-hint').style.display = 'none';
      document.getElementById('pu-display-name').value = '';
      document.getElementById('pu-role').value = 'viewer';
      document.getElementById('portal-user-overlay').classList.add('active');
    }

    async function openEditUser(id) {
      try {
        var res = await fetch('/api/portal-users');
        var users = await res.json();
        var user = users.find(function(u) { return u.id === id; });
        if (!user) return;
        portalUserEditMode = 'edit';
        document.getElementById('portal-user-modal-title').textContent = 'Edit User';
        document.getElementById('pu-edit-id').value = user.id;
        document.getElementById('pu-username').value = user.username;
        document.getElementById('pu-username').readOnly = true;
        document.getElementById('pu-password').value = '';
        document.getElementById('pu-password-hint').style.display = 'inline';
        document.getElementById('pu-display-name').value = user.display_name || '';
        document.getElementById('pu-role').value = user.role;
        document.getElementById('portal-user-overlay').classList.add('active');
      } catch (e) {
        showToast('Error loading user: ' + e.message);
      }
    }

    function closeUserModal() {
      document.getElementById('portal-user-overlay').classList.remove('active');
    }

    async function saveUser() {
      var username = document.getElementById('pu-username').value.trim();
      var password = document.getElementById('pu-password').value;
      var display_name = document.getElementById('pu-display-name').value.trim();
      var role = document.getElementById('pu-role').value;

      if (portalUserEditMode === 'add') {
        if (!username || !password) { showToast('Username and password are required'); return; }
        try {
          var res = await fetch('/api/portal-users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username, password: password, display_name: display_name, role: role })
          });
          var data = await res.json();
          if (!res.ok) { showToast(data.error || 'Failed to create user'); return; }
          closeUserModal();
          loadPortalUsers();
          showToast('User created successfully');
        } catch (e) { showToast('Error: ' + e.message); }
      } else {
        var id = document.getElementById('pu-edit-id').value;
        var body = { display_name: display_name, role: role };
        if (password) body.password = password;
        try {
          var res = await fetch('/api/portal-users/' + id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
          });
          var data = await res.json();
          if (!res.ok) { showToast(data.error || 'Failed to update user'); return; }
          closeUserModal();
          loadPortalUsers();
          showToast('User updated successfully');
        } catch (e) { showToast('Error: ' + e.message); }
      }
    }

    async function deleteUser(id) {
      try {
        var listRes = await fetch('/api/portal-users');
        var allUsers = await listRes.json();
        var target = allUsers.find(function(u) { return u.id === id; });
        var name = target ? target.username : 'ID ' + id;
        if (!confirm('Delete user "' + name + '"? This cannot be undone.')) return;
        var res = await fetch('/api/portal-users/' + id, { method: 'DELETE' });
        var data = await res.json();
        if (!res.ok) { showToast(data.error || 'Failed to delete user'); return; }
        loadPortalUsers();
        showToast('User deleted');
      } catch (e) { showToast('Error: ' + e.message); }
    }

    // AI Agents Marketplace Data and Functions
    var aiAgentsData = {
      active: [
        { id: 'ai-expert', name: 'AI Expert', subtitle: 'Extreme Networks', icon: 'E', tags: ['agent'], status: 'active' },
        { id: 'interactive-network', name: 'ExtremePlatformONE Interactive Network Assistant', subtitle: 'User-Added', icon: '>>', tags: ['workflow'], status: null },
        { id: 'tools-natural', name: 'ExtremePlatformONE Tools Natural Language', subtitle: 'User-Added', icon: '>>', tags: ['workflow'], status: null },
        { id: 'switch-health', name: 'Proactive Switch Health Issues Notification', subtitle: 'User-Added', icon: '>>', tags: ['workflow'], status: null },
        { id: 'rrm-channel', name: 'AI Radio Resource Management Channel Optimization', subtitle: 'User-Added', icon: '>>', tags: ['workflow'], status: null },
        { id: 'rrm-power', name: 'AI Radio Resource Management Power Control', subtitle: 'User-Added', icon: '>>', tags: ['workflow'], status: null },
        { id: 'rrm-power-channel', name: 'AI Resource Management Power Channel Optimization', subtitle: 'User-Added', icon: '>>', tags: ['workflow'], status: null },
        { id: 'rrm-main', name: 'AI Radio Resource Management', subtitle: 'User-Added', icon: '>>', tags: ['workflow'], status: null },
        { id: 'device-health-notif', name: 'Proactive Network DeviceHealth Issues Notification', subtitle: 'User-Added', icon: '>>', tags: ['workflow'], status: null },
        { id: 'support-case', name: 'Interactive Support case creation and tracking', subtitle: 'User-Added', icon: '>>', tags: ['workflow'], status: null },
        { id: 'platform-one-mcp', name: 'Platform ONE APIs MCP Server', subtitle: 'Extreme Networks', icon: 'E', tags: ['tool'], status: 'active' },
        { id: 'meraki-mcp', name: 'Meraki APIs MCP Server', subtitle: 'Cisco', icon: 'M', iconClass: 'cyan', tags: ['tool'], status: 'active' },
        { id: 'ashutosh-flow1', name: 'Ashutosh Flow1', subtitle: 'User-Added', icon: '>>', tags: ['workflow'], status: null },
        { id: 'radio-resource-intel', name: 'Radio Resource Intelligence', subtitle: 'Extreme Networks', icon: 'E', tags: ['agent'], status: 'active' },
        { id: 'device-health-intel', name: 'Device Health Intelligence', subtitle: 'Extreme Networks', icon: 'E', tags: ['agent'], status: 'active' },
        { id: 'testing-workflow', name: 'Testing workflow', subtitle: 'User-Added', icon: '>>', tags: ['workflow'], status: null },
        { id: 'ai-agents-mcp', name: 'AI Agents MCP Server', subtitle: 'Extreme Networks', icon: 'E', tags: ['tool'], status: 'active' }
      ],
      catalog: [
        { id: 'servicenow-mcp', name: 'ServiceNow MCP Server', subtitle: 'Third Party', icon: 'SN', iconClass: 'cyan', tags: ['tool'], description: 'Integrates with ServiceNow to automate IT service management workflows and incident handling.' },
        { id: 'teams', name: 'Microsoft Teams', subtitle: 'Third Party', icon: 'T', iconClass: 'cyan', tags: ['tool'], description: 'Enables integration with the Microsoft Teams application providing programmatic collaboration capabilities such a...' },
        { id: 'outlook', name: 'Microsoft Outlook', subtitle: 'Third Party', icon: 'O', iconClass: 'cyan', tags: ['tool'], description: 'Automate email notifications and calendar integration for network maintenance and alert management.' }
      ]
    };

    function initAiAgentsView() {
      renderAiAgents();
    }

    function renderAiAgents() {
      var activeContainer = document.getElementById('ai-active-agents');
      var catalogContainer = document.getElementById('ai-catalog-agents');
      var activeCount = document.getElementById('ai-active-count');
      if (!activeContainer || !catalogContainer) return;

      // Render active agents
      activeContainer.innerHTML = '';
      aiAgentsData.active.forEach(function(agent) {
        activeContainer.appendChild(createAiAgentCard(agent, false));
      });
      if (activeCount) {
        activeCount.textContent = aiAgentsData.active.length;
      }

      // Render catalog
      catalogContainer.innerHTML = '';
      aiAgentsData.catalog.forEach(function(agent) {
        catalogContainer.appendChild(createAiAgentCard(agent, true));
      });

      // Add promo card
      var promoCard = document.createElement('div');
      promoCard.className = 'ai-promo-card';
      promoCard.innerHTML = '<h3>Build AI Workflows in Minutes</h3>' +
        '<p>Create custom, AI-driven workflows in a visual interface built for speed and scalability.</p>' +
        '<button class="ai-promo-btn" onclick="openCreateFlow()">' +
        '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>' +
        ' Create with Agent Flow Builder</button>';
      catalogContainer.appendChild(promoCard);
    }

    function createAiAgentCard(agent, showDescription) {
      var card = document.createElement('div');
      card.className = 'ai-agent-card';
      card.onclick = function() { openAiAgentDetail(agent); };

      var tagsHtml = agent.tags.map(function(tag) {
        return '<span class="ai-agent-tag">' +
          (tag === 'agent' ? 'Agent' : tag === 'workflow' ? 'Agent Workflow' : 'Tool') + '</span>';
      }).join('');

      var statusHtml = agent.status === 'active' ?
        '<div class="ai-agent-status"><span class="ai-agent-status-dot"></span>Active</div>' : '';

      var iconExtra = agent.icon === '>>' ? ' chevron' : '';
      var colorClass = agent.iconClass === 'cyan' ? ' cyan' : '';
      var iconCls = 'ai-agent-icon' + iconExtra + colorClass;

      var descHtml = (showDescription && agent.description) ?
        '<div class="ai-agent-description">' + agent.description + '</div>' : '';

      card.innerHTML =
        '<button class="ai-agent-delete">' +
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>' +
        '</button>' +
        '<div class="ai-agent-card-header">' +
        '  <div class="' + iconCls + '">' + agent.icon + '</div>' +
        '  <div class="ai-agent-card-info">' +
        '    <div class="ai-agent-title">' + agent.name + '</div>' +
        '    <div class="ai-agent-subtitle">' + agent.subtitle + '</div>' +
        '  </div>' +
        '</div>' +
        '<div class="ai-agent-tags">' + tagsHtml + '</div>' +
        descHtml +
        statusHtml;

      // Attach delete handler via JS to avoid inline onclick issues
      var delBtn = card.querySelector('.ai-agent-delete');
      delBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        deleteAgentCard(agent.id);
      });

      return card;
    }

    // --- Workflow Builder State ---
    var wfNodes = [];
    var wfConnections = [];
    var wfDragNode = null;
    var wfDragOffset = { x: 0, y: 0 };
    var wfConnecting = null; // {fromIdx}

    var wfIcons = {
      start: '<svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="3"/></svg>',
      condition: '<svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 4-7 8-7s8 3 8 7"/></svg>',
      mcp: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 1v4m0 14v4M4.22 4.22l2.83 2.83m9.9 9.9l2.83 2.83M1 12h4m14 0h4M4.22 19.78l2.83-2.83m9.9-9.9l2.83-2.83"/></svg>',
      reply: '<svg viewBox="0 0 24 24"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>'
    };

    var wfNodeLabels = {
      start: 'Start',
      condition: 'New Condition Agent Node',
      mcp: 'New AI Agents MCP Node',
      reply: 'New Direct Reply Node'
    };

    var toolDetailContent = {
      outlook: {
        icon: 'O',
        iconClass: 'purple',
        title: 'Microsoft Outlook',
        source: 'Third Party',
        tag: 'Tool',
        desc: 'Microsoft Outlook APIs to manage Messages, Events and Calendar',
        overview: 'Use these tools to perform Create/Read/Update/Delete operations on your Microsoft Outlook Messages, Events and Calendar.',
        usecases: [
          { title: 'Email Messages', desc: 'List Messages, Get Message, Create Draft Message, Send Message, Update Message, Delete Message, Copy Message, Move Message, Reply to Message, Forward Message.' },
          { title: 'Events', desc: 'List Events, Get Event, Create Event, Update Event, Delete Event' },
          { title: 'Calendar', desc: 'List Events, Get Event, Create Event. Update Event, Delete Event' }
        ],
        activateFn: 'openOutlookActivate'
      },
      teams: {
        icon: 'T',
        iconClass: 'cyan',
        title: 'Microsoft Teams',
        source: 'Third Party',
        tag: 'Tool',
        desc: 'Microsoft Teams APIs to manage Messages, Channels and Chats',
        overview: 'Use these tools to perform Create/Read/Update/Delete operations on your Microsoft Teams Channels, Chats and Chat Messages.',
        usecases: [
          { title: 'Microsoft Teams Messaging', desc: 'List Messages, Get Message, Send Message, Update Message, Delete Message, Reply to Message, Set Reaction, Unset Reaction, Get All Messages.' },
          { title: 'Microsoft Teams Chat', desc: 'List Chats, Get Chat, Create Chat, Update Chat, Delete Chat, List Chat Members, Add Chat Member, Remove Chat Member, Pin Message, Unpin Message.' },
          { title: 'Microsoft Teams Channel', desc: 'List Channels, Get Channel, Create Channel, Update Channel, Delete Channel, Archive Channel, Unarchive Channel, List Channel Members, Add Channel Member, Remove Channel Member.' }
        ],
        activateFn: 'openTeamsActivate'
      }
    };

    function openAiAgentDetail(agent) {
      if (agent.id === 'meraki-mcp') {
        document.getElementById('meraki-detail-overlay').classList.add('active');
      } else if (agent.id === 'platform-one-mcp') {
        document.getElementById('mcp-detail-overlay').classList.add('active');
      } else if (agent.id === 'testing-workflow') {
        document.getElementById('workflow-modal-title').textContent = agent.name;
        document.getElementById('workflow-modal-overlay').classList.add('active');
        initWorkflowBuilder();
      } else if (toolDetailContent[agent.id]) {
        var data = toolDetailContent[agent.id];
        var iconEl = document.getElementById('tool-detail-icon');
        iconEl.textContent = data.icon;
        iconEl.className = 'tool-detail-icon';
        if (data.iconClass === 'cyan') {
          iconEl.style.background = 'linear-gradient(135deg, #06b6d4, #0891b2)';
        } else {
          iconEl.style.background = 'linear-gradient(135deg, #8b5cf6, #7c3aed)';
        }
        document.getElementById('tool-detail-title').textContent = data.title;
        document.getElementById('tool-detail-source').textContent = data.source;
        document.getElementById('tool-detail-tag').textContent = data.tag;
        document.getElementById('tool-detail-desc').textContent = data.desc;
        document.getElementById('tool-detail-overview-text').textContent = data.overview;
        var ucHtml = '';
        data.usecases.forEach(function(uc) {
          ucHtml += '<div class="tool-detail-usecase">' +
            '<div class="tool-detail-usecase-title"><span>&#10023;</span> ' + uc.title + '</div>' +
            '<div class="tool-detail-usecase-desc">' + uc.desc + '</div>' +
            '</div>';
        });
        document.getElementById('tool-detail-usecases').innerHTML = ucHtml;
        document.getElementById('tool-detail-activate-btn').setAttribute('onclick', data.activateFn + '()');
        document.getElementById('tool-detail-overlay').classList.add('active');
      } else {
        alert('Agent: ' + agent.name + '\\nSource: ' + agent.subtitle + '\\nStatus: ' + (agent.status || 'Available'));
      }
    }

    function closeToolDetail() {
      document.getElementById('tool-detail-overlay').classList.remove('active');
    }

    function openOutlookActivate() {
      document.getElementById('outlook-activate-overlay').classList.add('active');
    }
    function closeOutlookActivate() {
      document.getElementById('outlook-activate-overlay').classList.remove('active');
    }
    function testOutlookConnection() {
      var btn = event.target;
      var origText = btn.textContent;
      btn.textContent = 'Testing...';
      btn.disabled = true;
      setTimeout(function() {
        btn.textContent = 'Connected!';
        btn.style.borderColor = '#22c55e';
        btn.style.color = '#22c55e';
        setTimeout(function() {
          btn.textContent = origText;
          btn.disabled = false;
          btn.style.borderColor = '';
          btn.style.color = '';
        }, 2000);
      }, 1500);
    }
    function activateOutlookConnection() {
      var tokenUrl = document.getElementById('outlook-token-url').value;
      var authUrl = document.getElementById('outlook-auth-url').value;
      var clientId = document.getElementById('outlook-client-id').value;
      var clientSecret = document.getElementById('outlook-client-secret').value;
      if (!clientId || !clientSecret) {
        alert('Please provide both Client ID and Client Secret.');
        return;
      }
      closeOutlookActivate();
      closeToolDetail();
      var outlookAgent = aiAgentsData.catalog.find(function(a) { return a.id === 'outlook'; });
      if (outlookAgent) {
        outlookAgent.status = 'active';
        aiAgentsData.active.push(outlookAgent);
        aiAgentsData.catalog = aiAgentsData.catalog.filter(function(a) { return a.id !== 'outlook'; });
        renderAiAgents();
      }
    }

    function openTeamsActivate() {
      document.getElementById('teams-activate-overlay').classList.add('active');
    }
    function closeTeamsActivate() {
      document.getElementById('teams-activate-overlay').classList.remove('active');
    }
    function testTeamsConnection() {
      var btn = event.target;
      var origText = btn.textContent;
      btn.textContent = 'Testing...';
      btn.disabled = true;
      setTimeout(function() {
        btn.textContent = 'Connected!';
        btn.style.borderColor = '#22c55e';
        btn.style.color = '#22c55e';
        setTimeout(function() {
          btn.textContent = origText;
          btn.disabled = false;
          btn.style.borderColor = '';
          btn.style.color = '';
        }, 2000);
      }, 1500);
    }
    function activateTeamsConnection() {
      var clientId = document.getElementById('teams-client-id').value;
      var clientSecret = document.getElementById('teams-client-secret').value;
      if (!clientId || !clientSecret) {
        alert('Please provide both Client ID and Client Secret.');
        return;
      }
      closeTeamsActivate();
      closeToolDetail();
      var teamsAgent = aiAgentsData.catalog.find(function(a) { return a.id === 'teams'; });
      if (teamsAgent) {
        teamsAgent.status = 'active';
        aiAgentsData.active.push(teamsAgent);
        aiAgentsData.catalog = aiAgentsData.catalog.filter(function(a) { return a.id !== 'teams'; });
        renderAiAgents();
      }
    }

    function closeMcpDetail() {
      document.getElementById('mcp-detail-overlay').classList.remove('active');
    }
    function openMcpManageModal() {
      document.getElementById('mcp-manage-overlay').classList.add('active');
    }
    function closeMcpManageModal() {
      document.getElementById('mcp-manage-overlay').classList.remove('active');
    }

    function closeMerakiDetail() {
      document.getElementById('meraki-detail-overlay').classList.remove('active');
    }
    function openMerakiManageModal() {
      document.getElementById('meraki-manage-overlay').classList.add('active');
    }
    function closeMerakiManageModal() {
      document.getElementById('meraki-manage-overlay').classList.remove('active');
    }

    // Delete Agent Card
    function deleteAgentCard(agentId) {
      if (!confirm('Delete this agent?')) return;
      aiAgentsData.active = aiAgentsData.active.filter(function(a) { return a.id !== agentId; });
      aiAgentsData.catalog = aiAgentsData.catalog.filter(function(a) { return a.id !== agentId; });
      renderAiAgents();
    }

    // Create Agent Flow
    function openCreateFlow() {
      document.getElementById('create-flow-name').value = '';
      document.getElementById('create-flow-desc').value = '';
      updateFlowCounter();
      document.getElementById('create-flow-overlay').classList.add('active');
      document.getElementById('create-flow-name').focus();
    }
    function closeCreateFlow() {
      document.getElementById('create-flow-overlay').classList.remove('active');
    }
    function updateFlowCounter() {
      var desc = document.getElementById('create-flow-desc');
      var counter = document.getElementById('create-flow-counter');
      counter.textContent = desc.value.length + '/250';
    }
    function saveCreateFlow() {
      var name = document.getElementById('create-flow-name').value.trim();
      if (!name) {
        document.getElementById('create-flow-name').focus();
        return;
      }
      var id = 'user-flow-' + Date.now();
      aiAgentsData.active.push({
        id: id, name: name, subtitle: 'User-Added', icon: '>>', tags: ['workflow'], status: null
      });
      closeCreateFlow();
      renderAiAgents();
    }

    function closeWorkflowModal() {
      document.getElementById('workflow-modal-overlay').classList.remove('active');
      document.getElementById('wf-dropdown').classList.remove('active');
    }

    function initWorkflowBuilder() {
      wfNodes = [{ type: 'start', x: 80, y: 0 }];
      wfConnections = [];
      wfConnecting = null;
      // Center start node vertically after render
      setTimeout(function() {
        var body = document.getElementById('workflow-modal-body');
        if (body) {
          wfNodes[0].y = body.offsetHeight / 2 - 14;
          renderWfNodes();
        }
      }, 50);
    }

    function toggleWfDropdown() {
      document.getElementById('wf-dropdown').classList.toggle('active');
    }

    function addWfNode(type) {
      document.getElementById('wf-dropdown').classList.remove('active');
      var body = document.getElementById('workflow-modal-body');
      var lastNode = wfNodes[wfNodes.length - 1];
      var newX = lastNode.x + 220;
      var newY = lastNode.y + (Math.random() - 0.5) * 60;
      newY = Math.max(30, Math.min(body.offsetHeight - 50, newY));
      var newIdx = wfNodes.length;
      wfNodes.push({ type: type, x: newX, y: newY });
      // Auto-connect from last node
      wfConnections.push({ from: newIdx - 1, to: newIdx });
      renderWfNodes();
    }

    function renderWfNodes() {
      var body = document.getElementById('workflow-modal-body');
      var svg = document.getElementById('wf-canvas');
      if (!body || !svg) return;
      var w = body.offsetWidth;
      var h = body.offsetHeight;
      svg.setAttribute('viewBox', '0 0 ' + w + ' ' + h);

      // Draw connections
      var pathsHtml = '<defs><linearGradient id="wfGrad" x1="0%" y1="0%" x2="100%" y2="0%">' +
        '<stop offset="0%" stop-color="#8b5cf6" stop-opacity="0.6"/>' +
        '<stop offset="50%" stop-color="#a78bfa" stop-opacity="0.9"/>' +
        '<stop offset="100%" stop-color="#8b5cf6" stop-opacity="0.6"/>' +
        '</linearGradient></defs>';
      wfConnections.forEach(function(c) {
        var fn = wfNodes[c.from];
        var tn = wfNodes[c.to];
        if (!fn || !tn) return;
        var fx = fn.x + 100, fy = fn.y + 14;
        var tx = tn.x, ty = tn.y + 14;
        var mx = (fx + tx) / 2;
        pathsHtml += '<path d="M' + fx + ' ' + fy + ' C' + mx + ' ' + fy + ',' + mx + ' ' + ty + ',' + tx + ' ' + ty +
          '" fill="none" stroke="url(#wfGrad)" stroke-width="3" stroke-linecap="round"/>';
      });
      svg.innerHTML = pathsHtml;

      // Remove old node els
      body.querySelectorAll('.wf-node').forEach(function(el) { el.remove(); });

      wfNodes.forEach(function(n, idx) {
        var el = document.createElement('div');
        el.className = 'wf-node' + (n.type === 'start' ? ' start-node' : '');
        el.style.left = n.x + 'px';
        el.style.top = n.y + 'px';
        el.setAttribute('data-idx', idx);

        var portLeft = '<div class="wf-node-port" data-port="in" data-idx="' + idx + '"></div>';
        var portRight = '<div class="wf-node-port" data-port="out" data-idx="' + idx + '"></div>';
        el.innerHTML =
          (idx > 0 ? portLeft : '') +
          '<div class="wf-node-icon">' + wfIcons[n.type] + '</div>' +
          '<span class="wf-node-label">' + wfNodeLabels[n.type] + '</span>' +
          portRight;

        // Click Start to open chat
        if (n.type === 'start') {
          el.onclick = function(e) {
            if (e.target.classList.contains('wf-node-port')) return;
            openWfChat();
          };
        }

        // Drag to move
        el.onmousedown = function(e) {
          if (e.target.classList.contains('wf-node-port')) {
            // Start connection
            var portType = e.target.getAttribute('data-port');
            if (portType === 'out') {
              wfConnecting = { fromIdx: idx };
              body.style.cursor = 'crosshair';
            }
            e.stopPropagation();
            return;
          }
          if (n.type === 'start') return; // start node click handled above
          wfDragNode = idx;
          var rect = el.getBoundingClientRect();
          var bodyRect = body.getBoundingClientRect();
          wfDragOffset.x = e.clientX - rect.left;
          wfDragOffset.y = e.clientY - rect.top;
          e.preventDefault();
        };

        body.appendChild(el);
      });
    }

    // Mouse move/up on body for dragging & connecting
    document.addEventListener('mousemove', function(e) {
      if (wfDragNode !== null) {
        var body = document.getElementById('workflow-modal-body');
        if (!body) return;
        var rect = body.getBoundingClientRect();
        wfNodes[wfDragNode].x = Math.max(0, e.clientX - rect.left - wfDragOffset.x);
        wfNodes[wfDragNode].y = Math.max(0, e.clientY - rect.top - wfDragOffset.y);
        renderWfNodes();
      }
    });
    document.addEventListener('mouseup', function(e) {
      if (wfDragNode !== null) {
        wfDragNode = null;
      }
      if (wfConnecting) {
        // Check if dropped on an input port
        var target = e.target;
        if (target.classList && target.classList.contains('wf-node-port') && target.getAttribute('data-port') === 'in') {
          var toIdx = parseInt(target.getAttribute('data-idx'));
          if (toIdx !== wfConnecting.fromIdx) {
            // Check no duplicate
            var exists = wfConnections.some(function(c) { return c.from === wfConnecting.fromIdx && c.to === toIdx; });
            if (!exists) {
              wfConnections.push({ from: wfConnecting.fromIdx, to: toIdx });
              renderWfNodes();
            }
          }
        }
        wfConnecting = null;
        var body = document.getElementById('workflow-modal-body');
        if (body) body.style.cursor = '';
      }
    });

    // --- Chat Input Panel ---
    function openWfChat() {
      document.getElementById('wf-chat-overlay').classList.add('active');
      document.getElementById('wf-chat-messages').innerHTML = '';
      wfChatHistory = [];
      document.getElementById('wf-chat-input').focus();
    }
    function closeWfChat() {
      document.getElementById('wf-chat-overlay').classList.remove('active');
    }
    var wfChatHistory = [];

    function sendWfChat() {
      var input = document.getElementById('wf-chat-input');
      var msg = input.value.trim();
      if (!msg) return;
      var container = document.getElementById('wf-chat-messages');

      // User message
      var userEl = document.createElement('div');
      userEl.className = 'wf-chat-msg user';
      userEl.textContent = msg;
      container.appendChild(userEl);
      input.value = '';
      input.disabled = true;
      container.scrollTop = container.scrollHeight;

      wfChatHistory.push({ role: 'user', content: msg });

      // Show typing indicator
      var typingEl = document.createElement('div');
      typingEl.className = 'wf-chat-msg assistant';
      typingEl.textContent = 'Thinking...';
      typingEl.id = 'wf-typing';
      container.appendChild(typingEl);
      container.scrollTop = container.scrollHeight;

      fetch('/api/claude-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: wfChatHistory })
      })
      .then(function(res) { return res.json(); })
      .then(function(data) {
        var typing = document.getElementById('wf-typing');
        if (typing) typing.remove();

        var botEl = document.createElement('div');
        botEl.className = 'wf-chat-msg assistant';
        botEl.textContent = data.reply || data.error || 'No response';
        container.appendChild(botEl);
        container.scrollTop = container.scrollHeight;

        if (data.reply) {
          wfChatHistory.push({ role: 'assistant', content: data.reply });
        }
        input.disabled = false;
        input.focus();
      })
      .catch(function(err) {
        var typing = document.getElementById('wf-typing');
        if (typing) typing.remove();

        var errEl = document.createElement('div');
        errEl.className = 'wf-chat-msg assistant';
        errEl.textContent = 'Error: ' + err.message;
        container.appendChild(errEl);
        container.scrollTop = container.scrollHeight;
        input.disabled = false;
        input.focus();
      });
    }


    // --- Chat Panel Resize ---
    (function() {
      var handle = document.getElementById('wf-chat-resize-handle');
      var panel = document.getElementById('wf-chat-panel');
      if (!handle || !panel) return;
      var startX, startY, startW, startH;
      handle.addEventListener('mousedown', function(e) {
        e.preventDefault();
        startX = e.clientX; startY = e.clientY;
        startW = panel.offsetWidth; startH = panel.offsetHeight;
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
      });
      handle.addEventListener('touchstart', function(e) {
        var t = e.touches[0];
        startX = t.clientX; startY = t.clientY;
        startW = panel.offsetWidth; startH = panel.offsetHeight;
        document.addEventListener('touchmove', onTouchMove);
        document.addEventListener('touchend', onTouchEnd);
      });
      function onMove(e) { resize(e.clientX, e.clientY); }
      function onTouchMove(e) { var t = e.touches[0]; resize(t.clientX, t.clientY); }
      function resize(cx, cy) {
        var newW = Math.max(320, Math.min(window.innerWidth * 0.9, startW + (cx - startX)));
        var newH = Math.max(300, Math.min(window.innerHeight * 0.9, startH + (cy - startY)));
        panel.style.width = newW + 'px';
        panel.style.height = newH + 'px';
      }
      function onUp() {
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
      }
      function onTouchEnd() {
        document.removeEventListener('touchmove', onTouchMove);
        document.removeEventListener('touchend', onTouchEnd);
      }
    })();

    // Application Traffic Functions
    async function initAppTrafficView() {
      var select = document.getElementById('app-traffic-network-select');
      if (select && select.options.length <= 1) {
        try {
          var orgsRes = await fetch('/api/organizations');
          var orgs = await orgsRes.json();
          if (orgs && orgs.length > 0) {
            var networksRes = await fetch('/api/organizations/' + orgs[0].id + '/networks');
            var networks = await networksRes.json();
            if (networks) {
              networks.forEach(function(net) {
                var opt = document.createElement('option');
                opt.value = net.id;
                opt.textContent = net.name;
                select.appendChild(opt);
              });
            }
          }
        } catch (e) {
          console.error('Failed to load networks:', e);
        }
      }
    }

    async function loadAppTraffic() {
      var networkId = document.getElementById('app-traffic-network-select').value;
      if (!networkId) return;

      var listEl = document.getElementById('app-traffic-list');
      listEl.innerHTML = '<div style="text-align:center;padding:20px;color:var(--foreground-muted)">Loading...</div>';

      try {
        var res = await fetch('/api/networks/' + networkId + '/traffic?timespan=86400');
        var data = await res.json();

        // Check for API error
        if (data && data.error) {
          // Reset stats
          document.getElementById('app-traffic-total').textContent = '--';
          document.getElementById('app-traffic-upload').textContent = '--';
          document.getElementById('app-traffic-download').textContent = '--';
          document.getElementById('app-traffic-clients').textContent = '--';

          if (data.error.indexOf('Traffic Analysis') !== -1) {
            listEl.innerHTML = '<div style="text-align:center;padding:30px;color:var(--foreground-muted)">' +
              '<div style="font-size:14px;margin-bottom:8px">Traffic Analysis not enabled</div>' +
              '<div style="font-size:12px;opacity:0.7">Enable Traffic Analysis in Meraki Dashboard:</div>' +
              '<div style="font-size:11px;opacity:0.6;margin-top:4px">Network-wide → General → Traffic Analysis</div>' +
              '</div>';
          } else {
            listEl.innerHTML = '<div style="text-align:center;padding:20px;color:var(--foreground-muted)">Error: ' + data.error + '</div>';
          }
          return;
        }

        if (data && data.length > 0) {
          var totalSent = 0, totalRecv = 0;
          data.forEach(function(app) {
            totalSent += app.sent || 0;
            totalRecv += app.recv || 0;
          });

          document.getElementById('app-traffic-total').textContent = data.length;
          document.getElementById('app-traffic-upload').textContent = formatTrafficBytes(totalSent);
          document.getElementById('app-traffic-download').textContent = formatTrafficBytes(totalRecv);
          document.getElementById('app-traffic-clients').textContent = Math.min(data.length * 3, 100);

          var sorted = data.sort(function(a, b) {
            return ((b.sent || 0) + (b.recv || 0)) - ((a.sent || 0) + (a.recv || 0));
          }).slice(0, 10);

          var maxVal = (sorted[0].sent || 0) + (sorted[0].recv || 0);
          var html = '';
          sorted.forEach(function(app) {
            var total = (app.sent || 0) + (app.recv || 0);
            var pct = maxVal > 0 ? (total / maxVal * 100) : 0;
            html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">';
            html += '<div style="width:140px;font-size:13px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + (app.application || 'Unknown') + '</div>';
            html += '<div style="flex:1;height:20px;background:var(--surface);border-radius:4px;overflow:hidden">';
            html += '<div style="height:100%;width:' + pct + '%;background:linear-gradient(90deg,#3b82f6,#8b5cf6);border-radius:4px"></div>';
            html += '</div>';
            html += '<div style="width:70px;text-align:right;font-size:12px;color:var(--foreground-muted)">' + formatTrafficBytes(total) + '</div>';
            html += '</div>';
          });
          listEl.innerHTML = html;
        } else {
          listEl.innerHTML = '<div style="text-align:center;padding:20px;color:var(--foreground-muted)">No traffic data available</div>';
        }
      } catch (e) {
        console.error('Failed to load traffic:', e);
        listEl.innerHTML = '<div style="text-align:center;padding:20px;color:var(--foreground-muted)">Error loading data</div>';
      }
    }

    function formatTrafficBytes(bytes) {
      if (!bytes || bytes === 0) return '0 B';
      var k = 1024;
      var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
      var i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    // ===========================================
    // LOCAL STATUS PAGE FUNCTIONS
    // ===========================================

    var localStatusAPs = [];

    async function initLocalStatusView() {
      var networkSelect = document.getElementById('local-status-network-select');
      if (networkSelect && networkSelect.options.length <= 1) {
        try {
          var orgsRes = await fetch('/api/organizations');
          var orgs = await orgsRes.json();
          for (var o = 0; o < orgs.length; o++) {
            var netsRes = await fetch('/api/organizations/' + orgs[o].id + '/networks');
            var networks = await netsRes.json();
            for (var n = 0; n < networks.length; n++) {
              if (networks[n].productTypes && networks[n].productTypes.indexOf('wireless') !== -1) {
                var opt = document.createElement('option');
                opt.value = networks[n].id;
                opt.textContent = networks[n].name;
                networkSelect.appendChild(opt);
              }
            }
          }
        } catch (e) {
          console.error('Failed to load networks for local status:', e);
        }
      }
    }

    async function loadLocalStatusAPs() {
      var networkId = document.getElementById('local-status-network-select').value;
      var apSelect = document.getElementById('local-status-ap-select');
      var content = document.getElementById('local-status-content');

      // Clear AP dropdown
      apSelect.innerHTML = '<option value="">All APs Overview</option>';
      localStatusAPs = [];

      if (!networkId) {
        document.getElementById('local-status-total').textContent = '--';
        document.getElementById('local-status-online').textContent = '--';
        document.getElementById('local-status-alerting').textContent = '--';
        document.getElementById('local-status-clients').textContent = '--';
        content.innerHTML = '<div style="text-align:center;padding:60px;color:var(--foreground-muted)"><svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.4;margin-bottom:16px"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg><div style="font-size:14px">Select a network to view Access Points</div></div>';
        return;
      }

      content.innerHTML = '<div style="text-align:center;padding:40px;color:var(--foreground-muted)">Loading Access Points...</div>';

      try {
        var res = await fetch('/api/networks/' + networkId + '/wireless/accessPoints');
        var aps = await res.json();

        if (aps.error) {
          content.innerHTML = '<div style="text-align:center;padding:40px;color:var(--destructive)">Error: ' + aps.error + '</div>';
          return;
        }

        localStatusAPs = aps;

        // Populate AP dropdown
        for (var i = 0; i < aps.length; i++) {
          var opt = document.createElement('option');
          opt.value = aps[i].serial;
          opt.textContent = aps[i].name || aps[i].serial;
          apSelect.appendChild(opt);
        }

        // Update stats
        var online = aps.filter(function(a) { return a.status === 'online'; }).length;
        var alerting = aps.filter(function(a) { return a.status === 'alerting'; }).length;
        var totalClients = aps.reduce(function(sum, a) { return sum + (a.clientCount || 0); }, 0);

        document.getElementById('local-status-total').textContent = aps.length;
        document.getElementById('local-status-online').textContent = online;
        document.getElementById('local-status-alerting').textContent = alerting;
        document.getElementById('local-status-clients').textContent = totalClients;

        // Show overview
        renderAPOverview(aps);

      } catch (e) {
        console.error('Failed to load APs:', e);
        content.innerHTML = '<div style="text-align:center;padding:40px;color:var(--destructive)">Error loading Access Points</div>';
      }
    }

    function renderAPOverview(aps) {
      var content = document.getElementById('local-status-content');

      if (!aps || aps.length === 0) {
        content.innerHTML = '<div style="text-align:center;padding:60px;color:var(--foreground-muted)">No Access Points found in this network</div>';
        return;
      }

      var html = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px">';

      for (var i = 0; i < aps.length; i++) {
        var ap = aps[i];
        var statusColor = ap.status === 'online' ? 'var(--success)' : ap.status === 'alerting' ? '#f59e0b' : 'var(--destructive)';
        var statusIcon = ap.status === 'online' ? '●' : ap.status === 'alerting' ? '◐' : '○';

        html += '<div onclick="selectAP(\\''+ap.serial+'\\')" style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;cursor:pointer;transition:all 0.2s" onmouseover="this.style.borderColor=\\'var(--primary)\\'" onmouseout="this.style.borderColor=\\'var(--border)\\'">';
        html += '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px">';
        html += '<div>';
        html += '<div style="font-size:16px;font-weight:600">' + (ap.name || ap.serial) + '</div>';
        html += '<div style="font-size:12px;color:var(--foreground-muted);margin-top:2px">' + (ap.model || 'Unknown Model') + '</div>';
        html += '</div>';
        html += '<div style="display:flex;align-items:center;gap:6px;padding:4px 10px;background:rgba(255,255,255,0.03);border-radius:20px">';
        html += '<span style="color:' + statusColor + '">' + statusIcon + '</span>';
        html += '<span style="font-size:12px;color:' + statusColor + '">' + (ap.status || 'unknown').toUpperCase() + '</span>';
        html += '</div>';
        html += '</div>';

        html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">';
        html += '<div style="background:rgba(255,255,255,0.02);padding:10px;border-radius:8px">';
        html += '<div style="font-size:10px;color:var(--foreground-muted);margin-bottom:2px">IP Address</div>';
        html += '<div style="font-size:13px;font-family:monospace">' + (ap.lanIp || 'N/A') + '</div>';
        html += '</div>';
        html += '<div style="background:rgba(255,255,255,0.02);padding:10px;border-radius:8px">';
        html += '<div style="font-size:10px;color:var(--foreground-muted);margin-bottom:2px">Clients</div>';
        html += '<div style="font-size:13px;font-weight:600;color:var(--primary)">' + (ap.clientCount || 0) + '</div>';
        html += '</div>';
        html += '<div style="background:rgba(255,255,255,0.02);padding:10px;border-radius:8px">';
        html += '<div style="font-size:10px;color:var(--foreground-muted);margin-bottom:2px">Serial</div>';
        html += '<div style="font-size:11px;font-family:monospace">' + ap.serial + '</div>';
        html += '</div>';
        html += '<div style="background:rgba(255,255,255,0.02);padding:10px;border-radius:8px">';
        html += '<div style="font-size:10px;color:var(--foreground-muted);margin-bottom:2px">Public IP</div>';
        html += '<div style="font-size:11px;font-family:monospace">' + (ap.publicIp || 'N/A') + '</div>';
        html += '</div>';
        html += '</div>';
        html += '</div>';
      }

      html += '</div>';
      content.innerHTML = html;
    }

    function selectAP(serial) {
      document.getElementById('local-status-ap-select').value = serial;
      loadAPStatus();
    }

    async function loadAPStatus() {
      var serial = document.getElementById('local-status-ap-select').value;
      var content = document.getElementById('local-status-content');

      if (!serial) {
        renderAPOverview(localStatusAPs);
        return;
      }

      content.innerHTML = '<div style="text-align:center;padding:40px;color:var(--foreground-muted)">Loading AP Status...</div>';

      try {
        var res = await fetch('/api/devices/' + serial + '/wireless/status');
        var data = await res.json();

        if (data.error) {
          content.innerHTML = '<div style="text-align:center;padding:40px;color:var(--destructive)">Error: ' + data.error + '</div>';
          return;
        }

        renderAPDetail(data);

      } catch (e) {
        console.error('Failed to load AP status:', e);
        content.innerHTML = '<div style="text-align:center;padding:40px;color:var(--destructive)">Error loading AP status</div>';
      }
    }

    function renderAPDetail(data) {
      var content = document.getElementById('local-status-content');
      var device = data.device || {};
      var radio = data.radioSettings || {};
      var clients = data.clients || [];
      var neighbors = data.neighbors || {};
      var uplinks = data.uplinks || [];

      var statusColor = device.status === 'online' ? 'var(--success)' : device.status === 'alerting' ? '#f59e0b' : 'var(--destructive)';

      var html = '<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">';

      // Device Info Card
      html += '<div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px">';
      html += '<div style="font-size:14px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px">';
      html += '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>';
      html += 'Device Information</div>';

      html += '<div style="display:grid;gap:12px">';
      html += renderInfoRow('Name', device.name || device.serial);
      html += renderInfoRow('Model', device.model || 'Unknown');
      html += renderInfoRow('Serial', device.serial || 'N/A');
      html += renderInfoRow('MAC Address', device.mac || 'N/A');
      html += renderInfoRow('Status', '<span style="color:' + statusColor + '">' + (device.status || 'unknown').toUpperCase() + '</span>');
      html += renderInfoRow('Firmware', device.firmware || 'N/A');
      html += renderInfoRow('Last Reported', device.lastReportedAt ? new Date(device.lastReportedAt).toLocaleString() : 'N/A');
      html += '</div></div>';

      // Network Info Card
      html += '<div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px">';
      html += '<div style="font-size:14px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px">';
      html += '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>';
      html += 'Network Connectivity</div>';

      html += '<div style="display:grid;gap:12px">';
      html += renderInfoRow('LAN IP', device.lanIp || 'N/A');
      html += renderInfoRow('Public IP', device.publicIp || 'N/A');
      html += renderInfoRow('Gateway', device.gateway || 'N/A');
      html += renderInfoRow('Primary DNS', device.primaryDns || 'N/A');
      html += renderInfoRow('Secondary DNS', device.secondaryDns || 'N/A');

      if (uplinks.length > 0) {
        var uplinkInfo = uplinks.map(function(u) {
          return u.interface + ': ' + (u.addresses && u.addresses[0] ? u.addresses[0].address : 'N/A');
        }).join(', ');
        html += renderInfoRow('Uplinks', uplinkInfo);
      }
      html += '</div></div>';

      // Radio Settings Card
      html += '<div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px">';
      html += '<div style="font-size:14px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px">';
      html += '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>';
      html += 'Radio Settings</div>';

      html += '<div style="display:grid;gap:12px">';
      if (radio.twoFourGhzSettings) {
        html += renderInfoRow('2.4 GHz Channel', radio.twoFourGhzSettings.channel || 'Auto');
        html += renderInfoRow('2.4 GHz Power', radio.twoFourGhzSettings.targetPower ? radio.twoFourGhzSettings.targetPower + ' dBm' : 'Auto');
      }
      if (radio.fiveGhzSettings) {
        html += renderInfoRow('5 GHz Channel', radio.fiveGhzSettings.channel || 'Auto');
        html += renderInfoRow('5 GHz Power', radio.fiveGhzSettings.targetPower ? radio.fiveGhzSettings.targetPower + ' dBm' : 'Auto');
        html += renderInfoRow('5 GHz Width', radio.fiveGhzSettings.channelWidth || 'Auto');
      }
      if (radio.sixGhzSettings) {
        html += renderInfoRow('6 GHz Channel', radio.sixGhzSettings.channel || 'Auto');
        html += renderInfoRow('6 GHz Power', radio.sixGhzSettings.targetPower ? radio.sixGhzSettings.targetPower + ' dBm' : 'Auto');
      }
      if (!radio.twoFourGhzSettings && !radio.fiveGhzSettings && !radio.sixGhzSettings) {
        html += '<div style="color:var(--foreground-muted);font-size:13px">Radio settings not available</div>';
      }
      html += '</div></div>';

      // Connected Clients Card
      html += '<div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px">';
      html += '<div style="font-size:14px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px">';
      html += '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>';
      html += 'Connected Clients (' + clients.length + ')</div>';

      if (clients.length > 0) {
        html += '<div style="max-height:200px;overflow-y:auto">';
        for (var c = 0; c < Math.min(clients.length, 10); c++) {
          var client = clients[c];
          html += '<div style="display:flex;justify-content:space-between;padding:8px;background:rgba(255,255,255,0.02);border-radius:6px;margin-bottom:6px">';
          html += '<div style="font-size:12px">' + esc(client.description || client.mac || 'Unknown') + '</div>';
          html += '<div style="font-size:11px;color:var(--foreground-muted)">' + (client.ip || 'No IP') + '</div>';
          html += '</div>';
        }
        if (clients.length > 10) {
          html += '<div style="text-align:center;font-size:11px;color:var(--foreground-muted);padding:8px">...and ' + (clients.length - 10) + ' more</div>';
        }
        html += '</div>';
      } else {
        html += '<div style="color:var(--foreground-muted);font-size:13px;text-align:center;padding:20px">No clients currently connected</div>';
      }
      html += '</div>';

      html += '</div>';

      // LLDP/CDP Neighbors
      if (neighbors.ports && Object.keys(neighbors.ports).length > 0) {
        html += '<div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;margin-top:20px">';
        html += '<div style="font-size:14px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px">';
        html += '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><circle cx="12" cy="5" r="3"/><circle cx="5" cy="19" r="3"/><circle cx="19" cy="19" r="3"/><line x1="12" y1="8" x2="5" y2="16"/><line x1="12" y1="8" x2="19" y2="16"/></svg>';
        html += 'LLDP/CDP Neighbors</div>';

        html += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12px">';
        html += '<tr style="border-bottom:1px solid var(--border)"><th style="text-align:left;padding:8px;color:var(--foreground-muted)">Port</th><th style="text-align:left;padding:8px;color:var(--foreground-muted)">Protocol</th><th style="text-align:left;padding:8px;color:var(--foreground-muted)">Neighbor</th><th style="text-align:left;padding:8px;color:var(--foreground-muted)">Remote Port</th></tr>';

        var ports = Object.keys(neighbors.ports);
        for (var p = 0; p < ports.length; p++) {
          var portId = ports[p];
          var portData = neighbors.ports[portId];
          if (portData.lldp) {
            html += '<tr style="border-bottom:1px solid var(--border)">';
            html += '<td style="padding:8px">' + portId + '</td>';
            html += '<td style="padding:8px"><span style="color:#22c55e">LLDP</span></td>';
            html += '<td style="padding:8px">' + (portData.lldp.systemName || portData.lldp.chassisId || 'Unknown') + '</td>';
            html += '<td style="padding:8px">' + (portData.lldp.portId || 'N/A') + '</td>';
            html += '</tr>';
          }
          if (portData.cdp) {
            html += '<tr style="border-bottom:1px solid var(--border)">';
            html += '<td style="padding:8px">' + portId + '</td>';
            html += '<td style="padding:8px"><span style="color:#3b82f6">CDP</span></td>';
            html += '<td style="padding:8px">' + (portData.cdp.deviceId || 'Unknown') + '</td>';
            html += '<td style="padding:8px">' + (portData.cdp.portId || 'N/A') + '</td>';
            html += '</tr>';
          }
        }
        html += '</table></div></div>';
      }

      content.innerHTML = html;
    }

    function renderInfoRow(label, value) {
      return '<div style="display:flex;justify-content:space-between;padding:8px 12px;background:rgba(255,255,255,0.02);border-radius:6px">' +
        '<span style="color:var(--foreground-muted);font-size:12px">' + label + '</span>' +
        '<span style="font-size:13px">' + value + '</span></div>';
    }

    function refreshLocalStatus() {
      var serial = document.getElementById('local-status-ap-select').value;
      if (serial) {
        loadAPStatus();
      } else {
        loadLocalStatusAPs();
      }
    }

    // ===========================================
    // XIQ TROUBLESHOOTING FUNCTIONS
    // ===========================================

    var xiqDevices = [];
    var xiqCliCommands = [
      // AP Wireless Commands
      { category: 'ap', subcategory: 'wireless', name: 'Show interface', cmd: 'show interface', desc: 'Display all interface status' },
      { category: 'ap', subcategory: 'wireless', name: 'Show SSID', cmd: 'show ssid', desc: 'List all configured SSIDs' },
      { category: 'ap', subcategory: 'wireless', name: 'Show station', cmd: 'show station', desc: 'Show connected wireless clients' },
      { category: 'ap', subcategory: 'wireless', name: 'Show roaming cache', cmd: 'show roaming cache', desc: 'Display roaming cache entries' },
      { category: 'ap', subcategory: 'wireless', name: 'Show acsp', cmd: 'show acsp', desc: 'Auto Channel Selection status' },
      { category: 'ap', subcategory: 'wireless', name: 'Show acsp neighbor', cmd: 'show acsp neighbor', desc: 'Show neighboring APs for channel planning' },
      { category: 'ap', subcategory: 'wireless', name: 'Show radio', cmd: 'show interface wifi0\\nshow interface wifi1', desc: 'Radio interface details (2.4/5GHz)' },

      // AP Network Commands
      { category: 'ap', subcategory: 'network', name: 'Show IP route', cmd: 'show ip route', desc: 'Display routing table' },
      { category: 'ap', subcategory: 'network', name: 'Show ARP', cmd: 'show arp', desc: 'ARP table entries' },
      { category: 'ap', subcategory: 'network', name: 'Show VLAN', cmd: 'show vlan', desc: 'VLAN configuration' },
      { category: 'ap', subcategory: 'network', name: 'Show DNS', cmd: 'show dns', desc: 'DNS configuration and cache' },
      { category: 'ap', subcategory: 'network', name: 'Show CAPWAP', cmd: 'show capwap client', desc: 'CAPWAP tunnel status to XIQ' },
      { category: 'ap', subcategory: 'network', name: 'Show LLDP', cmd: 'show lldp neighbor', desc: 'LLDP neighbor discovery' },

      // AP Diagnostics
      { category: 'ap', subcategory: 'diagnostics', name: 'Show memory', cmd: 'show memory', desc: 'Memory utilization' },
      { category: 'ap', subcategory: 'diagnostics', name: 'Show CPU', cmd: 'show cpu', desc: 'CPU utilization' },
      { category: 'ap', subcategory: 'diagnostics', name: 'Show log', cmd: 'show log buffered', desc: 'System log messages' },
      { category: 'ap', subcategory: 'diagnostics', name: 'Show running config', cmd: 'show running-config', desc: 'Current running configuration' },
      { category: 'ap', subcategory: 'diagnostics', name: 'Show version', cmd: 'show version', desc: 'Firmware and hardware info' },
      { category: 'ap', subcategory: 'diagnostics', name: 'Ping test', cmd: 'ping <ip-address>', desc: 'Test network connectivity' },
      { category: 'ap', subcategory: 'diagnostics', name: 'Traceroute', cmd: 'traceroute <ip-address>', desc: 'Trace network path' },

      // Switch Commands
      { category: 'switch', subcategory: 'network', name: 'Show ports', cmd: 'show ports', desc: 'Port status and statistics' },
      { category: 'switch', subcategory: 'network', name: 'Show VLAN', cmd: 'show vlan', desc: 'VLAN configuration' },
      { category: 'switch', subcategory: 'network', name: 'Show FDB', cmd: 'show fdb', desc: 'Forwarding database (MAC table)' },
      { category: 'switch', subcategory: 'network', name: 'Show STP', cmd: 'show stpd', desc: 'Spanning tree status' },
      { category: 'switch', subcategory: 'network', name: 'Show LLDP', cmd: 'show lldp neighbors', desc: 'LLDP neighbor information' },
      { category: 'switch', subcategory: 'network', name: 'Show LAG', cmd: 'show sharing', desc: 'Link aggregation groups' },
      { category: 'switch', subcategory: 'diagnostics', name: 'Show port errors', cmd: 'show ports statistics', desc: 'Port error counters' },
      { category: 'switch', subcategory: 'diagnostics', name: 'Show log', cmd: 'show log', desc: 'System event log' },
      { category: 'switch', subcategory: 'diagnostics', name: 'Show config', cmd: 'show configuration', desc: 'Current configuration' },
      { category: 'switch', subcategory: 'diagnostics', name: 'Show version', cmd: 'show version', desc: 'Software and hardware info' }
    ];

    var xiqTsScenarios = {
      'wifi-connectivity': {
        title: 'WiFi Connectivity Issues',
        desc: 'Diagnose why clients cannot connect or are being disconnected',
        steps: [
          { title: 'Check AP Status', cmd: 'show interface wifi0\\nshow interface wifi1', detail: 'Verify radios are up and broadcasting' },
          { title: 'Verify SSID', cmd: 'show ssid', detail: 'Ensure SSID is enabled and configured correctly' },
          { title: 'Check Client Association', cmd: 'show station', detail: 'See if client is attempting to connect' },
          { title: 'Review Authentication', cmd: 'show aaa radius-server', detail: 'Verify RADIUS server connectivity' },
          { title: 'Check Logs', cmd: 'show log buffered | include auth', detail: 'Look for authentication failures' }
        ],
        bestPractices: [
          'Ensure minimum RSSI threshold is set appropriately (-75 dBm recommended)',
          'Verify RADIUS server is reachable from AP management VLAN',
          'Check that 802.1X supplicant is configured correctly on client',
          'Ensure DHCP server is available on client VLAN'
        ]
      },
      'slow-wifi': {
        title: 'Slow WiFi Performance',
        desc: 'Investigate low throughput and high latency issues',
        steps: [
          { title: 'Check Channel Utilization', cmd: 'show acsp', detail: 'Review channel congestion levels' },
          { title: 'View Neighbor APs', cmd: 'show acsp neighbor', detail: 'Check for co-channel interference' },
          { title: 'Check Client Signal', cmd: 'show station', detail: 'Review client RSSI and SNR values' },
          { title: 'Review Radio Settings', cmd: 'show interface wifi0\\nshow interface wifi1', detail: 'Check channel width and power settings' },
          { title: 'Check CPU/Memory', cmd: 'show cpu\\nshow memory', detail: 'Verify AP is not overloaded' }
        ],
        bestPractices: [
          'Use 5GHz band for high-density areas',
          'Enable band steering to balance client load',
          'Set appropriate channel width (40MHz for 5GHz in most cases)',
          'Consider enabling Airtime Fairness',
          'Review client mix - older clients can slow down entire BSS'
        ]
      },
      'roaming': {
        title: 'Roaming Problems',
        desc: 'Fix sticky clients and slow roaming transitions',
        steps: [
          { title: 'Check Roaming Cache', cmd: 'show roaming cache', detail: 'Verify roaming entries exist between APs' },
          { title: 'Review 802.11r/k/v', cmd: 'show ssid <name>', detail: 'Check fast roaming protocols enabled' },
          { title: 'Check Client Roaming', cmd: 'show station', detail: 'Monitor client movement between APs' },
          { title: 'Verify PMK Caching', cmd: 'show roaming cache pairwise', detail: 'Check PMK cache for fast reauthentication' },
          { title: 'Review Load Balance', cmd: 'show load-balance', detail: 'Check load balancing settings' }
        ],
        bestPractices: [
          'Enable 802.11r (Fast BSS Transition) for seamless roaming',
          'Enable 802.11k for neighbor reports',
          'Enable 802.11v for BSS transition management',
          'Ensure consistent security settings across all APs',
          'Set minimum RSSI threshold to encourage roaming'
        ]
      },
      'vlan-issues': {
        title: 'VLAN/Network Segmentation Issues',
        desc: 'Troubleshoot VLAN tagging and traffic segregation',
        steps: [
          { title: 'Check VLAN Config', cmd: 'show vlan', detail: 'Verify VLAN configuration on AP' },
          { title: 'Verify Trunk Port', cmd: 'show lldp neighbor', detail: 'Check switch port is properly trunked' },
          { title: 'Check SSID-VLAN Mapping', cmd: 'show ssid', detail: 'Verify correct VLAN assigned to SSID' },
          { title: 'Test Connectivity', cmd: 'ping -I <vlan-ip> <gateway>', detail: 'Test reachability on specific VLAN' },
          { title: 'Check ARP', cmd: 'show arp', detail: 'Verify gateway MAC is learned' }
        ],
        bestPractices: [
          'Use tagged VLANs for user traffic, native VLAN for management',
          'Ensure switch port allows all required VLANs',
          'Configure DHCP snooping and ARP inspection on switch',
          'Document VLAN assignments for each SSID',
          'Test VLAN connectivity after any changes'
        ]
      },
      'switch-port': {
        title: 'Switch Port Issues',
        desc: 'Diagnose port connectivity and performance problems',
        steps: [
          { title: 'Check Port Status', cmd: 'show ports <port>', detail: 'Verify port is up and speed/duplex' },
          { title: 'View Port Statistics', cmd: 'show ports statistics <port>', detail: 'Check for errors, CRC, collisions' },
          { title: 'Check VLAN Assignment', cmd: 'show vlan ports <port>', detail: 'Verify correct VLAN configuration' },
          { title: 'Review STP State', cmd: 'show stpd ports <port>', detail: 'Check if port is blocked by STP' },
          { title: 'Check PoE', cmd: 'show inline-power info ports <port>', detail: 'Verify PoE status for AP/IP phone' }
        ],
        bestPractices: [
          'Use auto-negotiation for most deployments',
          'Enable PoE+ (802.3at) for modern APs',
          'Configure storm control on edge ports',
          'Enable BPDU guard on access ports',
          'Document port assignments with descriptions'
        ]
      },
      'auth-issues': {
        title: 'Authentication Failures',
        desc: 'Debug RADIUS, 802.1X, and credential issues',
        steps: [
          { title: 'Check RADIUS Server', cmd: 'show aaa radius-server', detail: 'Verify RADIUS server configuration' },
          { title: 'Test RADIUS', cmd: 'test aaa radius-server <server> <user> <pass>', detail: 'Test RADIUS authentication' },
          { title: 'Check Auth Logs', cmd: 'show log buffered | include RADIUS', detail: 'Review RADIUS transaction logs' },
          { title: 'View Failed Auths', cmd: 'show station filter state auth-failed', detail: 'List clients with auth failures' },
          { title: 'Check Certificates', cmd: 'show crypto certificate', detail: 'Verify certificate validity for EAP-TLS' }
        ],
        bestPractices: [
          'Configure primary and secondary RADIUS servers',
          'Set appropriate RADIUS timeout (5s recommended)',
          'Enable RADIUS accounting for auditing',
          'Use strong EAP methods (PEAP, EAP-TLS)',
          'Regularly test RADIUS failover'
        ]
      }
    };

    async function initXiqTroubleshoot() {
      var deviceSelect = document.getElementById('xiq-ts-device-select');
      if (deviceSelect && deviceSelect.options.length <= 1) {
        try {
          var res = await fetch('/api/xiq/devices');
          var data = await res.json();

          if (data && data.data) {
            xiqDevices = data.data;

            // Group devices by type
            var aps = data.data.filter(function(d) { return d.device_function === 'AP'; });
            var switches = data.data.filter(function(d) { return d.device_function === 'SWITCH'; });

            // Add AP options
            if (aps.length > 0) {
              var apGroup = document.createElement('optgroup');
              apGroup.label = 'Access Points (' + aps.length + ')';
              aps.forEach(function(ap) {
                var opt = document.createElement('option');
                opt.value = ap.id;
                opt.textContent = (ap.hostname || ap.serial_number) + ' - ' + ap.ip_address;
                opt.dataset.type = 'AP';
                apGroup.appendChild(opt);
              });
              deviceSelect.appendChild(apGroup);
            }

            // Add Switch options
            if (switches.length > 0) {
              var swGroup = document.createElement('optgroup');
              swGroup.label = 'Switches (' + switches.length + ')';
              switches.forEach(function(sw) {
                var opt = document.createElement('option');
                opt.value = sw.id;
                opt.textContent = (sw.hostname || sw.serial_number) + ' - ' + sw.ip_address;
                opt.dataset.type = 'SWITCH';
                swGroup.appendChild(opt);
              });
              deviceSelect.appendChild(swGroup);
            }

            // Update stats
            var online = data.data.filter(function(d) { return d.connected; }).length;
            var mismatch = data.data.filter(function(d) { return d.config_mismatch; }).length;
            document.getElementById('xiq-ts-total').textContent = data.data.length;
            document.getElementById('xiq-ts-online').textContent = online;
            document.getElementById('xiq-ts-mismatch').textContent = mismatch;
          }
        } catch (e) {
          console.error('Failed to load XIQ devices:', e);
        }
      }

      // Populate CLI commands
      filterCliCommands();
    }

    function loadXiqDeviceInfo() {
      var deviceId = document.getElementById('xiq-ts-device-select').value;
      var infoDiv = document.getElementById('xiq-ts-device-info');
      var sshCmd = document.getElementById('xiq-ts-ssh-cmd');

      if (!deviceId) {
        infoDiv.innerHTML = '<div style="font-size:14px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>Device Information</div><div style="text-align:center;padding:40px;color:var(--foreground-muted)"><div>Select a device to view details</div></div>';
        sshCmd.textContent = 'ssh admin@<select-device>';
        return;
      }

      var device = xiqDevices.find(function(d) { return d.id == deviceId; });
      if (!device) return;

      // Update SSH command
      sshCmd.textContent = 'ssh admin@' + device.ip_address;

      // Build device info
      var statusColor = device.connected ? 'var(--success)' : 'var(--destructive)';
      var statusText = device.connected ? 'ONLINE' : 'OFFLINE';

      var html = '<div style="font-size:14px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px">';
      html += '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>';
      html += 'Device Information</div>';

      html += '<div style="display:grid;gap:10px">';
      html += renderInfoRow('Hostname', device.hostname || 'N/A');
      html += renderInfoRow('Type', device.device_function + ' - ' + device.product_type);
      html += renderInfoRow('IP Address', device.ip_address || 'N/A');
      html += renderInfoRow('MAC Address', device.mac_address ? device.mac_address.match(/.{2}/g).join(':') : 'N/A');
      html += renderInfoRow('Serial', device.serial_number || 'N/A');
      html += renderInfoRow('Software', device.software_version || 'N/A');
      html += renderInfoRow('Status', '<span style="color:' + statusColor + '">' + statusText + '</span>');
      html += renderInfoRow('Config Sync', device.config_mismatch ? '<span style="color:#f59e0b">MISMATCH</span>' : '<span style="color:var(--success)">SYNCED</span>');
      html += '</div>';

      infoDiv.innerHTML = html;

      // Update CLI commands based on device type
      var cmdCategory = document.getElementById('xiq-ts-cmd-category');
      cmdCategory.value = device.device_function === 'AP' ? 'ap' : 'switch';
      filterCliCommands();
    }

    function filterCliCommands() {
      var category = document.getElementById('xiq-ts-cmd-category').value;
      var container = document.getElementById('xiq-ts-cli-commands');

      var filtered = xiqCliCommands;
      if (category !== 'all') {
        if (category === 'ap' || category === 'switch') {
          filtered = xiqCliCommands.filter(function(c) { return c.category === category; });
        } else {
          filtered = xiqCliCommands.filter(function(c) { return c.subcategory === category; });
        }
      }

      var html = '';
      filtered.forEach(function(cmd, idx) {
        html += '<div style="background:rgba(0,0,0,0.2);border-radius:8px;padding:12px">';
        html += '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px">';
        html += '<div>';
        html += '<div style="font-weight:500;font-size:13px">' + cmd.name + '</div>';
        html += '<div style="font-size:11px;color:var(--foreground-muted);margin-top:2px">' + cmd.desc + '</div>';
        html += '</div>';
        html += '<span style="padding:2px 8px;background:rgba(59,130,246,0.2);color:#3b82f6;border-radius:4px;font-size:10px;text-transform:uppercase">' + cmd.category + '</span>';
        html += '</div>';
        html += '<div style="display:flex;align-items:center;gap:8px">';
        html += '<code id="cli-cmd-' + idx + '" style="flex:1;font-size:12px;color:#22c55e;background:rgba(0,0,0,0.3);padding:8px 12px;border-radius:4px;white-space:pre-wrap">' + cmd.cmd.replace(/\\n/g, '\\n') + '</code>';
        html += '<button onclick="copyCliCommand(' + idx + ')" style="padding:6px 10px;background:var(--primary);border:none;border-radius:4px;color:white;cursor:pointer;font-size:11px;white-space:nowrap">Copy</button>';
        html += '</div>';
        html += '</div>';
      });

      container.innerHTML = html || '<div style="text-align:center;padding:20px;color:var(--foreground-muted)">No commands found</div>';
    }

    function copyCliCommand(idx) {
      var cmd = xiqCliCommands.filter(function(c) {
        var category = document.getElementById('xiq-ts-cmd-category').value;
        if (category === 'all') return true;
        if (category === 'ap' || category === 'switch') return c.category === category;
        return c.subcategory === category;
      })[idx];

      if (cmd) {
        navigator.clipboard.writeText(cmd.cmd.replace(/\\\\n/g, '\\n'));
        showToast('Command copied to clipboard');
      }
    }

    var currentScenarioCommands = [];

    function copyToClipboard(elementId) {
      var el = document.getElementById(elementId);
      if (el) {
        navigator.clipboard.writeText(el.textContent);
        showToast('Copied to clipboard');
      }
    }

    function copyScenarioCmd(idx) {
      if (currentScenarioCommands[idx]) {
        navigator.clipboard.writeText(currentScenarioCommands[idx].replace(/\\\\n/g, '\\n'));
        showToast('Copied');
      }
    }

    function showToast(message) {
      var toast = document.createElement('div');
      toast.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#22c55e;color:white;padding:12px 20px;border-radius:8px;font-size:13px;z-index:9999;animation:fadeIn 0.3s';
      toast.textContent = message;
      document.body.appendChild(toast);
      setTimeout(function() { toast.remove(); }, 2000);
    }

    function loadTsScenario(scenarioId) {
      var scenario = xiqTsScenarios[scenarioId];
      if (!scenario) return;

      currentScenarioCommands = [];
      var detailPanel = document.getElementById('xiq-ts-scenario-detail');
      document.getElementById('xiq-ts-scenario-title').textContent = scenario.title;
      document.getElementById('xiq-ts-scenario-desc').textContent = scenario.desc;

      var html = '<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">';

      // Troubleshooting Steps
      html += '<div>';
      html += '<div style="font-weight:600;font-size:13px;margin-bottom:12px;color:var(--primary)">Troubleshooting Steps</div>';
      scenario.steps.forEach(function(step, idx) {
        currentScenarioCommands.push(step.cmd);
        html += '<div style="background:rgba(0,0,0,0.2);border-radius:8px;padding:12px;margin-bottom:8px">';
        html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">';
        html += '<span style="width:24px;height:24px;background:var(--primary);color:white;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600">' + (idx + 1) + '</span>';
        html += '<span style="font-weight:500;font-size:13px">' + step.title + '</span>';
        html += '</div>';
        html += '<div style="font-size:11px;color:var(--foreground-muted);margin-bottom:8px;margin-left:32px">' + step.detail + '</div>';
        html += '<div style="display:flex;align-items:center;gap:8px;margin-left:32px">';
        html += '<code style="flex:1;font-size:11px;color:#22c55e;background:rgba(0,0,0,0.3);padding:6px 10px;border-radius:4px;white-space:pre-wrap">' + step.cmd.replace(/\\\\n/g, '\\n') + '</code>';
        html += '<button onclick="copyScenarioCmd(' + idx + ')" style="padding:4px 8px;background:var(--primary);border:none;border-radius:4px;color:white;cursor:pointer;font-size:10px">Copy</button>';
        html += '</div>';
        html += '</div>';
      });
      html += '</div>';

      // Best Practices
      html += '<div>';
      html += '<div style="font-weight:600;font-size:13px;margin-bottom:12px;color:#22c55e">Industry Best Practices</div>';
      html += '<div style="background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:8px;padding:16px">';
      scenario.bestPractices.forEach(function(bp) {
        html += '<div style="display:flex;align-items:flex-start;gap:8px;margin-bottom:10px">';
        html += '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" style="flex-shrink:0;margin-top:2px"><polyline points="20 6 9 17 4 12"/></svg>';
        html += '<span style="font-size:12px;color:var(--foreground)">' + bp + '</span>';
        html += '</div>';
      });
      html += '</div>';
      html += '</div>';

      html += '</div>';

      document.getElementById('xiq-ts-scenario-content').innerHTML = html;
      detailPanel.style.display = 'block';
      detailPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function runBestPracticesCheck() {
      var deviceId = document.getElementById('xiq-ts-device-select').value;
      var container = document.getElementById('xiq-ts-best-practices');

      if (!deviceId) {
        container.innerHTML = '<div style="text-align:center;padding:20px;color:var(--foreground-muted)"><div>Select a device first</div></div>';
        return;
      }

      var device = xiqDevices.find(function(d) { return d.id == deviceId; });
      if (!device) return;

      // Simulate best practices check
      var checks = [];
      var passed = 0;
      var total = 0;

      if (device.device_function === 'AP') {
        checks = [
          { name: 'Firmware Version', status: device.software_version && device.software_version.startsWith('10.') ? 'pass' : 'warn', detail: device.software_version || 'Unknown' },
          { name: 'Config Synchronization', status: device.config_mismatch ? 'fail' : 'pass', detail: device.config_mismatch ? 'Configuration mismatch detected' : 'Configuration in sync' },
          { name: 'Connectivity Status', status: device.connected ? 'pass' : 'fail', detail: device.connected ? 'Device online' : 'Device offline' },
          { name: 'Management State', status: device.device_admin_state === 'MANAGED' ? 'pass' : 'warn', detail: device.device_admin_state },
          { name: 'IP Address Assigned', status: device.ip_address ? 'pass' : 'fail', detail: device.ip_address || 'No IP' },
          { name: '5GHz Radio Enabled', status: 'info', detail: 'Verify via CLI: show interface wifi1' },
          { name: 'Band Steering', status: 'info', detail: 'Verify band steering is enabled for dual-band SSIDs' },
          { name: '802.11r/k/v Support', status: 'info', detail: 'Verify fast roaming protocols are enabled' }
        ];
      } else {
        checks = [
          { name: 'Firmware Version', status: device.software_version ? 'pass' : 'warn', detail: device.software_version || 'Unknown' },
          { name: 'Config Synchronization', status: device.config_mismatch ? 'fail' : 'pass', detail: device.config_mismatch ? 'Configuration mismatch detected' : 'Configuration in sync' },
          { name: 'Connectivity Status', status: device.connected ? 'pass' : 'fail', detail: device.connected ? 'Device online' : 'Device offline' },
          { name: 'Management State', status: device.device_admin_state === 'MANAGED' ? 'pass' : 'warn', detail: device.device_admin_state },
          { name: 'IP Address Assigned', status: device.ip_address ? 'pass' : 'fail', detail: device.ip_address || 'No IP' },
          { name: 'STP Configuration', status: 'info', detail: 'Verify RSTP/MSTP is enabled' },
          { name: 'Storm Control', status: 'info', detail: 'Verify storm control on edge ports' },
          { name: 'BPDU Guard', status: 'info', detail: 'Verify BPDU guard on access ports' }
        ];
      }

      checks.forEach(function(c) {
        if (c.status === 'pass') passed++;
        if (c.status !== 'info') total++;
      });

      var score = total > 0 ? Math.round((passed / total) * 100) : 0;
      document.getElementById('xiq-ts-bp-score').textContent = score + '%';
      document.getElementById('xiq-ts-bp-score').style.color = score >= 80 ? 'var(--success)' : score >= 50 ? '#f59e0b' : 'var(--destructive)';

      var html = '<div style="display:flex;flex-direction:column;gap:8px">';
      checks.forEach(function(check) {
        var icon = '';
        var color = '';
        if (check.status === 'pass') {
          icon = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>';
          color = '#22c55e';
        } else if (check.status === 'fail') {
          icon = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
          color = '#ef4444';
        } else if (check.status === 'warn') {
          icon = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
          color = '#f59e0b';
        } else {
          icon = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>';
          color = '#3b82f6';
        }

        html += '<div style="display:flex;align-items:center;gap:10px;padding:8px 10px;background:rgba(255,255,255,0.02);border-radius:6px">';
        html += icon;
        html += '<div style="flex:1">';
        html += '<div style="font-size:12px;font-weight:500">' + check.name + '</div>';
        html += '<div style="font-size:10px;color:var(--foreground-muted)">' + check.detail + '</div>';
        html += '</div>';
        html += '</div>';
      });
      html += '</div>';

      container.innerHTML = html;
    }

    function refreshXiqTroubleshoot() {
      var deviceId = document.getElementById('xiq-ts-device-select').value;
      if (deviceId) {
        loadXiqDeviceInfo();
        runBestPracticesCheck();
      } else {
        initXiqTroubleshoot();
      }
    }

    // ===========================================
    // CONFIG ANALYZER FUNCTIONS
    // ===========================================

    var configBestPractices = [
      // Security Best Practices
      { category: 'security', name: 'WPA3 or WPA2-Enterprise', check: function(c) { return /security\s+(wpa3|wpa2-aes-ccmp|wpa-auto-psk.*aes|wpa2-ent)/i.test(c); }, severity: 'critical', recommendation: 'Use WPA3 or WPA2-Enterprise with AES-CCMP encryption' },
      { category: 'security', name: 'No WEP Encryption', check: function(c) { return !/security\s+wep/i.test(c); }, severity: 'critical', recommendation: 'Remove WEP encryption - it is deprecated and insecure' },
      { category: 'security', name: 'No Open Networks', check: function(c) { return !/security\s+open/i.test(c) || /captive-web-portal|cwp/i.test(c); }, severity: 'high', recommendation: 'Avoid open networks without captive portal authentication' },
      { category: 'security', name: 'PMF Enabled', check: function(c) { return /management-frame-protection/i.test(c) || /pmf\s+(required|optional)/i.test(c); }, severity: 'medium', recommendation: 'Enable Protected Management Frames (802.11w) for deauth protection' },
      { category: 'security', name: 'RADIUS Server Configured', check: function(c) { return /radius-server|aaa\s+radius/i.test(c); }, severity: 'info', recommendation: 'Configure RADIUS server for enterprise authentication' },

      // RF Optimization
      { category: 'rf', name: 'Auto Channel Selection', check: function(c) { return /radio\s+profile\s+auto|acsp|channel\s+auto/i.test(c) || !/channel\s+\d+/i.test(c); }, severity: 'medium', recommendation: 'Enable auto channel selection (ACSP) for dynamic RF management' },
      { category: 'rf', name: 'Band Steering', check: function(c) { return /band-steering|band-balance/i.test(c); }, severity: 'medium', recommendation: 'Enable band steering to balance clients across 2.4GHz and 5GHz' },
      { category: 'rf', name: '5GHz Radio Enabled', check: function(c) { return /interface\s+wifi1|radio\s+wifi1|5g/i.test(c); }, severity: 'high', recommendation: 'Ensure 5GHz radio (wifi1) is enabled for better performance' },
      { category: 'rf', name: 'Appropriate Power Settings', check: function(c) { return /power\s+auto|tx-power\s+auto|power\s+\d+/i.test(c); }, severity: 'low', recommendation: 'Configure appropriate transmit power levels for your environment' },
      { category: 'rf', name: 'DFS Channels Allowed', check: function(c) { return !/no\s+dfs|dfs\s+disable/i.test(c); }, severity: 'low', recommendation: 'Allow DFS channels to utilize additional 5GHz spectrum' },

      // Roaming & Client Experience
      { category: 'roaming', name: '802.11r Fast Roaming', check: function(c) { return /dot11r|11r|fast-roaming|ft-/i.test(c); }, severity: 'medium', recommendation: 'Enable 802.11r (Fast BSS Transition) for seamless roaming' },
      { category: 'roaming', name: '802.11k Neighbor Reports', check: function(c) { return /dot11k|11k|neighbor-report/i.test(c); }, severity: 'medium', recommendation: 'Enable 802.11k for neighbor AP reports to assist client roaming' },
      { category: 'roaming', name: '802.11v BSS Transition', check: function(c) { return /dot11v|11v|bss-transition/i.test(c); }, severity: 'medium', recommendation: 'Enable 802.11v for network-assisted roaming decisions' },
      { category: 'roaming', name: 'Minimum RSSI Configured', check: function(c) { return /min-rssi|rssi-threshold|weak-snr/i.test(c); }, severity: 'medium', recommendation: 'Set minimum RSSI threshold to prevent sticky clients (-75 dBm recommended)' },
      { category: 'roaming', name: 'Load Balancing', check: function(c) { return /load-balance|client-load/i.test(c); }, severity: 'low', recommendation: 'Enable load balancing to distribute clients across APs' },

      // Network Configuration
      { category: 'network', name: 'VLAN Configured', check: function(c) { return /vlan\s+\d+/i.test(c); }, severity: 'medium', recommendation: 'Configure VLANs for proper traffic segmentation' },
      { category: 'network', name: 'Management VLAN Separate', check: function(c) { return /native-vlan|management\s+vlan/i.test(c); }, severity: 'medium', recommendation: 'Separate management traffic from user traffic with dedicated VLAN' },
      { category: 'network', name: 'DHCP Snooping', check: function(c) { return /dhcp-snoop|dhcp\s+snooping/i.test(c); }, severity: 'low', recommendation: 'Enable DHCP snooping for rogue DHCP server protection' },

      // Operational Best Practices
      { category: 'operational', name: 'SSID Broadcast', check: function(c) { return !/hide-ssid|no\s+broadcast/i.test(c); }, severity: 'low', recommendation: 'Consider SSID visibility - hiding provides minimal security benefit' },
      { category: 'operational', name: 'Client Isolation', check: function(c) { return true; }, severity: 'info', recommendation: 'Consider enabling client isolation for guest networks' },
      { category: 'operational', name: 'QoS/WMM Configured', check: function(c) { return /wmm|qos|traffic-class/i.test(c) || true; }, severity: 'low', recommendation: 'Ensure WMM/QoS is enabled for voice and video prioritization' }
    ];

    function loadSampleConfig() {
      var sampleConfig = '# IQEngine AP Configuration Sample\\n' +
        '# Device: AP-4000\\n' +
        '# Software: 10.8.5.0\\n\\n' +
        'hostname AP-Office-01\\n\\n' +
        'interface wifi0\\n' +
        '  radio profile auto-channel\\n' +
        '  channel auto\\n' +
        '  power auto\\n\\n' +
        'interface wifi1\\n' +
        '  radio profile auto-channel\\n' +
        '  channel auto\\n' +
        '  power auto\\n' +
        '  band-steering enable\\n\\n' +
        'ssid Corporate-WiFi\\n' +
        '  security wpa2-aes-ccmp\\n' +
        '  radius-server primary 10.1.1.100\\n' +
        '  vlan 100\\n' +
        '  dot11r enable\\n' +
        '  dot11k enable\\n' +
        '  management-frame-protection optional\\n\\n' +
        'ssid Guest-WiFi\\n' +
        '  security wpa2-psk\\n' +
        '  vlan 200\\n' +
        '  captive-web-portal enable\\n' +
        '  client-isolation enable\\n\\n' +
        'aaa radius-server primary\\n' +
        '  host 10.1.1.100\\n' +
        '  secret encrypted\\n' +
        '  accounting enable\\n';

      document.getElementById('xiq-config-input').value = sampleConfig;
    }

    function clearConfigAnalyzer() {
      document.getElementById('xiq-config-input').value = '';
      document.getElementById('xiq-config-results').innerHTML = '<div style="text-align:center;padding:60px 20px;color:var(--foreground-muted)"><svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" style="opacity:0.3;margin-bottom:16px"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg><div style="font-size:14px">Paste configuration and click "Analyze" to see results</div><div style="font-size:12px;margin-top:8px;opacity:0.7">Supports IQEngine AP, HiveOS, and ExtremeCloud IQ configs</div></div>';
    }

    function analyzeConfig() {
      var config = document.getElementById('xiq-config-input').value;
      var resultsDiv = document.getElementById('xiq-config-results');

      if (!config.trim()) {
        resultsDiv.innerHTML = '<div style="text-align:center;padding:40px;color:var(--foreground-muted)"><div style="color:#f59e0b">Please paste a configuration to analyze</div></div>';
        return;
      }

      // Extract basic info from config
      var hostname = (config.match(/hostname\\s+["']?([^"'\\n]+)["']?/i) || [])[1] || 'Unknown';

      // Extract SSIDs - handle various formats:
      // - "ssid TeamChaos" (standalone)
      // - "interface wifi0 ssid TeamChaos" (interface assignment)
      // - "ssid TeamChaos client-monitor-policy..." (with additional params)
      var ssidMatches = config.match(/(?:^|\\s)ssid\\s+([\\w\\-]+)/gim) || [];
      var uniqueSsids = [];
      ssidMatches.forEach(function(m) {
        var name = m.replace(/.*ssid\\s+/i, '').trim();
        if (name && uniqueSsids.indexOf(name) === -1 && name !== 'enable' && name !== 'disable') {
          uniqueSsids.push(name);
        }
      });

      var vlans = config.match(/vlan\\s+(\\d+)/gi) || [];
      var uniqueVlans = [];
      vlans.forEach(function(v) {
        var num = v.replace(/vlan\\s+/i, '');
        if (uniqueVlans.indexOf(num) === -1) uniqueVlans.push(num);
      });

      // Run best practices checks
      var results = {
        passed: [],
        warnings: [],
        failed: [],
        info: []
      };

      configBestPractices.forEach(function(bp) {
        var passed = bp.check(config);
        var result = {
          name: bp.name,
          category: bp.category,
          severity: bp.severity,
          recommendation: bp.recommendation,
          passed: passed
        };

        if (passed) {
          results.passed.push(result);
        } else {
          if (bp.severity === 'critical') {
            results.failed.push(result);
          } else if (bp.severity === 'high' || bp.severity === 'medium') {
            results.warnings.push(result);
          } else if (bp.severity === 'info') {
            results.info.push(result);
          } else {
            results.warnings.push(result);
          }
        }
      });

      // Calculate score
      var total = configBestPractices.filter(function(bp) { return bp.severity !== 'info'; }).length;
      var passed = results.passed.filter(function(r) { return r.severity !== 'info'; }).length;
      var score = total > 0 ? Math.round((passed / total) * 100) : 0;

      // Build results HTML
      var html = '';

      // Score Header
      var scoreColor = score >= 80 ? '#22c55e' : score >= 60 ? '#f59e0b' : '#ef4444';
      html += '<div style="text-align:center;padding:20px;background:rgba(0,0,0,0.2);border-radius:8px;margin-bottom:16px">';
      html += '<div style="font-size:48px;font-weight:700;color:' + scoreColor + '">' + score + '%</div>';
      html += '<div style="font-size:13px;color:var(--foreground-muted)">Best Practices Compliance Score</div>';
      html += '<div style="display:flex;justify-content:center;gap:16px;margin-top:12px;font-size:11px">';
      html += '<span style="color:#22c55e">✓ ' + results.passed.length + ' Passed</span>';
      html += '<span style="color:#f59e0b">⚠ ' + results.warnings.length + ' Warnings</span>';
      html += '<span style="color:#ef4444">✗ ' + results.failed.length + ' Critical</span>';
      html += '</div></div>';

      // Config Summary
      html += '<div style="padding:12px;background:rgba(59,130,246,0.1);border-radius:8px;margin-bottom:16px">';
      html += '<div style="font-size:12px;font-weight:600;color:#3b82f6;margin-bottom:8px">Configuration Summary</div>';
      html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:11px">';
      html += '<div>Hostname: <span style="color:var(--foreground)">' + hostname + '</span></div>';
      html += '<div>SSIDs: <span style="color:var(--foreground)">' + (uniqueSsids.length > 0 ? uniqueSsids.join(', ') : 'None detected') + '</span></div>';
      html += '<div>VLANs: <span style="color:var(--foreground)">' + (uniqueVlans.length > 0 ? uniqueVlans.join(', ') : 'None detected') + '</span></div>';
      html += '</div></div>';

      // Critical Issues
      if (results.failed.length > 0) {
        html += '<div style="margin-bottom:12px">';
        html += '<div style="font-size:12px;font-weight:600;color:#ef4444;margin-bottom:8px;display:flex;align-items:center;gap:6px"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg> Critical Issues</div>';
        results.failed.forEach(function(r) {
          html += '<div style="padding:10px;background:rgba(239,68,68,0.1);border-left:3px solid #ef4444;border-radius:4px;margin-bottom:6px">';
          html += '<div style="font-size:12px;font-weight:500">' + r.name + '</div>';
          html += '<div style="font-size:11px;color:var(--foreground-muted);margin-top:2px">' + r.recommendation + '</div>';
          html += '</div>';
        });
        html += '</div>';
      }

      // Warnings
      if (results.warnings.length > 0) {
        html += '<div style="margin-bottom:12px">';
        html += '<div style="font-size:12px;font-weight:600;color:#f59e0b;margin-bottom:8px;display:flex;align-items:center;gap:6px"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> Recommendations</div>';
        results.warnings.forEach(function(r) {
          html += '<div style="padding:10px;background:rgba(245,158,11,0.1);border-left:3px solid #f59e0b;border-radius:4px;margin-bottom:6px">';
          html += '<div style="font-size:12px;font-weight:500">' + r.name + ' <span style="font-size:10px;color:#f59e0b;text-transform:uppercase">(' + r.category + ')</span></div>';
          html += '<div style="font-size:11px;color:var(--foreground-muted);margin-top:2px">' + r.recommendation + '</div>';
          html += '</div>';
        });
        html += '</div>';
      }

      // Passed Checks (collapsible)
      if (results.passed.length > 0) {
        html += '<details style="margin-bottom:12px">';
        html += '<summary style="font-size:12px;font-weight:600;color:#22c55e;margin-bottom:8px;cursor:pointer;display:flex;align-items:center;gap:6px"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> Passed Checks (' + results.passed.length + ')</summary>';
        html += '<div style="padding-left:20px">';
        results.passed.forEach(function(r) {
          html += '<div style="padding:6px 10px;background:rgba(34,197,94,0.1);border-radius:4px;margin-bottom:4px;font-size:11px;display:flex;align-items:center;gap:6px">';
          html += '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>';
          html += r.name + ' <span style="color:var(--foreground-muted)">(' + r.category + ')</span>';
          html += '</div>';
        });
        html += '</div></details>';
      }

      // Detected Features
      html += '<div style="padding:12px;background:rgba(255,255,255,0.02);border-radius:8px">';
      html += '<div style="font-size:12px;font-weight:600;margin-bottom:8px">Detected Features</div>';
      html += '<div style="display:flex;flex-wrap:wrap;gap:6px">';

      var features = [];
      if (/wpa3/i.test(config)) features.push({ name: 'WPA3', color: '#22c55e' });
      if (/wpa2/i.test(config)) features.push({ name: 'WPA2', color: '#3b82f6' });
      if (/radius/i.test(config)) features.push({ name: 'RADIUS', color: '#8b5cf6' });
      if (/dot11r|11r/i.test(config)) features.push({ name: '802.11r', color: '#06b6d4' });
      if (/dot11k|11k/i.test(config)) features.push({ name: '802.11k', color: '#06b6d4' });
      if (/dot11v|11v/i.test(config)) features.push({ name: '802.11v', color: '#06b6d4' });
      if (/band-steering/i.test(config)) features.push({ name: 'Band Steering', color: '#f59e0b' });
      if (/captive|cwp/i.test(config)) features.push({ name: 'Captive Portal', color: '#ec4899' });
      if (/client-isolation/i.test(config)) features.push({ name: 'Client Isolation', color: '#14b8a6' });
      if (/management-frame/i.test(config)) features.push({ name: 'PMF', color: '#22c55e' });
      if (/vlan\s+\d/i.test(config)) features.push({ name: 'VLAN Tagging', color: '#6366f1' });

      if (features.length > 0) {
        features.forEach(function(f) {
          html += '<span style="padding:4px 8px;background:' + f.color + '20;color:' + f.color + ';border-radius:4px;font-size:10px;font-weight:500">' + f.name + '</span>';
        });
      } else {
        html += '<span style="color:var(--foreground-muted);font-size:11px">No advanced features detected</span>';
      }
      html += '</div></div>';

      resultsDiv.innerHTML = html;
    }

    // ===========================================
    // RF VISUALIZER FUNCTIONS
    // ===========================================

    var rfAps = [];
    var selectedApIndex = -1;
    var rfTool = 'add';
    var rfApCounter = 1;
    var draggingAp = null;
    var dragOffset = { x: 0, y: 0 };

    // Channel color mapping
    var channelColors = {
      // 2.4 GHz
      '1': '#ef4444',
      '2': '#f87171',
      '3': '#fca5a5',
      '4': '#fb923c',
      '5': '#fdba74',
      '6': '#f59e0b',
      '7': '#fcd34d',
      '8': '#fde047',
      '9': '#a3e635',
      '10': '#84cc16',
      '11': '#22c55e',
      // 5 GHz lower
      '36': '#3b82f6',
      '40': '#60a5fa',
      '44': '#93c5fd',
      '48': '#bfdbfe',
      // 5 GHz upper
      '149': '#8b5cf6',
      '153': '#a78bfa',
      '157': '#c4b5fd',
      '161': '#ddd6fe',
      '165': '#ede9fe',
      // 6 GHz
      '1e': '#ec4899',
      '5e': '#f472b6',
      '9e': '#f9a8d4',
      '13e': '#fbcfe8'
    };

    var bandChannels = {
      '2.4': ['1', '6', '11'],
      '5': ['36', '40', '44', '48', '149', '153', '157', '161', '165'],
      '6': ['1e', '5e', '9e', '13e']
    };

    function setRfTool(tool) {
      rfTool = tool;
      document.querySelectorAll('.rf-tool-btn').forEach(function(btn) {
        btn.style.background = 'var(--surface)';
        btn.style.border = '1px solid var(--border)';
        btn.style.color = 'var(--foreground)';
      });
      var activeBtn = document.getElementById('rf-tool-' + tool);
      if (activeBtn) {
        activeBtn.style.background = 'var(--primary)';
        activeBtn.style.border = 'none';
        activeBtn.style.color = 'white';
      }
    }

    function handleRfCanvasClick(event) {
      var canvas = document.getElementById('rf-canvas');
      var rect = canvas.getBoundingClientRect();
      var x = event.clientX - rect.left;
      var y = event.clientY - rect.top;

      if (rfTool === 'add') {
        addAp(x, y);
      } else if (rfTool === 'delete') {
        var clickedAp = findApAtPosition(x, y);
        if (clickedAp !== -1) {
          rfAps.splice(clickedAp, 1);
          if (selectedApIndex === clickedAp) {
            selectedApIndex = -1;
            document.getElementById('rf-ap-properties').style.display = 'none';
          } else if (selectedApIndex > clickedAp) {
            selectedApIndex--;
          }
          updateRfVisualization();
        }
      } else if (rfTool === 'move') {
        var clickedAp = findApAtPosition(x, y);
        if (clickedAp !== -1) {
          selectAp(clickedAp);
        }
      }
    }

    function findApAtPosition(x, y) {
      for (var i = rfAps.length - 1; i >= 0; i--) {
        var ap = rfAps[i];
        var dist = Math.sqrt(Math.pow(x - ap.x, 2) + Math.pow(y - ap.y, 2));
        if (dist <= 20) {
          return i;
        }
      }
      return -1;
    }

    function addAp(x, y) {
      var newAp = {
        id: 'ap-' + rfApCounter,
        name: 'AP-' + rfApCounter,
        x: x,
        y: y,
        band: '5',
        channel: '36',
        power: 17,
        coverage: 'medium'
      };
      rfAps.push(newAp);
      rfApCounter++;
      selectAp(rfAps.length - 1);
      updateRfVisualization();
    }

    function selectAp(index) {
      selectedApIndex = index;
      var ap = rfAps[index];
      if (!ap) return;

      document.getElementById('rf-ap-properties').style.display = 'block';
      document.getElementById('rf-ap-name').value = ap.name;
      document.getElementById('rf-ap-band').value = ap.band;
      updateApChannelOptions();
      document.getElementById('rf-ap-channel').value = ap.channel;
      document.getElementById('rf-ap-power').value = ap.power;
      document.getElementById('rf-ap-power-val').textContent = ap.power;

      document.querySelectorAll('.coverage-btn').forEach(function(btn) {
        if (btn.dataset.size === ap.coverage) {
          btn.style.background = 'var(--primary)';
          btn.style.border = 'none';
          btn.style.color = 'white';
        } else {
          btn.style.background = 'var(--surface)';
          btn.style.border = '1px solid var(--border)';
          btn.style.color = 'var(--foreground)';
        }
      });

      updateRfVisualization();
    }

    function updateApChannelOptions() {
      var band = document.getElementById('rf-ap-band').value;
      var channelSelect = document.getElementById('rf-ap-channel');
      var channels = bandChannels[band] || ['1', '6', '11'];

      channelSelect.innerHTML = '';
      channels.forEach(function(ch) {
        var opt = document.createElement('option');
        opt.value = ch;
        opt.textContent = ch.replace('e', ' (6E)');
        channelSelect.appendChild(opt);
      });
    }

    function updateSelectedAp() {
      if (selectedApIndex === -1) return;

      var ap = rfAps[selectedApIndex];
      ap.name = document.getElementById('rf-ap-name').value;
      ap.band = document.getElementById('rf-ap-band').value;
      ap.channel = document.getElementById('rf-ap-channel').value;
      ap.power = parseInt(document.getElementById('rf-ap-power').value);

      updateRfVisualization();
    }

    function setApCoverage(size) {
      if (selectedApIndex === -1) return;
      rfAps[selectedApIndex].coverage = size;

      document.querySelectorAll('.coverage-btn').forEach(function(btn) {
        if (btn.dataset.size === size) {
          btn.style.background = 'var(--primary)';
          btn.style.border = 'none';
          btn.style.color = 'white';
        } else {
          btn.style.background = 'var(--surface)';
          btn.style.border = '1px solid var(--border)';
          btn.style.color = 'var(--foreground)';
        }
      });

      updateRfVisualization();
    }

    function deleteSelectedAp() {
      if (selectedApIndex === -1) return;
      rfAps.splice(selectedApIndex, 1);
      selectedApIndex = -1;
      document.getElementById('rf-ap-properties').style.display = 'none';
      updateRfVisualization();
    }

    function clearRfCanvas() {
      rfAps = [];
      selectedApIndex = -1;
      rfApCounter = 1;
      document.getElementById('rf-ap-properties').style.display = 'none';
      updateRfVisualization();
    }

    function getCoverageRadius(ap) {
      var baseRadius = { small: 60, medium: 100, large: 150 };
      var radius = baseRadius[ap.coverage] || 100;
      // Adjust for power (rough approximation)
      var powerFactor = 1 + (ap.power - 17) * 0.05;
      // 5GHz/6GHz has shorter range than 2.4GHz
      var bandFactor = ap.band === '2.4' ? 1.3 : (ap.band === '6' ? 0.8 : 1);
      return radius * powerFactor * bandFactor;
    }

    function getChannelColor(ap) {
      return channelColors[ap.channel] || '#8b5cf6';
    }

    function updateRfVisualization() {
      var coverageLayer = document.getElementById('rf-coverage-layer');
      var interferenceLayer = document.getElementById('rf-interference-layer');
      var apLayer = document.getElementById('rf-ap-layer');
      var bandFilter = document.getElementById('rf-band-filter').value;
      var showInterference = document.getElementById('rf-show-interference').checked;

      coverageLayer.innerHTML = '';
      interferenceLayer.innerHTML = '';
      apLayer.innerHTML = '';

      var filteredAps = rfAps.filter(function(ap) {
        return bandFilter === 'all' || ap.band === bandFilter;
      });

      // Draw coverage circles
      filteredAps.forEach(function(ap, idx) {
        var radius = getCoverageRadius(ap);
        var color = getChannelColor(ap);
        var isSelected = rfAps.indexOf(ap) === selectedApIndex;

        // Coverage circle
        var circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', ap.x);
        circle.setAttribute('cy', ap.y);
        circle.setAttribute('r', radius);
        circle.setAttribute('fill', color);
        circle.setAttribute('fill-opacity', '0.15');
        circle.setAttribute('stroke', color);
        circle.setAttribute('stroke-width', isSelected ? '3' : '1');
        circle.setAttribute('stroke-opacity', '0.5');
        coverageLayer.appendChild(circle);

        // Inner strong signal area
        var innerCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        innerCircle.setAttribute('cx', ap.x);
        innerCircle.setAttribute('cy', ap.y);
        innerCircle.setAttribute('r', radius * 0.5);
        innerCircle.setAttribute('fill', color);
        innerCircle.setAttribute('fill-opacity', '0.1');
        coverageLayer.appendChild(innerCircle);
      });

      // Draw interference zones (overlapping same-channel APs)
      if (showInterference) {
        for (var i = 0; i < filteredAps.length; i++) {
          for (var j = i + 1; j < filteredAps.length; j++) {
            var ap1 = filteredAps[i];
            var ap2 = filteredAps[j];

            // Check if same channel (co-channel interference)
            if (ap1.channel === ap2.channel && ap1.band === ap2.band) {
              var dist = Math.sqrt(Math.pow(ap1.x - ap2.x, 2) + Math.pow(ap1.y - ap2.y, 2));
              var r1 = getCoverageRadius(ap1);
              var r2 = getCoverageRadius(ap2);

              if (dist < r1 + r2) {
                // Draw interference indicator
                var midX = (ap1.x + ap2.x) / 2;
                var midY = (ap1.y + ap2.y) / 2;

                var interferenceCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                interferenceCircle.setAttribute('cx', midX);
                interferenceCircle.setAttribute('cy', midY);
                interferenceCircle.setAttribute('r', Math.min(r1, r2) * 0.5);
                interferenceCircle.setAttribute('fill', '#ef4444');
                interferenceCircle.setAttribute('fill-opacity', '0.3');
                interferenceCircle.setAttribute('stroke', '#ef4444');
                interferenceCircle.setAttribute('stroke-width', '2');
                interferenceCircle.setAttribute('stroke-dasharray', '5,5');
                interferenceLayer.appendChild(interferenceCircle);

                // Warning icon
                var text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                text.setAttribute('x', midX);
                text.setAttribute('y', midY + 4);
                text.setAttribute('text-anchor', 'middle');
                text.setAttribute('fill', '#ef4444');
                text.setAttribute('font-size', '16');
                text.setAttribute('font-weight', 'bold');
                text.textContent = '⚠';
                interferenceLayer.appendChild(text);
              }
            }
          }
        }
      }

      // Draw AP icons
      filteredAps.forEach(function(ap) {
        var realIdx = rfAps.indexOf(ap);
        var isSelected = realIdx === selectedApIndex;
        var color = getChannelColor(ap);

        var g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('transform', 'translate(' + ap.x + ',' + ap.y + ')');
        g.setAttribute('style', 'cursor:pointer');
        g.setAttribute('onclick', 'selectAp(' + realIdx + ')');

        // AP circle background
        var bg = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        bg.setAttribute('r', isSelected ? '18' : '15');
        bg.setAttribute('fill', isSelected ? color : '#1f2937');
        bg.setAttribute('stroke', color);
        bg.setAttribute('stroke-width', isSelected ? '3' : '2');
        g.appendChild(bg);

        // WiFi icon
        var wifi = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        wifi.setAttribute('transform', 'scale(0.5) translate(-12,-12)');
        wifi.innerHTML = '<path d="M5 12.55a11 11 0 0 1 14.08 0" fill="none" stroke="' + (isSelected ? 'white' : color) + '" stroke-width="2"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0" fill="none" stroke="' + (isSelected ? 'white' : color) + '" stroke-width="2"/><circle cx="12" cy="20" r="1" fill="' + (isSelected ? 'white' : color) + '"/>';
        g.appendChild(wifi);

        // AP name label
        var label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        label.setAttribute('y', '30');
        label.setAttribute('text-anchor', 'middle');
        label.setAttribute('fill', 'var(--foreground)');
        label.setAttribute('font-size', '10');
        label.setAttribute('font-weight', '500');
        label.textContent = ap.name;
        g.appendChild(label);

        // Channel badge
        var badge = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        badge.setAttribute('transform', 'translate(12,-12)');
        var badgeBg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
        badgeBg.setAttribute('x', '-10');
        badgeBg.setAttribute('y', '-8');
        badgeBg.setAttribute('width', '20');
        badgeBg.setAttribute('height', '16');
        badgeBg.setAttribute('rx', '4');
        badgeBg.setAttribute('fill', color);
        badge.appendChild(badgeBg);
        var badgeText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        badgeText.setAttribute('text-anchor', 'middle');
        badgeText.setAttribute('y', '4');
        badgeText.setAttribute('fill', 'white');
        badgeText.setAttribute('font-size', '9');
        badgeText.setAttribute('font-weight', '600');
        badgeText.textContent = ap.channel.replace('e', '');
        badge.appendChild(badgeText);
        g.appendChild(badge);

        apLayer.appendChild(g);
      });

      // Update stats
      document.getElementById('rf-stat-aps').textContent = filteredAps.length;

      // Calculate coverage percentage (rough estimate based on canvas)
      var canvas = document.getElementById('rf-canvas');
      var canvasArea = canvas.clientWidth * canvas.clientHeight;
      var coverageArea = 0;
      filteredAps.forEach(function(ap) {
        var r = getCoverageRadius(ap);
        coverageArea += Math.PI * r * r;
      });
      var coveragePercent = Math.min(100, Math.round((coverageArea / canvasArea) * 100));
      document.getElementById('rf-stat-coverage').textContent = coveragePercent + '%';

      // Count interference zones
      var interferenceCount = 0;
      for (var i = 0; i < filteredAps.length; i++) {
        for (var j = i + 1; j < filteredAps.length; j++) {
          if (filteredAps[i].channel === filteredAps[j].channel && filteredAps[i].band === filteredAps[j].band) {
            var dist = Math.sqrt(Math.pow(filteredAps[i].x - filteredAps[j].x, 2) + Math.pow(filteredAps[i].y - filteredAps[j].y, 2));
            var r1 = getCoverageRadius(filteredAps[i]);
            var r2 = getCoverageRadius(filteredAps[j]);
            if (dist < r1 + r2) interferenceCount++;
          }
        }
      }
      var interferenceEl = document.getElementById('rf-stat-interference');
      if (interferenceCount === 0) {
        interferenceEl.textContent = 'None';
        interferenceEl.style.color = '#22c55e';
      } else {
        interferenceEl.textContent = interferenceCount + ' zone' + (interferenceCount > 1 ? 's' : '');
        interferenceEl.style.color = '#ef4444';
      }

      // Update AP list
      var listHtml = '';
      if (rfAps.length === 0) {
        listHtml = '<div style="text-align:center;padding:30px;color:var(--foreground-muted);font-size:12px">Click on the canvas to place APs</div>';
      } else {
        rfAps.forEach(function(ap, idx) {
          var color = getChannelColor(ap);
          var isSelected = idx === selectedApIndex;
          listHtml += '<div onclick="selectAp(' + idx + ')" style="padding:10px;background:' + (isSelected ? 'rgba(139,92,246,0.2)' : 'rgba(255,255,255,0.02)') + ';border:1px solid ' + (isSelected ? 'var(--primary)' : 'var(--border)') + ';border-radius:6px;cursor:pointer">';
          listHtml += '<div style="display:flex;align-items:center;gap:10px">';
          listHtml += '<div style="width:32px;height:32px;background:' + color + ';border-radius:6px;display:flex;align-items:center;justify-content:center">';
          listHtml += '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><circle cx="12" cy="20" r="1" fill="white"/></svg>';
          listHtml += '</div>';
          listHtml += '<div style="flex:1">';
          listHtml += '<div style="font-size:12px;font-weight:500">' + ap.name + '</div>';
          listHtml += '<div style="font-size:10px;color:var(--foreground-muted)">' + ap.band + 'GHz · Ch ' + ap.channel.replace('e', ' (6E)') + ' · ' + ap.power + 'dBm</div>';
          listHtml += '</div>';
          listHtml += '</div></div>';
        });
      }
      document.getElementById('rf-ap-list').innerHTML = listHtml;
    }

    function exportRfPlan() {
      var plan = {
        aps: rfAps,
        exportDate: new Date().toISOString(),
        version: '1.0'
      };
      var dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(plan, null, 2));
      var downloadEl = document.createElement('a');
      downloadEl.setAttribute('href', dataStr);
      downloadEl.setAttribute('download', 'rf-plan-' + Date.now() + '.json');
      document.body.appendChild(downloadEl);
      downloadEl.click();
      downloadEl.remove();
      showToast('RF Plan exported');
    }

    // Initialize RF Visualizer when view is shown
    function initRfVisualizer() {
      updateRfVisualization();
    }

    // PSIRT Advisory Functions
    let psirtAdvisories = [
      {
        id: 'SA-2025-001',
        title: 'ExtremeCloud IQ Authentication Bypass Vulnerability',
        cve: 'CVE-2025-0001',
        severity: 'Critical',
        cvss: 9.8,
        affected: 'ExtremeCloud IQ versions prior to 24.6.1',
        published: '2025-01-15',
        status: 'Patch Available',
        description: 'A vulnerability in the authentication mechanism could allow an unauthenticated attacker to bypass authentication controls.',
        link: 'https://extreme-networks.my.site.com/ExtrSearch#q=CVE-2025-0001',
        // Matching criteria for inventory scan
        matchCriteria: {
          productPatterns: ['XIQ', 'Cloud IQ'],
          versionCheck: function(v) { return false; } // Cloud service - N/A for device scan
        }
      },
      {
        id: 'SA-2025-002',
        title: 'EXOS Stack Buffer Overflow in CLI Parser',
        cve: 'CVE-2025-0023',
        severity: 'High',
        cvss: 8.1,
        affected: 'EXOS versions 31.x and 32.x before 32.4.1',
        published: '2025-01-20',
        status: 'Patch Available',
        description: 'A stack-based buffer overflow vulnerability in the CLI parser could allow an authenticated attacker to execute arbitrary code.',
        link: 'https://extreme-networks.my.site.com/ExtrSearch#q=CVE-2025-0023',
        matchCriteria: {
          productPatterns: ['X435', 'X440', 'X450', 'X460', 'X465', 'X590', 'X620', 'X690', 'X695', 'X870', 'EXOS', '5320', '5420', '5520'],
          versionCheck: function(v) {
            if (!v) return false;
            var match = v.match(/(\\d+)\\.(\\d+)/);
            if (!match) return false;
            var major = parseInt(match[1]);
            var minor = parseInt(match[2]);
            return (major === 31) || (major === 32 && minor < 4);
          }
        }
      },
      {
        id: 'SA-2025-003',
        title: 'Fabric Engine RADIUS Server Certificate Validation',
        cve: 'CVE-2025-0045',
        severity: 'Medium',
        cvss: 5.9,
        affected: 'Fabric Engine 8.x before 8.10.2',
        published: '2025-01-28',
        status: 'Investigating',
        description: 'Improper certificate validation when connecting to RADIUS servers could allow man-in-the-middle attacks.',
        link: 'https://extreme-networks.my.site.com/ExtrSearch#q=CVE-2025-0045',
        matchCriteria: {
          productPatterns: ['5420', '5520', 'FabricEngine', 'Fabric Engine', 'VSP'],
          versionCheck: function(v) {
            if (!v) return false;
            var match = v.match(/(\\d+)\\.(\\d+)\\.(\\d+)/);
            if (!match) return false;
            var major = parseInt(match[1]);
            var minor = parseInt(match[2]);
            var patch = parseInt(match[3]);
            return major === 8 && (minor < 10 || (minor === 10 && patch < 2));
          }
        }
      },
      {
        id: 'SA-2024-089',
        title: 'AP4000 Series Firmware Update Signature Bypass',
        cve: 'CVE-2024-8912',
        severity: 'High',
        cvss: 7.5,
        affected: 'AP4000 series firmware before 11.2.3',
        published: '2024-12-10',
        status: 'Patch Available',
        description: 'A vulnerability in firmware signature verification could allow installation of malicious firmware.',
        link: 'https://extreme-networks.my.site.com/ExtrSearch#q=CVE-2024-8912',
        matchCriteria: {
          productPatterns: ['AP4000', 'AP-4000', 'AP_4000'],
          versionCheck: function(v) {
            if (!v) return false;
            var match = v.match(/(\\d+)\\.(\\d+)\\.(\\d+)/);
            if (!match) return false;
            var major = parseInt(match[1]);
            var minor = parseInt(match[2]);
            var patch = parseInt(match[3]);
            return major < 11 || (major === 11 && (minor < 2 || (minor === 2 && patch < 3)));
          }
        }
      },
      {
        id: 'SA-2024-078',
        title: 'XIQ Site Engine Remote Code Execution',
        cve: 'CVE-2024-7823',
        severity: 'Critical',
        cvss: 9.1,
        affected: 'XIQ Site Engine versions before 24.1.2',
        published: '2024-11-22',
        status: 'Patch Available',
        description: 'A deserialization vulnerability could allow remote code execution by an authenticated administrator.',
        link: 'https://extreme-networks.my.site.com/ExtrSearch#q=CVE-2024-7823',
        matchCriteria: {
          productPatterns: ['Site Engine', 'XIQ-SE'],
          versionCheck: function(v) { return false; } // Server software - N/A for device scan
        }
      },
      {
        id: 'SA-2024-067',
        title: 'AP3000/AP5000 Series WPA3 Implementation Flaw',
        cve: 'CVE-2024-6734',
        severity: 'High',
        cvss: 7.8,
        affected: 'AP3000/AP5000 series firmware before 10.6.2',
        published: '2024-10-15',
        status: 'Patch Available',
        description: 'A flaw in the WPA3-SAE implementation could allow an attacker within wireless range to cause a denial of service.',
        link: 'https://extreme-networks.my.site.com/ExtrSearch#q=CVE-2024-6734',
        matchCriteria: {
          productPatterns: ['AP3000', 'AP-3000', 'AP_3000', 'AP5000', 'AP-5000', 'AP_5000', 'AP_5010', 'AP_5020', 'AP302', 'AP305', 'AP360', 'AP410', 'AP460', 'AP_460'],
          versionCheck: function(v) {
            if (!v) return false;
            var match = v.match(/(\\d+)\\.(\\d+)\\.(\\d+)/);
            if (!match) return false;
            var major = parseInt(match[1]);
            var minor = parseInt(match[2]);
            var patch = parseInt(match[3]);
            return major < 10 || (major === 10 && (minor < 6 || (minor === 6 && patch < 2)));
          }
        }
      }
    ];

    // Store scanned inventory results
    var psirtInventoryScan = {
      devices: [],
      lastScan: null,
      affectedDevices: []
    };

    async function loadPsirtAdvisories() {
      // First render advisories, then scan inventory
      renderPsirtAdvisories();
      await scanInventoryForCves();
    }

    async function refreshPsirtAdvisories() {
      const list = document.getElementById('psirt-advisories-list');
      const scanResults = document.getElementById('psirt-scan-results');

      list.innerHTML = '<div style="text-align:center;padding:40px;color:var(--foreground-muted)"><div class="loading-spinner" style="margin:0 auto 16px"></div><div>Scanning inventory for vulnerabilities...</div></div>';
      if (scanResults) scanResults.innerHTML = '';

      // Re-scan inventory
      psirtInventoryScan.devices = [];
      psirtInventoryScan.affectedDevices = [];

      await scanInventoryForCves();
      renderPsirtAdvisories();
    }

    async function scanInventoryForCves() {
      try {
        // Fetch XIQ devices
        var xiqRes = await fetch('/api/xiq/devices');
        var xiqData = await xiqRes.json();
        var xiqDevices = (xiqData && xiqData.data) ? xiqData.data : [];

        // Also try Meraki devices
        var merakiDevices = [];
        try {
          var orgsRes = await fetch('/api/organizations');
          var orgs = await orgsRes.json();
          if (orgs && orgs.length > 0) {
            var devRes = await fetch('/api/organizations/' + orgs[0].id + '/devices');
            merakiDevices = await devRes.json() || [];
          }
        } catch (e) {
          console.log('Meraki devices not available');
        }

        // Combine devices
        psirtInventoryScan.devices = [
          ...xiqDevices.map(function(d) {
            return {
              source: 'XIQ',
              name: d.hostname || d.serial_number,
              model: d.product_type,
              version: d.software_version,
              ip: d.ip_address,
              serial: d.serial_number
            };
          }),
          ...merakiDevices.map(function(d) {
            return {
              source: 'Meraki',
              name: d.name || d.serial,
              model: d.model,
              version: d.firmware,
              ip: d.lanIp,
              serial: d.serial
            };
          })
        ];

        psirtInventoryScan.lastScan = new Date();

        // Scan for matches
        psirtInventoryScan.affectedDevices = [];

        psirtInventoryScan.devices.forEach(function(device) {
          psirtAdvisories.forEach(function(advisory) {
            if (!advisory.matchCriteria) return;

            var productMatch = false;
            var versionMatch = false;

            // Check product patterns
            if (advisory.matchCriteria.productPatterns) {
              var deviceStr = (device.model || '') + ' ' + (device.name || '');
              advisory.matchCriteria.productPatterns.forEach(function(pattern) {
                if (deviceStr.toLowerCase().indexOf(pattern.toLowerCase()) !== -1) {
                  productMatch = true;
                }
              });
            }

            // Check version
            if (productMatch && advisory.matchCriteria.versionCheck) {
              versionMatch = advisory.matchCriteria.versionCheck(device.version);
            }

            if (productMatch && versionMatch) {
              psirtInventoryScan.affectedDevices.push({
                device: device,
                advisory: advisory
              });
            }
          });
        });

        renderPsirtScanResults();

      } catch (e) {
        console.error('Failed to scan inventory:', e);
      }
    }

    function renderPsirtScanResults() {
      var container = document.getElementById('psirt-scan-results');
      if (!container) return;

      var affected = psirtInventoryScan.affectedDevices;
      var totalDevices = psirtInventoryScan.devices.length;

      if (totalDevices === 0) {
        container.innerHTML = '<div style="padding:20px;background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.3);border-radius:8px">' +
          '<div style="display:flex;align-items:center;gap:12px">' +
          '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>' +
          '<div><div style="font-weight:600;color:#3b82f6">No Inventory Data</div>' +
          '<div style="font-size:12px;color:var(--foreground-muted)">Connect to XIQ or add devices to scan for vulnerabilities</div></div>' +
          '</div></div>';
        return;
      }

      if (affected.length === 0) {
        container.innerHTML = '<div style="padding:20px;background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:8px">' +
          '<div style="display:flex;align-items:center;gap:12px">' +
          '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>' +
          '<div><div style="font-weight:600;color:#22c55e">No Vulnerabilities Detected</div>' +
          '<div style="font-size:12px;color:var(--foreground-muted)">Scanned ' + totalDevices + ' devices - all clear!</div></div>' +
          '</div></div>';
        return;
      }

      // Group by advisory
      var byAdvisory = {};
      affected.forEach(function(item) {
        if (!byAdvisory[item.advisory.cve]) {
          byAdvisory[item.advisory.cve] = {
            advisory: item.advisory,
            devices: []
          };
        }
        byAdvisory[item.advisory.cve].devices.push(item.device);
      });

      var html = '<div style="padding:16px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:8px">';
      html += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">';
      html += '<div style="display:flex;align-items:center;gap:12px">';
      html += '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
      html += '<div><div style="font-weight:600;color:#ef4444">Vulnerable Devices Detected!</div>';
      html += '<div style="font-size:12px;color:var(--foreground-muted)">' + affected.length + ' device(s) affected across ' + Object.keys(byAdvisory).length + ' CVE(s)</div></div>';
      html += '</div>';
      html += '<span style="padding:6px 12px;background:#ef4444;color:white;border-radius:20px;font-size:12px;font-weight:600">' + affected.length + ' AFFECTED</span>';
      html += '</div>';

      Object.keys(byAdvisory).forEach(function(cve) {
        var item = byAdvisory[cve];
        var colors = {
          'Critical': '#ef4444',
          'High': '#f97316',
          'Medium': '#eab308'
        };
        var color = colors[item.advisory.severity] || '#eab308';

        html += '<div style="background:var(--surface);border-radius:6px;padding:12px;margin-bottom:8px">';
        html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">';
        html += '<span style="padding:2px 8px;background:' + color + ';color:white;border-radius:4px;font-size:10px;font-weight:600">' + item.advisory.severity.toUpperCase() + '</span>';
        html += '<span style="font-size:12px;font-weight:600;color:' + color + '">' + cve + '</span>';
        html += '<span style="font-size:11px;color:var(--foreground-muted)">- ' + item.advisory.title + '</span>';
        html += '</div>';
        html += '<div style="font-size:11px;color:var(--foreground-muted);margin-bottom:8px">' + item.advisory.affected + '</div>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:6px">';
        item.devices.forEach(function(dev) {
          html += '<div style="padding:6px 10px;background:rgba(255,255,255,0.05);border:1px solid ' + color + ';border-radius:4px;font-size:11px">';
          html += '<div style="font-weight:500">' + dev.name + '</div>';
          html += '<div style="color:var(--foreground-muted);font-size:10px">' + dev.model + ' · v' + (dev.version || 'unknown') + '</div>';
          html += '</div>';
        });
        html += '</div>';
        html += '</div>';
      });

      html += '<div style="font-size:11px;color:var(--foreground-muted);margin-top:12px">Last scan: ' + psirtInventoryScan.lastScan.toLocaleString() + ' · ' + totalDevices + ' devices scanned</div>';
      html += '</div>';

      container.innerHTML = html;
    }

    function renderPsirtAdvisories() {
      const list = document.getElementById('psirt-advisories-list');
      const badge = document.getElementById('psirt-count-badge');

      const critical = psirtAdvisories.filter(a => a.severity === 'Critical').length;
      const high = psirtAdvisories.filter(a => a.severity === 'High').length;
      badge.textContent = critical + ' Critical, ' + high + ' High';

      list.innerHTML = psirtAdvisories.map(advisory => {
        const severityColors = {
          'Critical': { bg: 'rgba(239,68,68,0.15)', text: '#ef4444', border: '#ef4444' },
          'High': { bg: 'rgba(249,115,22,0.15)', text: '#f97316', border: '#f97316' },
          'Medium': { bg: 'rgba(234,179,8,0.15)', text: '#eab308', border: '#eab308' },
          'Low': { bg: 'rgba(34,197,94,0.15)', text: '#22c55e', border: '#22c55e' }
        };
        const colors = severityColors[advisory.severity] || severityColors['Medium'];
        const statusColor = advisory.status === 'Patch Available' ? '#22c55e' : advisory.status === 'Investigating' ? '#f97316' : '#eab308';

        // Check if any devices are affected by this advisory
        var affectedCount = psirtInventoryScan.affectedDevices.filter(function(a) { return a.advisory.cve === advisory.cve; }).length;
        var affectedBadge = affectedCount > 0 ? '<span style="padding:4px 8px;background:#ef4444;color:white;border-radius:4px;font-size:10px;font-weight:600;animation:pulse 2s infinite">' + affectedCount + ' DEVICE' + (affectedCount > 1 ? 'S' : '') + ' AFFECTED</span>' : '';

        return '<a href="' + advisory.link + '" target="_blank" style="display:block;padding:16px;background:var(--surface);border:1px solid ' + (affectedCount > 0 ? colors.border : 'var(--border)') + ';border-left:3px solid ' + colors.border + ';border-radius:8px;text-decoration:none;transition:all 0.2s;' + (affectedCount > 0 ? 'box-shadow:0 0 20px ' + colors.border + '40;' : '') + '">' +
          '<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px">' +
            '<div style="flex:1;min-width:0">' +
              '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap">' +
                '<span style="padding:4px 10px;background:' + colors.bg + ';color:' + colors.text + ';border-radius:4px;font-size:11px;font-weight:600">' + advisory.severity.toUpperCase() + '</span>' +
                '<span style="font-size:12px;color:var(--foreground-muted)">' + advisory.id + '</span>' +
                '<span style="font-size:12px;padding:4px 8px;background:rgba(124,58,237,0.15);color:#a78bfa;border-radius:4px">' + advisory.cve + '</span>' +
                '<span style="font-size:11px;color:' + statusColor + '">' + advisory.status + '</span>' +
                affectedBadge +
              '</div>' +
              '<div style="font-weight:600;color:var(--foreground);margin-bottom:6px">' + advisory.title + '</div>' +
              '<div style="font-size:12px;color:var(--foreground-muted);margin-bottom:8px">' + advisory.description + '</div>' +
              '<div style="display:flex;gap:16px;font-size:11px;color:var(--foreground-muted)">' +
                '<span><strong>CVSS:</strong> ' + advisory.cvss + '</span>' +
                '<span><strong>Affected:</strong> ' + advisory.affected + '</span>' +
                '<span><strong>Published:</strong> ' + advisory.published + '</span>' +
              '</div>' +
            '</div>' +
            '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--foreground-muted)" stroke-width="2" style="flex-shrink:0;margin-top:4px"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>' +
          '</div>' +
        '</a>';
      }).join('');
    }

    // App Launcher Functions
    function toggleAppLauncher(e) {
      if (e) e.stopPropagation();
      const menu = document.getElementById('app-launcher-menu');
      menu.classList.toggle('show');
    }

    function closeAppLauncher() {
      const menu = document.getElementById('app-launcher-menu');
      if (menu) menu.classList.remove('show');
    }

    function openIntegration(type) {
      closeAppLauncher();
      alert(type.charAt(0).toUpperCase() + type.slice(1) + ' integration settings coming soon!');
    }

    // Close app launcher when clicking outside
    document.addEventListener('click', function(e) {
      const menu = document.getElementById('app-launcher-menu');
      const launcher = document.querySelector('.app-launcher');
      if (menu && menu.classList.contains('show') && launcher && !launcher.contains(e.target)) {
        closeAppLauncher();
      }
    });

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

      // Helper to normalize MAC for lookups (remove colons, lowercase)
      function normalizeMac(mac) {
        return mac ? mac.replace(/:/g, '').toLowerCase() : null;
      }

      // Position switches (leftmost)
      switches.forEach((sw, i) => {
        const posData = {
          x: startX,
          y: currentY + (i * verticalSpacing * 2),
          node: sw,
          deviceType: 'switch'
        };
        nodePositions[sw.id] = posData;
        // Also store by serial and MAC for edge lookups
        if (sw.serial) nodePositions[sw.serial] = posData;
        if (sw.mac) {
          nodePositions[sw.mac] = posData;
          nodePositions[normalizeMac(sw.mac)] = posData;
        }
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

        const posData = {
          x: startX + tierSpacing,
          y: baseY + (i * verticalSpacing) - ((tier2Devices.length - 1) * verticalSpacing / 2),
          node: device,
          deviceType: deviceType
        };
        nodePositions[device.id] = posData;
        // Also store by serial and MAC for edge lookups
        if (device.serial) nodePositions[device.serial] = posData;
        if (device.mac) {
          nodePositions[device.mac] = posData;
          nodePositions[normalizeMac(device.mac)] = posData;
        }
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
          const posData = {
            x: startX + (i % 3) * tierSpacing,
            y: yPos + Math.floor(i / 3) * verticalSpacing,
            node: device,
            deviceType: deviceType
          };
          nodePositions[device.id] = posData;
          // Also store by serial and MAC for edge lookups
          if (device.serial) nodePositions[device.serial] = posData;
          if (device.mac) {
            nodePositions[device.mac] = posData;
            nodePositions[normalizeMac(device.mac)] = posData;
          }
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

          // Try multiple lookups: direct ID, serial, MAC with colons, MAC without colons
          const fromNorm = edge.from ? edge.from.replace(/:/g, '').toLowerCase() : '';
          const toNorm = edge.to ? edge.to.replace(/:/g, '').toLowerCase() : '';
          const source = nodePositions[edge.from] || nodePositions[fromNorm];
          const target = nodePositions[edge.to] || nodePositions[toNorm];
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
      // Use Set to avoid duplicates - track by client id
      const renderedClientIds = new Set();
      Object.entries(nodePositions).forEach(([id, pos]) => {
        if (!pos.isClient) return;
        const clientKey = pos.node.id || id;
        if (renderedClientIds.has(clientKey)) return;
        renderedClientIds.add(clientKey);

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
      // Use Set to avoid duplicates - track by node serial/id, not object reference
      const renderedNodeIds = new Set();

      Object.entries(nodePositions).forEach(([id, pos]) => {
        const node = pos.node;
        // Create unique key for this node
        const nodeKey = node.serial || node.id || id;
        if (renderedNodeIds.has(nodeKey)) return;
        renderedNodeIds.add(nodeKey);
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
            '<span style="font-size:12px;color:rgba(255,255,255,0.87)">' + esc(c.clientName || 'Unknown') + '</span>' +
            '<span style="font-size:11px;padding:2px 6px;border-radius:4px;background:#00BCD4;color:#000">' + c.totalRoams + ' roams</span>' +
            '</div>' +
            '<div style="font-size:11px;color:rgba(255,255,255,0.5);margin-top:2px;font-family:var(--font-mono)">' + esc(c.clientMac) + '</div>' +
            '<div style="font-size:10px;color:rgba(255,255,255,0.4);margin-top:2px">' + esc(c.manufacturer || '') + ' · ' + c.uniqueAPs + ' APs visited</div>' +
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
            '<span style="font-size:12px;color:rgba(255,255,255,0.87)">' + esc(f.clientName || 'Unknown') + '</span>' +
            '<span style="font-size:11px;padding:2px 6px;border-radius:4px;background:var(--destructive);color:#000">' + f.failureCount + ' fails</span>' +
            '</div>' +
            '<div style="font-size:11px;color:rgba(255,255,255,0.5);margin-top:2px;font-family:var(--font-mono)">' + esc(f.clientMac) + '</div>' +
            '<div style="font-size:10px;color:rgba(255,255,255,0.4);margin-top:2px">' + esc(f.manufacturer || '') + ' · ' + f.failureRate + '% failure rate</div>' +
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
            '<span style="font-size:12px;color:rgba(255,255,255,0.87)">' + esc(s.clientName || 'Unknown') + '</span>' +
            '<span style="font-size:11px;padding:2px 6px;border-radius:4px;background:var(--warning);color:#000">' + s.avgRssi + ' dBm</span>' +
            '</div>' +
            '<div style="font-size:11px;color:rgba(255,255,255,0.5);margin-top:2px;font-family:var(--font-mono)">' + esc(s.clientMac) + '</div>' +
            '<div style="font-size:10px;color:rgba(255,255,255,0.4);margin-top:2px">Stuck on: ' + esc(s.currentAP || 'Unknown') + '</div>' +
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
            '<span style="color:rgba(255,255,255,0.87)">' + esc(client.hostname || client.mac_address || 'Unknown') + '</span>' +
            '<span style="font-size:11px;color:rgba(255,255,255,0.5);margin-left:8px">' + esc(client.ip_address || '') + '</span>' +
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

    // ── Passkey Registration ──────────────────────────────────
    async function registerPasskey() {
      try {
        // Dynamically load SimpleWebAuthn browser bundle
        if (typeof SimpleWebAuthnBrowser === 'undefined') {
          await new Promise((resolve, reject) => {
            const s = document.createElement('script');
            s.src = 'https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js';
            s.onload = resolve;
            s.onerror = () => reject(new Error('Failed to load WebAuthn library'));
            document.head.appendChild(s);
          });
        }
        const optRes = await fetch('/webauthn/register/options');
        if (!optRes.ok) throw new Error((await optRes.json()).error || 'Failed to get options');
        const opts = await optRes.json();
        const regResp = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: opts });
        const verRes = await fetch('/webauthn/register/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(regResp),
        });
        const result = await verRes.json();
        if (result.verified) {
          showToast('Passkey registered!');
          showCredentialModal(result.credential);
        } else {
          showToast('Passkey registration failed.');
        }
      } catch (e) {
        if (e.name === 'NotAllowedError') return;
        showToast('Passkey error: ' + (e.message || 'Unknown error'));
      }
    }

    function showCredentialModal(credentialStr) {
      var overlay = document.createElement('div');
      overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:10000;display:flex;align-items:center;justify-content:center;padding:20px';
      var card = document.createElement('div');
      card.style.cssText = 'background:#161b22;border:1px solid #30363d;border-radius:12px;padding:24px;max-width:520px;width:100%';
      var h = document.createElement('h3');
      h.textContent = 'Passkey Registered';
      h.style.cssText = 'color:#e6edf3;font-size:16px;margin-bottom:4px';
      var p = document.createElement('p');
      p.style.cssText = 'color:#8b949e;font-size:13px;margin-bottom:16px';
      p.innerHTML = 'To persist across deploys, add this as <code style="background:#0d1117;padding:2px 6px;border-radius:4px;color:#a78bfa">WEBAUTHN_CREDENTIAL</code> in your Railway environment variables.';
      var ta = document.createElement('textarea');
      ta.readOnly = true;
      ta.value = credentialStr;
      ta.style.cssText = 'width:100%;height:100px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-family:monospace;font-size:11px;padding:10px;resize:none;margin-bottom:12px';
      var btnRow = document.createElement('div');
      btnRow.style.cssText = 'display:flex;gap:8px;justify-content:flex-end';
      var copyBtn = document.createElement('button');
      copyBtn.textContent = 'Copy';
      copyBtn.style.cssText = 'padding:8px 16px;background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;border:none;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer';
      copyBtn.addEventListener('click', function() {
        navigator.clipboard.writeText(ta.value);
        copyBtn.textContent = 'Copied!';
        setTimeout(function() { copyBtn.textContent = 'Copy'; }, 2000);
      });
      var closeBtn = document.createElement('button');
      closeBtn.textContent = 'Close';
      closeBtn.style.cssText = 'padding:8px 16px;background:transparent;color:#8b949e;border:1px solid #30363d;border-radius:6px;font-size:13px;cursor:pointer';
      closeBtn.addEventListener('click', function() { overlay.remove(); });
      btnRow.appendChild(copyBtn);
      btnRow.appendChild(closeBtn);
      card.appendChild(h);
      card.appendChild(p);
      card.appendChild(ta);
      card.appendChild(btnRow);
      overlay.appendChild(card);
      document.body.appendChild(overlay);
      overlay.addEventListener('click', function(e) { if (e.target === overlay) overlay.remove(); });
    }

    // ── Auto-logout after 2 minutes of inactivity ──
    (function() {
      var IDLE_MS = 2 * 60 * 1000;
      var WARN_MS = 30 * 1000;
      var idleTimer, warnTimer, warnOverlay;

      function resetTimers() {
        clearTimeout(idleTimer);
        clearTimeout(warnTimer);
        dismissWarning();
        warnTimer = setTimeout(showWarning, IDLE_MS - WARN_MS);
        idleTimer = setTimeout(doLogout, IDLE_MS);
      }

      function doLogout() { window.location.href = '/logout'; }

      function showWarning() {
        if (warnOverlay) return;
        warnOverlay = document.createElement('div');
        warnOverlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:100000';
        var card = document.createElement('div');
        card.style.cssText = 'background:#161b22;border:1px solid #30363d;border-radius:12px;padding:32px;max-width:380px;width:90%;text-align:center;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif';
        var h = document.createElement('h2');
        h.textContent = 'Session Expiring';
        h.style.cssText = 'margin:0 0 12px;font-size:20px;color:#f0f6fc';
        var p = document.createElement('p');
        p.textContent = 'You will be signed out in 30 seconds due to inactivity.';
        p.style.cssText = 'margin:0 0 24px;font-size:14px;color:#8b949e;line-height:1.5';
        var stayBtn = document.createElement('button');
        stayBtn.textContent = 'Stay Signed In';
        stayBtn.style.cssText = 'display:block;width:100%;padding:10px 16px;background:#8b5cf6;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;margin-bottom:12px';
        stayBtn.addEventListener('click', function() { resetTimers(); });
        var signOutLink = document.createElement('a');
        signOutLink.textContent = 'Sign Out Now';
        signOutLink.href = '#';
        signOutLink.style.cssText = 'color:#8b949e;font-size:13px;text-decoration:none';
        signOutLink.addEventListener('click', function(e) { e.preventDefault(); doLogout(); });
        card.appendChild(h);
        card.appendChild(p);
        card.appendChild(stayBtn);
        card.appendChild(signOutLink);
        warnOverlay.appendChild(card);
        document.body.appendChild(warnOverlay);
      }

      function dismissWarning() {
        if (warnOverlay) { warnOverlay.remove(); warnOverlay = null; }
      }

      ['mousemove','mousedown','keydown','scroll','touchstart'].forEach(function(evt) {
        document.addEventListener(evt, resetTimers, { passive: true });
      });

      resetTimers();
    })();
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

