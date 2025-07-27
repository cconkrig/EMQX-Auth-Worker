import bcrypt from "bcryptjs";
import { SignJWT, jwtVerify } from 'jose';

// CORS and security headers - dynamically set based on origin
function getCorsHeaders(origin) {
  // Allow specific cyber-comp.cc subdomains
  const allowedOrigins = [
    'https://msgwrk-qt4g0063hh.cyber-comp.cc'
  ];
  
  // STRICT: Require origin header and validate it
  if (!origin) {
    // No origin header - block the request
    return {
      "Access-Control-Allow-Origin": "",
      "Access-Control-Allow-Methods": "",
      "Access-Control-Allow-Headers": "",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    };
  }
  
  // Check if origin is allowed
  const isAllowed = allowedOrigins.includes(origin);
  
  return {
    "Access-Control-Allow-Origin": isAllowed ? origin : "",
    "Access-Control-Allow-Methods": isAllowed ? "POST, OPTIONS" : "",
    "Access-Control-Allow-Headers": isAllowed ? "Content-Type, Authorization" : "",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
  };
}

// Admin UI security headers - allows SvelteKit to run
const adminHeaders = {
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self';",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
};

function jsonResponse(body, status = 200, origin = null) {
  const corsHeaders = origin ? getCorsHeaders(origin) : getCorsHeaders("");
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders,
    },
  });
}

// Simple in-memory rate limiter (per IP, 10 failed req/min, max 10,000 IPs)
const RATE_LIMIT = 10;
const RATE_WINDOW = 60 * 1000; // 1 minute
const MAX_IPS = 10000;
const ipRateMap = new Map();

function cleanupRateLimitMap() {
  const now = Date.now();
  // Remove expired entries
  for (const [ip, entry] of ipRateMap.entries()) {
    if (now - entry.start > RATE_WINDOW) {
      ipRateMap.delete(ip);
    }
  }
  // Enforce hard cap
  if (ipRateMap.size > MAX_IPS) {
    // Evict oldest entries
    const keys = Array.from(ipRateMap.keys());
    const toDelete = ipRateMap.size - MAX_IPS;
    for (let i = 0; i < toDelete; i++) {
      ipRateMap.delete(keys[i]);
    }
  }
}

function getRateLimitEntry(ip) {
  const now = Date.now();
  let entry = ipRateMap.get(ip);
  if (!entry || now - entry.start > RATE_WINDOW) {
    entry = { count: 0, start: now };
  }
  ipRateMap.set(ip, entry);
  return entry;
}
function incrementRateLimit(ip) {
  const entry = getRateLimitEntry(ip);
  entry.count++;
  ipRateMap.set(ip, entry);
}
function isRateLimited(ip) {
  const entry = getRateLimitEntry(ip);
  return entry.count >= RATE_LIMIT;
}

function validateUsername(username) {
  return (
    typeof username === "string" &&
    username.length >= 3 &&
    username.length <= 64 &&
    /^[A-Za-z0-9_\-]+$/.test(username)
  );
}
function validatePassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 8 &&
    password.length <= 128
  );
}
function validateAction(action) {
  return action === "publish" || action === "subscribe";
}
function validateTopic(topic) {
  return (
    typeof topic === "string" &&
    topic.length > 0 &&
    topic.length <= 256 &&
    /^[^\u0000-\u001F\u007F]+$/.test(topic)
  );
}

function getJwtFromRequest(request) {
  const auth = request.headers.get("Authorization") || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

async function requireAdmin(request, env) {
  const token = getJwtFromRequest(request);
  if (!token) return null;
  try {
    const secret = new TextEncoder().encode(env.JWT_SECRET);
    const { payload } = await jwtVerify(token, secret);
    if (payload.roles && payload.roles.includes("admin")) return payload;
    return null;
  } catch {
    return null;
  }
}

async function handleAdminApi(request, env) {
  const url = new URL(request.url);
  const origin = request.headers.get("Origin");

  // SECURITY: Block requests without valid origin header
  const allowedOrigins = ['https://msgwrk-qt4g0063hh.cyber-comp.cc'];
  if (!origin || !allowedOrigins.includes(origin)) {
    return new Response("Forbidden", { 
      status: 403,
      headers: {
        "Content-Type": "text/plain",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
      }
    });
  }

  // Bootstrap endpoint - creates first admin user if none exists
  if (url.pathname === "/admin/api/bootstrap" && request.method === "POST") {
    try {
      // Check if any admin users exist
      const adminList = await env.USERS.list({ prefix: "admin:" });
      if (adminList.keys.length > 0) {
        return jsonResponse({ error: "Not Allowed" }, 400, origin);
      }

      const { username, password } = await request.json();
      if (!username || !password) {
        return jsonResponse({ error: "Missing username or password" }, 400, origin);
      }

      // Validate username and password
      if (!validateUsername(username) || !validatePassword(password)) {
        return jsonResponse({ error: "Invalid username or password format" }, 400, origin);
      }

      // Create admin user
      const hash = await bcrypt.hash(password, 12);
      const adminObj = { 
        password_hash: hash, 
        roles: ["admin"],
        created_at: new Date().toISOString()
      };
      await env.USERS.put(`admin:${username}`, JSON.stringify(adminObj));
      
      console.log(`[BOOTSTRAP] Created first admin user: ${username}`);
      return jsonResponse({ success: true, message: "Admin user created successfully" }, 200, origin);
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error creating admin user' }, 500, origin);
    }
  }

  // All other endpoints require admin JWT
  if (url.pathname.endsWith("/admin/api/login") && request.method === "POST") {
    const { username, password } = await request.json();
    if (!username || !password) {
      return jsonResponse({ error: "Missing credentials" }, 400, origin);
    }
    const adminRaw = await env.USERS.get(`admin:${username}`);
    if (!adminRaw) {
      return jsonResponse({ error: "Invalid credentials" }, 401, origin);
    }
    let admin;
    try {
      admin = JSON.parse(adminRaw);
    } catch {
      return jsonResponse({ error: "Corrupt admin data" }, 500, origin);
    }
    const ok = await bcrypt.compare(password, admin.password_hash);
    if (!ok) {
      return jsonResponse({ error: "Invalid credentials" }, 401, origin);
    }
    const secret = new TextEncoder().encode(env.JWT_SECRET);
    const token = await new SignJWT({ username, roles: admin.roles || [] })
      .setProtectedHeader({ alg: 'HS256' })
      .setExpirationTime('1h')
      .sign(secret);
    return jsonResponse({ token }, 200, origin);
  }

  const admin = await requireAdmin(request, env);
  if (!admin) return jsonResponse({ error: "Unauthorized" }, 401, origin);

  // Audit log helper
  function audit(action, target) {
    console.log(`[AUDIT] admin=${admin.username} action=${action} target=${target || ''}`);
  }

  if (url.pathname === "/admin/api/user" && request.method === "POST") {
    try {
      const { username, password, acls } = await request.json();
      if (!username || !password) return jsonResponse({ error: "Missing username or password" }, 400, origin);
      const hash = await bcrypt.hash(password, 12);
      const userObj = { password_hash: hash, acls: Array.isArray(acls) ? acls : [] };
      await env.USERS.put(`user:${username}`, JSON.stringify(userObj));
      audit('create_or_update_user', username);
      return jsonResponse({ success: true }, 200, origin);
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error creating/updating user' }, 500, origin);
    }
  }
  if (url.pathname === "/admin/api/user" && request.method === "DELETE") {
    try {
      const { username } = await request.json();
      if (!username) return jsonResponse({ error: "Missing username" }, 400, origin);
      await env.USERS.delete(`user:${username}`);
      audit('delete_user', username);
      return jsonResponse({ success: true }, 200, origin);
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error deleting user' }, 500, origin);
    }
  }
  if (url.pathname === "/admin/api/acl" && request.method === "POST") {
    try {
      const { username, acls } = await request.json();
      if (!username || !Array.isArray(acls)) return jsonResponse({ error: "Missing username or acls" }, 400, origin);
      const userRaw = await env.USERS.get(`user:${username}`);
      if (!userRaw) return jsonResponse({ error: "User not found" }, 404, origin);
      let user;
      try { user = JSON.parse(userRaw); } catch { return jsonResponse({ error: "Corrupt user data" }, 500, origin); }
      user.acls = acls;
      await env.USERS.put(`user:${username}`, JSON.stringify(user));
      audit('update_acls', username);
      return jsonResponse({ success: true }, 200, origin);
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error updating ACLs' }, 500, origin);
    }
  }
  if (url.pathname === "/admin/api/user-acls" && request.method === "PUT") {
    try {
      const { username, acls } = await request.json();
      if (!username || !Array.isArray(acls)) return jsonResponse({ error: "Missing username or acls" }, 400, origin);
      const userRaw = await env.USERS.get(`user:${username}`);
      if (!userRaw) return jsonResponse({ error: "User not found" }, 404, origin);
      let user;
      try { user = JSON.parse(userRaw); } catch { return jsonResponse({ error: "Corrupt user data" }, 500, origin); }
      user.acls = acls;
      await env.USERS.put(`user:${username}`, JSON.stringify(user));
      audit('update_acls', username);
      return jsonResponse({ success: true }, 200, origin);
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error updating ACLs' }, 500, origin);
    }
  }
  if (url.pathname === "/admin/api/users" && request.method === "GET") {
    try {
      const list = await env.USERS.list({ prefix: "user:" });
      const usernames = list.keys.map(k => k.name.slice(5));
      return jsonResponse({ users: usernames }, 200, origin);
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error listing users' }, 500, origin);
    }
  }
  if (url.pathname === "/admin/api/user-details" && request.method === "GET") {
    try {
      const username = url.searchParams.get('username');
      if (!username) return jsonResponse({ error: "Missing username" }, 400, origin);
      const userRaw = await env.USERS.get(`user:${username}`);
      if (!userRaw) return jsonResponse({ error: "User not found" }, 404, origin);
      let user;
      try { user = JSON.parse(userRaw); } catch { return jsonResponse({ error: "Corrupt user data" }, 500, origin); }
      return jsonResponse({ username, acls: user.acls || [] }, 200, origin);
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error fetching user details' }, 500, origin);
    }
  }
  const corsHeaders = getCorsHeaders(origin);
  return new Response("Not found", { status: 404, headers: corsHeaders });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    // Cleanup rate limiter map
    cleanupRateLimitMap();

    // Handle admin API (POST/GET as needed) - must come before static file handling
    if (url.pathname.startsWith("/admin/api")) {
      return await handleAdminApi(request, env);
    }

    // Serve static admin UI for GET requests to /admin and /admin/* using ASSETS binding
    if (
      (url.pathname === "/admin" || url.pathname.startsWith("/admin/")) &&
      request.method === "GET"
    ) {
      // Try to serve the specific file first
      let response = await env.ASSETS.fetch(request);
      
      // If the file exists, serve it directly
      if (response.status === 200) {
        const contentType = response.headers.get('content-type');
        // For non-HTML files (static assets), serve without admin headers
        if (contentType && !contentType.includes('text/html')) {
          return response;
        }
        // For HTML files, add admin headers
        const newHeaders = new Headers(response.headers);
        Object.entries(adminHeaders).forEach(([key, value]) => {
          newHeaders.set(key, value);
        });
        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: newHeaders,
        });
      }
      
      // If the file doesn't exist (404), serve index.html for SPA routing
      if (response.status === 404) {
        const indexRequest = new Request(new URL('/admin/index.html', request.url), {
          method: 'GET',
          headers: request.headers
        });
        response = await env.ASSETS.fetch(indexRequest);
        
        // Add admin headers to the SPA response
        const newHeaders = new Headers(response.headers);
        Object.entries(adminHeaders).forEach(([key, value]) => {
          newHeaders.set(key, value);
        });
        
        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: newHeaders,
        });
      }
      
      // For any other status, return as-is
      return response;
    }

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      const origin = request.headers.get("Origin");
      const corsHeaders = getCorsHeaders(origin);
      return new Response(null, { headers: corsHeaders });
    }

    // Only allow POST and OPTIONS for /auth and /acl
    if (
      (url.pathname === "/auth" || url.pathname === "/acl") &&
      request.method !== "POST" &&
      request.method !== "OPTIONS"
    ) {
      const origin = request.headers.get("Origin");
      const corsHeaders = getCorsHeaders(origin);
      return new Response("Method Not Allowed", { status: 405, headers: corsHeaders });
    }

    // Require Bearer token for POST, except for /admin/api routes
    if (
      request.method === "POST" &&
      !url.pathname.startsWith("/admin/api")
    ) {
      const authHeader = request.headers.get("Authorization") || "";
      const expected = `Bearer ${env.API_KEY}`;
      if (!env.API_KEY || authHeader !== expected) {
        const origin = request.headers.get("Origin");
        const corsHeaders = getCorsHeaders(origin);
        return new Response("Unauthorized", { status: 401, headers: corsHeaders });
      }
    }

    // Check rate limit (only for failed requests, so check after processing)
    // Logging helper
    function log(msg, ...args) {
      console.log(`[${url.pathname}] ${msg}`, ...args);
    }

    try {
      const origin = request.headers.get("Origin");

      if (url.pathname === "/auth" && request.method === "POST") {
        if (isRateLimited(ip)) {
          return jsonResponse({ result: "deny", reason: "Rate limit exceeded" }, 429, origin);
        }
        const { username, password } = await request.json();
        log("Auth attempt for", username);

        if (!validateUsername(username) || !validatePassword(password)) {
          log("Invalid username or password format");
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny", reason: "Invalid credentials" }, 400, origin);
        }

        const userKey = `user:${username}`;
        const userRaw = await env.USERS.get(userKey);
        if (!userRaw) {
          log("Auth user not found, returning ignore for EMQX fallback");
          return jsonResponse({ result: "ignore" }, 200, origin);
        }

        let user;
        try {
          user = JSON.parse(userRaw);
        } catch (e) {
          log("Corrupt user data for", username);
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny" }, 200, origin);
        }

        const hash = user.password_hash;
        if (!hash) {
          log("No password hash for", username);
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny" }, 200, origin);
        }

        const ok = await bcrypt.compare(password, hash);
        log("Password check for", username, ok ? "OK" : "FAIL");
        if (!ok) {
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny" }, 200, origin);
        }
        return jsonResponse({ result: "allow" }, 200, origin);
      }

      if (url.pathname === "/acl" && request.method === "POST") {
        if (isRateLimited(ip)) {
          return jsonResponse({ result: "deny", reason: "Rate limit exceeded" }, 429, origin);
        }
        const { username, action, topic } = await request.json();
        log("ACL check for", username, action, topic);

        if (!validateUsername(username) || !validateAction(action) || !validateTopic(topic)) {
          log("Invalid ACL params");
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny", reason: "Invalid params" }, 400, origin);
        }

        const userKey = `user:${username}`;
        const userRaw = await env.USERS.get(userKey);
        if (!userRaw) {
          log("ACL failed for", username);
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny" }, 200, origin);
        }

        let user;
        try {
          user = JSON.parse(userRaw);
        } catch (e) {
          log("Corrupt user data for", username);
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny" }, 200, origin);
        }

        const acls = user.acls || [];
        const allowed = acls.some(
          (rule) =>
            rule.action === action &&
            topicMatches(rule.topic, topic)
        );
        log("ACL result for", username, allowed ? "ALLOW" : "DENY");
        if (!allowed) {
          incrementRateLimit(ip);
        }
        return jsonResponse({ result: allowed ? "allow" : "deny" }, 200, origin);
      }

      const corsHeaders = getCorsHeaders(origin);
      return new Response("Not found", { status: 404, headers: corsHeaders });
    } catch (err) {
      log("Internal error", err);
      incrementRateLimit(ip);
      return jsonResponse({ result: "deny" }, 500, origin);
    }
  },
};

// Robust MQTT topic matcher (supports #, +, and edge cases)
function topicMatches(pattern, topic) {
  const patternParts = pattern.split("/");
  const topicParts = topic.split("/");
  let i = 0;
  for (; i < patternParts.length; i++) {
    if (patternParts[i] === "#") return true;
    if (patternParts[i] === "+") {
      if (topicParts.length <= i) return false;
      continue;
    }
    if (topicParts[i] !== patternParts[i]) return false;
  }
  return i === topicParts.length;
} 