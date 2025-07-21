import bcrypt from "bcryptjs";

// CORS and security headers
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};

function jsonResponse(body, status = 200) {
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

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    // Cleanup rate limiter map
    cleanupRateLimitMap();

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // Only allow POST and OPTIONS
    if (request.method !== "POST" && request.method !== "OPTIONS") {
      return new Response("Method Not Allowed", { status: 405, headers: corsHeaders });
    }

    // Require Bearer token for POST
    if (request.method === "POST") {
      const authHeader = request.headers.get("Authorization") || "";
      const expected = `Bearer ${env.API_KEY}`;
      if (!env.API_KEY || authHeader !== expected) {
        return new Response("Unauthorized", { status: 401, headers: corsHeaders });
      }
    }

    // Check rate limit (only for failed requests, so check after processing)
    // Logging helper
    function log(msg, ...args) {
      console.log(`[${url.pathname}] ${msg}`, ...args);
    }

    try {
      if (url.pathname === "/auth" && request.method === "POST") {
        if (isRateLimited(ip)) {
          return jsonResponse({ result: "deny", reason: "Rate limit exceeded" }, 429);
        }
        const { username, password } = await request.json();
        log("Auth attempt for", username);

        if (!validateUsername(username) || !validatePassword(password)) {
          log("Invalid username or password format");
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny", reason: "Invalid credentials" }, 400);
        }

        const userKey = `user:${username}`;
        const userRaw = await env.USERS.get(userKey);
        if (!userRaw) {
          log("Auth failed for", username);
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny" }, 200);
        }

        let user;
        try {
          user = JSON.parse(userRaw);
        } catch (e) {
          log("Corrupt user data for", username);
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny" }, 200);
        }

        const hash = user.password_hash;
        if (!hash) {
          log("No password hash for", username);
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny" }, 200);
        }

        const ok = await bcrypt.compare(password, hash);
        log("Password check for", username, ok ? "OK" : "FAIL");
        if (!ok) {
          incrementRateLimit(ip);
        }
        return jsonResponse({ result: ok ? "allow" : "deny" }, 200);
      }

      if (url.pathname === "/acl" && request.method === "POST") {
        if (isRateLimited(ip)) {
          return jsonResponse({ result: "deny", reason: "Rate limit exceeded" }, 429);
        }
        const { username, action, topic } = await request.json();
        log("ACL check for", username, action, topic);

        if (!validateUsername(username) || !validateAction(action) || !validateTopic(topic)) {
          log("Invalid ACL params");
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny", reason: "Invalid params" }, 400);
        }

        const userKey = `user:${username}`;
        const userRaw = await env.USERS.get(userKey);
        if (!userRaw) {
          log("ACL failed for", username);
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny" }, 200);
        }

        let user;
        try {
          user = JSON.parse(userRaw);
        } catch (e) {
          log("Corrupt user data for", username);
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny" }, 200);
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
        return jsonResponse({ result: allowed ? "allow" : "deny" }, 200);
      }

      return new Response("Not found", { status: 404, headers: corsHeaders });
    } catch (err) {
      log("Internal error", err);
      incrementRateLimit(ip);
      return jsonResponse({ result: "deny" }, 500);
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