import bcrypt from "bcryptjs";
import { SignJWT, jwtVerify } from 'jose';

// Base64 decoder for Cloudflare Workers
function base64Decode(str) {
  try {
    return new Uint8Array(Buffer.from(str, 'base64'));
  } catch (e) {
    // Fallback for environments without Buffer
    const binaryString = atob(str);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }
}

// Web Crypto API password hashing functions
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const hash = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );
  
  // Store as base64: pbkdf2$iterations$salt$hash
  const saltB64 = btoa(String.fromCharCode(...salt));
  const hashB64 = btoa(String.fromCharCode(...new Uint8Array(hash)));
  return `pbkdf2$100000$${saltB64}$${hashB64}`;
}

async function verifyPassword(password, hash) {
  // Check if it's a bcrypt hash (starts with $2a$ or $2b$)
  if (hash.startsWith('$2a$') || hash.startsWith('$2b$')) {
    try {
      return await bcrypt.compare(password, hash);
    } catch (e) {
      return false;
    }
  }
  
  // PBKDF2 hash format: pbkdf2$iterations$salt$hash
  if (!hash.startsWith('pbkdf2$')) {
    return false;
  }
  
  const parts = hash.split('$');
  if (parts.length !== 4) {
    return false;
  }
  
  const iterations = parseInt(parts[1]);
  const saltB64 = parts[2];
  const hashB64 = parts[3];
  
  try {
    const encoder = new TextEncoder();
    const salt = base64Decode(saltB64);
    const storedHash = base64Decode(hashB64);
    
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveBits']
    );
    const computedHash = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: iterations,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );
    
    // Timing-safe comparison
    return crypto.subtle.timingSafeEqual(storedHash, new Uint8Array(computedHash));
  } catch (e) {
    return false;
  }
}

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
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "X-XSS-Protection": "1; mode=block",
      "Referrer-Policy": "no-referrer",
      "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    };
  }
  
  // Check if origin is allowed
  const isAllowed = allowedOrigins.includes(origin);
  
  return {
    "Access-Control-Allow-Origin": isAllowed ? origin : "",
    "Access-Control-Allow-Methods": isAllowed ? "POST, OPTIONS" : "",
    "Access-Control-Allow-Headers": isAllowed ? "Content-Type, Authorization" : "",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
  };
}

// Logging helper function
function log(pathname, msg, ...args) {
  console.log(`[${pathname}] ${msg}`, ...args);
}

// Audit log helper function
function audit(adminUsername, action, target) {
  console.log(`[AUDIT] admin=${adminUsername} action=${action} target=${target || ''}`);
}

// Get admin headers with CSP for static builds
function getAdminHeaders() {
  return {
    "Content-Security-Policy": [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-src 'none'",
      "object-src 'none'",
      "media-src 'none'",
      "manifest-src 'self'",
      "worker-src 'self'",
      "child-src 'none'",
      "upgrade-insecure-requests"
    ].join("; "),
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=(), ambient-light-sensor=()",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin"
  };
}

// CSP policy for API responses
const apiCspHeaders = {
  "Content-Security-Policy": [
    "default-src 'none'",
    "script-src 'none'",
    "style-src 'none'",
    "img-src 'none'",
    "font-src 'none'",
    "connect-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'none'",
    "frame-src 'none'",
    "object-src 'none'",
    "media-src 'none'",
    "manifest-src 'none'",
    "worker-src 'none'",
    "child-src 'none'"
  ].join("; "),
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "1; mode=block",
  "Referrer-Policy": "no-referrer"
};

function jsonResponse(body, status = 200, origin = null, rateLimitInfo = null) {
  const corsHeaders = origin ? getCorsHeaders(origin) : getCorsHeaders("");
  const headers = {
    "Content-Type": "application/json",
    ...corsHeaders,
    ...apiCspHeaders, // Add CSP headers for API responses
  };
  
  // Add rate limiting headers if provided
  if (rateLimitInfo) {
    headers["X-RateLimit-Limit"] = rateLimitInfo.limit.toString();
    headers["X-RateLimit-Remaining"] = rateLimitInfo.remaining.toString();
    headers["X-RateLimit-Reset"] = rateLimitInfo.reset.toString();
    if (rateLimitInfo.retryAfter) {
      headers["Retry-After"] = rateLimitInfo.retryAfter.toString();
    }
  }
  
  return new Response(JSON.stringify(body), {
    status,
    headers,
  });
}

// Enhanced Rate Limiting & Brute Force Protection
const ipRateMap = new Map();
const usernameRateMap = new Map();
const adminLoginAttempts = new Map();
const accountLockouts = new Map();

// Rate limiting configuration
const RATE_LIMIT = 10; // Failed requests per minute for general endpoints
const RATE_WINDOW = 60 * 1000; // 1 minute window
const MAX_IPS = 10000; // Maximum tracked IPs

// Brute force protection configuration
const ADMIN_LOGIN_LIMIT = 5; // Admin login attempts per 15 minutes
const ADMIN_LOGIN_WINDOW = 15 * 60 * 1000; // 15 minutes
const ACCOUNT_LOCKOUT_DURATION = 30 * 60 * 1000; // 30 minutes lockout
const PROGRESSIVE_DELAY_BASE = 1000; // Base delay in milliseconds
const MAX_DELAY = 30 * 1000; // Maximum delay of 30 seconds

// Admin API rate limiting
const ADMIN_API_LIMIT = 100; // Admin API calls per minute
const ADMIN_API_WINDOW = 60 * 1000; // 1 minute

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

// Enhanced rate limiting functions for brute force protection
function cleanupAllRateMaps() {
  const now = Date.now();
  
  // Cleanup IP rate map
  for (const [ip, entry] of ipRateMap.entries()) {
    if (now - entry.start > RATE_WINDOW) {
      ipRateMap.delete(ip);
    }
  }
  
  // Cleanup username rate map
  for (const [username, entry] of usernameRateMap.entries()) {
    if (now - entry.start > RATE_WINDOW) {
      usernameRateMap.delete(username);
    }
  }
  
  // Cleanup admin login attempts
  for (const [key, entry] of adminLoginAttempts.entries()) {
    if (now - entry.start > ADMIN_LOGIN_WINDOW) {
      adminLoginAttempts.delete(key);
    }
  }
  
  // Cleanup account lockouts
  for (const [key, lockoutTime] of accountLockouts.entries()) {
    if (now - lockoutTime > ACCOUNT_LOCKOUT_DURATION) {
      accountLockouts.delete(key);
    }
  }
  
  // Enforce hard caps
  if (ipRateMap.size > MAX_IPS) {
    const keys = Array.from(ipRateMap.keys());
    const toDelete = ipRateMap.size - MAX_IPS;
    for (let i = 0; i < toDelete; i++) {
      ipRateMap.delete(keys[i]);
    }
  }
}

function getAdminLoginAttempts(ip, username) {
  const key = `${ip}:${username}`;
  const now = Date.now();
  let entry = adminLoginAttempts.get(key);
  
  if (!entry || now - entry.start > ADMIN_LOGIN_WINDOW) {
    entry = { count: 0, start: now };
  }
  
  adminLoginAttempts.set(key, entry);
  return entry;
}

function incrementAdminLoginAttempts(ip, username) {
  const entry = getAdminLoginAttempts(ip, username);
  entry.count++;
  adminLoginAttempts.set(`${ip}:${username}`, entry);
}

function isAdminLoginRateLimited(ip, username) {
  const entry = getAdminLoginAttempts(ip, username);
  return entry.count >= ADMIN_LOGIN_LIMIT;
}

function lockoutAccount(ip, username) {
  const key = `${ip}:${username}`;
  accountLockouts.set(key, Date.now());
  console.log(`[SECURITY] Account locked out: ${username} from IP ${ip}`);
}

function isAccountLockedOut(ip, username) {
  const key = `${ip}:${username}`;
  const lockoutTime = accountLockouts.get(key);
  
  if (!lockoutTime) return false;
  
  const now = Date.now();
  if (now - lockoutTime > ACCOUNT_LOCKOUT_DURATION) {
    accountLockouts.delete(key);
    return false;
  }
  
  return true;
}

function getProgressiveDelay(attempts) {
  const delay = Math.min(PROGRESSIVE_DELAY_BASE * Math.pow(2, attempts), MAX_DELAY);
  return Math.floor(delay);
}

function getAdminApiRateLimitEntry(ip) {
  const now = Date.now();
  const key = `admin_api:${ip}`;
  let entry = adminLoginAttempts.get(key);
  
  if (!entry || now - entry.start > ADMIN_API_WINDOW) {
    entry = { count: 0, start: now };
  }
  
  adminLoginAttempts.set(key, entry);
  return entry;
}

function incrementAdminApiRateLimit(ip) {
  const entry = getAdminApiRateLimitEntry(ip);
  entry.count++;
  adminLoginAttempts.set(`admin_api:${ip}`, entry);
}

function isAdminApiRateLimited(ip) {
  const entry = getAdminApiRateLimitEntry(ip);
  return entry.count >= ADMIN_API_LIMIT;
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
  if (!(
    typeof topic === "string" &&
    topic.length > 0 &&
    topic.length <= 256 &&
    /^[^\u0000-\u001F\u007F]+$/.test(topic)
  )) {
    return false;
  }
  
  // XSS protection - check for potential script injection
  const lowerTopic = topic.toLowerCase();
  if (lowerTopic.includes('<script') || 
      lowerTopic.includes('javascript:') || 
      lowerTopic.includes('data:') ||
      lowerTopic.includes('vbscript:') ||
      lowerTopic.includes('onload') ||
      lowerTopic.includes('onerror')) {
    return false;
  }
  
  return true;
}

// Enhanced validation functions for comprehensive security
function sanitizeString(input, maxLength = 256) {
  if (typeof input !== "string") return null;
  if (input.length > maxLength) return null;
  // Remove null bytes and control characters
  return input.replace(/[\u0000-\u001F\u007F]/g, "");
}

// XSS Protection Functions
function escapeHtml(text) {
  if (typeof text !== "string") return "";
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;");
}

function sanitizeHtml(input, allowedTags = []) {
  if (typeof input !== "string") return "";
  
  // Remove all HTML tags except allowed ones
  let sanitized = input;
  
  if (allowedTags.length === 0) {
    // No tags allowed - escape everything
    return escapeHtml(input);
  }
  
  // Remove dangerous attributes and events
  sanitized = sanitized.replace(/on\w+\s*=\s*["'][^"']*["']/gi, ""); // Remove event handlers
  sanitized = sanitized.replace(/javascript\s*:/gi, ""); // Remove javascript: URLs
  sanitized = sanitized.replace(/data\s*:/gi, ""); // Remove data: URLs
  sanitized = sanitized.replace(/vbscript\s*:/gi, ""); // Remove vbscript: URLs
  
  // Only allow specific tags if needed
  const allowedTagsRegex = new RegExp(`<(?!\/?(?:${allowedTags.join('|')})\b)[^>]+>`, 'gi');
  sanitized = sanitized.replace(allowedTagsRegex, "");
  
  return sanitized;
}

function validateUrl(url) {
  if (typeof url !== "string") return null;
  
  // Only allow http, https, and relative URLs
  const allowedProtocols = /^(https?:\/\/|\/|#)/;
  if (!allowedProtocols.test(url)) return null;
  
  // Prevent javascript: and data: URLs
  if (url.toLowerCase().includes('javascript:') || url.toLowerCase().includes('data:')) {
    return null;
  }
  
  return url;
}

function validateAclRule(rule) {
  if (!rule || typeof rule !== "object") return false;
  if (Array.isArray(rule)) return false;
  
  const { action, topic } = rule;
  return validateAction(action) && validateTopic(topic);
}

function validateAclsArray(acls) {
  if (!Array.isArray(acls)) return false;
  if (acls.length > 100) return false; // Limit to 100 ACL rules per user
  
  return acls.every(rule => validateAclRule(rule));
}

function validateJsonPayload(payload, maxSize = 10240) { // 10KB limit
  if (!payload || typeof payload !== "object") return false;
  if (Array.isArray(payload)) return false;
  
  // Check payload size
  const payloadStr = JSON.stringify(payload);
  if (payloadStr.length > maxSize) return false;
  
  return true;
}

function sanitizeUsername(username) {
  const sanitized = sanitizeString(username, 64);
  if (!sanitized) return null;
  
  // Additional username-specific sanitization
  if (!/^[A-Za-z0-9_\-]+$/.test(sanitized)) return null;
  if (sanitized.length < 3) return null;
  
  // XSS protection - escape any potential HTML/script content
  const escaped = escapeHtml(sanitized);
  if (escaped !== sanitized) return null; // Reject if HTML encoding was needed
  
  return sanitized;
}

function sanitizePassword(password) {
  const sanitized = sanitizeString(password, 128);
  if (!sanitized) return null;
  
  if (sanitized.length < 8) return null;
  
  return sanitized;
}

function getJwtFromRequest(request) {
  const auth = request.headers.get("Authorization") || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

async function requireAdmin(request, env) {
  const token = getJwtFromRequest(request);
  if (!token) {
    console.log('[AUTH] No token provided');
    return null;
  }
  
  try {
    if (!env.JWT_SECRET) {
      console.log('[AUTH] No JWT_SECRET configured');
      return null;
    }
    
    const secret = new TextEncoder().encode(env.JWT_SECRET);
    let payload;
    try {
      const result = await jwtVerify(token, secret);
      payload = result.payload;
    } catch (jwtError) {
      console.log('[AUTH] JWT verification failed:', jwtError.message);
      return null;
    }
    
    if (!payload.roles || !payload.roles.includes("admin")) {
      console.log('[AUTH] User does not have admin role');
      return null;
    }
    
    // Validate session if sessionId is present
    if (payload.sessionId) {
      const sessionRaw = await env.USERS.get(`session:${payload.sessionId}`);
      if (!sessionRaw) {
        console.log('[AUTH] Session not found:', payload.sessionId);
        return null; // Session not found or expired
      }
      
      let sessionData;
      try {
        sessionData = JSON.parse(sessionRaw);
      } catch (e) {
        console.log('[AUTH] Corrupt session data:', e.message);
        return null; // Corrupt session data
      }
      
      const now = Date.now();
      
      // Check if session has expired
      if (now > sessionData.expiresAt) {
        console.log('[AUTH] Session expired:', payload.sessionId);
        // Clean up expired session
        await env.USERS.delete(`session:${payload.sessionId}`);
        return null;
      }
      
      // Update last activity timestamp
      sessionData.lastActivity = now;
      await env.USERS.put(`session:${payload.sessionId}`, JSON.stringify(sessionData), {
        expirationTtl: 3600 // 1 hour TTL
      });
      
      // Update user's session list
      const userSessionsKey = `user_sessions:${payload.username}`;
      const userSessionsRaw = await env.USERS.get(userSessionsKey);
      if (userSessionsRaw) {
        try {
          let userSessions = JSON.parse(userSessionsRaw);
          const sessionIndex = userSessions.findIndex(s => s.sessionId === payload.sessionId);
          if (sessionIndex !== -1) {
            userSessions[sessionIndex].lastActivity = now;
            await env.USERS.put(userSessionsKey, JSON.stringify(userSessions), {
              expirationTtl: 3600 // 1 hour TTL
            });
          }
        } catch (e) {
          console.log('[AUTH] Error updating session list:', e.message);
          // Ignore errors updating session list
        }
      }
    }
    
    console.log('[AUTH] Admin authentication successful for:', payload.username);
    return payload;
  } catch (e) {
    console.log('[AUTH] Authentication error:', e.message);
    return null;
  }
}

async function handleAdminApi(request, env) {
  const url = new URL(request.url);
  const origin = request.headers.get("Origin");
  const userAgent = request.headers.get("User-Agent") || "";
  const secFetchSite = request.headers.get("Sec-Fetch-Site");
  const secFetchMode = request.headers.get("Sec-Fetch-Mode");
  const secFetchDest = request.headers.get("Sec-Fetch-Dest");
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";

  // SECURITY: Block cross-origin requests from unauthorized domains
  const allowedOrigins = ['https://msgwrk-qt4g0063hh.cyber-comp.cc'];
  if (origin && !allowedOrigins.includes(origin)) {
    return new Response("Forbidden", { 
      status: 403,
      headers: {
        "Content-Type": "text/plain",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
      }
    });
  }

  // SECURITY: Block non-browser requests (Postman, curl, etc.)
  // Require Sec-Fetch-* headers which are only sent by legitimate browsers
  // These headers are much harder to spoof than User-Agent
  const hasSecFetchHeaders = secFetchSite && secFetchMode && secFetchDest;
  
  // Additional validation for Sec-Fetch-* headers
  const isValidSecFetch = hasSecFetchHeaders && (
    // Sec-Fetch-Site should be 'same-origin' for admin interface
    secFetchSite === 'same-origin' ||
    // Or 'same-site' for cross-site requests within the same domain
    secFetchSite === 'same-site'
  ) && (
    // Sec-Fetch-Mode should be 'cors' for API requests
    secFetchMode === 'cors' ||
    // Or 'navigate' for page loads
    secFetchMode === 'navigate'
  ) && (
    // Sec-Fetch-Dest should be 'empty' for API requests
    secFetchDest === 'empty' ||
    // Or 'document' for page loads
    secFetchDest === 'document'
  );

  if (!isValidSecFetch) {
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

      const payload = await request.json();
      
      // Validate JSON payload
      if (!validateJsonPayload(payload)) {
        return jsonResponse({ error: "Invalid request payload" }, 400, origin);
      }

      const { username, password } = payload;
      if (!username || !password) {
        return jsonResponse({ error: "Missing username or password" }, 400, origin);
      }

      // Sanitize and validate inputs
      const sanitizedUsername = sanitizeUsername(username);
      const sanitizedPassword = sanitizePassword(password);
      
      if (!sanitizedUsername) {
        return jsonResponse({ error: "Invalid username format" }, 400, origin);
      }
      
      if (!sanitizedPassword) {
        return jsonResponse({ error: "Invalid password format" }, 400, origin);
      }

      // Create admin user
      const hash = await hashPassword(sanitizedPassword);
      const adminObj = { 
        password_hash: hash, 
        roles: ["admin"],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
      await env.USERS.put(`admin:${sanitizedUsername}`, JSON.stringify(adminObj));
      
      console.log(`[BOOTSTRAP] Created first admin user: ${sanitizedUsername}`);
      return jsonResponse({ success: true, message: "Admin user created successfully" }, 200, origin);
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error creating admin user' }, 500, origin);
    }
  }

  // All other endpoints require admin JWT
  if (url.pathname.endsWith("/admin/api/login") && request.method === "POST") {
    try {
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      
      const payload = await request.json();
      
      // Validate JSON payload
      if (!validateJsonPayload(payload)) {
        return jsonResponse({ error: "Invalid request payload" }, 400, origin);
      }
      
      const { username, password } = payload;
      if (!username || !password) {
        return jsonResponse({ error: "Missing credentials" }, 400, origin);
      }
      
      // Sanitize and validate inputs
      const sanitizedUsername = sanitizeUsername(username);
      const sanitizedPassword = sanitizePassword(password);
      
      if (!sanitizedUsername) {
        return jsonResponse({ error: "Invalid username format" }, 400, origin);
      }
      
      if (!sanitizedPassword) {
        return jsonResponse({ error: "Invalid password format" }, 400, origin);
      }
      
      // Check for account lockout
      if (isAccountLockedOut(ip, sanitizedUsername)) {
        console.log(`[SECURITY] Login attempt blocked - account locked out: ${sanitizedUsername} from IP ${ip}`);
        return jsonResponse({ 
          error: "Account temporarily locked due to too many failed attempts. Please try again later." 
        }, 429, origin);
      }
      
      // Check rate limiting for admin login
      if (isAdminLoginRateLimited(ip, sanitizedUsername)) {
        console.log(`[SECURITY] Login attempt blocked - rate limited: ${sanitizedUsername} from IP ${ip}`);
        lockoutAccount(ip, sanitizedUsername);
        return jsonResponse({ 
          error: "Too many login attempts. Account locked for 30 minutes." 
        }, 429, origin);
      }
      
      const adminRaw = await env.USERS.get(`admin:${sanitizedUsername}`);
      if (!adminRaw) {
        incrementAdminLoginAttempts(ip, sanitizedUsername);
        console.log(`[SECURITY] Failed login attempt - user not found: ${sanitizedUsername} from IP ${ip}`);
        return jsonResponse({ error: "Invalid credentials" }, 401, origin);
      }
      let adminRecord;
      try {
        adminRecord = JSON.parse(adminRaw);
      } catch {
        incrementAdminLoginAttempts(ip, sanitizedUsername);
        console.log(`[SECURITY] Failed login attempt - corrupt data: ${sanitizedUsername} from IP ${ip}`);
        return jsonResponse({ error: "Corrupt admin data" }, 500, origin);
      }
      
      console.log(`[DEBUG] Admin hash starts with: ${adminRecord.password_hash.substring(0, 10)}`);
      
      const ok = await verifyPassword(sanitizedPassword, adminRecord.password_hash);
      
      if (!ok) {
        incrementAdminLoginAttempts(ip, sanitizedUsername);
        console.log(`[SECURITY] Failed login attempt - invalid password: ${sanitizedUsername} from IP ${ip}`);
        return jsonResponse({ error: "Invalid credentials" }, 401, origin);
      }
      
      // Migrate admin user from bcrypt to PBKDF2 on first successful login
      if (adminRecord.password_hash.startsWith('$2a$') || adminRecord.password_hash.startsWith('$2b$')) {
        console.log(`[MIGRATION] Migrating admin user ${sanitizedUsername} from bcrypt to PBKDF2`);
        const newHash = await hashPassword(sanitizedPassword);
        adminRecord.password_hash = newHash;
        adminRecord.updated_at = new Date().toISOString();
        await env.USERS.put(`admin:${sanitizedUsername}`, JSON.stringify(adminRecord));
        console.log(`[MIGRATION] Successfully migrated admin user ${sanitizedUsername}`);
      }
    
    // Generate session ID and store session metadata
    const sessionId = crypto.randomUUID();
    const now = Date.now();
    const sessionExpiry = now + (30 * 60 * 1000); // 30 minutes
    const tokenExpiry = now + (60 * 60 * 1000); // 1 hour
    
    const sessionData = {
      username,
      sessionId,
      createdAt: now,
      lastActivity: now,
      expiresAt: sessionExpiry,
      userAgent: request.headers.get("User-Agent") || "unknown",
      ip: request.headers.get("CF-Connecting-IP") || "unknown"
    };
    
    // Store session data
    await env.USERS.put(`session:${sessionId}`, JSON.stringify(sessionData), {
      expirationTtl: 3600 // 1 hour TTL
    });
    
    // Update user's active sessions list
    const userSessionsKey = `user_sessions:${username}`;
    const existingSessionsRaw = await env.USERS.get(userSessionsKey);
    let userSessions = [];
    if (existingSessionsRaw) {
      try {
        userSessions = JSON.parse(existingSessionsRaw);
      } catch {
        userSessions = [];
      }
    }
    
    // Limit concurrent sessions to 3 per user
    if (userSessions.length >= 3) {
      // Remove oldest session
      const oldestSession = userSessions.shift();
      if (oldestSession) {
        await env.USERS.delete(`session:${oldestSession.sessionId}`);
      }
    }
    
    userSessions.push({
      sessionId,
      createdAt: now,
      lastActivity: now
    });
    
    await env.USERS.put(userSessionsKey, JSON.stringify(userSessions), {
      expirationTtl: 3600 // 1 hour TTL
    });
    
    const secret = new TextEncoder().encode(env.JWT_SECRET);
    const token = await new SignJWT({ 
      username, 
      roles: adminRecord.roles || [],
      sessionId,
      exp: Math.floor(tokenExpiry / 1000)
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setExpirationTime('1h')
      .sign(secret);
      
    return jsonResponse({ 
      token,
      sessionId,
      expiresAt: tokenExpiry,
      sessionExpiresAt: sessionExpiry
    }, 200, origin);
  } catch (e) {
    return jsonResponse({ error: e.message || 'Error during login' }, 500, origin);
  }
  }
  
  let admin;
  try {
    admin = await requireAdmin(request, env);
  } catch (authError) {
    console.log('[ADMIN_API] Authentication error:', authError.message);
    return jsonResponse({ error: "Authentication error" }, 500, origin);
  }
  
  if (!admin) {
    console.log('[ADMIN_API] Authentication failed for:', url.pathname);
    return jsonResponse({ error: "Unauthorized" }, 401, origin);
  }

  // Rate limiting for admin API endpoints (excluding login and bootstrap)
  if (isAdminApiRateLimited(ip)) {
    console.log(`[SECURITY] Admin API rate limited: IP ${ip}`);
    return jsonResponse({ 
      error: "Too many requests. Please slow down." 
    }, 429, origin);
  }
  incrementAdminApiRateLimit(ip);



  if (url.pathname === "/admin/api/user" && request.method === "POST") {
    try {
      const payload = await request.json();
      
      // Validate JSON payload
      if (!validateJsonPayload(payload)) {
        return jsonResponse({ error: "Invalid request payload" }, 400, origin);
      }
      
      const { username, password, acls } = payload;
      
      // Validate required fields
      if (!username || !password) {
        return jsonResponse({ error: "Missing username or password" }, 400, origin);
      }
      
      // Sanitize and validate inputs
      const sanitizedUsername = sanitizeUsername(username);
      const sanitizedPassword = sanitizePassword(password);
      
      if (!sanitizedUsername) {
        return jsonResponse({ error: "Invalid username format" }, 400, origin);
      }
      
      if (!sanitizedPassword) {
        return jsonResponse({ error: "Invalid password format" }, 400, origin);
      }
      
      // Validate ACLs if provided
      let validatedAcls = [];
      if (acls !== undefined) {
        if (!validateAclsArray(acls)) {
          return jsonResponse({ error: "Invalid ACL format" }, 400, origin);
        }
        validatedAcls = acls;
      }
      
      const hash = await hashPassword(sanitizedPassword);
      const userObj = { 
        password_hash: hash, 
        acls: validatedAcls,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
      
      await env.USERS.put(`user:${sanitizedUsername}`, JSON.stringify(userObj));
      audit(admin.username, 'create_or_update_user', sanitizedUsername);
      return jsonResponse({ success: true }, 200, origin);
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error creating/updating user' }, 500, origin);
    }
  }
  if (url.pathname === "/admin/api/user" && request.method === "PUT") {
    try {
      const payload = await request.json();
      
      // Validate JSON payload
      if (!validateJsonPayload(payload)) {
        return jsonResponse({ error: "Invalid request payload" }, 400, origin);
      }
      
      const { username, password, newUsername } = payload;
      
      // Validate required fields
      if (!username || !password) {
        return jsonResponse({ error: "Missing username or password" }, 400, origin);
      }
      
      // Sanitize and validate inputs
      const sanitizedUsername = sanitizeUsername(username);
      const sanitizedPassword = sanitizePassword(password);
      const sanitizedNewUsername = newUsername ? sanitizeUsername(newUsername) : null;
      
      if (!sanitizedUsername) {
        return jsonResponse({ error: "Invalid username format" }, 400, origin);
      }
      
      if (!sanitizedPassword) {
        return jsonResponse({ error: "Invalid password format" }, 400, origin);
      }
      
      if (newUsername && !sanitizedNewUsername) {
        return jsonResponse({ error: "Invalid new username format" }, 400, origin);
      }
      
      // Check if user exists
      const userRaw = await env.USERS.get(`user:${sanitizedUsername}`);
      if (!userRaw) {
        return jsonResponse({ error: "User not found" }, 404, origin);
      }
      
      let user;
      try { 
        user = JSON.parse(userRaw); 
      } catch { 
        return jsonResponse({ error: "Corrupt user data" }, 500, origin); 
      }
      
      // Update password with PBKDF2 hash
      const newHash = await hashPassword(sanitizedPassword);
      user.password_hash = newHash;
      user.updated_at = new Date().toISOString();
      
      // Handle username change if provided
      if (sanitizedNewUsername && sanitizedNewUsername !== sanitizedUsername) {
        // Check if new username already exists
        const existingUser = await env.USERS.get(`user:${sanitizedNewUsername}`);
        if (existingUser) {
          return jsonResponse({ error: "New username already exists" }, 409, origin);
        }
        
        // Delete old user record and create new one
        await env.USERS.delete(`user:${sanitizedUsername}`);
        await env.USERS.put(`user:${sanitizedNewUsername}`, JSON.stringify(user));
        audit(admin.username, 'update_user_password_and_username', `${sanitizedUsername} -> ${sanitizedNewUsername}`);
        return jsonResponse({ success: true, newUsername: sanitizedNewUsername }, 200, origin);
      } else {
        // Just update password
        await env.USERS.put(`user:${sanitizedUsername}`, JSON.stringify(user));
        audit(admin.username, 'update_user_password', sanitizedUsername);
        return jsonResponse({ success: true }, 200, origin);
      }
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error updating user' }, 500, origin);
    }
  }
  if (url.pathname === "/admin/api/user" && request.method === "DELETE") {
    try {
      const payload = await request.json();
      
      // Validate JSON payload
      if (!validateJsonPayload(payload)) {
        return jsonResponse({ error: "Invalid request payload" }, 400, origin);
      }
      
      const { username } = payload;
      
      // Validate required fields
      if (!username) {
        return jsonResponse({ error: "Missing username" }, 400, origin);
      }
      
      // Sanitize and validate username
      const sanitizedUsername = sanitizeUsername(username);
      if (!sanitizedUsername) {
        return jsonResponse({ error: "Invalid username format" }, 400, origin);
      }
      
      await env.USERS.delete(`user:${sanitizedUsername}`);
      audit(admin.username, 'delete_user', sanitizedUsername);
      return jsonResponse({ success: true }, 200, origin);
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error deleting user' }, 500, origin);
    }
  }
  if (url.pathname === "/admin/api/acl" && request.method === "POST") {
    try {
      const payload = await request.json();
      
      // Validate JSON payload
      if (!validateJsonPayload(payload)) {
        return jsonResponse({ error: "Invalid request payload" }, 400, origin);
      }
      
      const { username, acls } = payload;
      
      // Validate required fields
      if (!username || !Array.isArray(acls)) {
        return jsonResponse({ error: "Missing username or acls" }, 400, origin);
      }
      
      // Sanitize and validate username
      const sanitizedUsername = sanitizeUsername(username);
      if (!sanitizedUsername) {
        return jsonResponse({ error: "Invalid username format" }, 400, origin);
      }
      
      // Validate ACLs
      if (!validateAclsArray(acls)) {
        return jsonResponse({ error: "Invalid ACL format" }, 400, origin);
      }
      
      const userRaw = await env.USERS.get(`user:${sanitizedUsername}`);
      if (!userRaw) {
        return jsonResponse({ error: "User not found" }, 404, origin);
      }
      
      let user;
      try { 
        user = JSON.parse(userRaw); 
      } catch { 
        return jsonResponse({ error: "Corrupt user data" }, 500, origin); 
      }
      
      user.acls = acls;
      user.updated_at = new Date().toISOString();
      
      await env.USERS.put(`user:${sanitizedUsername}`, JSON.stringify(user));
      audit(admin.username, 'update_acls', sanitizedUsername);
      return jsonResponse({ success: true }, 200, origin);
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error updating ACLs' }, 500, origin);
    }
  }
  if (url.pathname === "/admin/api/user-acls" && request.method === "PUT") {
    try {
      const payload = await request.json();
      
      // Validate JSON payload
      if (!validateJsonPayload(payload)) {
        return jsonResponse({ error: "Invalid request payload" }, 400, origin);
      }
      
      const { username, acls } = payload;
      
      // Validate required fields
      if (!username || !Array.isArray(acls)) {
        return jsonResponse({ error: "Missing username or acls" }, 400, origin);
      }
      
      // Sanitize and validate username
      const sanitizedUsername = sanitizeUsername(username);
      if (!sanitizedUsername) {
        return jsonResponse({ error: "Invalid username format" }, 400, origin);
      }
      
      // Validate ACLs
      if (!validateAclsArray(acls)) {
        return jsonResponse({ error: "Invalid ACL format" }, 400, origin);
      }
      
      const userRaw = await env.USERS.get(`user:${sanitizedUsername}`);
      if (!userRaw) {
        return jsonResponse({ error: "User not found" }, 404, origin);
      }
      
      let user;
      try { 
        user = JSON.parse(userRaw); 
      } catch { 
        return jsonResponse({ error: "Corrupt user data" }, 500, origin); 
      }
      
      user.acls = acls;
      user.updated_at = new Date().toISOString();
      
      await env.USERS.put(`user:${sanitizedUsername}`, JSON.stringify(user));
      audit(admin.username, 'update_acls', sanitizedUsername);
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
      if (!username) {
        return jsonResponse({ error: "Missing username" }, 400, origin);
      }
      
      // Sanitize and validate username parameter
      const sanitizedUsername = sanitizeUsername(username);
      if (!sanitizedUsername) {
        return jsonResponse({ error: "Invalid username format" }, 400, origin);
      }
      
      const userRaw = await env.USERS.get(`user:${sanitizedUsername}`);
      if (!userRaw) {
        return jsonResponse({ error: "User not found" }, 404, origin);
      }
      
      let user;
      try { 
        user = JSON.parse(userRaw); 
      } catch { 
        return jsonResponse({ error: "Corrupt user data" }, 500, origin); 
      }
      
      return jsonResponse({ username: sanitizedUsername, acls: user.acls || [] }, 200, origin);
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error fetching user details' }, 500, origin);
    }
  }
  
  // Session management endpoints
  if (url.pathname === "/admin/api/session/refresh" && request.method === "POST") {
    try {
      const now = Date.now();
      const sessionExpiry = now + (30 * 60 * 1000); // 30 minutes
      const tokenExpiry = now + (60 * 60 * 1000); // 1 hour
      
      // Update session data
      const sessionData = {
        username: admin.username,
        sessionId: admin.sessionId,
        createdAt: admin.iat ? admin.iat * 1000 : now,
        lastActivity: now,
        expiresAt: sessionExpiry,
        userAgent: request.headers.get("User-Agent") || "unknown",
        ip: request.headers.get("CF-Connecting-IP") || "unknown"
      };
      
      await env.USERS.put(`session:${admin.sessionId}`, JSON.stringify(sessionData), {
        expirationTtl: 3600 // 1 hour TTL
      });
      
      // Generate new token
      const secret = new TextEncoder().encode(env.JWT_SECRET);
      const token = await new SignJWT({ 
        username: admin.username, 
        roles: admin.roles || [],
        sessionId: admin.sessionId,
        exp: Math.floor(tokenExpiry / 1000)
      })
        .setProtectedHeader({ alg: 'HS256' })
        .setExpirationTime('1h')
        .sign(secret);
        
      audit(admin.username, 'refresh_session', admin.sessionId);
      return jsonResponse({ 
        token,
        expiresAt: tokenExpiry,
        sessionExpiresAt: sessionExpiry
      }, 200, origin);
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error refreshing session' }, 500, origin);
    }
  }
  
  if (url.pathname === "/admin/api/session/logout" && request.method === "POST") {
    try {
      if (admin.sessionId) {
        // Remove session data
        await env.USERS.delete(`session:${admin.sessionId}`);
        
        // Remove from user's session list
        const userSessionsKey = `user_sessions:${admin.username}`;
        const userSessionsRaw = await env.USERS.get(userSessionsKey);
        if (userSessionsRaw) {
          try {
            let userSessions = JSON.parse(userSessionsRaw);
            userSessions = userSessions.filter(s => s.sessionId !== admin.sessionId);
            await env.USERS.put(userSessionsKey, JSON.stringify(userSessions), {
              expirationTtl: 3600 // 1 hour TTL
            });
          } catch {
            // Ignore errors updating session list
          }
        }
        
        audit(admin.username, 'logout_session', admin.sessionId);
      }
      
      return jsonResponse({ success: true }, 200, origin);
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error logging out' }, 500, origin);
    }
  }
  
  if (url.pathname === "/admin/api/session/info" && request.method === "GET") {
    try {
      if (!admin.sessionId) {
        return jsonResponse({ error: "No active session" }, 400, origin);
      }
      
      const sessionRaw = await env.USERS.get(`session:${admin.sessionId}`);
      if (!sessionRaw) {
        return jsonResponse({ error: "Session not found" }, 404, origin);
      }
      
      let sessionData;
      try {
        sessionData = JSON.parse(sessionRaw);
      } catch {
        return jsonResponse({ error: "Corrupt session data" }, 500, origin);
      }
      
      // Get user's active sessions
      const userSessionsKey = `user_sessions:${admin.username}`;
      const userSessionsRaw = await env.USERS.get(userSessionsKey);
      let userSessions = [];
      if (userSessionsRaw) {
        try {
          userSessions = JSON.parse(userSessionsRaw);
        } catch {
          userSessions = [];
        }
      }
      
      return jsonResponse({
        currentSession: {
          sessionId: sessionData.sessionId,
          createdAt: sessionData.createdAt,
          lastActivity: sessionData.lastActivity,
          expiresAt: sessionData.expiresAt,
          userAgent: sessionData.userAgent,
          ip: sessionData.ip
        },
        activeSessions: userSessions.length,
        maxSessions: 3
      }, 200, origin);
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error fetching session info' }, 500, origin);
    }
  }
  
  if (url.pathname === "/admin/api/session/logout-all" && request.method === "POST") {
    try {
      // Get all user sessions
      const userSessionsKey = `user_sessions:${admin.username}`;
      const userSessionsRaw = await env.USERS.get(userSessionsKey);
      
      if (userSessionsRaw) {
        try {
          let userSessions = JSON.parse(userSessionsRaw);
          
          // Delete all session data
          for (const session of userSessions) {
            await env.USERS.delete(`session:${session.sessionId}`);
          }
          
          // Clear user's session list
          await env.USERS.delete(userSessionsKey);
          
          audit(admin.username, 'logout_all_sessions', `${userSessions.length} sessions`);
        } catch {
          // Ignore errors
        }
      }
      
      return jsonResponse({ success: true }, 200, origin);
    } catch (e) {
      return jsonResponse({ error: e.message || 'Error logging out all sessions' }, 500, origin);
    }
  }
  
  const corsHeaders = getCorsHeaders(origin);
  return new Response("Not found", { status: 404, headers: corsHeaders });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    // HTTPS Enforcement - Redirect HTTP to HTTPS for admin routes
    if (url.pathname.startsWith("/admin") && url.protocol === "http:") {
      const httpsUrl = url.href.replace("http:", "https:");
      return new Response(null, {
        status: 301,
        headers: {
          "Location": httpsUrl,
          "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
          "X-Content-Type-Options": "nosniff",
          "X-Frame-Options": "DENY",
          "Referrer-Policy": "no-referrer",
        },
      });
    }

    // Cleanup all rate limiting maps
    cleanupAllRateMaps();

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
        // For HTML files, add admin headers with CSP nonce
        const newHeaders = new Headers(response.headers);
        const adminHeaders = getAdminHeaders();
        
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
        
        // Add admin headers to the SPA response with CSP nonce
        const newHeaders = new Headers(response.headers);
        const adminHeaders = getAdminHeaders();
        
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

    // HTTPS Enforcement for API endpoints - Redirect HTTP to HTTPS
    if ((url.pathname === "/auth" || url.pathname === "/acl") && url.protocol === "http:") {
      const httpsUrl = url.href.replace("http:", "https:");
      return new Response(null, {
        status: 301,
        headers: {
          "Location": httpsUrl,
          "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
          "X-Content-Type-Options": "nosniff",
          "X-Frame-Options": "DENY",
          "Referrer-Policy": "no-referrer",
        },
      });
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
    try {
      const origin = request.headers.get("Origin");

      if (url.pathname === "/auth" && request.method === "POST") {
        if (isRateLimited(ip)) {
          return jsonResponse({ result: "deny", reason: "Rate limit exceeded" }, 429, origin);
        }
        const { username, password } = await request.json();
        log(url.pathname, "Auth attempt for", username);

        if (!validateUsername(username) || !validatePassword(password)) {
          log(url.pathname, "Invalid username or password format");
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny", reason: "Invalid credentials" }, 400, origin);
        }

        const userKey = `user:${username}`;
        const userRaw = await env.USERS.get(userKey);
        if (!userRaw) {
          log(url.pathname, "Auth user not found, returning ignore for EMQX fallback");
          return jsonResponse({ result: "ignore" }, 200, origin);
        }

        let user;
        try {
          user = JSON.parse(userRaw);
        } catch (e) {
          log(url.pathname, "Corrupt user data for", username);
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny" }, 200, origin);
        }

        const hash = user.password_hash;
        if (!hash) {
          log(url.pathname, "No password hash for", username);
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny" }, 200, origin);
        }

        const ok = await verifyPassword(password, hash);
        log(url.pathname, "Password check for", username, ok ? "OK" : "FAIL");
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
        log(url.pathname, "ACL check for", username, action, topic);

        if (!validateUsername(username) || !validateAction(action) || !validateTopic(topic)) {
          log(url.pathname, "Invalid ACL params");
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny", reason: "Invalid params" }, 400, origin);
        }

        const userKey = `user:${username}`;
        const userRaw = await env.USERS.get(userKey);
        if (!userRaw) {
          log(url.pathname, "ACL failed for", username);
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny" }, 200, origin);
        }

        let user;
        try {
          user = JSON.parse(userRaw);
        } catch (e) {
          log(url.pathname, "Corrupt user data for", username);
          incrementRateLimit(ip);
          return jsonResponse({ result: "deny" }, 200, origin);
        }

        const acls = user.acls || [];
        const allowed = acls.some(
          (rule) =>
            rule.action === action &&
            topicMatches(rule.topic, topic)
        );
        log(url.pathname, "ACL result for", username, allowed ? "ALLOW" : "DENY");
        if (!allowed) {
          incrementRateLimit(ip);
        }
        return jsonResponse({ result: allowed ? "allow" : "deny" }, 200, origin);
      }

      const corsHeaders = getCorsHeaders(origin);
      return new Response("Not found", { status: 404, headers: corsHeaders });
    } catch (err) {
      log(url.pathname, "Internal error", err);
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
    if (patternParts[i] !== topicParts[i]) return false;
  }
  return i === topicParts.length;
}