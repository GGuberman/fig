// Health Tracker - Cloudflare Worker
// Handles: auth (magic token), data sync (read/write), CORS

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// Simple token auth — no passwords, no OAuth complexity.
// User picks a username, Worker issues a signed token stored in KV.
// Token = base64(username:random_secret) — good enough for personal health data.
async function generateToken(username) {
  const secret = crypto.randomUUID().replace(/-/g, "");
  return btoa(`${username}:${secret}`);
}

function parseToken(authHeader) {
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  try {
    const decoded = atob(authHeader.slice(7));
    const colon = decoded.indexOf(":");
    if (colon === -1) return null;
    return {
      username: decoded.slice(0, colon),
      secret: decoded.slice(colon + 1),
    };
  } catch {
    return null;
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS });
    }

    // ── POST /auth/register ──────────────────────────────
    // Body: { username }
    // Creates account if username not taken, returns token
    if (path === "/auth/register" && request.method === "POST") {
      const { username } = await request.json();
      if (!username || username.length < 2 || username.length > 32) {
        return err("Username must be 2-32 characters");
      }
      if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
        return err("Username can only contain letters, numbers, _ and -");
      }

      const existing = await env.TRACKER_KV.get(`user:${username}`);
      if (existing) return err("Username already taken", 409);

      const token = await generateToken(username);
      await env.TRACKER_KV.put(`user:${username}`, token);
      await env.TRACKER_KV.put(`data:${username}`, JSON.stringify(null));

      return json({ token, username });
    }

    // ── POST /auth/login ─────────────────────────────────
    // Body: { username, token }
    // Validates token, returns ok
    if (path === "/auth/login" && request.method === "POST") {
      const { username, token } = await request.json();
      if (!username || !token) return err("Missing username or token");

      const stored = await env.TRACKER_KV.get(`user:${username}`);
      if (!stored || stored !== token) return err("Invalid credentials", 401);

      return json({ ok: true, username });
    }

    // ── Auth required for all routes below ───────────────
    const parsed = parseToken(request.headers.get("Authorization"));
    if (!parsed) return err("Missing or invalid token", 401);

    const { username } = parsed;
    const storedToken = await env.TRACKER_KV.get(`user:${username}`);
    const sentToken = request.headers.get("Authorization").slice(7);
    if (!storedToken || storedToken !== sentToken) {
      return err("Invalid token", 401);
    }

    // ── GET /data ────────────────────────────────────────
    // Returns the user's full tracker data
    if (path === "/data" && request.method === "GET") {
      const raw = await env.TRACKER_KV.get(`data:${username}`);
      const data = raw ? JSON.parse(raw) : null;
      return json({ data });
    }

    // ── PUT /data ────────────────────────────────────────
    // Body: full tracker data object
    // Overwrites stored data (client is source of truth)
    if (path === "/data" && request.method === "PUT") {
      const body = await request.json();
      if (!body || typeof body !== "object") return err("Invalid data");

      // Basic size check — KV values max 25MB, we limit to 2MB
      const serialized = JSON.stringify(body);
      if (serialized.length > 2_000_000) return err("Data too large (max 2MB)");

      await env.TRACKER_KV.put(`data:${username}`, serialized);
      return json({ ok: true, savedAt: new Date().toISOString() });
    }

    // ── DELETE /data ─────────────────────────────────────
    // Wipes all user data (keeps account)
    if (path === "/data" && request.method === "DELETE") {
      await env.TRACKER_KV.put(`data:${username}`, JSON.stringify(null));
      return json({ ok: true });
    }

    // ── DELETE /account ───────────────────────────────────
    // Full account deletion
    if (path === "/account" && request.method === "DELETE") {
      await env.TRACKER_KV.delete(`user:${username}`);
      await env.TRACKER_KV.delete(`data:${username}`);
      return json({ ok: true });
    }

    return err("Not found", 404);
  },
};
