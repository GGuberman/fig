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

    // ── GET /config ──────────────────────────────────────
    // Public, unauthenticated. Lets the static frontend learn the WORLD_ID_APP_ID
    // without baking it into the HTML.
    if (path === "/config" && request.method === "GET") {
      return json({
        worldIdAppId: env.WORLD_ID_APP_ID || null,
        worldIdAction: "verify-human",
      });
    }

    // ── GET /attestations/:nullifier ─────────────────────
    // PUBLIC read of all attestations for a verified human, keyed by World ID nullifier.
    // No auth: this is the whole point — a partner reads attestations to gate rebates,
    // the user controls disclosure by sharing the URL.
    if (path.startsWith("/attestations/") && request.method === "GET") {
      const nullifier = path.split("/")[2];
      if (!nullifier || !/^0x[a-fA-F0-9]{40,}$/.test(nullifier)) {
        return err("Invalid nullifier_hash");
      }
      const list = await env.TRACKER_KV.list({ prefix: `attest:${nullifier}:` });
      const records = await Promise.all(
        list.keys.map((k) => env.TRACKER_KV.get(k.name).then((v) => (v ? JSON.parse(v) : null)))
      );
      return json({
        nullifier_hash: nullifier,
        attestations: records.filter(Boolean),
        signer: "worker:hmac-sha256-v1",
      });
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
      // Best-effort: also clear reverse-index of any World ID claim by this user
      const userData = JSON.parse((await env.TRACKER_KV.get(`data:${username}`)) || "null") || {};
      if (userData?.worldid?.nullifier_hash) {
        await env.TRACKER_KV.delete(`worldid:${userData.worldid.nullifier_hash}`);
      }
      return json({ ok: true });
    }

    // ── POST /auth/worldid/verify ────────────────────────
    // Body: { proof, action, signal }   (proof comes from IDKit on the client)
    // Verifies the proof against Worldcoin, stores nullifier ↔ user binding.
    if (path === "/auth/worldid/verify" && request.method === "POST") {
      if (!env.WORLD_ID_APP_ID) {
        return err("Worker missing WORLD_ID_APP_ID secret. Run `wrangler secret put WORLD_ID_APP_ID`.", 500);
      }
      const { proof, action = "verify-human", signal = "" } = await request.json();
      if (!proof || !proof.nullifier_hash || !proof.merkle_root || !proof.proof) {
        return err("Malformed proof — expected {nullifier_hash, merkle_root, proof, verification_level}");
      }

      // Forward to Worldcoin for ZK verification
      const verifyResp = await fetch(
        `https://developer.worldcoin.org/api/v2/verify/${env.WORLD_ID_APP_ID}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            nullifier_hash: proof.nullifier_hash,
            merkle_root: proof.merkle_root,
            proof: proof.proof,
            verification_level: proof.verification_level,
            action,
            signal,
          }),
        }
      );
      const verifyData = await verifyResp.json().catch(() => ({}));
      if (!verifyResp.ok || verifyData.success === false) {
        return err(verifyData.detail || `Worldcoin verify failed (${verifyResp.status})`, 400);
      }

      // Sybil check: if this nullifier is already bound to a different Fig handle, reject.
      const existing = await env.TRACKER_KV.get(`worldid:${proof.nullifier_hash}`);
      if (existing && existing !== username) {
        return err("This World ID is already bound to another Fig handle. Sign in there or contact support.", 409);
      }

      // Bind: store on user data + reverse-index nullifier → handle.
      const dataRaw = await env.TRACKER_KV.get(`data:${username}`);
      const data = dataRaw ? JSON.parse(dataRaw) : {};
      const userData = data && typeof data === "object" ? data : {};
      userData.worldid = {
        nullifier_hash: proof.nullifier_hash,
        verification_level: proof.verification_level,
        action,
        verifiedAt: new Date().toISOString(),
      };
      await env.TRACKER_KV.put(`data:${username}`, JSON.stringify(userData));
      await env.TRACKER_KV.put(`worldid:${proof.nullifier_hash}`, username);

      return json({
        ok: true,
        nullifier_hash: proof.nullifier_hash,
        verification_level: proof.verification_level,
      });
    }

    // ── POST /attestations ───────────────────────────────
    // Body: { kind, value, period_start, period_end }
    // Issues an HMAC-signed attestation tied to the user's World ID nullifier.
    if (path === "/attestations" && request.method === "POST") {
      if (!env.ATTEST_KEY) {
        return err("Worker missing ATTEST_KEY secret. Run `wrangler secret put ATTEST_KEY`.", 500);
      }
      const dataRaw = await env.TRACKER_KV.get(`data:${username}`);
      const userData = dataRaw ? JSON.parse(dataRaw) : null;
      const nullifier = userData?.worldid?.nullifier_hash;
      if (!nullifier) {
        return err("Sign in with World ID before publishing attestations.", 412);
      }

      const body = await request.json();
      const { kind, value = null, period_start = null, period_end = null } = body || {};
      if (!kind || typeof kind !== "string" || kind.length > 64) {
        return err("Each attestation needs a `kind` string (≤64 chars), e.g. streak.savings.30d");
      }

      const record = {
        nullifier_hash: nullifier,
        verification_level: userData.worldid.verification_level,
        kind,
        value,
        period_start,
        period_end,
        issued_at: new Date().toISOString(),
        issuer: "fig-worker-v1",
      };

      // HMAC-SHA256 over a canonical JSON of the record (sans signature).
      const canonical = JSON.stringify(record);
      const sig = await hmacSign(env.ATTEST_KEY, canonical);
      record.signature = sig;
      record.canonical_payload = canonical;

      const key = `attest:${nullifier}:${kind}:${record.issued_at}`;
      await env.TRACKER_KV.put(key, JSON.stringify(record));

      return json({ ok: true, attestation: record, public_url: `${url.origin}/attestations/${nullifier}` });
    }

    return err("Not found", 404);
  },
};

// ── HMAC helpers ────────────────────────────────────────
async function hmacSign(secretHex, message) {
  const keyBytes = hexToBytes(secretHex);
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return bytesToHex(new Uint8Array(sig));
}
function hexToBytes(hex) {
  const clean = hex.replace(/^0x/, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
