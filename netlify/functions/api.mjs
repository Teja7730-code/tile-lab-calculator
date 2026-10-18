import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const STORE_NAME = "ilc-quality-hub";
const DATABASE_KEY = "ilc-database";

const USERNAME = process.env.LAB_USERNAME;
const PASSWORD = process.env.LAB_PASSWORD;

const headers = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};

function response(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers });
}

function issueToken(username) {
  const payload = Buffer.from(JSON.stringify({
    u: username,
    t: Date.now()
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", PASSWORD)
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}

function validToken(token) {
  if (!token || !USERNAME || !PASSWORD) return false;

  try {
    const parts = token.split(".");
    if (parts.length !== 2) return false;

    const [payload, signature] = parts;
    const expected = crypto
      .createHmac("sha256", PASSWORD)
      .update(payload)
      .digest("base64url");

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;

    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return data.u === USERNAME &&
      Number.isFinite(data.t) &&
      Date.now() - data.t < 30 * 24 * 60 * 60 * 1000;
  } catch {
    return false;
  }
}

function validDatabase(data) {
  return !!data &&
    typeof data === "object" &&
    !!data.round &&
    typeof data.round === "object" &&
    !!data.materials &&
    typeof data.materials === "object" &&
    !Array.isArray(data.materials);
}

export default async function (request) {
  if (request.method !== "POST") {
    return response({ ok: false, error: "POST only" }, 405);
  }

  if (!USERNAME || !PASSWORD) {
    console.error("ILC login configuration missing:", {
      LAB_USERNAME: Boolean(USERNAME),
      LAB_PASSWORD: Boolean(PASSWORD)
    });
    return response({
      ok: false,
      error: "Server login is not configured. In Netlify, set LAB_USERNAME and LAB_PASSWORD for Functions in the production deploy context, then redeploy."
    }, 500);
  }

  try {
    const body = await request.json();
    const action = body?.action;

    if (action === "login") {
      if (body.username !== USERNAME || body.password !== PASSWORD) {
        return response({ ok: false, error: "Invalid username or password" }, 401);
      }
      return response({ ok: true, token: issueToken(USERNAME) });
    }

    if (!validToken(body?.token)) {
      return response({ ok: false, error: "Session expired. Please sign in again." }, 401);
    }

    const store = getStore({ name: STORE_NAME, consistency: "strong" });

    if (action === "get") {
      const data = await store.get(DATABASE_KEY, { type: "json" });
      return response({
        ok: true,
        data: validDatabase(data) ? data : null
      });
    }

    if (action === "save") {
      if (!validDatabase(body.data)) {
        return response({
          ok: false,
          error: "Invalid database payload. Expected round and materials data."
        }, 400);
      }

      await store.setJSON(DATABASE_KEY, body.data);
      const verify = await store.get(DATABASE_KEY, { type: "json" });

      const verified = validDatabase(verify) &&
        JSON.stringify(verify) === JSON.stringify(body.data);

      if (!verified) {
        return response({ ok: false, saved: false, verified: false, error: "Cloud save verification failed." }, 500);
      }

      return response({ ok: true, saved: true, verified: true });
    }

    return response({ ok: false, error: "Unknown action" }, 400);
  } catch (error) {
    console.error("ILC API error:", error);
    return response({
      ok: false,
      error: error?.message || "Server error"
    }, 500);
  }
}
