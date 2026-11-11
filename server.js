require("dotenv").config();

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const { promisify } = require("node:util");
const { Pool } = require("pg");

const scrypt = promisify(crypto.scrypt);
const PORT = Number(process.env.PORT || 3000);
const SESSION_DAYS = 14;
const PASSWORD_RESET_MINUTES = 30;
const SESSION_COOKIE = "township_session";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const IS_PRODUCTION = process.env.NODE_ENV === "production";

if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL must be configured.");
if (SESSION_SECRET.length < 32) throw new Error("SESSION_SECRET must contain at least 32 characters.");
if (IS_PRODUCTION && (!process.env.APP_ORIGIN || !process.env.APP_ORIGIN.startsWith("https://"))) {
  throw new Error("APP_ORIGIN must be the site's HTTPS origin in production.");
}
if (IS_PRODUCTION && process.env.COOKIE_SECURE !== "true") {
  throw new Error("Set COOKIE_SECURE=true when running in production.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: true } : undefined,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000
});

const rateLimits = new Map();
const passwordParameters = { N: 16_384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function sendJson(response, status, payload, headers = {}) {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(body),
    ...headers
  });
  response.end(body);
}

function setSecurityHeaders(response) {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
}

function cookiesFrom(request) {
  const cookieHeader = request.headers.cookie || "";
  return Object.fromEntries(cookieHeader.split(";").map(part => {
    const separator = part.indexOf("=");
    if (separator < 0) return ["", ""];
    return [part.slice(0, separator).trim(), part.slice(separator + 1).trim()];
  }).filter(([name]) => name));
}

function sessionCookie(value, maxAge) {
  const secure = process.env.COOKIE_SECURE === "true" ? "; Secure" : "";
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`;
}

function tokenHash(token) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(token).digest("hex");
}

function passwordResetTokenHash(token) {
  return crypto.createHmac("sha256", SESSION_SECRET).update("password-reset:").update(token).digest("hex");
}

function validatePassword(password) {
  if (typeof password !== "string" || password.length < 12 || Buffer.byteLength(password, "utf8") > 72) {
    throw badRequest("Use a password of at least 12 characters (maximum 72 bytes).");
  }
  return password;
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt, 64, passwordParameters);
  return `scrypt$${passwordParameters.N}$${passwordParameters.r}$${passwordParameters.p}$${salt.toString("base64url")}$${hash.toString("base64url")}`;
}

async function sendPasswordResetEmail(email, token) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.RESEND_FROM_EMAIL;
  const appOrigin = process.env.APP_ORIGIN;
  if (!apiKey || !from || !appOrigin) {
    throw new Error("Set RESEND_API_KEY, RESEND_FROM_EMAIL, and APP_ORIGIN to enable password reset emails.");
  }

  let origin;
  try {
    const parsedOrigin = new URL(appOrigin);
    if ((parsedOrigin.protocol !== "http:" && parsedOrigin.protocol !== "https:") ||
        parsedOrigin.origin !== appOrigin.replace(/\/$/, "")) {
      throw new Error();
    }
    origin = parsedOrigin.origin;
  } catch {
    throw new Error("APP_ORIGIN must be an exact http or https origin to enable password reset emails.");
  }
  
  const resetUrl = new URL("/", origin);
  resetUrl.searchParams.set("reset", token);
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    
    signal: AbortSignal.timeout(10_000),
    body: JSON.stringify({
      from,
      to: [email],
      subject: "Reset your Township Economy password",
      html: `<p>We received a request to reset your Township Economy password.</p><p><a href="${resetUrl.href}">Reset your password</a></p><p>This link expires in ${PASSWORD_RESET_MINUTES} minutes and can only be used once. If you did not request this, you can ignore this email.</p>`,
      text: `We received a request to reset your Township Economy password.\n\nReset your password: ${resetUrl.href}\n\nThis link expires in ${PASSWORD_RESET_MINUTES} minutes and can only be used once. If you did not request this, you can ignore this email.`
    })
  });
  if (!response.ok) throw new Error(`Resend returned HTTP ${response.status}.`);
}

async function processPasswordResetRequest(email) {
  const result = await pool.query("SELECT id, email FROM users WHERE email = $1", [email]);
  const user = result.rows[0];
  if (!user) return;

  const token = crypto.randomBytes(32).toString("base64url");
  const tokenDigest = passwordResetTokenHash(token);
  const expiresAt = new Date(Date.now() + PASSWORD_RESET_MINUTES * 60 * 1000);
  await pool.query("DELETE FROM password_reset_tokens WHERE user_id = $1", [user.id]);
  await pool.query(
    "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
    [tokenDigest, user.id, expiresAt]
  );
  
  try {
    await sendPasswordResetEmail(user.email, token);
  } catch (error) {
    try {
      await pool.query("DELETE FROM password_reset_tokens WHERE token_hash = $1", [tokenDigest]);
    } catch (cleanupError) {
      console.error("Could not remove an undelivered password reset token:", cleanupError.code || cleanupError.message);
    }
    console.error("Could not deliver a password reset email:", error.message);
  }
}

function checkRateLimit(request, key, limit) {
  const now = Date.now();
  const address = request.socket.remoteAddress || "unknown";
  const bucketKey = `${key}:${address}`;
  const bucket = rateLimits.get(bucketKey);
  if (!bucket || bucket.resetAt <= now) {
    rateLimits.set(bucketKey, { count: 1, resetAt: now + 15 * 60 * 1000 });
    return true;
  }
  if (bucket.count >= limit) return false;
  bucket.count += 1;
  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateLimits) {
    if (bucket.resetAt <= now) rateLimits.delete(key);
  }
}, 60_000).unref();

setInterval(() => {
  Promise.all([
    pool.query("DELETE FROM sessions WHERE expires_at <= now()"),
    pool.query("DELETE FROM password_reset_tokens WHERE expires_at <= now()")
  ]).catch(error => console.error("Could not remove expired authentication records:", error));
}, 60 * 60 * 1000).unref();

function assertSameOrigin(request) {
  const origin = request.headers.origin;
  const configuredOrigin = process.env.APP_ORIGIN;
...
  if (actual !== expected) {
    console.error("Origin verification failed:", {
      receivedOrigin: actual,
      expectedOrigin: expected
    });

    const error = new Error(
      "This request could not be verified. Reload the page and try again."
    );
    error.status = 403;
    throw error;
  }
}


async function readJson(request) {
  if (!String(request.headers["content-type"] || "").toLowerCase().startsWith("application/json")) {
    const error = new Error("Send this request as JSON.");
    error.status = 415;
    throw error;
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 32 * 1024) {
      const error = new Error("Request is too large.");
      error.status = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  let body;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw badRequest("Request contains invalid JSON.");
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw badRequest("Request body must be a JSON object.");
  }
  return body;
}

function text(value, field, maxLength, required = true) {
  if (typeof value !== "string") {
    if (!required && (value === undefined || value === null || value === "")) return "";
    throw badRequest(`${field} must be text.`);
  }
  const normalized = value.trim();
  if (required && !normalized) throw badRequest(`${field} is required.`);
  if (normalized.length > maxLength) throw badRequest(`${field} must be ${maxLength} characters or fewer.`);
  return normalized;
}

function badRequest(message) {
  const error = new Error(message);
  error.status = 400;
  return error;
}

function optionalUrl(value, field) {
  const raw = text(value, field, 200, false);
  if (!raw) return "";
  try {
    const url = new URL(raw);
    if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error();
    return url.href;
  } catch {
    throw badRequest(`${field} must be a valid http or https URL.`);
  }
}

function validateContactFields(input) {
  const whatsapp = text(input.whatsapp, "WhatsApp number", 24, false);
  const digits = whatsapp.replace(/\D/g, "");
  if (whatsapp && (digits.length < 8 || digits.length > 15)) {
    throw badRequest("WhatsApp number must include a country code and contain 8–15 digits.");
  }
  return {
    whatsapp,
    instagram: optionalUrl(input.instagram, "Instagram URL"),
    facebook: optionalUrl(input.facebook, "Facebook URL"),
    tiktok: optionalUrl(input.tiktok, "TikTok URL"),
    website: optionalUrl(input.website, "Website URL")
  };
}

function validateListing(kind, input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw badRequest("Listing details are required.");
  if (kind === "members") {
    const tags = Array.isArray(input.tags) ? input.tags : [];
    if (tags.length > 10) throw badRequest("Choose no more than 10 skills or interests.");
    return {
      name: text(input.name, "Name", 70),
      role: text(input.role, "Role", 70),
      location: text(input.location, "Area", 70),
      tags: tags.map(tag => text(tag, "Skill or interest", 40)),
      about: text(input.about, "About", 240, false)
    };
  }
  const contact = text(input.contact, "Contact email", 254).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact)) throw badRequest("Enter a valid contact email.");
  if (kind === "jobs") {
    const type = text(input.type, "Listing type", 20);
    if (type !== "Hiring" && type !== "Seeking work") throw badRequest("Choose Hiring or Seeking work.");
    return {
      title: text(input.title, "Role or opportunity", 80),
      company: text(input.company, "Name or organisation", 70),
      type,
      location: text(input.location, "Area", 70),
      description: text(input.description, "Details", 300),
      contact,
      ...validateContactFields(input)
    };
  }
  if (kind === "services") {
    return {
      name: text(input.name, "Provider name", 80),
      category: text(input.category, "Service type", 70),
      location: text(input.location, "Area", 70),
      description: text(input.description, "Service details", 300),
      contact,
      ...validateContactFields(input)
    };
  }
  throw badRequest("Choose a valid listing category.");
}

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  await pool.query(
    "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
    [tokenHash(token), userId, expiresAt]
  );
  return token;
}

async function currentUser(request) {
  const token = cookiesFrom(request)[SESSION_COOKIE];
  if (!token || token.length > 100) return null;
  const result = await pool.query(
    `SELECT users.id, users.display_name, users.email
     FROM sessions JOIN users ON users.id = sessions.user_id
     WHERE sessions.token_hash = $1 AND sessions.expires_at > now()`,
    [tokenHash(token)]
  );
  return result.rows[0] || null;
}

function publicUser(user) {
  return { id: user.id, name: user.display_name, email: user.email };
}

async function requireUser(request, response) {
  const user = await currentUser(request);
  if (!user) sendJson(response, 401, { error: "Sign in to browse and manage community listings." });
  return user;
}

function parseListingKind(value) {
  if (value === "members" || value === "jobs" || value === "services") return value;
  throw badRequest("Choose a valid listing category.");
}

async function handleApi(request, response, url) {
  const route = url.pathname;
  const method = request.method;
  if (method === "POST" || method === "PATCH" || method === "DELETE") assertSameOrigin(request);

  if (route === "/api/auth/me" && method === "GET") {
    const user = await currentUser(request);
    sendJson(response, 200, { user: user ? publicUser(user) : null });
    return;
  }

  if (route === "/api/auth/register" && method === "POST") {
    if (!checkRateLimit(request, "register", 5)) {
      sendJson(response, 429, { error: "Too many sign-up attempts. Please wait and try again." });
      return;
    }
    const body = await readJson(request);
    const displayName = text(body.name, "Name", 70);
    const email = text(body.email, "Email", 254).toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw badRequest("Enter a valid email address.");
    const password = validatePassword(body.password);
    const passwordHash = await hashPassword(password);
    const user = { id: crypto.randomUUID(), display_name: displayName, email };
    try {
      await pool.query(
        "INSERT INTO users (id, display_name, email, password_hash) VALUES ($1, $2, $3, $4)",
        [user.id, user.display_name, user.email, passwordHash]
      );
    } catch (error) {
      if (error.code === "23505") {
        sendJson(response, 409, { error: "An account with that email already exists. Sign in instead." });
        return;
      }
      throw error;
    }
    const token = await createSession(user.id);
    sendJson(response, 201, { user: publicUser(user) }, { "Set-Cookie": sessionCookie(token, SESSION_DAYS * 24 * 60 * 60) });
    return;
  }

  if (route === "/api/auth/login" && method === "POST") {
    if (!checkRateLimit(request, "login", 10)) {
      sendJson(response, 429, { error: "Too many sign-in attempts. Please wait and try again." });
      return;
    }
    const body = await readJson(request);
    const email = text(body.email, "Email", 254).toLowerCase();
    if (typeof body.password !== "string" || Buffer.byteLength(body.password, "utf8") > 72) {
      sendJson(response, 401, { error: "Email or password is incorrect." });
      return;
    }
    const result = await pool.query("SELECT id, display_name, email, password_hash FROM users WHERE email = $1", [email]);
    const user = result.rows[0];
    const [scheme, n, r, p, saltText, hashText] = (user?.password_hash || "").split("$");
    let passwordMatches = false;
    if (scheme === "scrypt" && Number(n) === passwordParameters.N && Number(r) === passwordParameters.r && Number(p) === passwordParameters.p) {
      const salt = Buffer.from(saltText, "base64url");
      const expected = Buffer.from(hashText, "base64url");
      const candidate = await scrypt(body.password, salt, expected.length, passwordParameters);
      passwordMatches = candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
    }
    if (!user || !passwordMatches) {
      sendJson(response, 401, { error: "Email or password is incorrect." });
      return;
    }
    const token = await createSession(user.id);
    sendJson(response, 200, { user: publicUser(user) }, { "Set-Cookie": sessionCookie(token, SESSION_DAYS * 24 * 60 * 60) });
    return;
  }

  if (route === "/api/auth/forgot-password" && method === "POST") {
    if (!checkRateLimit(request, "forgot-password", 5)) {
      sendJson(response, 429, { error: "Too many reset requests. Please wait and try again." });
      return;
    }
    const body = await readJson(request);
    const email = text(body.email, "Email", 254).toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw badRequest("Enter a valid email address.");

    setImmediate(() => {
      processPasswordResetRequest(email).catch(error => {
        console.error("Could not process a password reset request:", error.code || error.message);
      });
    });
    sendJson(response, 202, {
      message: "If an account exists for that email, a password reset link will be sent."
    });
    return;
  }

  if (route === "/api/auth/reset-password" && method === "POST") {
    if (!checkRateLimit(request, "reset-password", 10)) {
      sendJson(response, 429, { error: "Too many reset attempts. Please wait and try again." });
      return;
    }
    const body = await readJson(request);
    if (typeof body.token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(body.token)) {
      throw badRequest("This password reset link is invalid or has expired. Request a new link.");
    }
    const password = validatePassword(body.password);
    const passwordHash = await hashPassword(password);
    const client = await pool.connect();
    let userId;
    try {
      await client.query("BEGIN");
      const consumed = await client.query(
        "DELETE FROM password_reset_tokens WHERE token_hash = $1 AND expires_at > now() RETURNING user_id",
        [passwordResetTokenHash(body.token)]
      );
      userId = consumed.rows[0]?.user_id;
      if (userId) {
        const updated = await client.query("UPDATE users SET password_hash = $1 WHERE id = $2 RETURNING id", [passwordHash, userId]);
        if (!updated.rowCount) userId = null;
        if (userId) {
          await client.query("DELETE FROM sessions WHERE user_id = $1", [userId]);
          await client.query("DELETE FROM password_reset_tokens WHERE user_id = $1", [userId]);
        }
      }
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    if (!userId) {
      throw badRequest("This password reset link is invalid or has expired. Request a new link.");
    }
    sendJson(response, 200, { ok: true });
    return;
  }

  if (route === "/api/auth/logout" && method === "POST") {
    const token = cookiesFrom(request)[SESSION_COOKIE];
    if (token) await pool.query("DELETE FROM sessions WHERE token_hash = $1", [tokenHash(token)]);
    sendJson(response, 200, { ok: true }, { "Set-Cookie": sessionCookie("", 0) });
    return;
  }

  const listingRoute = route.match(/^\/api\/listings(?:\/([0-9a-f-]{36}))?$/i);
  if (listingRoute) {
    const user = await requireUser(request, response);
    if (!user) return;
    const listingId = listingRoute[1];
    if (!listingId && method === "GET") {
      const kind = parseListingKind(url.searchParams.get("kind"));
      const result = await pool.query(
        `SELECT id, user_id, kind, status, data, created_at, updated_at
         FROM listings WHERE kind = $1 ORDER BY created_at DESC`,
        [kind]
      );
      sendJson(response, 200, {
        listings: result.rows.map(row => ({
          id: row.id,
          kind: row.kind,
          status: row.status,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          isOwner: row.user_id === user.id,
          ...row.data
        }))
      });
      return;
    }
    if (!listingId && method === "POST") {
      const body = await readJson(request);
      const kind = parseListingKind(body.kind);
      const data = validateListing(kind, body.data);
      const result = await pool.query(
        "INSERT INTO listings (id, user_id, kind, data) VALUES ($1, $2, $3, $4::jsonb) RETURNING id, kind, status, data, created_at, updated_at",
        [crypto.randomUUID(), user.id, kind, JSON.stringify(data)]
      );
      const row = result.rows[0];
      sendJson(response, 201, { listing: { id: row.id, kind: row.kind, status: row.status, createdAt: row.created_at, updatedAt: row.updated_at, isOwner: true, ...row.data } });
      return;
    }
    if (listingId && method === "PATCH") {
      const body = await readJson(request);
      if (body.status !== "active" && body.status !== "closed") throw badRequest("Choose active or closed status.");
      const result = await pool.query(
        "UPDATE listings SET status = $1, updated_at = now() WHERE id = $2 AND user_id = $3 RETURNING id",
        [body.status, listingId, user.id]
      );
      if (!result.rowCount) {
        sendJson(response, 404, { error: "Listing not found or you do not own it." });
        return;
      }
      sendJson(response, 200, { ok: true });
      return;
    }
    if (listingId && method === "DELETE") {
      const result = await pool.query("DELETE FROM listings WHERE id = $1 AND user_id = $2 RETURNING id", [listingId, user.id]);
      if (!result.rowCount) {
        sendJson(response, 404, { error: "Listing not found or you do not own it." });
        return;
      }
      sendJson(response, 200, { ok: true });
      return;
    }
  }

  sendJson(response, 404, { error: "API route not found." });
}

async function handleRequest(request, response) {
  setSecurityHeaders(response);
  const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
  if (url.pathname.startsWith("/api/")) {
    await handleApi(request, response, url);
    return;
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    sendJson(response, 405, { error: "Method not allowed." }, { Allow: "GET, HEAD" });
    return;
  }
  if (url.pathname === "/favicon.svg") {
    const favicon = await fs.readFile(path.join(__dirname, "favicon.svg"));
    response.writeHead(200, {
      "Content-Type": "image/svg+xml; charset=utf-8",
      "Cache-Control": "public, max-age=86400",
      "Content-Length": favicon.length
    });
    response.end(request.method === "HEAD" ? undefined : favicon);
    return;
  }
  if (url.pathname !== "/" && url.pathname !== "/index.html") {
    sendJson(response, 404, { error: "Page not found." });
    return;
  }
  const html = await fs.readFile(path.join(__dirname, "index.html"));
  response.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-cache",
    "Content-Length": html.length
  });
  response.end(request.method === "HEAD" ? undefined : html);
}

const server = http.createServer((request, response) => {
  handleRequest(request, response).catch(error => {
    if (response.headersSent) {
      console.error("Request failed after headers were sent:", error);
      response.destroy();
      return;
    }
    const status = Number.isInteger(error.status) ? error.status : 500;
    if (status >= 500) console.error("Request failed:", error);
    sendJson(response, status, { error: status >= 500 ? "The server could not complete this request." : error.message });
  });
});

async function start() {
  const schema = await fs.readFile(path.join(__dirname, "schema.sql"), "utf8");
  await pool.query(schema);
  server.listen(PORT, () => console.log(`Township Economy is listening on http://localhost:${PORT}`));
}

async function shutdown() {
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

if (require.main === module) {
  start().catch(error => {
    console.error("Could not start Township Economy:", error);
    process.exitCode = 1;
  });
}

module.exports = { validateListing, parseListingKind, validatePassword, sendPasswordResetEmail };
