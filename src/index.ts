import { Hono } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { eq, and } from "drizzle-orm";
import { getDb, schema } from "./db";
import {
  verifyPassword,
  hashPassword,
  generateToken,
  hashToken,
  SESSION_COOKIE,
  sessionExpiry,
  MAX_FAILED_ATTEMPTS,
  lockoutUntil,
} from "./auth";

/* ---------- runtime bindings ---------- */

type Bindings = {
  DATABASE_URL: string;
  RESEND_API_KEY: string;
  SESSION_SECRET: string;
  APP_BASE_URL: string;
  APP_NAME: string;
  PROOFS: R2Bucket;
};

// what we hang off the request context once a session is validated
type Variables = {
  user: {
    id: string;
    email: string;
    name: string;
    role: (typeof schema.users.$inferSelect)["role"];
    resellerId: string | null;
  };
};

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

/* ---------- helpers ---------- */

function isSecure(url: string) {
  return url.startsWith("https://");
}

/* ============================================================
 * PUBLIC AUTH ROUTES
 * ========================================================== */

app.post("/api/auth/login", async (c) => {
  const db = getDb(c.env.DATABASE_URL);
  const body = await c.req.json<{ email?: string; password?: string }>();
  const email = (body.email ?? "").trim().toLowerCase();
  const password = body.password ?? "";

  if (!email || !password) {
    return c.json({ error: "email_and_password_required" }, 400);
  }

  const [user] = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.email, email))
    .limit(1);

  // Uniform error whether the user exists or not — no account enumeration.
  const invalid = () => c.json({ error: "invalid_credentials" }, 401);

  if (!user) return invalid();
  if (user.status !== "active") return c.json({ error: "account_inactive" }, 403);

  // lockout check
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    return c.json({ error: "account_locked" }, 423);
  }

  // user hasn't set a password yet
  if (!user.passwordHash || user.forcePasswordSetup) {
    return c.json({ error: "password_setup_required" }, 409);
  }

  const ok = await verifyPassword(password, user.passwordHash);
  if (!ok) {
    const attempts = user.failedAttempts + 1;
    await db
      .update(schema.users)
      .set({
        failedAttempts: attempts,
        lockedUntil: attempts >= MAX_FAILED_ATTEMPTS ? lockoutUntil() : null,
      })
      .where(eq(schema.users.id, user.id));
    return invalid();
  }

  // success — mint session
  const raw = generateToken();
  const tokenHash = await hashToken(raw);
  await db.insert(schema.sessions).values({
    userId: user.id,
    token: tokenHash,
    expiresAt: sessionExpiry(),
  });
  await db
    .update(schema.users)
    .set({ failedAttempts: 0, lockedUntil: null, lastLoginAt: new Date() })
    .where(eq(schema.users.id, user.id));

  setCookie(c, SESSION_COOKIE, raw, {
    httpOnly: true,
    secure: isSecure(c.env.APP_BASE_URL),
    sameSite: "Lax",
    path: "/",
    maxAge: 7 * 24 * 60 * 60,
  });

  return c.json({
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    },
  });
});

app.post("/api/auth/logout", async (c) => {
  const raw = getCookie(c, SESSION_COOKIE);
  if (raw) {
    const db = getDb(c.env.DATABASE_URL);
    const tokenHash = await hashToken(raw);
    await db
      .update(schema.sessions)
      .set({ revoked: true })
      .where(eq(schema.sessions.token, tokenHash));
    deleteCookie(c, SESSION_COOKIE, { path: "/" });
  }
  return c.json({ ok: true });
});

/* ============================================================
 * SESSION MIDDLEWARE  (everything under /api/app/* requires login)
 * ========================================================== */

app.use("/api/app/*", async (c, next) => {
  const raw = getCookie(c, SESSION_COOKIE);
  if (!raw) return c.json({ error: "not_authenticated" }, 401);

  const db = getDb(c.env.DATABASE_URL);
  const tokenHash = await hashToken(raw);

  const [row] = await db
    .select({
      sessionId: schema.sessions.id,
      expiresAt: schema.sessions.expiresAt,
      revoked: schema.sessions.revoked,
      userId: schema.users.id,
      email: schema.users.email,
      name: schema.users.name,
      role: schema.users.role,
      resellerId: schema.users.resellerId,
      status: schema.users.status,
    })
    .from(schema.sessions)
    .innerJoin(schema.users, eq(schema.sessions.userId, schema.users.id))
    .where(eq(schema.sessions.token, tokenHash))
    .limit(1);

  if (!row || row.revoked || row.expiresAt < new Date()) {
    return c.json({ error: "session_expired" }, 401);
  }
  if (row.status !== "active") {
    return c.json({ error: "account_inactive" }, 403);
  }

  c.set("user", {
    id: row.userId,
    email: row.email,
    name: row.name,
    role: row.role,
    resellerId: row.resellerId,
  });
  await next();
});

app.get("/api/app/me", (c) => {
  return c.json({ user: c.get("user") });
});

/* ---------- role guard helper (used by later routes) ---------- */

export function requireRole(
  ...roles: (typeof schema.users.$inferSelect)["role"][]
) {
  return async (c: any, next: any) => {
    const user = c.get("user");
    if (!user || !roles.includes(user.role)) {
      return c.json({ error: "forbidden" }, 403);
    }
    await next();
  };
}

/* ---------- health ---------- */

app.get("/api/health", async (c) => {
  try {
    const db = getDb(c.env.DATABASE_URL);
    await db.select().from(schema.users).limit(1);
    return c.json({ ok: true, db: "connected" });
  } catch (e) {
    return c.json({ ok: false, error: String(e) }, 500);
  }
});

export default app;
