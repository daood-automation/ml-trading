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

/* ============================================================
 * OWNER BOOTSTRAP
 * One-time creation of the first owner login. Gated by SESSION_SECRET
 * AND only works while no owner exists yet, so it can't be used to add
 * rogue admins later. No email needed — you call it once to create your
 * own login, then this route is inert.
 * ========================================================== */

app.post("/api/bootstrap-owner", async (c) => {
  const db = getDb(c.env.DATABASE_URL);
  const body = await c.req.json<{
    key?: string;
    email?: string;
    password?: string;
    name?: string;
  }>();

  if (!body.key || body.key !== c.env.SESSION_SECRET) {
    return c.json({ error: "forbidden" }, 403);
  }
  const email = (body.email ?? "").trim().toLowerCase();
  const password = body.password ?? "";
  const name = (body.name ?? "Owner").trim();
  if (!email || password.length < 8) {
    return c.json({ error: "email_and_8char_password_required" }, 400);
  }

  const [existingOwner] = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.role, "owner"))
    .limit(1);
  if (existingOwner) return c.json({ error: "owner_already_exists" }, 409);

  const passwordHash = await hashPassword(password);
  const [u] = await db
    .insert(schema.users)
    .values({
      email,
      name,
      role: "owner",
      status: "active",
      passwordHash,
      forcePasswordSetup: false,
    })
    .returning();

  return c.json({ ok: true, user: { id: u.id, email: u.email, role: u.role } });
});

/* ============================================================
 * SET / RESET PASSWORD  (token-based, token stored hashed)
 * ========================================================== */

app.post("/api/auth/set-password", async (c) => {
  const db = getDb(c.env.DATABASE_URL);
  const body = await c.req.json<{ token?: string; password?: string }>();
  const token = body.token ?? "";
  const password = body.password ?? "";
  if (!token || password.length < 8) {
    return c.json({ error: "token_and_8char_password_required" }, 400);
  }

  const tokenHash = await hashToken(token);
  const [row] = await db
    .select()
    .from(schema.passwordTokens)
    .where(eq(schema.passwordTokens.tokenHash, tokenHash))
    .limit(1);

  if (!row || row.usedAt || row.expiresAt < new Date()) {
    return c.json({ error: "invalid_or_expired_token" }, 400);
  }

  const passwordHash = await hashPassword(password);
  await db
    .update(schema.users)
    .set({
      passwordHash,
      forcePasswordSetup: false,
      failedAttempts: 0,
      lockedUntil: null,
    })
    .where(eq(schema.users.id, row.userId));
  await db
    .update(schema.passwordTokens)
    .set({ usedAt: new Date() })
    .where(eq(schema.passwordTokens.id, row.id));

  return c.json({ ok: true });
});

/* ============================================================
 * CREATE USER  (owner / managers add staff or resellers)
 * Creates the login + a hashed setup token. Until Resend is wired,
 * the setup link is returned in the response so you can hand it over;
 * TODO(email): send this link via Resend instead of returning it.
 * ========================================================== */

app.post(
  "/api/app/users",
  requireRole("owner", "finance_manager", "shipping_manager"),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL);
    const body = await c.req.json<{
      email?: string;
      name?: string;
      role?: (typeof schema.users.$inferSelect)["role"];
      resellerId?: string | null;
    }>();

    const email = (body.email ?? "").trim().toLowerCase();
    const name = (body.name ?? "").trim();
    const role = body.role;
    if (!email || !name || !role) {
      return c.json({ error: "email_name_role_required" }, 400);
    }
    // only an owner may mint another owner
    const actor = c.get("user");
    if (role === "owner" && actor.role !== "owner") {
      return c.json({ error: "only_owner_can_create_owner" }, 403);
    }

    const [existing] = await db
      .select()
      .from(schema.users)
      .where(eq(schema.users.email, email))
      .limit(1);
    if (existing) return c.json({ error: "email_already_exists" }, 409);

    const [u] = await db
      .insert(schema.users)
      .values({
        email,
        name,
        role,
        status: "active",
        forcePasswordSetup: true,
        resellerId: body.resellerId ?? null,
      })
      .returning();

    // setup token (raw returned once, only hash stored)
    const raw = generateToken();
    const tokenHash = await hashToken(raw);
    await db.insert(schema.passwordTokens).values({
      userId: u.id,
      tokenHash,
      purpose: "set",
      expiresAt: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
    });

    const setupLink = `${c.env.APP_BASE_URL}/set-password?token=${raw}`;
    return c.json({
      ok: true,
      user: { id: u.id, email: u.email, role: u.role },
      setupLink, // TODO(email): send via Resend, stop returning this
    });
  }
);

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
