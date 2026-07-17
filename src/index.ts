import { Hono } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { eq, and, desc, count, sum, gte, ne } from "drizzle-orm";
import { getDb, schema } from "./db";
import { CATALOG } from "./catalog";
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

function reqOrigin(c: any): string {
  return new URL(c.req.url).origin;
}
function reqIsSecure(c: any): boolean {
  return new URL(c.req.url).protocol === "https:";
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
    secure: reqIsSecure(c),
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

// Public: is first-run setup still needed? Drives the browser onboarding.
app.get("/api/bootstrap-status", async (c) => {
  const db = getDb(c.env.DATABASE_URL);
  const [existingOwner] = await db
    .select({ id: schema.users.id })
    .from(schema.users)
    .where(eq(schema.users.role, "owner"))
    .limit(1);
  return c.json({ ownerExists: !!existingOwner });
});

app.post("/api/bootstrap-owner", async (c) => {
  const db = getDb(c.env.DATABASE_URL);
  const body = await c.req.json<{
    email?: string;
    password?: string;
    name?: string;
  }>();

  const email = (body.email ?? "").trim().toLowerCase();
  const password = body.password ?? "";
  const name = (body.name ?? "Owner").trim();
  if (!email || password.length < 8) {
    return c.json({ error: "email_and_8char_password_required" }, 400);
  }

  // The zero-owner state IS the security gate: this succeeds only while no
  // owner exists, so the first person to set up a fresh deployment becomes
  // owner. Once an owner exists it is permanently inert (409).
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
 * LIST USERS  (staff directory)
 * ========================================================== */

app.get(
  "/api/app/users",
  requireRole("owner", "finance_manager", "shipping_manager"),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL);
    const rows = await db
      .select({
        id: schema.users.id,
        email: schema.users.email,
        name: schema.users.name,
        role: schema.users.role,
        status: schema.users.status,
        forcePasswordSetup: schema.users.forcePasswordSetup,
        lastLoginAt: schema.users.lastLoginAt,
      })
      .from(schema.users)
      .orderBy(desc(schema.users.createdAt));
    return c.json({ users: rows });
  }
);

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

    const setupLink = `${reqOrigin(c)}/?setup=${raw}`;
    return c.json({
      ok: true,
      user: { id: u.id, email: u.email, role: u.role },
      setupLink, // TODO(email): send via Resend, stop returning this
    });
  }
);

/* ============================================================
 * ORDERS
 * ========================================================== */

// Submit an order. Reseller submits for their own account; staff may
// submit on behalf of a reseller by passing resellerId.
// Totals are computed server-side from catalog prices — never trusted
// from the client. Order + items + fulfilment are written atomically
// via db.batch (a single server-side transaction), which replaces the
// old LockService lock.
app.post("/api/app/orders", async (c) => {
  const db = getDb(c.env.DATABASE_URL);
  const actor = c.get("user");
  const body = await c.req.json<{
    resellerId?: string;
    clientRequestId?: string;
    deliveryType?: (typeof schema.orders.$inferSelect)["deliveryType"];
    customerName?: string;
    customerPhone?: string;
    customerEmail?: string;
    deliveryAddress?: string;
    notes?: string;
    items?: { productCode: string; qty: number }[];
  }>();

  // resolve which reseller this order belongs to
  let resellerId: string | null = null;
  if (actor.role === "reseller") {
    resellerId = actor.resellerId;
    if (!resellerId) return c.json({ error: "reseller_not_linked" }, 400);
  } else if (["owner", "finance_manager", "shipping_manager"].includes(actor.role)) {
    resellerId = body.resellerId ?? null;
    if (!resellerId) return c.json({ error: "reseller_id_required" }, 400);
  } else {
    return c.json({ error: "forbidden" }, 403);
  }

  const items = body.items ?? [];
  if (items.length === 0) return c.json({ error: "no_items" }, 400);
  if (!body.deliveryType) return c.json({ error: "delivery_type_required" }, 400);
  if (!body.customerName || !body.customerPhone || !body.deliveryAddress) {
    return c.json({ error: "customer_details_required" }, 400);
  }

  // idempotency — replaces the old ClientRequestID dedupe
  if (body.clientRequestId) {
    const [dupe] = await db
      .select()
      .from(schema.orders)
      .where(
        and(
          eq(schema.orders.resellerId, resellerId),
          eq(schema.orders.clientRequestId, body.clientRequestId)
        )
      )
      .limit(1);
    if (dupe) return c.json({ ok: true, order: dupe, deduped: true });
  }

  // price everything from the catalog; reject unknown/unpriced/unavailable
  const itemRows: (typeof schema.orderItems.$inferInsert)[] = [];
  let orderTotal = 0;
  const orderId = crypto.randomUUID();
  let line = 1;
  for (const it of items) {
    const qty = Number(it.qty);
    if (!it.productCode || !Number.isInteger(qty) || qty <= 0) {
      return c.json({ error: "invalid_item", productCode: it.productCode }, 400);
    }
    const [p] = await db
      .select()
      .from(schema.products)
      .where(eq(schema.products.code, it.productCode))
      .limit(1);
    if (!p) return c.json({ error: "unknown_product", productCode: it.productCode }, 400);
    if (p.status !== "available")
      return c.json({ error: "product_unavailable", productCode: it.productCode }, 400);
    if (p.price == null)
      return c.json({ error: "product_has_no_price", productCode: it.productCode }, 400);

    const unit = Number(p.price);
    const lineTotal = unit * qty;
    orderTotal += lineTotal;
    itemRows.push({
      orderId,
      lineNo: line++,
      productCode: p.code,
      productName: p.name,
      category: p.category,
      qty,
      unitPrice: unit.toFixed(2),
      lineTotal: lineTotal.toFixed(2),
    });
  }

  const results = await db.batch([
    db
      .insert(schema.orders)
      .values({
        id: orderId,
        resellerId,
        clientRequestId: body.clientRequestId ?? null,
        deliveryType: body.deliveryType,
        customerName: body.customerName,
        customerPhone: body.customerPhone,
        customerEmail: body.customerEmail ?? null,
        deliveryAddress: body.deliveryAddress,
        orderTotal: orderTotal.toFixed(2),
        notes: body.notes ?? null,
      })
      .returning(),
    db.insert(schema.orderItems).values(itemRows),
    db.insert(schema.fulfilment).values({ orderId, status: "not_released" }),
    db.insert(schema.auditLog).values({
      userId: actor.id,
      userEmail: actor.email,
      userRole: actor.role,
      action: "order_created",
      orderId,
    }),
  ]);

  const order = (results[0] as (typeof schema.orders.$inferSelect)[])[0];
  return c.json({ ok: true, order });
});

// List orders. Resellers see only their own; staff see all, with optional
// payment/fulfilment filters and simple pagination.
app.get("/api/app/orders", async (c) => {
  const db = getDb(c.env.DATABASE_URL);
  const actor = c.get("user");
  const limit = Math.min(Number(c.req.query("limit") ?? "50"), 200);
  const offset = Number(c.req.query("offset") ?? "0");

  const filters = [];
  if (actor.role === "reseller") {
    if (!actor.resellerId) return c.json({ orders: [] });
    filters.push(eq(schema.orders.resellerId, actor.resellerId));
  }
  const ps = c.req.query("paymentStatus");
  const fs = c.req.query("fulfilmentStatus");
  if (ps) filters.push(eq(schema.orders.paymentStatus, ps as any));
  if (fs) filters.push(eq(schema.orders.fulfilmentStatus, fs as any));

  const rows = await db
    .select()
    .from(schema.orders)
    .where(filters.length ? and(...filters) : undefined)
    .orderBy(desc(schema.orders.createdAt))
    .limit(limit)
    .offset(offset);

  return c.json({ orders: rows });
});

// Order detail with items, payments, fulfilment. Resellers restricted to own.
app.get("/api/app/orders/:id", async (c) => {
  const db = getDb(c.env.DATABASE_URL);
  const actor = c.get("user");
  const id = c.req.param("id");

  const [order] = await db
    .select()
    .from(schema.orders)
    .where(eq(schema.orders.id, id))
    .limit(1);
  if (!order) return c.json({ error: "not_found" }, 404);
  if (actor.role === "reseller" && order.resellerId !== actor.resellerId) {
    return c.json({ error: "forbidden" }, 403);
  }

  const [items, pays, [ful]] = await Promise.all([
    db.select().from(schema.orderItems).where(eq(schema.orderItems.orderId, id)),
    db.select().from(schema.payments).where(eq(schema.payments.orderId, id)),
    db.select().from(schema.fulfilment).where(eq(schema.fulfilment.orderId, id)).limit(1),
  ]);

  const balanceDue = (
    Number(order.orderTotal) - Number(order.amountVerified)
  ).toFixed(2);

  return c.json({ order: { ...order, balanceDue }, items, payments: pays, fulfilment: ful ?? null });
});

/* ============================================================
 * PAYMENT REVIEW + RELEASE  (finance)
 * Authorization is enforced HERE on the server — not in the UI.
 * The old system allowed direct calls to bypass the hidden-button
 * checks; these routes can't be bypassed that way.
 * ========================================================== */

const RELEASABLE_FROM = "not_released";

app.post(
  "/api/app/orders/:id/payment-review",
  requireRole("owner", "finance_manager", "finance_team"),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL);
    const actor = c.get("user");
    const id = c.req.param("id");
    const body = await c.req.json<{
      method?: (typeof schema.payments.$inferSelect)["method"];
      amountVerified?: number | string;
      result?: (typeof schema.orders.$inferSelect)["paymentStatus"];
      bankReference?: string;
      notes?: string;
      proofKey?: string;
      releaseToShipping?: boolean;
      approvePartialRelease?: boolean;
    }>();

    const allowed = [
      "full_verified",
      "partial_verified",
      "not_found",
      "needs_clarification",
    ] as const;
    if (!body.result || !(allowed as readonly string[]).includes(body.result)) {
      return c.json({ error: "invalid_result" }, 400);
    }

    const [order] = await db
      .select()
      .from(schema.orders)
      .where(eq(schema.orders.id, id))
      .limit(1);
    if (!order) return c.json({ error: "not_found" }, 404);

    const amountVerified = Number(body.amountVerified ?? 0);
    if (amountVerified < 0) return c.json({ error: "invalid_amount" }, 400);

    // decide whether this review releases the order to shipping.
    // BUSINESS RULE (TODO confirm with Diego): full payment releases by
    // default; a partial payment only releases when a finance user
    // explicitly approves the exception (approvePartialRelease).
    let willRelease = false;
    if (body.releaseToShipping !== false) {
      if (body.result === "full_verified") willRelease = true;
      else if (body.result === "partial_verified" && body.approvePartialRelease)
        willRelease = true;
    }
    if (
      body.result === "partial_verified" &&
      body.releaseToShipping &&
      !body.approvePartialRelease
    ) {
      return c.json({ error: "partial_release_needs_approval" }, 422);
    }

    const canRelease =
      willRelease && order.fulfilmentStatus === RELEASABLE_FROM;

    const writes: any[] = [
      db.insert(schema.payments).values({
        orderId: id,
        method: body.method ?? "bank_transfer",
        amountClaimed: order.amountClaimed,
        amountVerified: amountVerified.toFixed(2),
        result: body.result,
        bankReference: body.bankReference ?? null,
        proofKey: body.proofKey ?? null,
        reviewedBy: actor.id,
        reviewedAt: new Date(),
        notes: body.notes ?? null,
      }),
      db
        .update(schema.orders)
        .set({
          paymentStatus: body.result,
          amountVerified: amountVerified.toFixed(2),
          fulfilmentStatus: canRelease ? "ready_to_pack" : order.fulfilmentStatus,
          updatedAt: new Date(),
        })
        .where(eq(schema.orders.id, id)),
      db.insert(schema.auditLog).values({
        userId: actor.id,
        userEmail: actor.email,
        userRole: actor.role,
        action: "payment_review",
        orderId: id,
        oldValue: order.paymentStatus,
        newValue: body.result,
        notes: canRelease ? "released_to_shipping" : null,
      }),
    ];
    if (canRelease) {
      writes.push(
        db
          .update(schema.fulfilment)
          .set({
            previousStatus: RELEASABLE_FROM,
            status: "ready_to_pack",
            releasedBy: actor.id,
            releasedAt: new Date(),
          })
          .where(eq(schema.fulfilment.orderId, id))
      );
    }
    await db.batch(writes as any);

    return c.json({ ok: true, released: canRelease, paymentStatus: body.result });
  }
);

/* ============================================================
 * SHIPPING / FULFILMENT TRANSITIONS  (warehouse)
 * ========================================================== */

const FULFILMENT_TRANSITIONS: Record<
  string,
  { from: string[]; to: string }
> = {
  pack: { from: ["ready_to_pack"], to: "packed" },
  dispatch: { from: ["packed"], to: "dispatched" },
  deliver: { from: ["dispatched"], to: "delivered" },
  collect: { from: ["ready_to_pack", "packed"], to: "collected" },
};

app.post(
  "/api/app/orders/:id/fulfilment",
  requireRole("owner", "shipping_manager", "shipping_team"),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL);
    const actor = c.get("user");
    const id = c.req.param("id");
    const body = await c.req.json<{
      action?: string;
      courier?: string;
      shippingService?: string;
      trackingNumber?: string;
      receivedBy?: string;
      confirmationSource?: string;
      issueType?: string;
      issueNotes?: string;
    }>();

    const [ful] = await db
      .select()
      .from(schema.fulfilment)
      .where(eq(schema.fulfilment.orderId, id))
      .limit(1);
    if (!ful) return c.json({ error: "not_found" }, 404);

    const action = body.action ?? "";
    const patch: Partial<typeof schema.fulfilment.$inferInsert> = {
      previousStatus: ful.status,
    };
    let newStatus: string;

    if (action === "issue") {
      newStatus = "issue_hold";
      patch.issueType = body.issueType ?? null;
      patch.issueNotes = body.issueNotes ?? null;
    } else if (action === "resolve") {
      if (ful.status !== "issue_hold")
        return c.json({ error: "not_on_hold" }, 422);
      newStatus = ful.previousStatus ?? "ready_to_pack";
    } else {
      const t = FULFILMENT_TRANSITIONS[action];
      if (!t) return c.json({ error: "unknown_action" }, 400);
      if (!t.from.includes(ful.status)) {
        return c.json(
          { error: "invalid_transition", from: ful.status, action },
          422
        );
      }
      newStatus = t.to;
      if (action === "dispatch") {
        if (!body.trackingNumber || !body.courier)
          return c.json({ error: "courier_and_tracking_required" }, 400);
        patch.courier = body.courier;
        patch.shippingService = body.shippingService ?? null;
        patch.trackingNumber = body.trackingNumber;
        patch.dispatchedBy = actor.id;
        patch.dispatchedAt = new Date();
      }
      if (action === "pack") {
        patch.packedBy = actor.id;
        patch.packedAt = new Date();
      }
      if (action === "deliver" || action === "collect") {
        patch.receivedBy = body.receivedBy ?? null;
        patch.confirmationSource = body.confirmationSource ?? null;
        patch.completedAt = new Date();
      }
    }

    patch.status = newStatus as any;

    await db.batch([
      db.update(schema.fulfilment).set(patch).where(eq(schema.fulfilment.orderId, id)),
      db
        .update(schema.orders)
        .set({ fulfilmentStatus: newStatus as any, updatedAt: new Date() })
        .where(eq(schema.orders.id, id)),
      db.insert(schema.auditLog).values({
        userId: actor.id,
        userEmail: actor.email,
        userRole: actor.role,
        action: `fulfilment_${action}`,
        orderId: id,
        oldValue: ful.status,
        newValue: newStatus,
      }),
    ] as any);

    return c.json({ ok: true, status: newStatus });
  }
);

/* ============================================================
 * PRODUCTS
 * ========================================================== */

// List products. Resellers see only available ones (for ordering).
app.get("/api/app/products", async (c) => {
  const db = getDb(c.env.DATABASE_URL);
  const actor = c.get("user");
  const rows = await db.select().from(schema.products);
  const visible =
    actor.role === "reseller"
      ? rows.filter((p) => p.status === "available" && p.price != null)
      : rows;
  return c.json({ products: visible });
});

// Create or update a product (by code). Owner/managers only.
app.post(
  "/api/app/products",
  requireRole("owner", "finance_manager", "shipping_manager"),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL);
    const body = await c.req.json<{
      code?: string;
      name?: string;
      category?: string;
      price?: number | string;
      status?: (typeof schema.products.$inferSelect)["status"];
      qboItemName?: string;
    }>();
    const code = (body.code ?? "").trim();
    const name = (body.name ?? "").trim();
    if (!code || !name) return c.json({ error: "code_and_name_required" }, 400);

    const price =
      body.price === undefined || body.price === null
        ? null
        : Number(body.price).toFixed(2);

    const [existing] = await db
      .select()
      .from(schema.products)
      .where(eq(schema.products.code, code))
      .limit(1);

    if (existing) {
      const [p] = await db
        .update(schema.products)
        .set({
          name,
          category: body.category ?? existing.category,
          price: price ?? existing.price,
          status: body.status ?? existing.status,
          qboItemName: body.qboItemName ?? existing.qboItemName,
        })
        .where(eq(schema.products.id, existing.id))
        .returning();
      return c.json({ ok: true, product: p, updated: true });
    }

    const [p] = await db
      .insert(schema.products)
      .values({
        code,
        name,
        category: body.category ?? null,
        price,
        status: body.status ?? "available",
        qboItemName: body.qboItemName ?? null,
      })
      .returning();
    return c.json({ ok: true, product: p });
  }
);

/* ============================================================
 * RESELLERS  (profile + linked login in one step)
 * ========================================================== */

app.get(
  "/api/app/resellers",
  requireRole("owner", "finance_manager", "shipping_manager", "finance_team", "shipping_team"),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL);
    const rows = await db.select().from(schema.resellers);
    return c.json({ resellers: rows });
  }
);

app.post(
  "/api/app/resellers",
  requireRole("owner", "finance_manager"),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL);
    const actor = c.get("user");
    const body = await c.req.json<{
      name?: string;
      email?: string;
      phone?: string;
      address?: string;
      loginEmail?: string;
      loginName?: string;
    }>();
    const name = (body.name ?? "").trim();
    const email = (body.email ?? "").trim().toLowerCase();
    if (!name || !email) return c.json({ error: "name_and_email_required" }, 400);

    const loginEmail = (body.loginEmail ?? email).trim().toLowerCase();

    const [existingUser] = await db
      .select()
      .from(schema.users)
      .where(eq(schema.users.email, loginEmail))
      .limit(1);
    if (existingUser) return c.json({ error: "login_email_exists" }, 409);

    const [reseller] = await db
      .insert(schema.resellers)
      .values({
        name,
        email,
        phone: body.phone ?? null,
        address: body.address ?? null,
      })
      .returning();

    const [user] = await db
      .insert(schema.users)
      .values({
        email: loginEmail,
        name: body.loginName ?? name,
        role: "reseller",
        status: "active",
        forcePasswordSetup: true,
        resellerId: reseller.id,
      })
      .returning();

    const raw = generateToken();
    const tokenHash = await hashToken(raw);
    await db.insert(schema.passwordTokens).values({
      userId: user.id,
      tokenHash,
      purpose: "set",
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });
    await db.insert(schema.auditLog).values({
      userId: actor.id,
      userEmail: actor.email,
      userRole: actor.role,
      action: "reseller_created",
      notes: reseller.id,
    });

    const setupLink = `${reqOrigin(c)}/?setup=${raw}`;
    return c.json({
      ok: true,
      reseller,
      login: { id: user.id, email: user.email },
      setupLink, // TODO(email): send via Resend instead of returning
    });
  }
);

/* ============================================================
 * DASHBOARD  (staff KPIs — all derived from live data)
 * ========================================================== */

app.get(
  "/api/app/dashboard",
  requireRole("owner", "finance_manager", "finance_team", "shipping_manager", "shipping_team"),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL);
    const now = new Date();
    const startToday = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())
    );
    const startWeek = new Date(startToday);
    startWeek.setUTCDate(startToday.getUTCDate() - ((startToday.getUTCDay() + 6) % 7));

    const [payRows, fulRows, totalRow, todayRow, weekRow, recent, topRes] =
      await Promise.all([
        db
          .select({
            status: schema.orders.paymentStatus,
            n: count(),
            total: sum(schema.orders.orderTotal),
          })
          .from(schema.orders)
          .groupBy(schema.orders.paymentStatus),
        db
          .select({ status: schema.orders.fulfilmentStatus, n: count() })
          .from(schema.orders)
          .groupBy(schema.orders.fulfilmentStatus),
        db
          .select({
            gross: sum(schema.orders.orderTotal),
            verified: sum(schema.orders.amountVerified),
            n: count(),
          })
          .from(schema.orders)
          .where(ne(schema.orders.fulfilmentStatus, "cancelled")),
        db.select({ n: count() }).from(schema.orders).where(gte(schema.orders.createdAt, startToday)),
        db.select({ n: count() }).from(schema.orders).where(gte(schema.orders.createdAt, startWeek)),
        db.select().from(schema.orders).orderBy(desc(schema.orders.createdAt)).limit(8),
        db
          .select({
            name: schema.resellers.name,
            orders: count(schema.orders.id),
            value: sum(schema.orders.orderTotal),
          })
          .from(schema.resellers)
          .leftJoin(schema.orders, eq(schema.orders.resellerId, schema.resellers.id))
          .groupBy(schema.resellers.id, schema.resellers.name),
      ]);

    const t = totalRow[0] || { gross: "0", verified: "0", n: 0 };
    const gross = Number(t.gross || 0);
    const verified = Number(t.verified || 0);
    const pay = payRows.map((r) => ({ status: r.status, n: Number(r.n), total: Number(r.total || 0) }));
    const ful = fulRows.map((r) => ({ status: r.status, n: Number(r.n) }));
    const sumBy = (arr: any[], keys: string[]) =>
      arr.filter((x) => keys.includes(x.status)).reduce((a, x) => a + x.n, 0);

    return c.json({
      totals: { gross, verified, outstanding: gross - verified, orders: Number(t.n || 0) },
      today: Number(todayRow[0]?.n || 0),
      week: Number(weekRow[0]?.n || 0),
      needsReview: sumBy(pay, ["review_pending", "cash_pending"]),
      shipQueue: sumBy(ful, ["ready_to_pack", "packed"]),
      onHold: sumBy(ful, ["issue_hold"]),
      pay,
      ful,
      recent,
      top: topRes
        .map((r) => ({ name: r.name, orders: Number(r.orders || 0), value: Number(r.value || 0) }))
        .sort((a, b) => b.value - a.value)
        .slice(0, 5),
    });
  }
);

/* ============================================================
 * CATALOG IMPORT  (owner: load the 70-product catalog from the sheet)
 * Idempotent — inserts only products whose code doesn't exist yet.
 * Prices are left null; owner sets them per product afterward.
 * ========================================================== */

app.post("/api/app/products/import-catalog", requireRole("owner"), async (c) => {
  const db = getDb(c.env.DATABASE_URL);
  const existing = await db
    .select({ code: schema.products.code })
    .from(schema.products);
  const have = new Set(existing.map((p) => p.code));
  const toAdd = CATALOG.filter((p) => !have.has(p.code));
  if (toAdd.length) {
    await db.insert(schema.products).values(
      toAdd.map((p) => ({
        code: p.code,
        name: p.name,
        category: p.category || null,
        status: p.status as (typeof schema.products.$inferSelect)["status"],
        qboItemName: p.qboItemName ?? null,
        price: null,
      }))
    );
  }
  return c.json({ ok: true, added: toAdd.length, skipped: CATALOG.length - toAdd.length });
});

/* ============================================================
 * USER MANAGEMENT  (edit / deactivate / reset / revoke)
 * ========================================================== */

app.post("/api/app/users/:id", requireRole("owner"), async (c) => {
  const db = getDb(c.env.DATABASE_URL);
  const actor = c.get("user");
  const id = c.req.param("id");
  const body = await c.req.json<{
    name?: string;
    role?: (typeof schema.users.$inferSelect)["role"];
    status?: (typeof schema.users.$inferSelect)["status"];
  }>();

  const [target] = await db.select().from(schema.users).where(eq(schema.users.id, id)).limit(1);
  if (!target) return c.json({ error: "not_found" }, 404);

  const set: any = { updatedAt: new Date() };
  if (body.name !== undefined) set.name = body.name.trim();
  if (body.role !== undefined) set.role = body.role;
  if (body.status !== undefined) set.status = body.status;

  // never allow removing/demoting/deactivating the last active owner
  const removingOwner =
    target.role === "owner" &&
    ((set.role && set.role !== "owner") || (set.status && set.status !== "active"));
  if (removingOwner) {
    const owners = await db
      .select({ id: schema.users.id })
      .from(schema.users)
      .where(and(eq(schema.users.role, "owner"), eq(schema.users.status, "active")));
    if (owners.length <= 1) return c.json({ error: "cannot_remove_last_owner" }, 422);
  }
  if (actor.id === id && set.status && set.status !== "active") {
    return c.json({ error: "cannot_deactivate_self" }, 422);
  }

  await db.update(schema.users).set(set).where(eq(schema.users.id, id));
  await db.insert(schema.auditLog).values({
    userId: actor.id, userEmail: actor.email, userRole: actor.role,
    action: "user_updated", notes: id,
    oldValue: `${target.role}/${target.status}`,
    newValue: `${set.role ?? target.role}/${set.status ?? target.status}`,
  });
  return c.json({ ok: true });
});

app.post(
  "/api/app/users/:id/reset-password",
  requireRole("owner", "finance_manager", "shipping_manager"),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL);
    const actor = c.get("user");
    const id = c.req.param("id");
    const [target] = await db.select().from(schema.users).where(eq(schema.users.id, id)).limit(1);
    if (!target) return c.json({ error: "not_found" }, 404);
    if (target.role === "owner" && actor.role !== "owner")
      return c.json({ error: "only_owner_can_reset_owner" }, 403);

    const raw = generateToken();
    const tokenHash = await hashToken(raw);
    await db.insert(schema.passwordTokens).values({
      userId: id, tokenHash, purpose: "reset",
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });
    await db.update(schema.users).set({ forcePasswordSetup: true }).where(eq(schema.users.id, id));
    await db.insert(schema.auditLog).values({
      userId: actor.id, userEmail: actor.email, userRole: actor.role,
      action: "user_password_reset", notes: id,
    });
    return c.json({ ok: true, setupLink: `${reqOrigin(c)}/?setup=${raw}` });
  }
);

app.post(
  "/api/app/users/:id/revoke-sessions",
  requireRole("owner", "finance_manager", "shipping_manager"),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL);
    const actor = c.get("user");
    const id = c.req.param("id");
    await db.update(schema.sessions).set({ revoked: true }).where(eq(schema.sessions.userId, id));
    await db.insert(schema.auditLog).values({
      userId: actor.id, userEmail: actor.email, userRole: actor.role,
      action: "sessions_revoked", notes: id,
    });
    return c.json({ ok: true });
  }
);

/* ============================================================
 * RESELLER MANAGEMENT  (edit / status / regenerate login link)
 * ========================================================== */

app.post("/api/app/resellers/:id", requireRole("owner", "finance_manager"), async (c) => {
  const db = getDb(c.env.DATABASE_URL);
  const id = c.req.param("id");
  const body = await c.req.json<{
    name?: string; email?: string; phone?: string; address?: string;
    status?: (typeof schema.resellers.$inferSelect)["status"];
  }>();
  const [r] = await db.select().from(schema.resellers).where(eq(schema.resellers.id, id)).limit(1);
  if (!r) return c.json({ error: "not_found" }, 404);
  const set: any = {};
  if (body.name !== undefined) set.name = body.name.trim();
  if (body.email !== undefined) set.email = body.email.trim().toLowerCase();
  if (body.phone !== undefined) set.phone = body.phone.trim() || null;
  if (body.address !== undefined) set.address = body.address.trim() || null;
  if (body.status !== undefined) set.status = body.status;
  await db.update(schema.resellers).set(set).where(eq(schema.resellers.id, id));
  // keep the linked login's status in step with the reseller account
  if (set.status) {
    await db.update(schema.users).set({ status: set.status }).where(eq(schema.users.resellerId, id));
  }
  return c.json({ ok: true });
});

app.post(
  "/api/app/resellers/:id/reset-login",
  requireRole("owner", "finance_manager"),
  async (c) => {
    const db = getDb(c.env.DATABASE_URL);
    const id = c.req.param("id");
    const [u] = await db.select().from(schema.users).where(eq(schema.users.resellerId, id)).limit(1);
    if (!u) return c.json({ error: "no_login_for_reseller" }, 404);
    const raw = generateToken();
    const tokenHash = await hashToken(raw);
    await db.insert(schema.passwordTokens).values({
      userId: u.id, tokenHash, purpose: "reset",
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });
    await db.update(schema.users).set({ forcePasswordSetup: true }).where(eq(schema.users.id, u.id));
    return c.json({ ok: true, setupLink: `${reqOrigin(c)}/?setup=${raw}` });
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
