import {
  pgTable,
  pgEnum,
  uuid,
  text,
  varchar,
  numeric,
  integer,
  timestamp,
  boolean,
  index,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";

/* ============================================================
 * ENUMS
 * Replaces the free-text status strings the Apps Script version
 * compared with .indexOf('verified') / .indexOf('hold') etc.
 * A constrained type here removes a whole class of the fragility
 * flagged in the old Code.gs.
 * ========================================================== */

export const userRole = pgEnum("user_role", [
  "owner",
  "finance_manager",
  "finance_team",
  "shipping_manager",
  "shipping_team",
  "reseller",
]);

export const accountStatus = pgEnum("account_status", [
  "active",
  "inactive",
  "removed",
]);

export const productStatus = pgEnum("product_status", [
  "available",
  "out_of_stock",
  "inactive",
]);

export const deliveryType = pgEnum("delivery_type", [
  "direct_to_customer",
  "reseller_self_order",
  "reseller_collection",
]);

// Single source of truth for where an order sits. The old system
// spread this across OrderStatus / PaymentResult / FulfilmentStatus /
// QBOStatus free-text columns; here payment and fulfilment are
// separate typed axes and the "order status" is derived, not stored.
export const paymentStatus = pgEnum("payment_status", [
  "awaiting_payment", // no payment claimed yet
  "review_pending", // non-cash claim, needs finance review
  "cash_pending", // cash claim, needs confirmation
  "partial_verified",
  "full_verified",
  "not_found", // finance could not find the payment
  "needs_clarification",
  "cancelled",
]);

export const fulfilmentStatus = pgEnum("fulfilment_status", [
  "not_released", // finance has not approved yet
  "ready_to_pack", // approved, in shipping queue
  "packed",
  "dispatched",
  "delivered",
  "collected",
  "issue_hold",
  "cancelled",
]);

export const qboStatus = pgEnum("qbo_status", [
  "not_ready",
  "pending",
  "recorded",
]);

export const paymentMethod = pgEnum("payment_method", [
  "bank_transfer",
  "other_bank",
  "cash",
  "none",
]);

/* ============================================================
 * USERS  (replaces Auth_Users + AdminUsers + Resellers login)
 * One table, one auth system. Resellers and staff both live here.
 * A reseller row additionally links to a resellers profile row.
 * ========================================================== */

export const users = pgTable(
  "users",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    email: varchar("email", { length: 255 }).notNull(),
    name: varchar("name", { length: 255 }).notNull(),
    role: userRole("role").notNull(),
    status: accountStatus("status").notNull().default("active"),

    // password auth
    passwordHash: text("password_hash"), // null until they complete setup
    forcePasswordSetup: boolean("force_password_setup").notNull().default(true),
    failedAttempts: integer("failed_attempts").notNull().default(0),
    lockedUntil: timestamp("locked_until", { withTimezone: true }),

    // reseller link (null for staff)
    resellerId: uuid("reseller_id"),

    lastLoginAt: timestamp("last_login_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => ({
    emailUnique: uniqueIndex("users_email_unique").on(t.email),
    roleIdx: index("users_role_idx").on(t.role),
  })
);

/* ============================================================
 * RESELLERS  (business profile, separate from login identity)
 * ========================================================== */

export const resellers = pgTable(
  "resellers",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    name: varchar("name", { length: 255 }).notNull(),
    email: varchar("email", { length: 255 }).notNull(),
    phone: varchar("phone", { length: 64 }),
    address: text("address"),
    status: accountStatus("status").notNull().default("active"),
    receiveStatusEmails: boolean("receive_status_emails")
      .notNull()
      .default(false),
    notes: text("notes"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => ({
    emailUnique: uniqueIndex("resellers_email_unique").on(t.email),
  })
);

/* ============================================================
 * SESSIONS  (replaces the OTP_Login / Auth_Sessions token rows)
 * Opaque token in an httpOnly cookie -> row here.
 * ========================================================== */

export const sessions = pgTable(
  "sessions",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    token: text("token").notNull(), // random, stored hashed in prod
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revoked: boolean("revoked").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => ({
    tokenUnique: uniqueIndex("sessions_token_unique").on(t.token),
    userIdx: index("sessions_user_idx").on(t.userId),
  })
);

/* ============================================================
 * PASSWORD SETUP / RESET TOKENS
 * Store ONLY the hash. No SetupLink column, no raw-token fallback
 * (that fallback in the old Auth_System.gs defeated the hashing).
 * ========================================================== */

export const passwordTokens = pgTable(
  "password_tokens",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    purpose: varchar("purpose", { length: 32 }).notNull(), // 'set' | 'reset'
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    usedAt: timestamp("used_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => ({
    hashIdx: index("password_tokens_hash_idx").on(t.tokenHash),
  })
);

/* ============================================================
 * PRODUCTS
 * ========================================================== */

export const products = pgTable(
  "products",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    code: varchar("code", { length: 64 }).notNull(),
    name: varchar("name", { length: 255 }).notNull(),
    category: varchar("category", { length: 128 }),
    status: productStatus("status").notNull().default("available"),
    qboItemName: varchar("qbo_item_name", { length: 255 }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => ({
    codeUnique: uniqueIndex("products_code_unique").on(t.code),
    statusIdx: index("products_status_idx").on(t.status),
  })
);

/* ============================================================
 * ORDERS
 * Money is numeric, not parsed strings. Dates are timestamptz.
 * Payment and fulfilment are separate typed axes.
 * ========================================================== */

export const orders = pgTable(
  "orders",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    // human-facing sequential id (ORD-0001). Generated in a txn.
    orderNo: varchar("order_no", { length: 32 }).notNull(),

    // idempotency: replaces the ClientRequestID dedupe in submitResellerOrder
    clientRequestId: varchar("client_request_id", { length: 128 }),

    resellerId: uuid("reseller_id")
      .notNull()
      .references(() => resellers.id),

    deliveryType: deliveryType("delivery_type").notNull(),

    customerName: varchar("customer_name", { length: 255 }).notNull(),
    customerPhone: varchar("customer_phone", { length: 64 }).notNull(),
    customerEmail: varchar("customer_email", { length: 255 }),
    deliveryAddress: text("delivery_address").notNull(),

    // money — numeric, never a formatted string
    orderTotal: numeric("order_total", { precision: 12, scale: 2 })
      .notNull()
      .default("0"),
    amountClaimed: numeric("amount_claimed", { precision: 12, scale: 2 })
      .notNull()
      .default("0"),
    amountVerified: numeric("amount_verified", { precision: 12, scale: 2 })
      .notNull()
      .default("0"),

    paymentMethod: paymentMethod("payment_method").notNull().default("none"),
    paymentStatus: paymentStatus("payment_status")
      .notNull()
      .default("awaiting_payment"),
    fulfilmentStatus: fulfilmentStatus("fulfilment_status")
      .notNull()
      .default("not_released"),
    qboStatus: qboStatus("qbo_status").notNull().default("not_ready"),

    notes: text("notes"),

    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => ({
    orderNoUnique: uniqueIndex("orders_order_no_unique").on(t.orderNo),
    clientReqIdx: index("orders_client_req_idx").on(t.clientRequestId),
    resellerIdx: index("orders_reseller_idx").on(t.resellerId),
    paymentStatusIdx: index("orders_payment_status_idx").on(t.paymentStatus),
    fulfilmentStatusIdx: index("orders_fulfilment_status_idx").on(
      t.fulfilmentStatus
    ),
    createdAtIdx: index("orders_created_at_idx").on(t.createdAt),
  })
);

// balanceDue is derived (orderTotal - amountVerified), not stored,
// so it can never drift out of sync the way the old BalanceDue column could.

/* ============================================================
 * ORDER ITEMS
 * ========================================================== */

export const orderItems = pgTable(
  "order_items",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orderId: uuid("order_id")
      .notNull()
      .references(() => orders.id, { onDelete: "cascade" }),
    lineNo: integer("line_no").notNull(),
    productCode: varchar("product_code", { length: 64 }).notNull(),
    productName: varchar("product_name", { length: 255 }).notNull(),
    category: varchar("category", { length: 128 }),
    qty: integer("qty").notNull(),
    unitPrice: numeric("unit_price", { precision: 12, scale: 2 }).notNull(),
    lineTotal: numeric("line_total", { precision: 12, scale: 2 }).notNull(),
  },
  (t) => ({
    orderIdx: index("order_items_order_idx").on(t.orderId),
  })
);

/* ============================================================
 * PAYMENTS  (one row per payment review event)
 * ========================================================== */

export const payments = pgTable(
  "payments",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orderId: uuid("order_id")
      .notNull()
      .references(() => orders.id, { onDelete: "cascade" }),
    method: paymentMethod("method").notNull(),
    amountClaimed: numeric("amount_claimed", { precision: 12, scale: 2 })
      .notNull()
      .default("0"),
    amountVerified: numeric("amount_verified", { precision: 12, scale: 2 })
      .notNull()
      .default("0"),
    result: paymentStatus("result").notNull(),
    bankReference: varchar("bank_reference", { length: 255 }),
    // R2 object key for the proof, not a Drive URL
    proofKey: text("proof_key"),
    reviewedBy: uuid("reviewed_by").references(() => users.id),
    reviewedAt: timestamp("reviewed_at", { withTimezone: true }),
    notes: text("notes"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => ({
    orderIdx: index("payments_order_idx").on(t.orderId),
  })
);

/* ============================================================
 * FULFILMENT  (shipping detail, one row per order)
 * ========================================================== */

export const fulfilment = pgTable(
  "fulfilment",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orderId: uuid("order_id")
      .notNull()
      .references(() => orders.id, { onDelete: "cascade" }),
    status: fulfilmentStatus("status").notNull().default("not_released"),
    previousStatus: fulfilmentStatus("previous_status"),

    releasedBy: uuid("released_by").references(() => users.id),
    releasedAt: timestamp("released_at", { withTimezone: true }),
    packedBy: uuid("packed_by").references(() => users.id),
    packedAt: timestamp("packed_at", { withTimezone: true }),
    dispatchedBy: uuid("dispatched_by").references(() => users.id),
    dispatchedAt: timestamp("dispatched_at", { withTimezone: true }),
    completedAt: timestamp("completed_at", { withTimezone: true }),

    courier: varchar("courier", { length: 128 }),
    shippingService: varchar("shipping_service", { length: 128 }),
    trackingNumber: varchar("tracking_number", { length: 128 }),
    receivedBy: varchar("received_by", { length: 255 }),
    confirmationSource: varchar("confirmation_source", { length: 255 }),
    proofUrl: text("proof_url"),

    issueType: varchar("issue_type", { length: 128 }),
    issueNotes: text("issue_notes"),
    notes: text("notes"),
  },
  (t) => ({
    orderUnique: uniqueIndex("fulfilment_order_unique").on(t.orderId),
  })
);

/* ============================================================
 * AUDIT LOG
 * ========================================================== */

export const auditLog = pgTable(
  "audit_log",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    userId: uuid("user_id").references(() => users.id),
    userEmail: varchar("user_email", { length: 255 }),
    userRole: userRole("user_role"),
    action: varchar("action", { length: 64 }).notNull(),
    orderId: uuid("order_id"),
    oldValue: text("old_value"),
    newValue: text("new_value"),
    notes: text("notes"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => ({
    createdAtIdx: index("audit_log_created_at_idx").on(t.createdAt),
    orderIdx: index("audit_log_order_idx").on(t.orderId),
  })
);

/* ============================================================
 * RELATIONS
 * ========================================================== */

export const usersRelations = relations(users, ({ one }) => ({
  reseller: one(resellers, {
    fields: [users.resellerId],
    references: [resellers.id],
  }),
}));

export const ordersRelations = relations(orders, ({ one, many }) => ({
  reseller: one(resellers, {
    fields: [orders.resellerId],
    references: [resellers.id],
  }),
  items: many(orderItems),
  payments: many(payments),
  fulfilment: one(fulfilment, {
    fields: [orders.id],
    references: [fulfilment.orderId],
  }),
}));

export const orderItemsRelations = relations(orderItems, ({ one }) => ({
  order: one(orders, {
    fields: [orderItems.orderId],
    references: [orders.id],
  }),
}));

export const paymentsRelations = relations(payments, ({ one }) => ({
  order: one(orders, {
    fields: [payments.orderId],
    references: [orders.id],
  }),
}));

export const fulfilmentRelations = relations(fulfilment, ({ one }) => ({
  order: one(orders, {
    fields: [fulfilment.orderId],
    references: [orders.id],
  }),
}));
