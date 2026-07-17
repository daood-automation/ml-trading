# MLT Ops — Build Status

Last updated by the build session that stood up the core spine.

## What is built and deployed (live on the Worker)

**Backend (Hono + Drizzle + Neon):**
- Password auth: login, logout, session cookie (httpOnly, hashed token in DB), account lockout after 5 failed attempts.
- Owner bootstrap (one-time), set-password flow (hashed tokens only), create-user with setup link.
- Orders: submit (server-priced from catalog, written atomically, idempotent via clientRequestId), list (role-scoped, filterable), detail (items + payments + fulfilment + derived balance).
- Payment review + release to shipping — **authorization enforced server-side**, not in the UI.
- Shipping transitions: pack, dispatch (requires courier+tracking), deliver, collect, issue-hold, resolve — with state-transition validation.
- Products: list + create/update (with price).
- Resellers: list + create (profile + linked login + setup link).
- Audit log written on every state change.
- `/api/health` returns `{ok, db:"connected"}`.

**Frontend:** single-file operations console served by the Worker. Login, set-password, role-based nav, orders list + detail with a payment→delivery state track, new-order wizard, shipping queue, product management, reseller management. All interpolated data is HTML-escaped.

**Pipeline:** push to `main` → GitHub Actions runs DB migrations against Neon → deploys the Worker.

## To start using it: create your owner login (one command)

The system has no users yet. Create yours by calling the bootstrap endpoint once
(replace the URL with your Worker URL, and pick your email/password):

```bash
curl -X POST https://YOUR-WORKER-URL/api/bootstrap-owner \
  -H "Content-Type: application/json" \
  -d '{"key":"THE_SESSION_SECRET","email":"you@example.com","password":"choose-a-strong-one","name":"Your Name"}'
```

`key` is the `SESSION_SECRET` value. This endpoint only works while no owner exists,
so it can't be abused later. Then open the Worker URL in a browser and sign in.

After that: add a product or two (with prices) under **Products**, then place a test
order to exercise the full flow.

## Decisions still needed (I did NOT guess these on a money system)

1. **Finance release rules.** Current rule: full payment releases to shipping; partial
   payment releases only if a finance user ticks the exception. Confirm this matches
   how Diego wants it, incl. cash handling. (marked `TODO(confirm)` in code)
2. **Product catalog + pricing.** Real product codes, names, prices — and whether pricing
   is flat or per-reseller. Orders reject products with no price set.
3. **Roles/users.** Which of the six roles map to real people on day one.
4. **Emails.** Which notifications matter (setup link, payment verified, dispatched).
   Setup links are currently RETURNED in the API response, not emailed — Resend not wired.

## Not yet built (was cut from the core-spine scope, add next)

- Email sending (Resend) — setup links, notifications.
- Payment-proof file upload (R2) — proofKey field exists; upload/download not wired.
- PrintNode picking sheets, CSV report exports, audit-log viewer UI.
- Dashboard/KPIs.

## Not production-ready until

- The decisions above are confirmed and real data is loaded.
- End-to-end tested with real accounts (login → order → review → ship).
- A security pass on the live flows.

## Security cleanup (do at end of build session)

- **Rotate the GitHub token** that was pasted in chat.
- **Reset the Neon database password** (the connection string was pasted in chat), then
  update the `DATABASE_URL` secret in both GitHub Actions and Cloudflare.
