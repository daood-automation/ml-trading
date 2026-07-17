/**
 * Auth primitives for the Worker runtime.
 *
 * Fixes carried over from the review of the old Apps Script code:
 *  - Passwords are stretched with PBKDF2 (100k iterations) + per-user
 *    random salt. The old authHash_ was a single unsalted SHA-256 round,
 *    which cracks fast if a backup leaks.
 *  - Setup/reset tokens: we store ONLY a hash of the token. The raw token
 *    is emailed once and never persisted. The old system stored the full
 *    setup link (raw token included) in the sheet — an account-takeover hole.
 *  - Session tokens are random and stored hashed; the cookie holds the raw
 *    value, the DB holds its SHA-256. A DB leak can't be replayed as a login.
 *
 * Workers has WebCrypto (crypto.subtle) but no bcrypt/argon2 native module,
 * so PBKDF2 via WebCrypto is the correct stretching primitive here.
 */

const PBKDF2_ITERATIONS = 100_000;
const enc = new TextEncoder();

function toB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromB64(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/* ---------- passwords ---------- */

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    key,
    256
  );
  // format: pbkdf2$<iterations>$<salt_b64>$<hash_b64>
  return `pbkdf2$${PBKDF2_ITERATIONS}$${toB64(salt)}$${toB64(
    new Uint8Array(bits)
  )}`;
}

export async function verifyPassword(
  password: string,
  stored: string
): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = parseInt(parts[1], 10);
  const salt = fromB64(parts[2]);
  const expected = fromB64(parts[3]);
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    key,
    expected.length * 8
  );
  return constantTimeEqual(new Uint8Array(bits), expected);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/* ---------- opaque tokens (sessions + setup/reset) ---------- */

// A high-entropy random token. Returned raw once; only its hash is stored.
export function generateToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return toHex(bytes);
}

export async function hashToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(token));
  return toHex(new Uint8Array(digest));
}

/* ---------- session cookie config ---------- */

export const SESSION_COOKIE = "mlt_session";
export const SESSION_TTL_DAYS = 7;

export function sessionExpiry(): Date {
  return new Date(Date.now() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000);
}

/* ---------- account lockout (replaces nothing in old code — new control) ---------- */

export const MAX_FAILED_ATTEMPTS = 5;
export const LOCKOUT_MINUTES = 15;

export function lockoutUntil(): Date {
  return new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000);
}
