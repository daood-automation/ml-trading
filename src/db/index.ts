import { drizzle } from "drizzle-orm/neon-http";
import { neon } from "@neondatabase/serverless";
import * as schema from "./schema";

// One connection per request on Workers. Neon's HTTP driver is
// designed for exactly this serverless pattern (no pooling to manage,
// unlike the raw pg client we would have needed on a long-lived server).
export function getDb(databaseUrl: string) {
  const sql = neon(databaseUrl);
  return drizzle(sql, { schema });
}

export type DB = ReturnType<typeof getDb>;
export { schema };
