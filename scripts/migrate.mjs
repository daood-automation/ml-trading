import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";
import { migrate } from "drizzle-orm/neon-http/migrator";

const url = process.env.DATABASE_URL;
if (!url) {
  console.error("DATABASE_URL is not set");
  process.exit(1);
}

const sql = neon(url);
const db = drizzle(sql);

console.log("Applying migrations from ./drizzle ...");
await migrate(db, { migrationsFolder: "./drizzle" });
console.log("Migrations applied.");
