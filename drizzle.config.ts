import { defineConfig } from "drizzle-kit";

// Reads DATABASE_URL from your environment (.env locally).
// This is only used by drizzle-kit for generating/pushing migrations
// from your laptop — the Worker itself connects separately at runtime.
export default defineConfig({
  schema: "./src/db/schema.ts",
  out: "./drizzle",
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_URL!,
  },
  verbose: true,
  strict: true,
});
