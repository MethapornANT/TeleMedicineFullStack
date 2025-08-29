import "dotenv/config";
import { z } from "zod";

const EnvSchema = z.object({
  PORT: z.coerce.number().default(4005),
  NODE_ENV: z.enum(["development","test","production"]).default("development"),
  DB_HOST: z.string(),
  DB_PORT: z.coerce.number(),
  DB_USER: z.string(),
  DB_PASS: z.string(),
  DB_NAME: z.string(),
  JWT_SECRET: z.string().min(16, "JWT_SECRET too short")
});

export const env = EnvSchema.parse(process.env);
