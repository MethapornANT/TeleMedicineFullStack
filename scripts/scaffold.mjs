// scripts/scaffold.mjs
import { mkdirSync, writeFileSync, existsSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const R = (...p) => path.resolve(__dirname, "..", ...p);

function ensureDir(dirPath) {
  const full = R(dirPath);
  if (!existsSync(full)) mkdirSync(full, { recursive: true });
  return full;
}
function write(relPath, content) {
  const full = R(relPath);
  ensureDir(path.dirname(relPath));
  writeFileSync(full, content, "utf8");
}

// 1) โฟลเดอร์บางๆ
ensureDir("config");
ensureDir("scripts");

// 2) server.js
write("server.js", `import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { env } from "./config/env.js";
import { getHealth } from "./function.js";

const app = express();
app.use(express.json());

// Security baseline
app.use(helmet());
app.use(cors({ origin: "*", methods: ["GET","POST","PUT","DELETE","PATCH"] }));
app.use(rateLimit({
  windowMs: 60 * 1000,  // 1 นาที
  max: 120,             // 120 req/IP/นาที
  standardHeaders: true,
  legacyHeaders: false
}));

// Routes (ยังไม่ทำ API อื่น)
app.get("/health", async (req, res, next) => {
  try {
    const data = await getHealth();
    res.json(data);
  } catch (e) { next(e); }
});

// 404
app.use((req, res) => res.status(404).json({ error: "Not Found" }));

// Error handler
app.use((err, req, res, next) => {
  const status = err.statusCode || 500;
  res.status(status).json({ error: "INTERNAL_ERROR" });
});

app.listen(env.PORT, () => {
  console.log("server started on port", env.PORT);
});
`);

// 3) function.js
write("function.js", `// รวมฟังก์ชันทั้งหมดที่ server.js จะเรียกใช้ (สตับก่อน)
import { pool } from "./config/db.js";

/** ตรวจสุขภาพระบบแบบเบา ๆ */
export async function getHealth() {
  // จะลอง ping DB ก็ได้:
  // const [rows] = await pool.query("SELECT 1 AS ok");
  return { ok: true, ts: new Date().toISOString() };
}

/** ตัวอย่าง pattern ปลอดภัยสำหรับ query ในอนาคต:
export async function findUserByEmail(email) {
  const [rows] = await pool.query("SELECT id, email FROM users WHERE email = ?", [email]);
  return rows[0] || null;
}
*/
`);

// 4) config/env.js
write("config/env.js", `import "dotenv/config";
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
`);

// 5) config/db.js
write("config/db.js", `import mysql from "mysql2/promise";
import { env } from "./env.js";

// ใช้ Pool + Prepared Statements กัน SQL injection
export const pool = mysql.createPool({
  host: env.DB_HOST,
  port: env.DB_PORT,
  user: env.DB_USER,
  password: env.DB_PASS,
  database: env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true
});
`);

// 6) .env
write(".env", `NODE_ENV=development
PORT=4005
DB_HOST=192.168.1.42
DB_PORT=3306
DB_USER=root
DB_PASS=1234
DB_NAME=telemedicinedb
JWT_SECRET=few878f3hfh892f3
`);

// 7) package.json
write("package.json", `{
  "name": "telemed-backend",
  "type": "module",
  "version": "0.1.0",
  "scripts": {
    "dev": "nodemon server.js",
    "start": "node server.js"
  },
  "dependencies": {
    "cors": "^2.8.5",
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "express-rate-limit": "^7.3.0",
    "helmet": "^7.1.0",
    "mysql2": "^3.10.3",
    "zod": "^3.23.8"
  },
  "devDependencies": {
    "nodemon": "^3.1.7"
  }
}
`);

// 8) .gitignore
write(".gitignore", `node_modules
.env
npm-debug.log*
`);

// 9) README
write("README.md", `# Telemed Backend (Minimal Scaffold)
- Run: \`npm i\`, แล้ว \`npm run dev\`
- มี \`GET /health\` สำหรับเช็คระบบ
- Security baseline: helmet, cors, rate limit
- DB: mysql2/promise pool + prepared statements (ยังไม่ใส่ DDL ในโค้ด)
- โครงบาง ๆ ตามสั่ง: server.js + function.js
`);

console.log("Scaffold complete. Now run: npm i && npm run dev");
