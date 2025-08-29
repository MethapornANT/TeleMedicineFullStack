import mysql from "mysql2/promise";
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
