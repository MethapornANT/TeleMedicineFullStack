// server.js
/**
 * Telemedicine Backend (single-file)
 * - Security: helmet, cors, rate-limit
 * - Validation: zod -> message ภาษาไทย
 * - Error format เดียวทั้งระบบ
 *
 * NOTE: ตั้ง env vars ก่อนรัน (PORT, DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, JWT_SECRET)
 */

///////////////////////////////
// 1) IMPORTS
///////////////////////////////
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import mysql from "mysql2/promise";
import Redis from "ioredis";
import swaggerUi from "swagger-ui-express";
import fs from "fs";
import path from "path";
import multer from "multer";
import { fileURLToPath } from "url";


///////////////////////////////
// 2) CONFIG / ENV
///////////////////////////////
const env = {
  PORT: process.env.PORT || 4005,
  DB_HOST: process.env.DB_HOST || "localhost",
  DB_PORT: Number(process.env.DB_PORT || 3306),
  DB_USER: process.env.DB_USER || "root",
  DB_PASSWORD: process.env.DB_PASSWORD || process.env.DB_PASS || "1234",
  DB_NAME: process.env.DB_NAME || "telemedicinedb",
  JWT_SECRET: process.env.JWT_SECRET || "change-me-very-secret",
  REDIS_URL: process.env.REDIS_URL || "",
};

///////////////////////////////
// 3) DB POOL
///////////////////////////////
const pool = mysql.createPool({
  host: env.DB_HOST,
  port: env.DB_PORT,
  user: env.DB_USER,
  password: env.DB_PASSWORD,
  database: env.DB_NAME,
  connectionLimit: 10,
  waitForConnections: true,
});

///////////////////////////////
// 4) EXPRESS APP + MIDDLEWARE
///////////////////////////////
const app = express();
app.set("trust proxy", process.env.NODE_ENV === "production" ? 1 : false);
app.use(express.json());
app.use(
  helmet({
    // อนุญาตให้ resource (ภาพใน /uploads) ถูกฝังข้าม origin
    crossOriginResourcePolicy: { policy: "cross-origin" },

    // ถ้าเปิดใช้งาน COEP ที่เข้มงวด อาจต้องปิดหรือปรับด้วย:
    crossOriginEmbedderPolicy: false,
  })
);
const allowOrigins = (process.env.ALLOW_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: allowOrigins.length ? allowOrigins : "*",
  credentials: !!allowOrigins.length,
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH"]
}));

// global rate-limit (ทั้งหมด)
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      return res.status(429).json({
        error: {
          code: "RATE_LIMITED",
          message:
            "ขออภัย มีการเรียกใช้งานบ่อยเกินไป กรุณาลองใหม่อีกครั้งภายหลัง",
        },
      });
    },
  })
);

// login endpoint rate-limit (ต่อ IP)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 นาที
  max: 6, // อนุญาต 6 ครั้ง/หน้าต่างเวลา
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: {
      code: "RATE_LIMITED",
      message: "ลองเข้าสู่ระบบมากเกินไป กรุณารอแล้วลองใหม่อีกครั้ง",
    },
  },
});

// (debug) ดู IP ที่ระบบเห็น
// app.use((req, _res, next) => {
//   console.log("[CLIENT IP]", req.ip, "xff:", req.headers["x-forwarded-for"]);
//   next();
// });

// --------------------------- UPLOADS CONFIG ---------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const UPLOAD_DIR = path.resolve(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ก่อน app.use("/uploads", express.static(UPLOAD_DIR));
app.use("/uploads", (req, res, next) => {
  // Allow fetch/embed from any origin
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
  next();
}, express.static(UPLOAD_DIR));


// จำกัดไฟล์ภาพเท่านั้น
const fileFilter = (_req, file, cb) => {
  const allowed = ["image/jpeg", "image/png", "image/webp", "image/jpg"];
  if (allowed.includes(file.mimetype)) return cb(null, true);
  cb(new Error("ชนิดไฟล์ไม่รองรับ"));
};

// ชื่อไฟล์ใหม่แบบแฮชกันชน
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    const ts = Date.now().toString();
    const rnd = crypto.randomBytes(16).toString("hex");
    const hash = crypto.createHash("md5").update(`${ts}-${rnd}-${file.originalname || ""}`).digest("hex");
    cb(null, `${ts}_${hash}${ext}`);
  },
});

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
});

// ลบไฟล์เก่าอย่างปลอดภัย
function deleteFileSafe(publicPath) {
  try {
    if (!publicPath || !publicPath.startsWith("/uploads/")) return;
    const full = path.join(UPLOAD_DIR, publicPath.replace("/uploads/", ""));
    if (full.startsWith(UPLOAD_DIR) && fs.existsSync(full)) fs.unlinkSync(full);
  } catch {}
}

///////////////////////////////
// 5) REDIS & IP-BLOCK HELPERS
///////////////////////////////
let redisClient = null;
const useRedis = !!env.REDIS_URL;
if (useRedis) {
  redisClient = new Redis(env.REDIS_URL);
  redisClient.on("error", (e) => console.error("Redis error:", e));
}

// fallback in-memory (หายเมื่อรีสตาร์ท)
const ipBlocks = new Map(); // ip -> untilTs

async function blockIp(ip, seconds) {
  if (!ip) return;
  if (useRedis && redisClient) {
    await redisClient.setex(`ipblock:${ip}`, seconds, "1");
  } else {
    ipBlocks.set(ip, Date.now() + seconds * 1000);
  }
}
async function isIpBlocked(ip) {
  if (!ip) return false;
  if (useRedis && redisClient) {
    const v = await redisClient.get(`ipblock:${ip}`);
    return !!v;
  } else {
    const until = ipBlocks.get(ip);
    if (!until) return false;
    if (Date.now() > until) {
      ipBlocks.delete(ip);
      return false;
    }
    return true;
  }
}
async function unblockIp(ip) {
  if (!ip) return;
  if (useRedis && redisClient) {
    await redisClient.del(`ipblock:${ip}`);
  } else {
    ipBlocks.delete(ip);
  }
}

function getClientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (xf) return xf.split(",")[0].trim();
  return req.ip || req.connection?.remoteAddress || "";
}

// escalation: ครั้งที่ถูกล็อก (0-based) → ระยะเวลา (วินาที)
function getLockDurationSeconds(lockCount) {
  if (lockCount <= 0) return 30 * 60;
  if (lockCount === 1) return 60 * 60;
  if (lockCount === 2) return 90 * 60;
  if (lockCount === 3) return 120 * 60;
  return 24 * 60 * 60;
}

///////////////////////////////
// 6) GENERIC HELPERS
///////////////////////////////
function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function formatZod(err) {
  return (
    err.issues?.map((i) => ({
      field: i.path?.join(".") || "",
      message: i.message,
    })) || []
  );
}
function respondValidation(res, err) {
  return res.status(400).json({
    error: {
      code: "VALIDATION_ERROR",
      message: "กรุณากรอกข้อมูลให้ครบถ้วนและถูกต้อง",
      details: formatZod(err),
    },
  });
}

function getTokenFromReq(req) {
  // รองรับ Authorization ทุกทรง + ตัดเครื่องหมาย quote ทิ้ง
  const raw = req.get("authorization") || req.get("Authorization") || "";
  let token = null;
  const m = raw.match(/Bearer\s+(.+)/i);
  if (m && m[1]) token = m[1].trim().replace(/^"(.+)"$/, "$1").replace(/^'(.+)'$/, "$1");

  // ช่องทางสำรอง
  if (!token && req.headers["x-access-token"]) token = String(req.headers["x-access-token"]).trim();
  if (!token && req.query && (req.query.access_token || req.query.token)) {
    token = String(req.query.access_token || req.query.token).trim();
  }
  return token || null;
}

function requireAuth(roles = []) {
  return (req, res, next) => {
    try {
      const token = getTokenFromReq(req);
      if (!token) {
        return res.status(401).json({
          error: { code: "UNAUTHORIZED", message: "กรุณาเข้าสู่ระบบก่อน" },
        });
      }

      const payload = verifyJwt(token); // จะ throw ถ้าเสีย/หมดอายุ
      if (roles.length && !roles.includes(payload.role)) {
        return res.status(403).json({
          error: { code: "FORBIDDEN", message: "ไม่มีสิทธิ์เข้าถึงทรัพยากรนี้" },
        });
      }

      req.user = payload;
      next();
    } catch {
      return res.status(401).json({
        error: {
          code: "UNAUTHORIZED",
          message: "โทเค็นไม่ถูกต้องหรือหมดอายุ กรุณาเข้าสู่ระบบใหม่",
        },
      });
    }
  };
}


///////////////////////////////
// 7) UTILS (ID / TIME / PASSWORD / JWT)
///////////////////////////////
function genId(kind) {
  const prefixMap = { doctor: "D", patient: "P", slot: "S", appt: "A", spec: "SP" };
  const p = prefixMap[kind] || "X";
  const ts = Date.now().toString();
  let rand = "";
  while (p.length + ts.length + rand.length < 36) rand += Math.floor(Math.random() * 10);
  return (p + ts + rand).slice(0, 36);
}

function looksLikeId(s) {
  return typeof s === "string" && s.length === 36;
}

// เป็นตัวเลขล้วนไหม (สำหรับ id แบบ INT)
function isNumericId(v) {
  return typeof v === "string" && /^\d+$/.test(v);
}

// === Helpers for date-only slots (daily model) ===
function isDateOnly(s) {
  return typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s);
}
function atStartOfDay(dateStr/* YYYY-MM-DD */) {
  const d = new Date(`${dateStr}T00:00:00`);
  return d;
}
function atEndOfDay(dateStr/* YYYY-MM-DD */) {
  const d = new Date(`${dateStr}T23:59:59`);
  return d;
}
function enumerateDailyFromSlot(startIso, endIso) {
  const d0 = new Date(startIso); d0.setHours(0,0,0,0);
  const d1 = new Date(endIso);   d1.setHours(0,0,0,0);
  const out = [];
  for (let d = new Date(d0); d.getTime() <= d1.getTime(); d.setDate(d.getDate()+1)) {
    const y = d.getFullYear();
    const m = String(d.getMonth()+1).padStart(2,"0");
    const dd = String(d.getDate()).padStart(2,"0");
    out.push(`${y}-${m}-${dd}`);
  }
  return out;
}


function toSqlDatetime(isoString) {
  const d = new Date(isoString);
  if (Number.isNaN(d.getTime())) {
    const e = new Error("รูปแบบเวลาไม่ถูกต้อง");
    e.statusCode = 400;
    e.code = "INVALID_DATETIME";
    throw e;
  }
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(
    d.getHours()
  )}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `scrypt$1$${salt}$${hash}`;
}
function verifyPassword(password, stored) {
  try {
    const [algo, _v, salt, hash] = stored.split("$");
    if (algo !== "scrypt") return false;
    const verify = crypto.scryptSync(password, salt, 64).toString("hex");
    return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(verify, "hex"));
  } catch {
    return false;
  }
}

function issueJwt(payload, expiresIn = "2h") {
  // ตั้งค่า default = 2 ชั่วโมง
  return jwt.sign(payload, env.JWT_SECRET, { algorithm: "HS256", expiresIn });
}
function verifyJwt(token) {
  return jwt.verify(token, env.JWT_SECRET, { algorithms: ["HS256"] });
}

///////////////////////////////
// 8) BUSINESS / DB FUNCTIONS
//    (Prepared statements only)
///////////////////////////////
export async function registerUser({ role, full_name, email, phone, password, specialties, userpicPath }) {
  const id = genId(role === "doctor" ? "doctor" : "patient");
  const password_hash = hashPassword(password);

  const sql =
    "INSERT INTO users (id, role, full_name, email, phone, password_hash, userpic) VALUES (?, ?, ?, ?, ?, ?, ?)";

  try {
    await pool.query(sql, [id, role, full_name, email, phone || null, password_hash, userpicPath || null]);

    if (role === "doctor" && Array.isArray(specialties) && specialties.length) {
      const values = specialties.map((sid) => [id, sid]);
      const insertSql = "INSERT IGNORE INTO doctor_specialties (doctor_id, specialty_id) VALUES ?";
      await pool.query(insertSql, [values]);
    }

    return {
      id,
      role,
      full_name,
      email,
      phone: phone || null,
      userpic: userpicPath || null,
      specialties: specialties || [],
    };
  } catch (err) {
    if (err?.code === "ER_DUP_ENTRY") {
      const e = new Error("อีเมลหรือเบอร์โทรนี้ถูกใช้ไปแล้ว");
      e.statusCode = 409;
      e.code = "DUPLICATE";
      throw e;
    }
    throw err;
  }
}


export async function listAllSpecialties() {
  const [rows] = await pool.query(
    "SELECT id, name FROM specialties ORDER BY name ASC"
  );
  return rows;
}

export async function setDoctorSpecialties(doctorId, specialtyIds = []) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // ตรวจสอบว่า doctorId เป็นหมอจริง
    const [users] = await conn.query("SELECT role FROM users WHERE id = ?", [doctorId]);
    if (!users[0]) {
      const e = new Error("ไม่พบผู้ใช้");
      e.statusCode = 404; e.code = "USER_NOT_FOUND";
      throw e;
    }
    if (users[0].role !== "doctor") {
      const e = new Error("อัปเดตสาขาได้เฉพาะผู้ใช้ที่เป็นหมอ");
      e.statusCode = 403; e.code = "FORBIDDEN";
      throw e;
    }

    // เคลียร์ของเดิมก่อน
    await conn.query("DELETE FROM doctor_specialties WHERE doctor_id = ?", [doctorId]);

    // ว่างก็จบได้เลย
    if (!specialtyIds.length) {
      await conn.commit();
      return [];
    }

    // ตรวจสอบว่า id ที่ส่งมามีอยู่จริงใน specialties
    const placeholders = specialtyIds.map(() => "?").join(",");
    const [exists] = await conn.query(
      `SELECT id FROM specialties WHERE id IN (${placeholders})`,
      specialtyIds
    );
    if (exists.length !== specialtyIds.length) {
      const e = new Error("มี specialty_id บางรายการไม่ถูกต้อง");
      e.statusCode = 400; e.code = "INVALID_SPECIALTY_ID";
      throw e;
    }

    // ใส่ใหม่ทั้งหมดแบบ bulk
    const values = specialtyIds.map(sid => [doctorId, sid]);
    const bulkPlaceholders = values.map(() => "(?, ?)").join(",");
    await conn.query(
      `INSERT INTO doctor_specialties (doctor_id, specialty_id) VALUES ${bulkPlaceholders}`,
      values.flat()
    );

    await conn.commit();
    return specialtyIds;
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

// เก็บไว้ให้เรียกใช้ที่อื่นได้ ถ้าอยากใช้แบบเดิม (ไม่ใช่ตัว escalated logic)
// ใน route /auth/login เราจะใช้ logic แบบ escalated + IP block ด้านล่าง
export async function loginUser(email, password) {
  const e = (email || "").trim().toLowerCase();
  const [rows] = await pool.query(
    "SELECT id, role, full_name, email, phone, password_hash, failed_login_attempts, locked_until FROM users WHERE email = ? LIMIT 1",
    [e]
  );
  const u = rows[0];

  const invalid = () => {
    const err = new Error("อีเมลหรือรหัสผ่านไม่ถูกต้อง");
    err.statusCode = 401;
    err.code = "INVALID_CREDENTIALS";
    return err;
  };

  if (!u) throw invalid();

  if (u.locked_until && new Date(u.locked_until) > new Date()) {
    const mLeft = Math.ceil((new Date(u.locked_until) - new Date()) / 60000);
    const err = new Error(`บัญชีถูกล็อกชั่วคราว ลองอีกครั้งใน ${mLeft} นาที`);
    err.statusCode = 423;
    err.code = "ACCOUNT_LOCKED";
    throw err;
  }

  const ok = verifyPassword(password, u.password_hash);
  if (!ok) {
    const newFailed = (u.failed_login_attempts || 0) + 1;
    if (newFailed >= 5) {
      const lockUntil = new Date(Date.now() + 30 * 60 * 1000);
      await pool.query(
        "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
        [newFailed, lockUntil, u.id]
      );
      const err = new Error(`พยายามเข้าสู่ระบบผิดหลายครั้ง บัญชีถูกล็อก 30 นาที`);
      err.statusCode = 423;
      err.code = "ACCOUNT_LOCKED";
      throw err;
    } else {
      await pool.query("UPDATE users SET failed_login_attempts = ? WHERE id = ?", [
        newFailed,
        u.id,
      ]);
      throw invalid();
    }
  }

  // success
  await pool.query(
    "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
    [u.id]
  );
  const token = issueJwt({ sub: u.id, role: u.role }); // 2h
  return {
    token,
    user: { id: u.id, role: u.role, full_name: u.full_name, email: u.email, phone: u.phone },
  };
}

export async function getUserProfile(userId) {
  const [rows] = await pool.query(
    "SELECT id, role, full_name, email, phone, userpic, created_at, updated_at FROM users WHERE id = ? LIMIT 1",
    [userId]
  );
  if (!rows[0]) {
    const e = new Error("ไม่พบผู้ใช้");
    e.statusCode = 404;
    e.code = "NOT_FOUND";
    throw e;
  }
  return rows[0];
}


export async function updateUserProfile(userId, patch) {
  // patch อาจมี: full_name, phone, specialty_ids, userpicPath
  const fields = [];
  const params = [];

  if (typeof patch.full_name === "string" && patch.full_name.length) {
    fields.push("full_name = ?");
    params.push(patch.full_name);
  }
  if (typeof patch.phone !== "undefined") {
    fields.push("phone = ?");
    params.push(patch.phone || null);
  }

  // จัดการรูปโปรไฟล์
  let oldPic = null;
  if (typeof patch.userpicPath !== "undefined") {
    // ดึงรูปเก่า
    const [urows] = await pool.query("SELECT userpic FROM users WHERE id = ? LIMIT 1", [userId]);
    oldPic = urows[0]?.userpic || null;

    fields.push("userpic = ?");
    params.push(patch.userpicPath || null);
  }

  // อัปเดตข้อมูลพื้นฐานก่อน (ถ้ามี)
  if (fields.length) {
    const sql = `UPDATE users SET ${fields.join(", ")}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
    try {
      await pool.query(sql, [...params, userId]);
    } catch (err) {
      if (err?.code === "ER_DUP_ENTRY") {
        const e = new Error("อีเมล/เบอร์โทรนี้ถูกใช้แล้ว");
        e.statusCode = 409; e.code = "DUPLICATE";
        throw e;
      }
      throw err;
    }
  }

  // specialties (เฉพาะหมอ)
  if (Array.isArray(patch.specialty_ids)) {
    await setDoctorSpecialties(userId, patch.specialty_ids);
  }

  // ลบไฟล์เก่าหลังอัปเดตรูปใหม่เรียบร้อย
  if (typeof patch.userpicPath !== "undefined" && oldPic && oldPic !== patch.userpicPath) {
    deleteFileSafe(oldPic);
  }

  // คืนโปรไฟล์ล่าสุด
  const [rows] = await pool.query(
    "SELECT id, role, full_name, email, phone, userpic, created_at, updated_at FROM users WHERE id = ? LIMIT 1",
    [userId]
  );
  if (!rows[0]) {
    const e = new Error("ไม่พบผู้ใช้");
    e.statusCode = 404; e.code = "NOT_FOUND";
    throw e;
  }
  return rows[0];
}

// 1) searchDoctors - คืน userpic ด้วย (เพื่อให้ UI แสดงรูปได้)
export async function searchDoctors({ q, specialty_id, specialty_name }) {
  const params = [];
  // include userpic field
  let sql = "SELECT u.id, u.full_name, u.email, u.phone, u.userpic FROM users u ";
  if (specialty_id || specialty_name) {
    sql +=
      "JOIN doctor_specialties ds ON ds.doctor_id = u.id JOIN specialties s ON s.id = ds.specialty_id ";
  }
  sql += "WHERE u.role = 'doctor' ";
  if (q) {
    sql += "AND u.full_name LIKE ? ";
    params.push(`%${q}%`);
  }
  if (specialty_id) {
    sql += "AND s.id = ? ";
    params.push(specialty_id);
  } else if (specialty_name) {
    sql += "AND s.name LIKE ? ";
    params.push(`%${specialty_name}%`);
  }
  sql += "ORDER BY u.full_name ASC LIMIT 100";
  const [rows] = await pool.query(sql, params);
  return rows;
}


export async function createDoctorSlot(doctorId, startISO, endISO) {
  const conn = await pool.getConnection();
  try {
    const isDateOnly = (s) => typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s);
    const normStart = isDateOnly(startISO) ? `${startISO}T00:00:00` : startISO;
    const normEnd   = isDateOnly(endISO)   ? `${endISO}T23:59:59` : endISO;

    const startDT = new Date(normStart);
    const endDT   = new Date(normEnd);
    if (isNaN(startDT) || isNaN(endDT) || endDT.getTime() < startDT.getTime()) {
      const e = new Error("ช่วงเวลาไม่ถูกต้อง");
      e.statusCode = 400; e.code = "INVALID_TIME_RANGE";
      throw e;
    }

    const pad = (n) => String(n).padStart(2,"0");
    const toSql = (d) => `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    const id = genId("slot");

    await conn.beginTransaction();

    // parent slot อย่างเดียว (ไม่แตก daily แล้ว)
    await conn.query(
      "INSERT IGNORE INTO doctor_slots (id, doctor_id, start_time, end_time, status) VALUES (?, ?, ?, ?, 'available')",
      [id, doctorId, toSql(startDT), toSql(endDT)]
    );

    await conn.commit();
    return {
      id,
      doctor_id: doctorId,
      start_time: toSql(startDT),
      end_time: toSql(endDT),
      status: "available",
    };
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

// 2) listDoctorSlot - สร้าง daily virtual slots และพิจารณา appointment.status (pending/confirmed)
//    รวมทั้ง auto-close slot ที่จบไปแล้ว (defensive)
export async function listDoctorSlot(doctorId, fromISO, toISO) {
  // แปลงกรอบวัน
  const toYMD = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : new Date(s).toISOString().slice(0, 10);
  const fromDay = fromISO ? toYMD(fromISO) : null;
  const toDay   = toISO   ? toYMD(toISO)   : null;

  // --- Optional: ปิด (closed) slot เก่าที่ผ่านไปแล้ว (ทำครั้งเดียวเมื่อเรียก)
  try {
    await pool.query("UPDATE doctor_slots SET status = 'closed', updated_at = CURRENT_TIMESTAMP WHERE DATE(end_time) < CURDATE() AND status <> 'closed'");
  } catch (e) {
    console.error("failed to auto-close old slots:", e?.message || e);
  }

  // ดึง parent slots ที่ทับซ้อนกับกรอบที่ค้นหา
  const params = [doctorId];
  let sql = `
    SELECT id, doctor_id, start_time, end_time, status
    FROM doctor_slots
    WHERE doctor_id = ?
  `;
  if (fromDay) { sql += " AND DATE(end_time)   >= ?"; params.push(fromDay); }
  if (toDay)   { sql += " AND DATE(start_time) <= ?"; params.push(toDay); }
  sql += " ORDER BY start_time ASC LIMIT 500";

  const [rows] = await pool.query(sql, params);

  if (!rows.length) return [];

  // ดึง appointments ในกรอบเดียวกัน เพื่อเช็ค “วันไหนถูกจองแล้ว”
  // **NOTE**: นับเป็น "reserved" ก็ต่อเมื่อ appointment.status เป็น pending หรือ confirmed
  const aParams = [doctorId];
  let aSql = `
    SELECT a.slot_id, a.chosen_date, a.status
    FROM appointments a
    WHERE a.doctor_id = ?
  `;
  if (fromDay) { aSql += " AND a.chosen_date >= ?"; aParams.push(fromDay); }
  if (toDay)   { aSql += " AND a.chosen_date <= ?"; aParams.push(toDay); }

  const [apts] = await pool.query(aSql, aParams);
  const reserved = new Map(); // key = slot_id|YYYY-MM-DD -> true
  for (const a of apts) {
    const st = String(a.status || "").toLowerCase();
    if (st === "pending" || st === "confirmed") {
      reserved.set(`${a.slot_id}|${a.chosen_date}`, true);
    }
  }

  // แตกเป็น daily “เสมือน” แล้วติดสถานะ
  const out = [];
  const todayYMD = new Date().toISOString().slice(0, 10);
  for (const s of rows) {
    const days = enumerateDailyFromSlot(s.start_time, s.end_time);
    for (const ymd of days) {
      if (fromDay && ymd < fromDay) continue;
      if (toDay && ymd > toDay) continue;

      // ถ้าวันนั้นเลยแล้ว ให้เป็น closed (defensive)
      if (ymd < todayYMD) {
        out.push({
          id: `${s.id}:${ymd}`,
          slot_id: s.id,
          doctor_id: s.doctor_id,
          start_time: `${ymd} 00:00:00`,
          end_time: `${ymd} 23:59:59`,
          status: "closed",
        });
        continue;
      }

      const hasReservedAppt = reserved.get(`${s.id}|${ymd}`) === true;
      const parentStatus = (s.status || "").toLowerCase();
      // parentMarkedBooked = parent status not 'available' and not 'closed'
      const parentMarkedBooked = parentStatus && parentStatus !== "available" && parentStatus !== "closed";

      let finalStatus = "available";
      if (hasReservedAppt || parentMarkedBooked) finalStatus = "booked";
      // note: if parentStatus === 'closed' we'd already returned closed above on date check

      out.push({
        id: `${s.id}:${ymd}`,
        slot_id: s.id,
        doctor_id: s.doctor_id,
        start_time: `${ymd} 00:00:00`,
        end_time: `${ymd} 23:59:59`,
        status: finalStatus,
      });
    }
  }

  // เรียงวัน
  out.sort((a,b) => new Date(a.start_time) - new Date(b.start_time));
  return out;
}

// 3) bookAppointment - ใส่นัด (pending) และอัพเดต parent slot -> 'booked' ภายใน transaction เดียวกัน
export async function bookAppointment(patientId, slotId, chosenDate /* YYYY-MM-DD */) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // 1) ล็อก slot แม่
    const [srows] = await conn.query(
      "SELECT id, doctor_id, start_time, end_time, status FROM doctor_slots WHERE id = ? FOR UPDATE",
      [slotId]
    );
    const slot = srows[0];
    if (!slot) {
      const e = new Error("ไม่พบเวลานัดหมาย");
      e.statusCode = 404; e.code = "SLOT_NOT_FOUND";
      throw e;
    }
    if (slot.status !== "available") {
      const e = new Error("ช่วงเวลานี้ไม่พร้อมให้นัดหมาย");
      e.statusCode = 409; e.code = "SLOT_NOT_AVAILABLE";
      throw e;
    }

    // 2) chosen_date ต้องอยู่ในช่วง slot
    const ymds = enumerateDailyFromSlot(slot.start_time, slot.end_time);
    if (!ymds.includes(chosenDate)) {
      const e = new Error("วันที่เลือกอยู่นอกช่วงเวลาทำงานของแพทย์");
      e.statusCode = 400; e.code = "DATE_OUT_OF_RANGE";
      throw e;
    }

    // 3) ห้ามจองวันเดียวกัน (ต้องล่วงหน้าอย่างน้อย 1 วัน)
    const today00 = new Date(); today00.setHours(0,0,0,0);
    const tomorrow00 = new Date(today00.getTime() + 24*60*60*1000);
    if (new Date(`${chosenDate}T00:00:00`) < tomorrow00) {
      const e = new Error("การจองทำได้ตั้งแต่พรุ่งนี้เป็นต้นไป");
      e.statusCode = 400; e.code = "BOOKING_TOO_SOON";
      throw e;
    }

    // 3.1) ห้ามผู้ป่วยคนเดียวกันมี appointment ที่ same chosen_date (กับใครก็ได้)
    const [existingByPatient] = await conn.query(
      "SELECT 1 FROM appointments WHERE patient_id = ? AND chosen_date = ? LIMIT 1",
      [patientId, chosenDate]
    );
    if (existingByPatient.length) {
      const e = new Error("คุณมีการจองในวันที่เลือกไว้แล้ว");
      e.statusCode = 409; e.code = "PATIENT_ALREADY_BOOKED_ON_DATE";
      throw e;
    }

    // 4) ใส่นัด (pending)
    const apptId = genId("appt");
    await conn.query(
      "INSERT INTO appointments (id, patient_id, doctor_id, slot_id, chosen_date, status) VALUES (?, ?, ?, ?, ?, 'pending')",
      [apptId, patientId, slot.doctor_id, slot.id, chosenDate]
    );

    // 5) mark parent slot as booked (so other UIs that rely on doctor_slots.status also see booked)
    //    ทำใน transaction เดียวกัน (ปลอดภัยกับ FOR UPDATE)
    await conn.query(
      "UPDATE doctor_slots SET status = 'booked', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      [slot.id]
    );

    await conn.commit();
    return {
      id: apptId,
      patient_id: patientId,
      doctor_id: slot.doctor_id,
      slot_id: slot.id,
      chosen_date: chosenDate,
      status: "pending",
      start_time: `${chosenDate} 00:00:00`,
      end_time: `${chosenDate} 23:59:59`,
    };
  } catch (err) {
    await conn.rollback();
    if (err?.code === "ER_DUP_ENTRY") {
      const e = new Error("วันดังกล่าวถูกจองแล้ว");
      e.statusCode = 409; e.code = "SLOT_ALREADY_BOOKED";
      throw e;
    }
    throw err;
  } finally {
    conn.release();
  }
}

export async function listAppointmentsForUser(userId, role) {
  if (role === "patient") {
    const [rows] = await pool.query(
      `SELECT a.id, a.status, a.created_at,
        DATE_FORMAT(a.chosen_date, '%Y-%m-%d') AS chosen_date,
        COALESCE(CONCAT(a.chosen_date, ' 00:00:00'), ds.start_time) AS start_time,
        COALESCE(CONCAT(a.chosen_date, ' 23:59:59'), ds.end_time)   AS end_time,
        d.id AS doctor_id, d.full_name AS doctor_name
       FROM appointments a
       LEFT JOIN doctor_slots ds ON ds.id = a.slot_id
       JOIN users d ON d.id = a.doctor_id
       WHERE a.patient_id = ?
       ORDER BY COALESCE(DATE_FORMAT(a.chosen_date, '%Y-%m-%d'), DATE(ds.start_time)) DESC, a.created_at DESC
       LIMIT 200`,
      [userId]
    );
    return rows;
  }

  if (role === "doctor") {
    const [rows] = await pool.query(
      `SELECT a.id, a.status, a.created_at,
         DATE_FORMAT(a.chosen_date, '%Y-%m-%d') AS chosen_date,
         COALESCE(CONCAT(a.chosen_date, ' 00:00:00'), ds.start_time) AS start_time,
         COALESCE(CONCAT(a.chosen_date, ' 23:59:59'), ds.end_time)   AS end_time,
              COALESCE(CONCAT(a.chosen_date, ' 00:00:00'), ds.start_time) AS start_time,
              COALESCE(CONCAT(a.chosen_date, ' 23:59:59'), ds.end_time)   AS end_time,
              p.id AS patient_id, p.full_name AS patient_name
       FROM appointments a
       LEFT JOIN doctor_slots ds ON ds.id = a.slot_id
       JOIN users p ON p.id = a.patient_id
       WHERE a.doctor_id = ?
       ORDER BY COALESCE(DATE_FORMAT(a.chosen_date, '%Y-%m-%d'), DATE(ds.start_time)) DESC, a.created_at DESC
       LIMIT 200`,
      [userId]
    );
    return rows;
  }

  return [];
}


///////////////////////////////
// 9) SCHEMAS
///////////////////////////////

const SpecialtyIdsSchema = z
  .array(z.string().min(1, "id ไม่ถูกต้อง").max(36, "id ยาวเกินกำหนด"))
  .max(10, "เลือกได้ไม่เกิน 10 สาขา");

const PhoneSchema = z.preprocess((v) => {
  if (v === undefined) return undefined;
  if (v === null) return null;
  if (typeof v === "string" && v.trim().toLowerCase() === "null") return null;
  if (typeof v === "string" && v.trim() === "") return undefined;
  const digits = String(v).replace(/\D/g, "");
  return digits;
}, z.union([
  z.string().regex(/^\d{9,10}$/, "เบอร์โทรต้องเป็นตัวเลข 9 หรือ 10 หลัก"),
  z.null()
]));

// Register schema (แก้ให้รองรับ specialties และบังคับให้ doctor ต้องเลือกอย่างน้อย 1)
const RegisterSchema = z.object({
  role: z.enum(["patient", "doctor"], { message: "role ไม่ถูกต้อง" }),
  full_name: z.string().min(1, "กรุณาระบุชื่อ-นามสกุล"),
  email: z.string().email("อีเมลไม่ถูกต้อง"),
  phone: PhoneSchema.optional(), 
  password: z.string().min(4, "รหัสผ่านต้องยาวอย่างน้อย 4 ตัวอักษร"),
  specialties: z.array(z.string()).optional().nullable(),
  })
  .superRefine((data, ctx) => {
    // ถ้าเป็น doctor → ต้องมี specialties อย่างน้อย 1 รายการ
    if (data.role === "doctor") {
      if (!data.specialties || !Array.isArray(data.specialties) || data.specialties.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "แพทย์ต้องเลือกสาขาอย่างน้อย 1 รายการ",
          path: ["specialties"],
        });
      }
    }
  });


const LoginSchema = z.object({
  email: z.string().email("อีเมลไม่ถูกต้อง"),
  password: z.string().min(1, "กรุณากรอกรหัสผ่าน"),
});

const UpdateProfileSchema = z.object({
  full_name: z.string().min(1, "กรุณาระบุชื่อ-นามสกุล").optional(),
  phone: PhoneSchema.optional(),                 // <<<< แก้ตรงนี้
  specialty_ids: SpecialtyIdsSchema.optional(),
});

const SearchDoctorsQuery = z.object({
  q: z.string().optional(),
  // specialty_id รับได้ทั้ง number หรือ string (เช่น UUID 36 ตัว)
  specialty_id: z.preprocess((v) => {
    if (v === undefined) return undefined;
    const s = String(v);
    // เป็นตัวเลขก็แปลงเป็น Number, ไม่งั้นคงเป็น string (เช่น UUID/รหัส prefixed)
    return /^\d+$/.test(s) ? Number(s) : s;
  }, z.union([z.number(), z.string()])).optional(),
  specialty_name: z.string().optional(),
});


const CreateSlotSchema = z.object({
  start_time: z.string().min(10, "ต้องระบุเวลาเริ่ม"),
  end_time: z.string().min(10, "ต้องระบุเวลาสิ้นสุด"),
}).superRefine((val, ctx) => {
  const s = val.start_time;
  const e = val.end_time;
  const dateMode = isDateOnly(s) && isDateOnly(e);
  try {
    const start = dateMode ? atStartOfDay(s) : new Date(s);
    const end   = dateMode ? atEndOfDay(e)   : new Date(e);
    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "รูปแบบเวลาไม่ถูกต้อง" });
    }
    if (end.getTime() <= start.getTime()) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "เวลาสิ้นสุดต้องมากกว่าเวลาเริ่ม" });
    }
  } catch {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "รูปแบบเวลาไม่ถูกต้อง" });
  }
});

// ACCEPT: "YYYY-MM-DD" หรือ ISO datetime ใด ๆ ที่ new Date() parse ได้
const DateOrDateTime = z.string().refine(
  (s) => (typeof s === "string") && (/^\d{4}-\d{2}-\d{2}$/.test(s) || !Number.isNaN(new Date(s).getTime())),
  { message: "รูปแบบเวลาไม่ถูกต้อง" }
);

const ListSlotsQuery = z.object({
  from: DateOrDateTime.optional(),
  to: DateOrDateTime.optional(),
});

const BookSchema = z.object({
  slot_id: z.string().min(1, "กรุณาระบุ slot_id"),
  chosen_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "รูปแบบวันที่ไม่ถูกต้อง (YYYY-MM-DD)"),
});

// รายงาน (date optional: ถ้าไม่ส่ง = สรุปทั้งหมดของ scope นั้น)
const ReportQuery = z.object({
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "รูปแบบวันที่ไม่ถูกต้อง (YYYY-MM-DD)").optional(),
  doctor_id: z.string().length(36).optional() // admin จะส่งมาก็ได้
});

// =========================== SWAGGER / OPENAPI ===========================
const openapiSpec = {
  openapi: "3.0.3",
  info: { title: "Telemedicine API", version: "1.0.0" },
  servers: [
  { url: "/" },  // ใช้ origin ปัจจุบัน บนคลาวด์จะถูกเอง
  { url: `http://localhost:${env.PORT}`, description: "local dev" }
],
  components: {
    securitySchemes: {
      BearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" }
    },
    schemas: {
      ErrorResponse: {
        type: "object",
        properties: {
          error: {
            type: "object",
            properties: {
              code: { type: "string" },
              message: { type: "string" },
              details: { type: "array", items: {
                type: "object",
                properties: { field: {type:"string"}, message:{type:"string"} }
              }}
            },
            required: ["code","message"]
          }
        }
      },
      RegisterRequest: {
        type: "object",
        required: ["role","full_name","email","password"],
        properties: {
          role: { type: "string", enum: ["patient","doctor"] },
          full_name: { type: "string" },
          email: { type: "string", format: "email" },
          phone: { type: "string", nullable: true },
          password: { type: "string" },
          specialties: { type: "array", items: { type: "string" } }
        }
      },
      LoginRequest: {
        type: "object",
        required: ["email","password"],
        properties: { email:{type:"string",format:"email"}, password:{type:"string"} }
      },
      TokenUser: {
        type: "object",
        properties: {
          id:{type:"string"}, role:{type:"string"},
          full_name:{type:"string"}, email:{type:"string"}, phone:{type:"string",nullable:true}
        }
      },
      TokenResponse: {
        type: "object",
        properties: { token:{type:"string"}, user:{ $ref:"#/components/schemas/TokenUser" } },
        required: ["token","user"]
      },
      Doctor: {
        type: "object",
        properties: { id:{type:"string"}, full_name:{type:"string"}, email:{type:"string"}, phone:{type:"string"} }
      },
      Specialty: { type:"object", properties:{ id:{type:"string"}, name:{type:"string"} } },
      SlotRequest: {
        type: "object",
        required: ["start_time","end_time"],
        properties: { start_time:{type:"string"}, end_time:{type:"string"} }
      },
      Slot: {
        type:"object",
        properties:{
          id:{type:"string"}, doctor_id:{type:"string"},
          start_time:{type:"string"}, end_time:{type:"string"}, status:{type:"string"}
        }
      },
      AppointmentRequest: {
        type:"object",
        required:["slot_id","chosen_date"],
        properties:{ slot_id:{type:"string"}, chosen_date:{type:"string", example:"2025-09-01"} }
      },
      Appointment: {
        type:"object",
        properties:{
          id:{type:"string"}, patient_id:{type:"string"}, doctor_id:{type:"string"},
          slot_id:{type:"string"}, chosen_date:{type:"string"}, status:{type:"string"},
          start_time:{type:"string"}, end_time:{type:"string"}
        }
      },
      UpdateApptStatusRequest: {
        type:"object",
        required:["status"],
        properties:{ status:{type:"string", enum:["pending","confirmed","rejected","cancelled"]} }
      },
      ReportResponse: {
        type:"object",
        properties:{
          date:{type:"string", example:"2025-08-27"},
          role:{type:"string", enum:["doctor","patient"]},
          total:{type:"integer"},
          by_status:{
            type:"object",
            properties:{ pending:{type:"integer"}, confirmed:{type:"integer"}, rejected:{type:"integer"}, cancelled:{type:"integer"} }
          },
          recent_7_days:{
            type:"array",
            items:{ type:"object", properties:{ date:{type:"string"}, total:{type:"integer"} } }
          }
        }
      }
    }
  },
  paths: {
    "/health": {
      get: {
        summary: "Healthcheck",
        responses: { "200": { description: "OK" } }
      }
    },
    "/auth/register": {
      post: {
        summary: "Register",
        requestBody: { required:true, content: { "application/json": { schema: { $ref:"#/components/schemas/RegisterRequest" } } } },
        responses: {
          "201": { description: "Created" },
          "400": { description: "Bad Request", content:{ "application/json": { schema:{ $ref:"#/components/schemas/ErrorResponse" } } } },
          "409": { description: "Duplicate", content:{ "application/json": { schema:{ $ref:"#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/auth/login": {
      post: {
        summary: "Login",
        requestBody: { required:true, content: { "application/json": { schema: { $ref:"#/components/schemas/LoginRequest" } } } },
        responses: {
          "200": { description: "OK", content: { "application/json": { schema: { $ref:"#/components/schemas/TokenResponse" } } } },
          "401": { description: "Invalid", content:{ "application/json": { schema:{ $ref:"#/components/schemas/ErrorResponse" } } } }
        }
      }
    },
    "/users/me": {
      get: {
        security: [{ BearerAuth: [] }],
        summary: "My profile",
        responses: { "200": { description:"OK" }, "401": { description:"Unauthorized" } }
      },
      put: {
        security: [{ BearerAuth: [] }],
        summary: "Update my profile",
        responses: { "200": { description:"OK" }, "400":{description:"Bad Request"} }
      }
    },
    "/doctors": {
      get: {
        summary: "Search doctors",
        parameters: [
          { name:"q", in:"query", schema:{type:"string"} },
          { name:"specialty", in:"query", schema:{type:"string"} },
          { name:"specialty_id", in:"query", schema:{type:"string"} },
          { name:"specialty_name", in:"query", schema:{type:"string"} },
        ],
        responses: { "200": { description:"OK" } }
      }
    },
    "/doctors/{id}/slots": {
      get: {
        summary: "List doctor slots (daily virtual)",
        parameters: [
          { name:"id", in:"path", required:true, schema:{type:"string"} },
          { name:"from", in:"query", schema:{type:"string"} },
          { name:"to", in:"query", schema:{type:"string"} }
        ],
        responses: { "200": { description:"OK" } }
      },
      post: {
        security: [{ BearerAuth: [] }],
        summary: "Create slot (doctor only)",
        parameters: [{ name:"id", in:"path", required:true, schema:{type:"string"} }],
        requestBody: { required:true, content:{"application/json": { schema: { $ref:"#/components/schemas/SlotRequest" } } } },
        responses: { "201": { description:"Created" }, "403":{description:"Forbidden"} }
      }
    },
    "/appointments": {
      post: {
        security: [{ BearerAuth: [] }],
        summary: "Book appointment (patient only)",
        requestBody: { required:true, content:{"application/json": { schema: { $ref:"#/components/schemas/AppointmentRequest" } } } },
        responses: { "201": { description:"Created" }, "400":{description:"Bad Request"} }
      }
    },
    "/appointments/me": {
      get: {
        security: [{ BearerAuth: [] }],
        summary: "My appointments (auto by role)",
        responses: { "200": { description:"OK" }, "401": { description:"Unauthorized" } }
      }
    },
    "/appointments/doctor/me": {
      get: { security: [{ BearerAuth: [] }], summary: "Doctor's appointments", responses: { "200": { description:"OK" } } }
    },
    "/appointments/patient/me": {
      get: { security: [{ BearerAuth: [] }], summary: "Patient's appointments", responses: { "200": { description:"OK" } } }
    },
    "/appointments/{id}/status": {
      patch: {
        security: [{ BearerAuth: [] }],
        summary: "Update status (doctor only)",
        parameters: [{ name:"id", in:"path", required:true, schema:{type:"string"} }],
        requestBody: { required:true, content:{"application/json": { schema: { $ref:"#/components/schemas/UpdateApptStatusRequest" } } } },
        responses: { "200": { description:"OK" }, "404":{description:"Not found"} }
      }
    },
    "/specialties": {
      get: { summary: "List specialties", responses: { "200": { description:"OK" } } }
    },
    "/reports/appointments/me": {
      get: {
        security: [{ BearerAuth: [] }],
        summary: "My appointment summary (by date)",
        parameters: [{ name:"date", in:"query", required:true, schema:{type:"string"}, example:"2025-08-27" }],
        responses: {
          "200": { description:"OK", content: {"application/json": { schema: { $ref:"#/components/schemas/ReportResponse" } } } },
          "400": { description:"Bad Request", content: {"application/json": { schema: { $ref:"#/components/schemas/ErrorResponse" } } } }
        }
      }
    }
  }
};

// mount docs
app.get("/docs.json", (_req, res) => res.json(openapiSpec));
app.use("/docs", swaggerUi.serve, swaggerUi.setup(openapiSpec));


///////////////////////////////
// 10) ROUTES
///////////////////////////////

// healthcheck
app.get("/health", (req, res) => {
  res.json({ ok: true, ts: new Date().toISOString() });
});

// register
app.post(
  "/auth/register",
  upload.single("userpic"), 
  asyncHandler(async (req, res) => {
    const body = { ...req.body };
    if (typeof body.specialties === "string") {
      try { body.specialties = JSON.parse(body.specialties); }
      catch { body.specialties = body.specialties.split(",").map(s => s.trim()).filter(Boolean); }
    }

    const parsed = RegisterSchema.safeParse(body);
    if (!parsed.success) return respondValidation(res, parsed.error);

    const userpicPath = req.file ? `/uploads/${req.file.filename}` : null;

    try {
      const user = await registerUser({ ...parsed.data, userpicPath });
      res.status(201).json({ user });
    } catch (err) {
      if (userpicPath) deleteFileSafe(userpicPath); // rollback file เมื่อ insert fail
      throw err;
    }
  })
);

// ESCALATED LOGIN + IP BLOCK
app.post(
  "/auth/login",
  loginLimiter,
  asyncHandler(async (req, res) => {
    // 1) validate
    const parsed = LoginSchema.safeParse(req.body || {});
    if (!parsed.success) return respondValidation(res, parsed.error);
    const { email, password } = parsed.data;

    const ip = getClientIp(req);

    // 2) ดึง user มาก่อน
    const [rows] = await pool.query(
      "SELECT id, role, email, full_name, password_hash, failed_login_attempts, lock_count, locked_until FROM users WHERE email = ? LIMIT 1",
      [email]
    );
    const user = rows[0];

    const invalid = () =>
      res.status(401).json({
        error: { code: "INVALID_CREDENTIALS", message: "อีเมลหรือรหัสผ่านไม่ถูกต้อง" },
      });

    if (!user) {
      await new Promise((r) => setTimeout(r, 300)); // slow bot
      return invalid();
    }

    // 3) ถ้าบัญชีถูกล็อกอยู่ ให้บอกไปก่อน (ยังไม่ตรวจรหัส)
    if (user.locked_until) {
      const untilTs = new Date(user.locked_until).getTime();
      if (Date.now() < untilTs) {
        const leftMin = Math.ceil((untilTs - Date.now()) / 60000);
        return res.status(423).json({
          error: { code: "ACCOUNT_LOCKED", message: `บัญชีถูกล็อกชั่วคราว โปรดลองอีกครั้งใน ${leftMin} นาที` },
        });
      }
    }

    // 4) ตรวจรหัสผ่านก่อน แล้วค่อยตัดสิน block
    const ok = verifyPassword(password, user.password_hash);

    if (ok) {
      // ล็อกอินสำเร็จ → reset ทุกอย่าง และปลด IP block ถ้ามี
      await pool.query(
        "UPDATE users SET failed_login_attempts = 0, lock_count = 0, locked_until = NULL WHERE id = ?",
        [user.id]
      );
      await unblockIp(ip);

      const token = issueJwt({ sub: user.id, role: user.role || "patient" }, "2h");
      return res.json({
        token,
        user: { id: user.id, email: user.email, full_name: user.full_name, role: user.role || "patient" },
      });
    }

    // 5) รหัสผิด → ตอนนี้ค่อยเช็คว่า IP โดน block อยู่ไหม
    if (await isIpBlocked(ip)) {
      return res
        .status(429)
        .json({ error: { code: "IP_BLOCKED", message: "จากการลองเข้าสู่ระบบมากเกินไป โปรดลองใหม่ภายหลัง" } });
    }

    // เพิ่ม failed แล้วพิจารณา escalated lock
    const newFailed = (user.failed_login_attempts || 0) + 1;
    await pool.query("UPDATE users SET failed_login_attempts = ? WHERE id = ?", [newFailed, user.id]);

    if (newFailed >= 5) {
      const currentLockCount = user.lock_count || 0;
      const durationSec = getLockDurationSeconds(currentLockCount);
      const until = new Date(Date.now() + durationSec * 1000);

      await pool.query("UPDATE users SET locked_until = ?, lock_count = ? WHERE id = ?", [
        until,
        currentLockCount + 1,
        user.id,
      ]);
      await blockIp(ip, durationSec);

      return res.status(429).json({
        error: {
          code: "TOO_MANY_ATTEMPTS",
          message: `ลองเข้าสู่ระบบมากเกินไป ระบบล็อกบัญชีเป็นเวลา ${Math.round(durationSec / 60)} นาที`,
        },
      });
    }

    return invalid();
  })
);

// แทน handler เดิมของ /users/me ด้วยโค้ดนี้
app.get(
  "/users/me",
  requireAuth(),
  asyncHandler(async (req, res) => {
    const user = await getUserProfile(req.user.sub);

    // ถ้าเป็นหมอ ให้ดึงสาขาที่ผูกไว้จาก doctor_specialties
    if (user.role === "doctor") {
      const [rows] = await pool.query(
        `SELECT s.id, s.name
         FROM doctor_specialties ds
         JOIN specialties s ON s.id = ds.specialty_id
         WHERE ds.doctor_id = ?
         ORDER BY s.name ASC`,
        [req.user.sub]
      );
      user.specialties = rows || []; // array of {id, name}
    } else {
      user.specialties = [];
    }

    res.json({ user });
  })
);


app.put(
  "/users/me",
  requireAuth(),
  upload.single("userpic"),
  asyncHandler(async (req, res) => {
    // ถ้ามาแบบ multipart/form-data, req.body ทุกค่าเป็น string
    // ถ้า client ส่ง specialty_ids เป็น JSON string หรือ CSV, แปลงให้เป็น array
    const body = { ...req.body };

    if (typeof body.specialty_ids === "string") {
      try {
        // พยายาม parse JSON ก่อน
        body.specialty_ids = JSON.parse(body.specialty_ids);
      } catch (e) {
        // ถ้าไม่ใช่ JSON ให้ถือเป็น CSV (comma separated ids)
        body.specialty_ids = body.specialty_ids
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
      }
    }

    const parsed = UpdateProfileSchema.safeParse(body);
    if (!parsed.success) return respondValidation(res, parsed.error);

    const patch = { ...parsed.data };

    if (req.file) {
      patch.userpicPath = `/uploads/${req.file.filename}`;
    }

    try {
      const user = await updateUserProfile(req.user.sub, patch);
      res.json({ user });
    } catch (err) {
      if (req.file) deleteFileSafe(`/uploads/${req.file.filename}`);
      throw err;
    }
  })
);

// doctors
app.get(
  "/doctors",
  asyncHandler(async (req, res) => {
    // ===== ALIAS HANDLING =====
    // รองรับ ?specialty= ทั้ง 3 รูปแบบ:
    // - เลขดิบ (เช่น 2)
    // - id 36 ตัว (เช่น SPxxxxxxxx...)
    // - ชื่อสาขา (string อื่นๆ)
    const q = { ...req.query };
    if (q.specialty && !q.specialty_name && !q.specialty_id) {
      const s = String(q.specialty).trim();
      if (looksLikeId(s)) {
        // UUID/รหัสยาว 36 ตัว
        q.specialty_id = s;
      } else if (isNumericId(s)) {
        // id เป็นตัวเลข
        q.specialty_id = Number(s);
      } else {
        // ถือเป็นชื่อ
        q.specialty_name = s;
      }
    }

    // ===== VALIDATE =====
    const parsed = SearchDoctorsQuery.safeParse(q);
    if (!parsed.success) return respondValidation(res, parsed.error);

    // ===== QUERY =====
    const data = await searchDoctors(parsed.data);
    res.json({ data });
  })
);

app.post(
  "/doctors/:id/slots",
  requireAuth(["doctor"]),
  asyncHandler(async (req, res) => {
    if (req.params.id !== req.user.sub) {
      return res.status(403).json({ error: { code: "FORBIDDEN", message: "ไม่สามารถจัดการเวลาให้ผู้อื่นได้" } });
    }
    
    const parsed = CreateSlotSchema.safeParse(req.body);
    if (!parsed.success) return respondValidation(res, parsed.error);
    const slot = await createDoctorSlot(req.user.sub, parsed.data.start_time, parsed.data.end_time);
    res.status(201).json({ slot });
  })
);

app.get(
  "/doctors/:id/slots",
  asyncHandler(async (req, res) => {
    const parsed = ListSlotsQuery.safeParse(req.query);
    if (!parsed.success) return respondValidation(res, parsed.error);
    const data = await listDoctorSlot(req.params.id, parsed.data.from, parsed.data.to);
    res.json({ data });
  })
);

// appointments
app.post(
  "/appointments",
  requireAuth(["patient"]),
  asyncHandler(async (req, res) => {
    const parsed = BookSchema.safeParse(req.body);
    if (!parsed.success) return respondValidation(res, parsed.error);
    const { slot_id, chosen_date } = parsed.data;
    const appt = await bookAppointment(req.user.sub, slot_id, chosen_date);
    res.status(201).json({ appointment: appt });
  })
);

app.patch(
  "/appointments/:id/status",
  requireAuth(["doctor"]),
  asyncHandler(async (req, res) => {
    const apptId = req.params.id;
    const parsed = UpdateApptStatusSchema.safeParse(req.body);
    if (!parsed.success) return respondValidation(res, parsed.error);

    // อนุญาตแก้เฉพาะนัดของหมอคนนี้
    const [rows] = await pool.query(
      "SELECT id, doctor_id FROM appointments WHERE id = ? LIMIT 1",
      [apptId]
    );
    const a = rows[0];
    if (!a || a.doctor_id !== req.user.sub) {
      return res.status(404).json({ error: { code: "NOT_FOUND", message: "ไม่พบนัดหมาย" } });
    }

    await pool.query("UPDATE appointments SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", [
      parsed.data.status,
      apptId,
    ]);

    res.json({ ok: true });
  })
);

app.get(
  "/appointments/me",
  requireAuth(),
  asyncHandler(async (req, res) => {
    const list = await listAppointmentsForUser(req.user.sub, req.user.role);
    res.json({ data: list });
  })
);

// เพิ่ม alias ให้ตรงข้อสอบ
app.get(
  "/appointments/doctor/me",
  requireAuth(["doctor"]),
  asyncHandler(async (req, res) => {
    const list = await listAppointmentsForUser(req.user.sub, "doctor");
    res.json({ data: list });
  })
);

app.get(
  "/appointments/patient/me",
  requireAuth(["patient"]),
  asyncHandler(async (req, res) => {
    const list = await listAppointmentsForUser(req.user.sub, "patient");
    res.json({ data: list });
  })
);

// GET /specialties - คืนรายการ specialties ทั้งหมด
app.get(
  "/specialties",
  asyncHandler(async (req, res) => {
    const [rows] = await pool.query("SELECT id, name FROM specialties ORDER BY name ASC");
    res.json({ data: rows });
  })
);

const UpdateApptStatusSchema = z.object({
  status: z.enum(["pending", "confirmed", "rejected", "cancelled"], { message: "สถานะไม่ถูกต้อง" }),
});

// =========================== REPORTS (admin OR doctor) ===========================
// GET /reports/appointments[?date=YYYY-MM-DD][&doctor_id=...]
// - admin: เห็นทั้งระบบ หรือ zoom-in ด้วย doctor_id
// - doctor: เห็นเฉพาะของตัวเอง (ห้ามส่ง doctor_id เป็นคนอื่น)
app.get(
  "/reports/appointments",
  requireAuth(["admin", "doctor"]),
  asyncHandler(async (req, res) => {
    // parse
    const parsed = ReportQuery.safeParse(req.query);
    if (!parsed.success) return respondValidation(res, parsed.error);
    const { date } = parsed.data || {};

    const role = req.user.role === "admin" ? "admin" : "doctor";
    const idCol = "doctor_id";

    // scope
    let scope = "system";
    let doctorId = null;

    if (role === "admin") {
      if (req.query.doctor_id && String(req.query.doctor_id).length === 36) {
        doctorId = String(req.query.doctor_id);
        scope = "doctor";
      }
    } else {
      scope = "doctor";
      doctorId = req.user.sub;
      if (req.query.doctor_id && req.query.doctor_id !== req.user.sub) {
        return res.status(403).json({ error: { code: "FORBIDDEN", message: "ดูเฉพาะของตนเองเท่านั้น" } });
      }
    }

    // เงื่อนไขหลัก
    const where = [];
    const params = [];
    if (doctorId) { where.push(`${idCol} = ?`); params.push(doctorId); }
    if (date)     { where.push(`chosen_date = ?`); params.push(date); }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

    // สรุปตามสถานะ
    const [statRows] = await pool.query(
      `SELECT status, COUNT(*) AS c
       FROM appointments
       ${whereSql}
       GROUP BY status`
    , params);

    const by_status = { pending: 0, confirmed: 0, rejected: 0, cancelled: 0 };
    for (const r of statRows) if (by_status.hasOwnProperty(r.status)) by_status[r.status] = Number(r.c) || 0;
    const total = Object.values(by_status).reduce((a, b) => a + b, 0);

    // trend 30 วันล่าสุด (ไม่สน date; ใช้วันนี้เป็นปลายทางเสมอ)
    const pad = (n) => String(n).padStart(2, "0");
    const ymd = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    const end = new Date(); end.setHours(0,0,0,0);
    const start = new Date(end.getTime() - 29 * 24 * 60 * 60 * 1000);
    const startY = ymd(start), endY = ymd(end);

    const trendParams = [startY, endY];
    let trendWhere = "chosen_date BETWEEN ? AND ?";
    if (doctorId) { trendWhere += " AND doctor_id = ?"; trendParams.push(doctorId); }

    const [trendRows] = await pool.query(
      `SELECT DATE_FORMAT(chosen_date, '%Y-%m-%d') AS d, COUNT(*) AS c
       FROM appointments
       WHERE ${trendWhere}
       GROUP BY d
       ORDER BY d ASC`,
      trendParams
    );
    const map = new Map(trendRows.map(r => [r.d, Number(r.c)]));
    const recent_30_days = [];
    for (let i = 0; i < 30; i++) {
      const day = new Date(start.getTime() + i * 24 * 60 * 60 * 1000);
      const k = ymd(day);
      recent_30_days.push({ date: k, total: map.get(k) || 0 });
    }

    // upcoming ที่ยืนยันแล้ว
    const upParams = [];
    let upWhere = "status = 'confirmed' AND chosen_date >= CURDATE()";
    if (doctorId) { upWhere += " AND doctor_id = ?"; upParams.push(doctorId); }
    const [upRows] = await pool.query(
      `SELECT COUNT(*) AS c, MIN(chosen_date) AS next_date
       FROM appointments
       WHERE ${upWhere}`,
      upParams
    );
    const upcoming = { count: Number(upRows[0]?.c || 0), next_date: upRows[0]?.next_date || null };

    res.json({
      scope,              // "system" | "doctor"
      doctor_id: doctorId || null,
      window: date ? { type: "daily", date } : { type: "all" },
      total,
      by_status,
      trend_30d: recent_30_days,
      upcoming
    });
  })
);


///////////////////////////////
// 11) GLOBAL ERROR HANDLER
///////////////////////////////
app.use((err, _req, res, _next) => {
  if (err?.code === "ER_DUP_ENTRY") {
    return res
      .status(409)
      .json({ error: { code: "DUPLICATE", message: "ข้อมูลนี้ถูกใช้งานอยู่แล้ว" } });
  }

  if (err?.statusCode) {
    return res
      .status(err.statusCode)
      .json({ error: { code: err.code || "ERROR", message: err.message || "เกิดข้อผิดพลาด" } });
  }

  if (err?.issues) {
    return respondValidation(res, err);
  }

  console.error(err);
  res
    .status(500)
    .json({ error: { code: "INTERNAL_ERROR", message: "ระบบขัดข้อง กรุณาลองใหม่อีกครั้ง" } });
});

///////////////////////////////
// 12) START SERVER
///////////////////////////////
app.listen(env.PORT, "0.0.0.0", () => {
  console.log("server started on port", env.PORT);
});
