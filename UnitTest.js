// UnitTest.js (ครบชุด: service + routes)
// รัน: npm test  หรือ  npm test -- --coverage

import { vi, describe, it, expect, beforeEach } from "vitest";
import request from "supertest";
import crypto from "crypto";
import jwt from "jsonwebtoken";

/**
 * =====================================================================
 * ENV สำหรับเทสต์
 * =====================================================================
 */
process.env.NODE_ENV = "test";
process.env.JWT_SECRET = "testsecret";
process.env.ALLOW_ORIGINS = ""; // กัน CORS งอแงเวลา supertest ยิงในเทสต์

/**
 * =====================================================================
 * MOCKS พื้นฐานของ dependency ภายนอก (DB/Redis/Swagger UI)
 * =====================================================================
 */

// 1) mysql2/promise -> คืน pool/conn ปลอม (รองรับทั้ง default และ named export)
const mockConn = {
  beginTransaction: vi.fn().mockResolvedValue(),
  query: vi.fn().mockResolvedValue([{ affectedRows: 1 }]),
  commit: vi.fn().mockResolvedValue(),
  rollback: vi.fn().mockResolvedValue(),
  release: vi.fn(),
};
const mockPool = {
  query: vi.fn(),
  getConnection: vi.fn().mockResolvedValue(mockConn),
};
vi.mock("mysql2/promise", () => ({
  __esModule: true,
  default: { createPool: () => mockPool },
  createPool: () => mockPool,
}));

// 2) swagger-ui-express -> ให้ผ่านเฉยๆ ไม่ลาก UI มาเกี่ยว
vi.mock("swagger-ui-express", () => ({
  __esModule: true,
  default: {
    serve: (_req, _res, next) => next(),
    setup: () => (_req, _res, next) => next(),
  },
}));

// 3) ioredis -> ไม่ให้ต่อ redis จริง
vi.mock("ioredis", () => ({
  __esModule: true,
  default: class RedisMock {
    constructor() {}
    on() {}
    setex() { return Promise.resolve(); }
    get() { return Promise.resolve(null); }
    del() { return Promise.resolve(); }
  },
}));

/**
 * =====================================================================
 * IMPORT server.js แบบ fresh ทุกเคส เพื่อให้ mock มีผลถูกต้อง
 * =====================================================================
 */
let mod;
async function freshImport() {
  vi.resetModules();

  mockPool.query.mockReset();
  mockConn.beginTransaction.mockClear();
  mockConn.query.mockClear();
  mockConn.commit.mockClear();
  mockConn.rollback.mockClear();
  mockPool.getConnection.mockClear();

  mod = await import("./server.js"); // ต้อง export app + ฟังก์ชันธุรกิจ
}
beforeEach(async () => {
  await freshImport();
});

/**
 * =====================================================================
 * Helpers (สร้างรหัสผ่านแบบเดียวกับ server.js และออก JWT)
 * =====================================================================
 */
function makeStored(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `scrypt$1$${salt}$${hash}`;
}
function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { algorithm: "HS256", expiresIn: "2h" });
}

/**
 * =====================================================================
 * SERVICE TESTS: ฟังก์ชันธุรกิจที่ export ออกจาก server.js
 * =====================================================================
 */

// [Service] registerUser: สมัครผู้ใช้ทั้งหมอ/คนไข้ และ handle duplicate
describe("registerUser()", () => {
  it("สมัครหมอและผูก specialties ได้", async () => {
    mockPool.query
      .mockResolvedValueOnce([{ affectedRows: 1 }]) // INSERT users
      .mockResolvedValueOnce([{ affectedRows: 2 }]); // INSERT IGNORE doctor_specialties

    const user = await mod.registerUser({
      role: "doctor",
      full_name: "Dr. Test",
      email: "doc@test.com",
      phone: "0812345678",
      password: "1234",
      specialties: ["SP001", "SP002"],
      userpicPath: null,
    });

    expect(user.role).toBe("doctor");
    expect(user.email).toBe("doc@test.com");
    expect(mockPool.query).toHaveBeenCalledTimes(2);
  });

  it("อีเมลซ้ำ -> โยน 409 DUPLICATE", async () => {
    const dup = new Error("dup");
    dup.code = "ER_DUP_ENTRY";
    mockPool.query.mockRejectedValueOnce(dup);

    await expect(
      mod.registerUser({
        role: "patient",
        full_name: "A",
        email: "a@x.com",
        phone: null,
        password: "1234",
        specialties: [],
        userpicPath: null,
      })
    ).rejects.toMatchObject({ statusCode: 409, code: "DUPLICATE" });
  });
});

// [Service] loginUser: ล็อกอินสำเร็จ/ผิด และอัปเดต counters
describe("loginUser()", () => {
  it("ล็อกอินถูก -> ออก token และ reset counters", async () => {
    const stored = makeStored("secret");
    mockPool.query
      .mockResolvedValueOnce([
        [{
          id: "P1234567890123456789012345678901234",
          role: "patient",
          full_name: "User X",
          email: "u@test.com",
          phone: null,
          password_hash: stored,
          failed_login_attempts: 2,
          locked_until: null,
        }],
      ])
      .mockResolvedValueOnce([{ affectedRows: 1 }]); // UPDATE reset

    const res = await mod.loginUser("u@test.com", "secret");
    expect(res.token).toBeTruthy();
    expect(res.user.email).toBe("u@test.com");
    expect(
      mockPool.query.mock.calls.map(c => String(c[0])).some(s => /UPDATE users SET failed_login_attempts = 0/i.test(s))
    ).toBe(true);
  });

  it("รหัสผิด -> INVALID_CREDENTIALS และเพิ่ม failed_login_attempts", async () => {
    const stored = makeStored("correct");
    mockPool.query
      .mockResolvedValueOnce([
        [{
          id: "Pxxxx",
          role: "patient",
          full_name: "User Y",
          email: "y@test.com",
          phone: null,
          password_hash: stored,
          failed_login_attempts: 0,
          locked_until: null,
        }],
      ])
      .mockResolvedValueOnce([{ affectedRows: 1 }]); // UPDATE +1

    await expect(mod.loginUser("y@test.com", "wrong")).rejects.toMatchObject({
      statusCode: 401,
      code: "INVALID_CREDENTIALS",
    });

    expect(
      mockPool.query.mock.calls.map(c => String(c[0])).some(s => /UPDATE users SET failed_login_attempts/i.test(s))
    ).toBe(true);
  });
});

// [Service] createDoctorSlot: สร้างช่วงวันล้วน + ตรวจเวลาผิด
describe("createDoctorSlot()", () => {
  it("ช่วงวันล้วน -> normalize เป็น 00:00:00 ถึง 23:59:59 และใช้ transaction", async () => {
    const out = await mod.createDoctorSlot("D123", "2025-09-01", "2025-09-03");
    expect(out.doctor_id).toBe("D123");
    expect(out.start_time).toBe("2025-09-01 00:00:00");
    expect(out.end_time).toBe("2025-09-03 23:59:59");
    expect(String(out.id)).toHaveLength(36);
    expect(mockPool.getConnection).toHaveBeenCalledTimes(1);
    expect(mockConn.beginTransaction).toHaveBeenCalledTimes(1);
    expect(mockConn.commit).toHaveBeenCalledTimes(1);
  });

  it("เวลาไม่ถูกต้อง -> โยน 400 INVALID_TIME_RANGE", async () => {
    await expect(
      mod.createDoctorSlot("D1", "2025-09-05T10:00:00Z", "2025-09-04T10:00:00Z")
    ).rejects.toMatchObject({ statusCode: 400, code: "INVALID_TIME_RANGE" });
  });
});

// [Service] listDoctorSlot: แตก parent slot เป็นรายวัน พร้อมสถานะจาก appointments
describe("listDoctorSlot()", () => {
  it("ดึง slot แล้ว map วัน พร้อม reserved จาก appointments", async () => {
    // 1) UPDATE auto-close (ignore result)
    mockPool.query.mockResolvedValueOnce([{ affectedRows: 1 }]);
    // 2) SELECT slots
    mockPool.query.mockResolvedValueOnce([
      [
        { id: "S1", doctor_id: "D1", start_time: "2025-09-01 00:00:00", end_time: "2025-09-03 23:59:59", status: "available" },
      ],
    ]);
    // 3) SELECT appointments
    mockPool.query.mockResolvedValueOnce([
      [
        { slot_id: "S1", chosen_date: "2025-09-02", status: "pending" },
      ],
    ]);

    const out = await mod.listDoctorSlot("D1", "2025-09-01", "2025-09-03");
    expect(out.length).toBe(3); // 1,2,3
    const d2 = out.find(x => x.start_time.startsWith("2025-09-02"));
    expect(d2.status).toBe("booked");
  });
});

// [Service] bookAppointment: จองนัด pending และ mark slot เป็น booked
describe("bookAppointment()", () => {
  it("บันทึกนัด + update slot เป็น booked ภายใน transaction", async () => {
    mockConn.query
      .mockResolvedValueOnce([[{ id: "S1", doctor_id: "D9", start_time: "2025-09-01 00:00:00", end_time: "2025-09-03 23:59:59", status: "available" }]]) // lock
      .mockResolvedValueOnce([[]])  // existing by patient (none)
      .mockResolvedValueOnce([{ affectedRows: 1 }])   // insert appt
      .mockResolvedValueOnce([{ affectedRows: 1 }]);  // update slot

    const appt = await mod.bookAppointment("P1", "S1", "2025-09-02");
    expect(appt.status).toBe("pending");
    expect(mockConn.beginTransaction).toHaveBeenCalledTimes(1);
    expect(mockConn.commit).toHaveBeenCalledTimes(1);
  });
});

// [Service] listAppointmentsForUser: คืนรายการนัดของ patient/doctor
describe("listAppointmentsForUser()", () => {
  it("patient ได้รายการนัด", async () => {
    mockPool.query.mockResolvedValueOnce([
      [
        { id: "A1", status: "pending", chosen_date: "2025-09-02", doctor_id: "D9", doctor_name: "Dr.Z" },
      ],
    ]);
    const rows = await mod.listAppointmentsForUser("P1", "patient");
    expect(rows[0].doctor_name).toBe("Dr.Z");
  });

  it("doctor ได้รายการนัดของตัวเอง", async () => {
    mockPool.query.mockResolvedValueOnce([
      [
        { id: "A1", status: "confirmed", chosen_date: "2025-09-02", patient_id: "P7", patient_name: "User A" },
      ],
    ]);
    const rows = await mod.listAppointmentsForUser("D1", "doctor");
    expect(rows[0].patient_name).toBe("User A");
  });
});

/**
 * =====================================================================
 * ROUTE TESTS: ยิงเส้นทางจริงผ่าน supertest (app จาก server.js)
 * =====================================================================
 */

// [Routes] Users: GET /users/me และ PUT /users/me (รวม specialties)
describe("getUserProfile() / updateUserProfile()", () => {
  it("getUserProfile คืน profile และ specialties เมื่อเป็น doctor", async () => {
    mockPool.query
      .mockResolvedValueOnce([
        [{ id: "D1", role: "doctor", full_name: "Dr X", email: "x@test.com", phone: null, userpic: null, created_at: null, updated_at: null }],
      ])
      .mockResolvedValueOnce([
        [{ id: "SP1", name: "Cardio" }],
      ]);

    const token = signToken({ sub: "D1", role: "doctor" });
    const res = await request(mod.app).get("/users/me").set("Authorization", `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.user.specialties[0].name).toBe("Cardio");
  });

  it("updateUserProfile เปลี่ยนชื่อ+เบอร์+specialties", async () => {
    const token = signToken({ sub: "D1", role: "doctor" });

    // 1) UPDATE users (pool)
    mockPool.query
      .mockResolvedValueOnce([{ affectedRows: 1 }])
      .mockResolvedValueOnce([
        [{
          id: "D1",
          role: "doctor",
          full_name: "New Name",
          email: "x@test.com",
          phone: "0811111111",
          userpic: null,
          created_at: null,
          updated_at: null
        }],
      ]);

    // 2) setDoctorSpecialties() (conn)
    mockConn.query
      .mockResolvedValueOnce([[{ role: "doctor" }]]) // SELECT role
      .mockResolvedValueOnce([{ affectedRows: 1 }])  // DELETE old
      .mockResolvedValueOnce([[{ id: "SP1" }]])      // SELECT exists
      .mockResolvedValueOnce([{ affectedRows: 1 }]); // INSERT new

    const res = await request(mod.app)
      .put("/users/me")
      .set("Authorization", `Bearer ${token}`)
      .send({ full_name: "New Name", phone: "081-111-1111", specialty_ids: ["SP1"] });

    expect(res.status).toBe(200);
    expect(res.body.user.full_name).toBe("New Name");
    expect(res.body.user.phone).toBe("0811111111");
    expect(mockConn.beginTransaction).toHaveBeenCalledTimes(1);
    expect(mockConn.commit).toHaveBeenCalledTimes(1);
  });
});

// [Routes] Basic: /health และ /docs.json
describe("Routes basic", () => {
  it("GET /health -> 200", async () => {
    const res = await request(mod.app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it("GET /docs.json -> 200 และมี openapi", async () => {
    const res = await request(mod.app).get("/docs.json");
    expect(res.status).toBe(200);
    expect(res.body.openapi).toBe("3.0.3");
  });
});

// [Routes] Auth (escalated path): ไม่พบ user / รหัสถูกและ reset counters
describe("Auth routes (escalated login path)", () => {
  it("POST /auth/login -> 401 เมื่อไม่พบ user", async () => {
    mockPool.query.mockResolvedValueOnce([[]]); // SELECT user (empty)
    const res = await request(mod.app).post("/auth/login").send({ email: "no@x.com", password: "xx" });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe("INVALID_CREDENTIALS");
  });

  it("POST /auth/login -> 200 เมื่อรหัสถูก และ reset counters", async () => {
    const stored = makeStored("okok");
    mockPool.query
      .mockResolvedValueOnce([
        [{
          id: "P2",
          role: "patient",
          email: "p@x.com",
          full_name: "P",
          password_hash: stored,
          failed_login_attempts: 3,
          lock_count: 0,
          locked_until: null,
        }],
      ])
      .mockResolvedValueOnce([{ affectedRows: 1 }]); // UPDATE reset

    const res = await request(mod.app).post("/auth/login").send({ email: "p@x.com", password: "okok" });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
  });
});

// [Routes] Doctors & Slots: search/list/create
describe("Doctors & Slots routes", () => {
  it("GET /doctors?q=... -> 200", async () => {
    mockPool.query.mockResolvedValueOnce([
      [{ id: "D1", full_name: "Dr A", email: "a@x.com", phone: "080", userpic: null }],
    ]);
    const res = await request(mod.app).get("/doctors").query({ q: "A" });
    expect(res.status).toBe(200);
    expect(res.body.data[0].full_name).toBe("Dr A");
  });

  it("POST /doctors/:id/slots (ต้อง role=doctor และ id=ตนเอง)", async () => {
    const token = signToken({ sub: "D1", role: "doctor" });
    mockConn.query.mockResolvedValueOnce([{ affectedRows: 1 }]); // INSERT IGNORE (ใน tx)

    const res = await request(mod.app)
      .post("/doctors/D1/slots")
      .set("Authorization", `Bearer ${token}`)
      .send({ start_time: "2025-09-01", end_time: "2025-09-03" });

    expect(res.status).toBe(201);
    expect(res.body.slot.status).toBe("available");
  });

  it("GET /doctors/:id/slots -> 200 พร้อม data array", async () => {
    mockPool.query.mockResolvedValueOnce([{ affectedRows: 0 }]); // auto-close
    mockPool.query.mockResolvedValueOnce([
      [{ id: "S1", doctor_id: "D1", start_time: "2025-09-01 00:00:00", end_time: "2025-09-01 23:59:59", status: "available" }],
    ]);
    mockPool.query.mockResolvedValueOnce([[]]); // appointments

    const res = await request(mod.app).get("/doctors/D1/slots").query({ from: "2025-09-01", to: "2025-09-01" });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
  });
});

// [Routes] Appointments: book/list/update status
describe("Appointments routes", () => {
  it("POST /appointments (patient only) -> 201", async () => {
    const token = signToken({ sub: "P1", role: "patient" });
    mockConn.query
      .mockResolvedValueOnce([[{ id: "S1", doctor_id: "D9", start_time: "2025-09-01 00:00:00", end_time: "2025-09-03 23:59:59", status: "available" }]])
      .mockResolvedValueOnce([[]])
      .mockResolvedValueOnce([{ affectedRows: 1 }])
      .mockResolvedValueOnce([{ affectedRows: 1 }]);

    const res = await request(mod.app)
      .post("/appointments")
      .set("Authorization", `Bearer ${token}`)
      .send({ slot_id: "S1", chosen_date: "2025-09-02" });

    expect(res.status).toBe(201);
    expect(res.body.appointment.slot_id).toBe("S1");
  });

  it("GET /appointments/me -> 200", async () => {
    const token = signToken({ sub: "P1", role: "patient" });
    mockPool.query.mockResolvedValueOnce([
      [{ id: "A1", status: "pending", chosen_date: "2025-09-02", doctor_id: "D9", doctor_name: "Dr.Z" }],
    ]);
    const res = await request(mod.app).get("/appointments/me").set("Authorization", `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.data[0].doctor_name).toBe("Dr.Z");
  });

  it("PATCH /appointments/:id/status (doctor only)", async () => {
    const token = signToken({ sub: "D1", role: "doctor" });
    mockPool.query
      .mockResolvedValueOnce([[{ id: "A1", doctor_id: "D1" }]]) // appt belongs to doctor
      .mockResolvedValueOnce([{ affectedRows: 1 }]);             // UPDATE status

    const res = await request(mod.app)
      .patch("/appointments/A1/status")
      .set("Authorization", `Bearer ${token}`)
      .send({ status: "confirmed" });

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });
});

// [Routes] Specialties & Reports: list specialties และรายงานสรุป
describe("Specialties & Reports", () => {
  it("GET /specialties -> 200", async () => {
    mockPool.query.mockResolvedValueOnce([[{ id: "SP1", name: "Cardio" }]]);
    const res = await request(mod.app).get("/specialties");
    expect(res.status).toBe(200);
    expect(res.body.data[0].name).toBe("Cardio");
  });

  it("GET /reports/appointments (doctor scope)", async () => {
    const token = signToken({ sub: "D1", role: "doctor" });

    // 1) สรุปตามสถานะ
    mockPool.query
      .mockResolvedValueOnce([[{ status: "confirmed", c: 2 }]])
      // 2) trend 30 วัน
      .mockResolvedValueOnce([[{ d: "2025-08-20", c: 1 }, { d: "2025-08-21", c: 1 }]])
      // 3) upcoming confirmed
      .mockResolvedValueOnce([[{ c: 1, next_date: "2025-09-10" }]]);

    const res = await request(mod.app)
      .get("/reports/appointments")
      .set("Authorization", `Bearer ${token}`)
      .query({ date: "2025-08-27" });

    expect(res.status).toBe(200);
    expect(res.body.by_status.confirmed).toBe(2);
    expect(res.body.upcoming.count).toBe(1);
  });
});

/**
 * =====================================================================
 * EXTRA TESTS (Edge cases) เพื่อดัน coverage > 80%
 * =====================================================================
 */

// [Auth Edge] บัญชีถูกล็อก และ escalated lock เมื่อพลาดครบเกณฑ์
describe("Auth locks (account locked & escalated)", () => {
  it("POST /auth/login -> 423 ACCOUNT_LOCKED เมื่อ locked_until ยังไม่หมด", async () => {
    const future = new Date(Date.now() + 10 * 60 * 1000).toISOString();


    mockPool.query.mockResolvedValueOnce([[
      {
        id: "PLOCK",
        role: "patient",
        email: "lock@x.com",
        full_name: "Locked",
        password_hash: makeStored("ignored"),
        failed_login_attempts: 5,
        lock_count: 1,
        locked_until: future,
      },
    ]]);

    const res = await request(mod.app)
      .post("/auth/login")
      .send({ email: "lock@x.com", password: "whatever" });

    expect(res.status).toBe(423);
    expect(res.body.error.code).toBe("ACCOUNT_LOCKED");
  });

  it("POST /auth/login -> 429 TOO_MANY_ATTEMPTS เมื่อแตะ 5 ครั้ง", async () => {
    mockPool.query
      .mockResolvedValueOnce([[
        {
          id: "PFAIL",
          role: "patient",
          email: "p@x.com",
          full_name: "PF",
          password_hash: makeStored("secret"),
          failed_login_attempts: 4,
          lock_count: 0,
          locked_until: null,
        },
      ]])
      .mockResolvedValueOnce([{ affectedRows: 1 }]) // UPDATE failed_login_attempts = 5
      .mockResolvedValueOnce([{ affectedRows: 1 }]); // UPDATE locked_until, lock_count

    const res = await request(mod.app)
      .post("/auth/login")
      .send({ email: "p@x.com", password: "wrong" });

    expect(res.status).toBe(429);
    expect(res.body.error.code).toBe("TOO_MANY_ATTEMPTS");
  });
});

// [Doctors Edge] forbidden เมื่อ id ไม่ตรง token + ทดสอบ alias ของ /doctors
describe("Doctors forbidden & alias", () => {
  it("POST /doctors/:id/slots -> 403 เมื่อ id ไม่ตรงกับ token.sub", async () => {
    const token = signToken({ sub: "D1", role: "doctor" });
    const res = await request(mod.app)
      .post("/doctors/D2/slots")
      .set("Authorization", `Bearer ${token}`)
      .send({ start_time: "2025-09-01", end_time: "2025-09-02" });

    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe("FORBIDDEN");
  });

  it("GET /doctors?specialty=2 -> map เป็น specialty_id แบบ number และมี 's.id = ?' ใน SQL", async () => {
    mockPool.query.mockResolvedValueOnce([[{ id: "D9", full_name: "Dr Num", email: "n@x.com", phone: "080", userpic: null }]]);
    const res = await request(mod.app).get("/doctors").query({ specialty: "2" });
    expect(res.status).toBe(200);
    const sql = String(mockPool.query.mock.calls[0][0]);
    expect(sql.includes("s.id = ?")).toBe(true);
  });

  it("GET /doctors?specialty=SPxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -> map เป็น specialty_id แบบ string 36 ตัว", async () => {
    const id36 = "SP1234567890123456789012345678901234";
    mockPool.query.mockResolvedValueOnce([[{ id: "D8", full_name: "Dr UUID", email: "u@x.com", phone: "080", userpic: null }]]);
    const res = await request(mod.app).get("/doctors").query({ specialty: id36 });
    expect(res.status).toBe(200);
    const sql = String(mockPool.query.mock.calls[0][0]);
    expect(sql.includes("s.id = ?")).toBe(true);
  });

  it("GET /doctors?specialty=Cardio -> map เป็น specialty_name และมี 's.name LIKE ?' ใน SQL", async () => {
    mockPool.query.mockResolvedValueOnce([[{ id: "D7", full_name: "Dr Name", email: "n@x.com", phone: "080", userpic: null }]]);
    const res = await request(mod.app).get("/doctors").query({ specialty: "Cardio" });
    expect(res.status).toBe(200);
    const sql = String(mockPool.query.mock.calls[0][0]);
    expect(sql.includes("s.name LIKE ?")).toBe(true);
  });
});

// [Appointments Edge] สิทธิ์/404/validation/ธุรกิจผิดเงื่อนไข
describe("Appointments edge cases", () => {
  it("GET /appointments/doctor/me -> 403 เมื่อ role เป็น patient", async () => {
    const token = signToken({ sub: "P1", role: "patient" });
    const res = await request(mod.app)
      .get("/appointments/doctor/me")
      .set("Authorization", `Bearer ${token}`);
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe("FORBIDDEN");
  });

  it("PATCH /appointments/:id/status -> 404 เมื่อไม่พบนัดของหมอคนนี้", async () => {
    const token = signToken({ sub: "D1", role: "doctor" });
    mockPool.query.mockResolvedValueOnce([[]]); // SELECT appointment -> empty

    const res = await request(mod.app)
      .patch("/appointments/AX/status")
      .set("Authorization", `Bearer ${token}`)
      .send({ status: "confirmed" });

    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe("NOT_FOUND");
  });

  it("POST /appointments -> 400 VALIDATION_ERROR เมื่อ chosen_date ไม่ถูกต้อง", async () => {
    const token = signToken({ sub: "P1", role: "patient" });
    const res = await request(mod.app)
      .post("/appointments")
      .set("Authorization", `Bearer ${token}`)
      .send({ slot_id: "S1", chosen_date: "bad-date" });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("VALIDATION_ERROR");
  });

  it("POST /appointments -> 409 PATIENT_ALREADY_BOOKED_ON_DATE เมื่อคนไข้จองวันเดียวกันแล้ว", async () => {
    const token = signToken({ sub: "P1", role: "patient" });
    mockConn.query
      .mockResolvedValueOnce([[{ id: "S1", doctor_id: "D9", start_time: "2025-09-01 00:00:00", end_time: "2025-09-03 23:59:59", status: "available" }]])
      .mockResolvedValueOnce([[{ x: 1 }]]); // existingByPatient -> มีอยู่แล้ว

    const res = await request(mod.app)
      .post("/appointments")
      .set("Authorization", `Bearer ${token}`)
      .send({ slot_id: "S1", chosen_date: "2025-09-02" });

    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe("PATIENT_ALREADY_BOOKED_ON_DATE");
  });

  it("POST /appointments -> 400 BOOKING_TOO_SOON เมื่อจองวันนี้", async () => {
    const token = signToken({ sub: "P1", role: "patient" });
    const today = new Date();
    const y = today.getFullYear();
    const m = String(today.getMonth() + 1).padStart(2, "0");
    const d = String(today.getDate()).padStart(2, "0");
    const todayYMD = `${y}-${m}-${d}`;

    mockConn.query.mockResolvedValueOnce([
      [{ id: "S1", doctor_id: "D9", start_time: `${todayYMD} 00:00:00`, end_time: `${todayYMD} 23:59:59`, status: "available" }],
    ]);

    const res = await request(mod.app)
      .post("/appointments")
      .set("Authorization", `Bearer ${token}`)
      .send({ slot_id: "S1", chosen_date: todayYMD });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("BOOKING_TOO_SOON");
  });
});

// [Users Edge] auth ขาด token และ specialties ผิด
describe("Users auth & specialties invalid", () => {
  it("GET /users/me -> 401 เมื่อไม่ส่งโทเค็น", async () => {
    const res = await request(mod.app).get("/users/me");
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe("UNAUTHORIZED");
  });

  it("PUT /users/me -> 400 INVALID_SPECIALTY_ID เมื่อส่ง specialty_ids ที่ไม่มีจริง", async () => {
    const token = signToken({ sub: "D1", role: "doctor" });

    mockPool.query.mockResolvedValueOnce([{ affectedRows: 1 }]); // UPDATE users (พื้นฐาน)
    mockConn.query
      .mockResolvedValueOnce([[{ role: "doctor" }]]) // SELECT role
      .mockResolvedValueOnce([{ affectedRows: 1 }])  // DELETE old
      .mockResolvedValueOnce([[]]);                  // SELECT exists -> ว่าง -> invalid

    const res = await request(mod.app)
      .put("/users/me")
      .set("Authorization", `Bearer ${token}`)
      .send({ full_name: "Nope", specialty_ids: ["BAD"] });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("INVALID_SPECIALTY_ID");
  });
});

// [Doctors Edge] validation error ของ Create Slot schema
describe("Doctors validation error on slot create", () => {
  it("POST /doctors/:id/slots -> 400 VALIDATION_ERROR เมื่อ end < start", async () => {
    const token = signToken({ sub: "D1", role: "doctor" });
    const res = await request(mod.app)
      .post("/doctors/D1/slots")
      .set("Authorization", `Bearer ${token}`)
      .send({ start_time: "2025-09-03T10:00:00Z", end_time: "2025-09-02T10:00:00Z" });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("VALIDATION_ERROR");
  });
});
