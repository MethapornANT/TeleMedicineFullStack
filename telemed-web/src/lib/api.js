// src/lib/api.js
import axios from "axios";

const BASE = import.meta.env.VITE_API_URL || "http://localhost:4005";

const api = axios.create({
  baseURL: BASE,
  timeout: 10000,
});

// attach token + handle FormData content-type
api.interceptors.request.use(
  (config) => {
    try {
      const token = localStorage.getItem("token");
      if (token) {
        config.headers = config.headers || {};
        config.headers.Authorization = "Bearer " + token;
      }
    } catch { /* noop */ }

    // ถ้าเป็น FormData ปล่อยให้ browser ใส่ boundary เอง
    if (config.data instanceof FormData) {
      if (config.headers) {
        delete config.headers["Content-Type"];
        delete config.headers["content-type"];
      }
    }

    return config;
  },
  (err) => Promise.reject(err)
);

// normalize backend error + เก็บ response เดิมไว้ด้วย
api.interceptors.response.use(
  (res) => res,
  (err) => {
    const resp = err?.response;
    if (resp) {
      const payload = resp.data;
      const message =
        payload?.error?.message ||
        payload?.message ||
        (typeof payload === "string" ? payload : "เกิดข้อผิดพลาดจากเซิร์ฟเวอร์");

      // แนบฟิลด์ normalize ลงบน err เดิม เพื่อให้ ex.response ยังใช้งานได้
      err.status = resp.status;
      err.message = message;
      err.payload = payload;

      return Promise.reject(err);
    }
    return Promise.reject({ status: 0, message: err?.message || "Network error", raw: err });
  }
);

export default api;
