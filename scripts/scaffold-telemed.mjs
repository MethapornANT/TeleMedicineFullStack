// scripts/scaffold-telemed.mjs
// Usage: node scripts/scaffold-telemed.mjs
import fs from "fs";
import path from "path";
const R = (...p) => path.join(process.cwd(), ...p);

const ensureDir = (p) => {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
};

const write = (p, content) => {
  fs.writeFileSync(p, content, "utf8");
  console.log("Wrote", p.replace(process.cwd() + path.sep, ""));
};

console.log("Scaffold starting...");

// base folder
const base = R("telemed-web");
ensureDir(base);

// package.json
const pkg = {
  name: "telemed-web",
  version: "0.1.0",
  private: true,
  scripts: {
    dev: "vite",
    build: "vite build",
    preview: "vite preview"
  },
  dependencies: {
    react: "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.14.1",
    axios: "^1.4.0"
  },
  devDependencies: {
    vite: "^5.0.0"
  }
};
write(R("telemed-web/package.json"), JSON.stringify(pkg, null, 2));

// public folder + note about background image
ensureDir(R("telemed-web/public"));
write(R("telemed-web/public/README.txt"), `Place your background image here as "bgbw.jpg"\nYou can copy your existing bgbw.jpg into this folder.\nIf you don't, a fallback gradient will be used.`);

// src + subfolders
ensureDir(R("telemed-web/src"));
ensureDir(R("telemed-web/src/pages"));
ensureDir(R("telemed-web/src/pages/Auth"));
ensureDir(R("telemed-web/src/pages/Patient"));
ensureDir(R("telemed-web/src/components"));
ensureDir(R("telemed-web/src/lib"));

// index.html
write(R("telemed-web/index.html"), `<!doctype html>
<html lang="th">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Telemed</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
`);

// src/main.jsx
write(R("telemed-web/src/main.jsx"), `import React from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App.jsx";
import "./index.css";

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);
`);

// src/index.css
write(R("telemed-web/src/index.css"), `:root{
  --bg-img: url('/bgbw.jpg');
  --page-bg-color: #0b0b0b;
  --overlay-gradient: linear-gradient(180deg, rgba(6,8,11,0.72), rgba(10,12,14,0.78));
  --card-border: rgba(255,255,255,0.03);
  --muted: #98a2b3;
  --accent: #165fbe;
  --accent-2: #1e71d6;
  --text-main: #e7eef8;
  --radius: 12px;
  font-family: Inter, system-ui, -apple-system, 'Segoe UI', Roboto, Arial;
}
* { box-sizing: border-box; }
html,body,#root { height:100%; margin:0; }
body {
  background-image: var(--bg-img);
  background-size: cover;
  background-position: center;
  color: var(--text-main);
}

/* overlay */
.app-overlay { position: fixed; inset:0; z-index:0; background: var(--overlay-gradient); }

/* container */
.container { position: relative; z-index:1; max-width:1200px; margin:28px auto; padding:0 20px; }

/* card */
.card {
  background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01));
  border-radius: var(--radius);
  padding: 16px;
  border: 1px solid var(--card-border);
  box-shadow: 0 12px 30px rgba(2,6,15,0.45);
  color: var(--text-main);
}

.row { display:flex; gap:12px; }
.col { display:flex; flex-direction:column; gap:12px; }
.btn {
  padding:10px 14px; border-radius:10px; font-weight:800; cursor:pointer;
  border:none; color:white; background: linear-gradient(90deg,var(--accent),var(--accent-2));
}
.small { font-size:13px; color:var(--muted); }

/* simple responsive */
@media (max-width: 900px) {
  .row { flex-direction: column; }
}
`);

// src/lib/api.js
write(R("telemed-web/src/lib/api.js"), `import axios from "axios";
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "http://localhost:4005",
  headers: { "Content-Type": "application/json" },
});
api.interceptors.request.use(config => {
  const token = localStorage.getItem("token");
  if (token) config.headers.Authorization = "Bearer " + token;
  return config;
});
export default api;
`);

// src/components/Nav.jsx
write(R("telemed-web/src/components/Nav.jsx"), `import React from "react";
import { Link, useNavigate } from "react-router-dom";

export default function Nav(){
  const role = localStorage.getItem("role");
  const nav = useNavigate();
  const logout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("role");
    nav("/login");
  };
  return (
    <>
      <nav style={{position:"relative", zIndex:2}}>
        <div className="container" style={{display:"flex", justifyContent:"space-between", alignItems:"center"}}>
          <Link to="/" style={{display:"flex", alignItems:"center", gap:12, textDecoration:"none", color:"var(--text-main)"}}>
            <div style={{width:36,height:36,borderRadius:8, background:"linear-gradient(90deg,#2b7bd1,#165fbe)"}}/>
            <strong style={{color:"var(--text-main)"}}>Telemed</strong>
          </Link>
          <div style={{display:"flex", alignItems:"center", gap:12}}>
            <Link to="/" style={{color:"rgba(231,238,248,0.8)", textDecoration:"none", fontWeight:700}}>Home</Link>
            <Link to="/patient" style={{color:"rgba(231,238,248,0.8)", textDecoration:"none", fontWeight:700}}>My Appointments</Link>
            <Link to="/profile" style={{color:"rgba(231,238,248,0.8)", textDecoration:"none", fontWeight:700}}>Profile</Link>
            <div style={{width:1, height:28, background:"rgba(255,255,255,0.03)"}} />
            <div style={{padding:"8px 10px", borderRadius:10, border:"1px solid rgba(255,255,255,0.02)", color:"var(--muted)"}}>
              {role ? (role === "doctor" ? "บัญชี: หมอ" : "บัญชี: คนไข้") : "ไม่ได้ล็อกอิน"}
            </div>
            <button onClick={logout} className="btn" style={{background:"linear-gradient(90deg,#1e63b8,#2b79d1)"}}>Logout</button>
          </div>
        </div>
      </nav>
    </>
  );
}
`);

// src/components/PrivateRoute.jsx
write(R("telemed-web/src/components/PrivateRoute.jsx"), `import React from "react";
import { Navigate } from "react-router-dom";
export default function PrivateRoute({ children, roles }) {
  const token = localStorage.getItem("token");
  const role = localStorage.getItem("role");
  if (!token) return <Navigate to="/login" replace />;
  if (roles && roles.length && !roles.includes(role)) return <Navigate to="/login" replace />;
  return children;
}
`);

// src/pages/Auth/Login.jsx
write(R("telemed-web/src/pages/Auth/Login.jsx"), `import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import api from "../../lib/api";

export default function Login(){
  const nav = useNavigate();
  const [form,setForm] = useState({email:"", password:""});
  const [err,setErr] = useState("");
  const [loading,setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setErr(""); setLoading(true);
    if (!form.email || !form.password) { setErr("กรุณาใส่อีเมลและรหัสผ่าน"); setLoading(false); return; }
    try {
      const { data } = await api.post("/auth/login", form);
      localStorage.setItem("token", data.token);
      localStorage.setItem("role", data.user?.role || "patient");
      nav(data.user?.role === "doctor" ? "/doctor" : "/patient");
    } catch (ex) {
      setErr(ex?.response?.data?.error?.message || "เข้าสู่ระบบไม่สำเร็จ");
    } finally { setLoading(false); }
  };

  return (
    <div style={{minHeight:"80vh", display:"grid", placeItems:"center"}}>
      <div className="card" style={{width:520}}>
        <h2>เข้าสู่ระบบ</h2>
        <p className="small">ใช้บัญชีอีเมลของคุณเพื่อเข้าสู่ระบบ</p>
        <form onSubmit={submit} style={{marginTop:12, display:"flex", flexDirection:"column", gap:10}}>
          <input placeholder="email" value={form.email} onChange={e=>setForm({...form,email:e.target.value})} />
          <input placeholder="password" type="password" value={form.password} onChange={e=>setForm({...form,password:e.target.value})} />
          {err && <div style={{color:"#f6b3b3"}}>{err}</div>}
          <div style={{display:"flex", gap:8}}>
            <button className="btn" type="submit" disabled={loading}>{loading ? "กำลัง..." : "เข้าสู่ระบบ"}</button>
            <Link to="/register" style={{alignSelf:"center", marginLeft:"auto"}}>สมัครสมาชิก</Link>
          </div>
        </form>
      </div>
    </div>
  );
}
`);

// src/pages/Auth/Register.jsx
write(R("telemed-web/src/pages/Auth/Register.jsx"), `import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import api from "../../lib/api";

export default function Register() {
  const nav = useNavigate();
  const [form,setForm] = useState({ role:"patient", full_name:"", email:"", phone:"", password:"" });
  const [err,setErr] = useState(""); const [loading,setLoading]=useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setErr("");
    if (!form.full_name || !form.email || !form.password) { setErr("กรุณาใส่ข้อมูลให้ครบ"); return; }
    setLoading(true);
    try {
      await api.post("/auth/register", form);
      nav("/login");
    } catch (ex) {
      setErr(ex?.response?.data?.error?.message || "สมัครสมาชิกไม่สำเร็จ");
    } finally { setLoading(false); }
  };

  return (
    <div style={{minHeight:"80vh", display:"grid", placeItems:"center"}}>
      <div className="card" style={{width:760}}>
        <h2>สมัครสมาชิก</h2>
        <p className="small">สร้างบัญชีใหม่เพื่อใช้งานระบบ นัดหมายกับแพทย์</p>
        <form onSubmit={submit} style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginTop:12}}>
          <select value={form.role} onChange={e=>setForm({...form, role: e.target.value})}>
            <option value="patient">Patient</option>
            <option value="doctor">Doctor</option>
          </select>
          <input placeholder="ชื่อ-นามสกุล" value={form.full_name} onChange={e=>setForm({...form, full_name:e.target.value})} />
          <input placeholder="email" value={form.email} onChange={e=>setForm({...form, email:e.target.value})} />
          <input placeholder="phone (optional)" value={form.phone} onChange={e=>setForm({...form, phone:e.target.value})} />
          <input placeholder="password" type="password" value={form.password} onChange={e=>setForm({...form, password:e.target.value})} />
          <div style={{gridColumn:"1 / -1", display:"flex", justifyContent:"space-between", alignItems:"center"}}>
            <div>{err && <span style={{color:"#f6b3b3"}}>{err}</span>}</div>
            <div style={{display:"flex", gap:8}}>
              <Link to="/login" style={{alignSelf:"center"}}>มีบัญชีแล้ว? เข้าสู่ระบบ</Link>
              <button className="btn" type="submit" disabled={loading}>{loading ? "กำลังสมัคร..." : "สมัครสมาชิก"}</button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
`);

// src/pages/Patient/Dashboard.jsx
write(R("telemed-web/src/pages/Patient/Dashboard.jsx"), `import React, { useEffect, useState } from "react";
import api from "../../lib/api";

export default function PatientDash(){
  const [loading,setLoading]=useState(true);
  const [appts,setAppts]=useState([]);
  const [err,setErr]=useState("");

  useEffect(()=> {
    (async()=>{
      try {
        const r = await api.get("/appointments/me");
        setAppts(r?.data?.data || []);
      } catch(e) {
        setErr("โหลดนัดไม่สำเร็จ");
      } finally { setLoading(false); }
    })();
  },[]);

  return (
    <div style={{minHeight:"60vh"}}>
      <div className="container">
        <h2>แดชบอร์ดคนไข้</h2>
        <p className="small">จัดการการนัดหมาย ดูประวัติ และติดต่อแพทย์ได้ที่นี่</p>

        <div style={{display:"grid", gridTemplateColumns:"1fr 340px", gap:18, marginTop:18}}>
          <div>
            <div className="card" style={{marginBottom:12}}>
              <div style={{display:"flex", gap:12}}>
                <div style={{flex:1}}>
                  <div className="small">นัดข้างหน้า</div>
                  <div style={{fontWeight:800, fontSize:20, marginTop:8}}>{loading ? "-" : appts.filter(a=>a.status==="upcoming").length}</div>
                </div>
                <div style={{flex:1}}>
                  <div className="small">สำเร็จแล้ว</div>
                  <div style={{fontWeight:800, fontSize:20, marginTop:8}}>{loading ? "-" : appts.filter(a=>a.status==="done").length}</div>
                </div>
                <div style={{flex:1}}>
                  <div className="small">ยกเลิก</div>
                  <div style={{fontWeight:800, fontSize:20, marginTop:8}}>{loading ? "-" : appts.filter(a=>a.status==="cancelled").length}</div>
                </div>
              </div>
            </div>

            <div className="card">
              <h3>นัดข้างหน้า</h3>
              {loading ? <div className="small">กำลังโหลด...</div> : (
                appts.length ? appts.map(a=>(
                  <div key={a.id} style={{padding:10, borderBottom:"1px solid rgba(255,255,255,0.02)"}}>
                    <div style={{fontWeight:800}}>{a.title || "การปรึกษาออนไลน์"}</div>
                    <div className="small">{a.doctor_name || "แพทย์" } • {new Date(a.start_time || a.start || Date.now()).toLocaleString()}</div>
                  </div>
                )) : <div className="small">ยังไม่มีนัด</div>
              )}
            </div>
          </div>

          <aside>
            <div className="card" style={{marginBottom:12}}>
              <div style={{fontWeight:800}}>การกระทำด่วน</div>
              <div style={{marginTop:12, display:"flex", flexDirection:"column", gap:8}}>
                <button className="btn" onClick={()=>alert("จอง (จำลอง)")}>จองนัดใหม่</button>
                <button className="btn" style={{background:"transparent", border:"1px solid rgba(255,255,255,0.04)", color:"var(--text-main)"}}>ติดต่อแพทย์</button>
              </div>
            </div>

            <div className="card">
              <div style={{fontWeight:800}}>ช่วยเหลือ / ข้อมูล</div>
              <div className="small" style={{marginTop:8}}>ติดต่อ support@telemed.local</div>
            </div>
          </aside>
        </div>
      </div>
    </div>
  );
}
`);

// src/pages/Profile.jsx
write(R("telemed-web/src/pages/Profile.jsx"), `import React from "react";

export default function Profile(){
  return (
    <div style={{minHeight:"60vh"}}>
      <div className="container">
        <div className="card">
          <h2>โปรไฟล์ของฉัน</h2>
          <p className="small">แก้ไขข้อมูลส่วนตัว</p>
        </div>
      </div>
    </div>
  );
}
`);

// src/App.jsx
write(R("telemed-web/src/App.jsx"), `import React from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import Nav from "./components/Nav.jsx";
import PrivateRoute from "./components/PrivateRoute.jsx";
import Login from "./pages/Auth/Login.jsx";
import Register from "./pages/Auth/Register.jsx";
import PatientDash from "./pages/Patient/Dashboard.jsx";
import Profile from "./pages/Profile.jsx";

export default function App(){
  return (
    <div>
      <div className="app-overlay" />
      <Nav />
      <main style={{paddingTop:20}}>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          <Route path="/patient" element={
            <PrivateRoute roles={["patient"]}><PatientDash /></PrivateRoute>
          } />

          <Route path="/profile" element={
            <PrivateRoute><Profile /></PrivateRoute>
          } />

          <Route path="/" element={<Navigate to="/patient" replace />} />
        </Routes>
      </main>
    </div>
  );
}
`);

// .env (example)
write(R("telemed-web/.env"), `VITE_API_URL=http://localhost:4005
`);

// README
write(R("telemed-web/README.md"), `Telemed web scaffold
Run:
  cd telemed-web
  npm install
  npm run dev

Place your background image at public/bgbw.jpg (optional).
`);

// .gitignore
write(R("telemed-web/.gitignore"), `node_modules
dist
.env
`);

// done
console.log("\\nScaffold complete. Next steps:");
console.log("  1) cd telemed-web");
console.log("  2) npm install");
console.log("  3) npm run dev");
console.log("\\nIf you want the script to also auto-run npm install, tell me and I'll extend it (but it's safer to run manually).");
