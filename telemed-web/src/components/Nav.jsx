import React from "react";
import { Link, useNavigate } from "react-router-dom";

export default function Nav(){
  const nav = useNavigate();

  const getRole = () => localStorage.getItem("role");
  const getToken = () => localStorage.getItem("token");

  const logout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("role");
    nav("/login");
  };

  const goHome = (e) => {
    if (e) e.preventDefault();
    const token = getToken();
    const role = getRole();
    if (!token) return nav("/login");
    return nav(role === "doctor" ? "/doctor/home" : "/patient/home");
  };

  const goMyAppointments = (e) => {
    if (e) e.preventDefault();
    const token = getToken();
    const role = getRole();
    if (!token) return nav("/login");
    return nav(role === "doctor" ? "/doctor" : "/patient");
  };

  const goProfile = (e) => {
    if (e) e.preventDefault();
    const token = getToken();
    if (!token) return nav("/login");
    return nav("/profile");
  };

  const role = getRole();
  const token = getToken();

  return (
    <>
      <style>{`
        :root{
          --nav-h: 84px;
          --accent: #2b6fb2;
          --muted: #6b7280;
        }
        header.site-nav{
          position: fixed;
          inset: 0 0 auto 0;
          height: var(--nav-h);
          display: flex;
          align-items: center;
          z-index: 50;
          background: #f3f4f6; /* พื้นหลังสีเทา */
          padding: 0 28px;
          box-shadow: 0 1px 4px rgba(0,0,0,0.08);
        }
        .site-inner{
          width: 100%;
          max-width: 1200px;
          margin: 0 auto;
          display:flex;
          align-items:center;
          justify-content:space-between;
          gap:18px;
        }
        .brand{ display:flex; align-items:center; gap:12px; text-decoration:none; color:#1f2b34; font-weight:700 }
        .brand-logo{ width:36px;height:36px;border-radius:10px;background:linear-gradient(90deg,#2b7bd1,#165fbe); box-shadow:0 8px 20px rgba(16,24,40,0.12) }
        .nav-center{ display:flex; gap:22px; align-items:center; justify-content:center; flex:1 }
        .nav-center a, .nav-center button { color:#6b7280; text-decoration:none; font-weight:600; background:transparent; border:none; cursor:pointer; padding:6px 8px; border-radius:8px; }
        .nav-center a:hover, .nav-center button:hover { background: rgba(11,18,25,0.05); color: #364152; }
        .right-area{ display:flex; gap:12px; align-items:center }
        .account-pill{ padding:8px 12px; border-radius:10px; background: rgba(255,255,255,0.8); color:var(--muted); border:1px solid rgba(16,24,40,0.04) }
        .btn-logout{ padding:8px 12px; border-radius:10px; background:var(--accent); color:white; border:none; cursor:pointer; box-shadow: 0 8px 20px rgba(43,111,178,0.18) }
        .btn-login{ padding:8px 12px; border-radius:10px; background:white; color:var(--muted); border:1px solid rgba(16,24,40,0.06); cursor:pointer }
        @media (max-width:880px){
          .nav-center{ display:none }
        }
      `}</style>

      <header className="site-nav" role="banner" aria-label="Site navigation">
        <div className="site-inner">
          <Link to="/" className="brand" aria-label="Telemed home" onClick={goHome}>
            <div className="brand-logo" />
            <span>Telemed</span>
          </Link>

          <nav className="nav-center" aria-label="Main navigation">
            <button onClick={goHome}>Home</button>
            <button onClick={goMyAppointments}>My Appointments</button>
            <button onClick={goProfile}>Profile</button>
          </nav>

          <div className="right-area" role="group">
            <div className="account-pill" aria-live="polite">
              { token ? (role === "doctor" ? "บัญชี: หมอ" : "บัญชี: คนไข้") : "ไม่ได้ล็อกอิน" }
            </div>

            { token ? (
              <button onClick={logout} className="btn-logout" aria-label="Logout">Logout</button>
            ) : (
              <button onClick={() => nav("/login")} className="btn-login" aria-label="Login">Login</button>
            ) }
          </div>
        </div>
      </header>
    </>
  );
}
