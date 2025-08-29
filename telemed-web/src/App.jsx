// src/App.jsx
import React, { useEffect } from "react";
import { Routes, Route, Navigate, useNavigate } from "react-router-dom";
import Nav from "./components/Nav.jsx";
import PrivateRoute from "./components/PrivateRoute.jsx";

// Auth pages
import Login from "./pages/Auth/Login.jsx";
import Register from "./pages/Auth/Register.jsx";

// Patient pages
import PatientDash from "./pages/Patient/Dashboard.jsx";
import PatientProfile from "./pages/Patient/Profile.jsx";
import PatientHome from "./pages/Patient/Home.jsx";
import PatientBook from "./pages/Patient/Book.jsx"; // <-- new

// Doctor pages
import DoctorDash from "./pages/Doctor/Dashboard.jsx";
import DoctorProfile from "./pages/Doctor/Profile.jsx";
import DoctorHome from "./pages/Doctor/Home.jsx";
import DoctorSlot from "./pages/Doctor/Slot.jsx"; // <-- optional: ถ้าทำให้หมอสร้าง slot

/**
 * ProfileRedirect
 * - อ่าน role จาก localStorage (ถ้าคุณมี auth context ให้เปลี่ยนไปอ่านจากนั้น)
 * - พาไป route ที่เหมาะสม (/doctor/profile หรือ /patient/profile) หรือ /login ถ้าไม่ล็อกอิน
 */
function ProfileRedirect() {
  const nav = useNavigate();
  useEffect(() => {
    const role = (localStorage.getItem("role") || "").toString();
    if (role === "doctor") {
      nav("/doctor/profile", { replace: true });
      return;
    }
    if (role === "patient") {
      nav("/patient/profile", { replace: true });
      return;
    }
    nav("/login", { replace: true });
  }, [nav]);
  return null;
}

/**
 * HomeRedirect
 * - ถ้า user ยังไม่ล็อกอิน -> public landing (/patient/home)
 * - ถ้าล็อกอินแล้ว -> ไปหน้าที่เหมาะกับ role (doctor -> /doctor, patient -> /patient)
 */
function HomeRedirect() {
  const nav = useNavigate();
  useEffect(() => {
    const token = localStorage.getItem("token");
    const role = (localStorage.getItem("role") || "").toString();
    if (!token) {
      // ไม่มี token → เด้งไปหน้า Login
     nav("/login", { replace: true });
      return;
    }
    // logged in -> role-specific dashboard
    if (role === "doctor") nav("/doctor", { replace: true });
    else if (role === "patient") nav("/patient", { replace: true });
    else nav("/patient/home", { replace: true });
  }, [nav]);
  return null;
}

export default function App() {
  return (
    <div>
      {/* overlay element (exists in your app already) */}
      <div className="app-overlay" />

      {/* top nav */}
      <Nav />

      <main style={{ paddingTop: 20 }}>
        <Routes>
          {/* Public auth */}
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          {/* Public Home pages (separate for patient/doctor as requested) */}
          <Route path="/patient/home" element={<PatientHome />} />
          <Route path="/doctor/home" element={<DoctorHome />} />

          {/* Patient private routes */}
          <Route
            path="/patient"
            element={
              <PrivateRoute roles={["patient"]}>
                <PatientDash />
              </PrivateRoute>
            }
          />
          <Route
            path="/patient/profile"
            element={
              <PrivateRoute roles={["patient"]}>
                <PatientProfile />
              </PrivateRoute>
            }
          />
          {/* Patient booking page (accessible from patient dashboard "จองนัดใหม่") */}
          <Route
            path="/patient/book"
            element={
              <PrivateRoute roles={["patient"]}>
                <PatientBook />
              </PrivateRoute>
            }
          />

          {/* Doctor private routes */}
          <Route
            path="/doctor"
            element={
              <PrivateRoute roles={["doctor"]}>
                <DoctorDash />
              </PrivateRoute>
            }
          />
          <Route
            path="/doctor/profile"
            element={
              <PrivateRoute roles={["doctor"]}>
                <DoctorProfile />
              </PrivateRoute>
            }
          />
          {/* Doctor slot creation (optional) */}
          <Route
            path="/doctor/slots"
            element={
              <PrivateRoute roles={["doctor"]}>
                <DoctorSlot />
              </PrivateRoute>
            }
          />

          {/* legacy /profile -> redirect based on role (requires auth) */}
          <Route
            path="/profile"
            element={
              <PrivateRoute>
                <ProfileRedirect />
              </PrivateRoute>
            }
          />
          <Route path="/" element={<Login />} />
          {/* Fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
