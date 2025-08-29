// telemed-web/src/pages/Patient/Profile.jsx
import React, { useEffect, useState, useMemo, useRef } from "react";
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  CircularProgress,
  Snackbar,
  Alert,
  Grid,
  Chip,
  Divider,
  Stack,
  Avatar,
  IconButton,
  Fade,
  Tooltip,
} from "@mui/material";
import EditIcon from "@mui/icons-material/Edit";
import SaveIcon from "@mui/icons-material/Save";
import CloseIcon from "@mui/icons-material/Close";
import PhotoCameraIcon from "@mui/icons-material/PhotoCamera";
import api from "../../lib/api";

const API_BASE = (import.meta.env.VITE_API_URL || "http://localhost:4005").replace(/\/+$/,"");

export default function Profile() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");
  const [profile, setProfile] = useState(null);
  const [form, setForm] = useState({ full_name: "", email: "", phone: "" });
  const [editing, setEditing] = useState(false);
  const [snack, setSnack] = useState({ open: false, msg: "", severity: "success" });

  // รูปโปรไฟล์
  const [userpicFile, setUserpicFile] = useState(null);
  const [userpicPreview, setUserpicPreview] = useState("");
  const fileRef = useRef(null);

  // สร้าง public URL สำหรับรูปที่เก็บใน backend
  const publicPicUrl = useMemo(() => {
    const p = profile?.userpic;
    if (!p) return "";
    return /^https?:\/\//i.test(p) ? p : `${API_BASE}${p}`;
  }, [profile?.userpic]);

  useEffect(() => {
    let mounted = true;
    (async () => {
      setErr("");
      try {
        const res = await api.get("/users/me");
        if (!mounted) return;
        const user = res?.data?.user || null;
        setProfile(user);
        setForm({
          full_name: user?.full_name || "",
          email: user?.email || "",
          phone: user?.phone || "",
        });
      } catch (e) {
        console.error("load profile: ", e);
        setErr(e?.message || "โหลดโปรไฟล์ไม่สำเร็จ โปรดลองใหม่");
      } finally {
        if (mounted) setLoading(false);
      }
    })();
    return () => (mounted = false);
  }, []);

  useEffect(() => {
    return () => {
      if (userpicPreview) URL.revokeObjectURL(userpicPreview);
    };
  }, [userpicPreview]);

  const validate = (data) => {
    const errors = [];
    if (!data.full_name || !data.full_name.trim()) errors.push("กรุณาระบุชื่อ-นามสกุล");
    if (!data.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/i.test(data.email.trim()))
      errors.push("รูปแบบอีเมลไม่ถูกต้อง");
    if (data.phone && !/^\d{9,10}$/.test(String(data.phone).trim()))
      errors.push("เบอร์ต้องเป็นตัวเลข 9-10 หลัก");
    return errors;
  };

  const pickPic = () => fileRef.current?.click();

  const onPicChange = (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const sizeMb = f.size / (1024 * 1024);
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    if (sizeMb > 5) {
      setSnack({ open: true, msg: "ขนาดรูปต้องไม่เกิน 5MB", severity: "error" });
      return;
    }
    if (!allowed.includes(f.type)) {
      setSnack({ open: true, msg: "รองรับเฉพาะ JPG/PNG/WebP", severity: "error" });
      return;
    }
    setUserpicFile(f);
    setUserpicPreview((old) => {
      if (old) URL.revokeObjectURL(old);
      return URL.createObjectURL(f);
    });
    setEditing(true); // เข้าโหมดแก้ไขเมื่อเลือกรูป
  };

  const handleSave = async (e) => {
    e?.preventDefault();
    setErr("");

    const errors = validate(form);
    if (errors.length) {
      setErr(errors.join(" • "));
      return;
    }

    setSaving(true);
    try {
      // ส่งเป็น FormData เสมอ (รองรับไฟล์)
      const fd = new FormData();
      fd.append("full_name", form.full_name);
      fd.append("phone", form.phone || "");
      if (userpicFile) fd.append("userpic", userpicFile);

      const res = await api.put("/users/me", fd);

      const user = res?.data?.user || {
        ...profile,
        full_name: form.full_name,
        phone: form.phone || null,
        userpic: profile?.userpic,
      };

      setProfile(user);
      setEditing(false);
      setUserpicFile(null);
      if (userpicPreview) {
        URL.revokeObjectURL(userpicPreview);
        setUserpicPreview("");
      }
      setSnack({ open: true, msg: "บันทึกสำเร็จ", severity: "success" });
    } catch (e) {
      console.error("save profile:", e);
      const payload = e?.payload ?? e?.response?.data;
      const msg = payload?.error?.message || e?.message || "บันทึกไม่สำเร็จ ลองอีกครั้ง";
      setErr(msg);
      setSnack({ open: true, msg, severity: "error" });
    } finally {
      setSaving(false);
    }
  };

  const handleCancel = () => {
    setEditing(false);
    setForm({
      full_name: profile?.full_name || "",
      email: profile?.email || "",
      phone: profile?.phone || "",
    });
    setUserpicFile(null);
    if (userpicPreview) {
      URL.revokeObjectURL(userpicPreview);
      setUserpicPreview("");
    }
    setErr("");
  };

  if (loading)
    return (
      <Box sx={{ minHeight: "60vh", display: "grid", placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );

  const renderProfileView = () => (
    <Grid container spacing={4} alignItems="center">
      <Grid item xs={12} md={4}>
        <Stack spacing={2} alignItems="center">
          <Box sx={{ position: "relative" }}>
            <Avatar
              src={userpicPreview || publicPicUrl || undefined}
              sx={{
                width: { xs: 120, md: 160 },
                height: { xs: 120, md: 160 },
                boxShadow: "0 18px 40px rgba(2,12,40,0.12)",
                border: "6px solid white",
                bgcolor: "#f1f5f9",
              }}
            >
              {profile?.full_name?.charAt(0) || "?"}
            </Avatar>

            <Tooltip title="เปลี่ยนรูปโปรไฟล์">
              <IconButton
                onClick={pickPic}
                size="small"
                sx={{
                  position: "absolute",
                  right: -6,
                  bottom: -6,
                  bgcolor: "background.paper",
                  border: "1px solid rgba(0,0,0,0.06)",
                  boxShadow: "0 8px 20px rgba(2,12,40,0.08)",
                  "&:hover": { bgcolor: "grey.100" },
                }}
                aria-label="เปลี่ยนรูปโปรไฟล์"
              >
                <PhotoCameraIcon />
              </IconButton>
            </Tooltip>
          </Box>

          <Stack direction="row" spacing={1}>
            <Typography variant="h6" sx={{ fontWeight: 700 }}>
              {profile?.full_name}
            </Typography>
          </Stack>

          <Chip
            label={profile?.role === "doctor" ? "บัญชี: หมอ" : "บัญชี: คนไข้"}
            size="small"
            sx={{ bgcolor: "#e8f6ef", color: "#046a50", fontWeight: 700 }}
          />
        </Stack>
      </Grid>

      <Grid item xs={12} md={8}>
        <Stack spacing={2}>
          <Box>
            <Typography variant="subtitle2" color="text.secondary">
              ชื่อ - นามสกุล
            </Typography>
            <Typography variant="body1">{profile?.full_name}</Typography>
          </Box>
          <Box>
            <Typography variant="subtitle2" color="text.secondary">
              อีเมล
            </Typography>
            <Typography variant="body1">{profile?.email}</Typography>
          </Box>
          <Box>
            <Typography variant="subtitle2" color="text.secondary">
              เบอร์โทร
            </Typography>
            <Typography variant="body1">{profile?.phone || "-"}</Typography>
          </Box>
        </Stack>
      </Grid>
    </Grid>
  );

  const renderEditForm = () => (
    <Box component="form" onSubmit={handleSave}>
      <Grid container spacing={3} alignItems="center">
        <Grid item xs={12} md={4}>
          <Stack alignItems="center" spacing={1}>
            <Avatar
              src={userpicPreview || publicPicUrl || undefined}
              sx={{
                width: { xs: 120, md: 160 },
                height: { xs: 120, md: 160 },
                boxShadow: "0 18px 40px rgba(2,12,40,0.12)",
                border: "6px solid white",
                bgcolor: "#f1f5f9",
              }}
            >
              {profile?.full_name?.charAt(0) || "?"}
            </Avatar>

            <input
              ref={fileRef}
              type="file"
              accept="image/jpeg,image/png,image/webp"
              hidden
              onChange={onPicChange}
            />

            <Button
              onClick={pickPic}
              variant="contained"
              size="small"
              sx={{ textTransform: "none", mt: 1 }}
            >
              เปลี่ยนรูปโปรไฟล์
            </Button>
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1 }}>
              JPG / PNG / WebP — สูงสุด 5MB
            </Typography>
          </Stack>
        </Grid>

        <Grid item xs={12} md={8}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <TextField
                label="ชื่อ - นามสกุล"
                value={form.full_name}
                onChange={(e) => setForm((p) => ({ ...p, full_name: e.target.value }))}
                fullWidth
                required
                variant="outlined"
                InputProps={{ sx: { borderRadius: 2 } }}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                label="อีเมล"
                value={form.email}
                fullWidth
                disabled
                variant="outlined"
                helperText="ไม่สามารถแก้ไขได้จากที่นี่"
                InputProps={{ sx: { borderRadius: 2 } }}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                label="เบอร์โทร (ไม่บังคับ)"
                value={form.phone || ""}
                onChange={(e) => setForm((p) => ({ ...p, phone: e.target.value }))}
                fullWidth
                variant="outlined"
                helperText="ตัวเลข 9-10 หลัก"
                InputProps={{ sx: { borderRadius: 2 } }}
              />
            </Grid>

            <Grid item xs={12} display="flex" justifyContent="flex-end" sx={{ mt: 1 }}>
              <Stack direction="row" spacing={2}>
                <Button onClick={handleCancel} variant="outlined" sx={{ textTransform: "none" }}>
                  ยกเลิก
                </Button>
                <Button onClick={handleSave} variant="contained" disabled={saving} sx={{ textTransform: "none" }}>
                  {saving ? <CircularProgress size={18} color="inherit" /> : "บันทึก"}
                </Button>
              </Stack>
            </Grid>
          </Grid>
        </Grid>
      </Grid>
    </Box>
  );

  return (
    <Box
      sx={{
        minHeight: "100vh",
        // ใช้ภาพ bgbw.jpg จาก public folder ตรงๆ (ไม่มี overlay)
        backgroundImage: "url('/bgbw.jpg')",
        backgroundRepeat: "no-repeat",
        backgroundSize: "cover",
        backgroundPosition: "center center",
        // ทำให้ background คงที่เมื่อเลื่อน (ภาพจะไม่เลื่อนตาม content)
        backgroundAttachment: "fixed",
        // ถ้าต้องการให้ content อยู่ตรงกลาง สร้าง padding top/bottom
        py: { xs: 6, md: 10 },
        display: "flex",
        alignItems: "start",
        justifyContent: "center",
      }}
    >
      {/* Card กว้างและอยู่กึ่งกลาง */}
      <Box sx={{ width: "100%", maxWidth: 1100, px: { xs: 2, md: 4 }, mt: { xs: 2, md: 6 } }}>
        <Paper
          elevation={8}
          sx={{
            borderRadius: 3,
            p: { xs: 3, md: 5 },
            overflow: "visible",
            position: "relative",
            // ให้การ์ดขาวชัดเจนบนพื้นหลังโดยไม่บดบังภาพทั้งหมด
            background: "rgba(255,255,255,0.98)",
            boxShadow: "0 32px 80px rgba(10,20,40,0.12)",
          }}
        >
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 800, letterSpacing: "-0.6px" }}>
                โปรไฟล์ของฉัน
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                ตรวจสอบและแก้ไขข้อมูลส่วนตัว
              </Typography>
            </Box>

            <Stack direction="row" spacing={1} alignItems="center">
              {!editing ? (
                <Tooltip title="แก้ไขข้อมูล">
                  <IconButton onClick={() => setEditing(true)} aria-label="แก้ไข">
                    <EditIcon />
                  </IconButton>
                </Tooltip>
              ) : (
                <Stack direction="row" spacing={1}>
                  <Tooltip title="ยกเลิก">
                    <IconButton onClick={handleCancel}>
                      <CloseIcon />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="บันทึก">
                    <IconButton onClick={handleSave} disabled={saving} color="primary">
                      <SaveIcon />
                    </IconButton>
                  </Tooltip>
                </Stack>
              )}
            </Stack>
          </Box>

          <Divider sx={{ my: 2 }} />

          {err && (
            <Box mb={2}>
              <Typography color="error" variant="body2">
                {err}
              </Typography>
            </Box>
          )}

          <input ref={fileRef} type="file" accept="image/jpeg,image/png,image/webp" hidden onChange={onPicChange} />

          <Fade in={!editing}>
            <Box sx={{ display: editing ? "none" : "block" }}>{renderProfileView()}</Box>
          </Fade>

          <Fade in={editing}>
            <Box sx={{ display: !editing ? "none" : "block" }}>{renderEditForm()}</Box>
          </Fade>
        </Paper>
      </Box>

      <Snackbar
        open={snack.open}
        autoHideDuration={3000}
        onClose={() => setSnack((s) => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
      >
        <Alert severity={snack.severity} sx={{ width: "100%" }}>
          {snack.msg}
        </Alert>
      </Snackbar>
    </Box>
  );
}
