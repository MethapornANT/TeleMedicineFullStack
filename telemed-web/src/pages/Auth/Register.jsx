// src/pages/Auth/Register.jsx
import React, { useState, useEffect, useRef } from "react";
import { useNavigate, Link as RouterLink } from "react-router-dom";
import {
  Avatar,
  Box,
  Button,
  CircularProgress,
  Container,
  FormControl,
  InputLabel,
  MenuItem,
  Paper,
  TextField,
  Typography,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Slide,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  Checkbox,
  IconButton,
  Select,
  Tooltip,
} from "@mui/material";
import { createTheme, ThemeProvider, styled } from "@mui/material/styles";
import { keyframes } from "@emotion/react";
import PhotoCameraIcon from "@mui/icons-material/PhotoCamera";
import api from "../../lib/api";

const fadeIn = keyframes`
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
`;

const shimmer = keyframes`
  0% { transform: translateX(-110%); opacity: 0; }
  40% { opacity: 1; }
  100% { transform: translateX(110%); opacity: 0; }
`;

const theme = createTheme({
  palette: {
    primary: { main: "#2b2b2b" },
    background: { default: "#ffffff", paper: "#ffffff" },
    text: { primary: "#0b1220", secondary: "#6b7280" },
  },
  typography: {
    fontFamily: ['"Inter"', "system-ui", "sans-serif"].join(","),
    h4: { fontWeight: 700, fontSize: "1.6rem", color: "#0b1220" },
  },
  components: {
    MuiPaper: {
      styleOverrides: {
        root: {
          borderRadius: 14,
          padding: "36px",
          animation: `${fadeIn} 320ms ease-out both`,
          boxShadow: "0 20px 40px rgba(8,12,20,0.06)",
        },
      },
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          "& .MuiOutlinedInput-root": {
            borderRadius: 10,
            backgroundColor: "#ffffff",
            "& fieldset": { borderColor: "#e6e7ea" },
            "&:hover fieldset": { borderColor: "#d7d9dd" },
            "&.Mui-focused fieldset": {
              borderColor: "#2b2b2b",
              boxShadow: "0 0 0 4px rgba(43,43,43,0.04)",
            },
          },
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 10,
          padding: "10px 14px",
          fontWeight: 700,
          textTransform: "none",
          boxShadow: "0 8px 18px rgba(11,18,25,0.04)",
        },
      },
    },
  },
});

const ShimmerButton = styled(Button)(({ theme }) => ({
  position: "relative",
  overflow: "hidden",
  zIndex: 1,
  background: "#2b2b2b",
  color: "#fff",
  "&:hover": { background: "#1f1f1f" },
  "&::after": {
    content: '""',
    position: "absolute",
    left: "-120%",
    top: 0,
    height: "100%",
    width: "40%",
    transform: "skewX(-12deg)",
    background:
      "linear-gradient(90deg, rgba(255,255,255,0.03), rgba(255,255,255,0.08), rgba(255,255,255,0.03))",
    opacity: 0,
    pointerEvents: "none",
  },
  "&:hover::after": {
    animation: `${shimmer} 900ms linear forwards`,
  },
}));

const Transition = React.forwardRef(function Transition(props, ref) {
  return <Slide direction="down" ref={ref} {...props} />;
});

const MAX_IMAGE_MB = 5;

export default function Register() {
  const nav = useNavigate();
  const fileInputRef = useRef(null);

  const [form, setForm] = useState({
    role: "patient",
    full_name: "",
    email: "",
    phone: "",
    password: "",
  });

  const [fieldErr, setFieldErr] = useState({
    full_name: "",
    email: "",
    phone: "",
    password: "",
    specialties: "",
    userpic: "",
  });
  const [submitErr, setSubmitErr] = useState("");
  const [loading, setLoading] = useState(false);
  const [successOpen, setSuccessOpen] = useState(false);

  // specialties data
  const [specialties, setSpecialties] = useState([]);
  const [specDialogOpen, setSpecDialogOpen] = useState(false);
  const [selectedSpecs, setSelectedSpecs] = useState([]);

  // userpic
  const [userpicFile, setUserpicFile] = useState(null);
  const [userpicPreview, setUserpicPreview] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const r = await api.get("/specialties");
        setSpecialties(r?.data?.data || []);
      } catch {
        setSpecialties([]);
      }
    })();
  }, []);

  useEffect(() => {
    if (form.role !== "doctor") {
      setSelectedSpecs([]);
      setFieldErr((fe) => ({ ...fe, specialties: "" }));
    }
  }, [form.role]);

  useEffect(() => {
    return () => {
      if (userpicPreview) URL.revokeObjectURL(userpicPreview);
    };
  }, [userpicPreview]);

  const isGmailOrHotmail = (value) => {
    if (!value) return false;
    const re = /^[^\s@]+@(gmail\.com|hotmail\.com)$/i;
    return re.test(value.trim());
  };
  const isPhoneValid = (value) => {
    if (!value) return false;
    const digits = value.replace(/\D/g, "");
    return /^[0-9]{9,10}$/.test(digits);
  };
  const isPasswordValid = (value) => typeof value === "string" && value.length >= 4;

  const validateAll = () => {
    const errs = { full_name: "", email: "", phone: "", password: "", specialties: "", userpic: "" };

    if (!form.full_name || form.full_name.trim().length < 2) {
      errs.full_name = "กรุณาระบุชื่อ-นามสกุล (อย่างน้อย 2 ตัวอักษร)";
    }
    if (!form.email) {
      errs.email = "กรุณาระบุอีเมล";
    } else if (!isGmailOrHotmail(form.email)) {
      errs.email = "อีเมลต้องลงท้ายด้วย @gmail.com หรือ @hotmail.com";
    }
    if (form.phone && !isPhoneValid(form.phone)) {
      errs.phone = "เบอร์โทรต้องเป็นตัวเลข 9 หรือ 10 หลัก";
    }
    if (!form.password) {
      errs.password = "กรุณาระบุรหัสผ่าน";
    } else if (!isPasswordValid(form.password)) {
      errs.password = "รหัสผ่านต้องอย่างน้อย 4 ตัวอักษร";
    }
    if (form.role === "doctor" && (!selectedSpecs || selectedSpecs.length === 0)) {
      errs.specialties = "แพทย์ต้องเลือกสาขาอย่างน้อย 1 รายการ";
    }

    if (userpicFile) {
      const sizeMb = userpicFile.size / (1024 * 1024);
      const allowed = ["image/jpeg", "image/png", "image/webp"];
      if (sizeMb > MAX_IMAGE_MB) errs.userpic = `ขนาดรูปต้องไม่เกิน ${MAX_IMAGE_MB}MB`;
      if (!allowed.includes(userpicFile.type)) errs.userpic = "รองรับเฉพาะ JPG/PNG/WebP";
    }

    setFieldErr(errs);
    return Object.values(errs).every((v) => !v);
  };

  const handleFilePick = () => fileInputRef.current?.click();

  const handleFileChange = (e) => {
    const f = e.target.files?.[0];
    if (!f) return;

    const sizeMb = f.size / (1024 * 1024);
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    if (sizeMb > MAX_IMAGE_MB) {
      setFieldErr((fe) => ({ ...fe, userpic: `ขนาดรูปต้องไม่เกิน ${MAX_IMAGE_MB}MB` }));
      setUserpicFile(null);
      setUserpicPreview("");
      return;
    }
    if (!allowed.includes(f.type)) {
      setFieldErr((fe) => ({ ...fe, userpic: "รองรับเฉพาะ JPG/PNG/WebP" }));
      setUserpicFile(null);
      setUserpicPreview("");
      return;
    }

    setFieldErr((fe) => ({ ...fe, userpic: "" }));
    setUserpicFile(f);
    const url = URL.createObjectURL(f);
    setUserpicPreview(url);
  };

  const submit = async (e) => {
    e.preventDefault();
    setSubmitErr("");

    const ok = validateAll();
    if (!ok) {
      setSubmitErr("กรุณาแก้ไขข้อผิดพลาดในฟอร์มก่อนดำเนินการ");
      return;
    }

    setLoading(true);
    try {
      const fd = new FormData();
      fd.append("role", form.role);
      fd.append("full_name", form.full_name.trim());
      fd.append("email", form.email.trim());
      if (form.phone) fd.append("phone", form.phone.trim());
      fd.append("password", form.password);

      if (form.role === "doctor" && selectedSpecs.length) {
        fd.append("specialties", JSON.stringify(selectedSpecs.map((s) => s.id)));
      }

      if (userpicFile) {
        fd.append("userpic", userpicFile);
      }

      const res = await api.post("/auth/register", fd);
      if (res?.data?.user || res?.status === 201) {
        setSuccessOpen(true);
      } else {
        setSubmitErr("สมัครสมาชิกไม่สำเร็จ");
      }
    } catch (ex) {
      // ✅ รองรับทั้งเคส normalize (ex.message/ex.payload) และของ axios เดิม (ex.response)
      const payload = ex?.payload ?? ex?.response?.data;
      const serverErr = payload?.error;

      if (serverErr?.details && Array.isArray(serverErr.details) && serverErr.details.length) {
        const msgs = serverErr.details.map((d) => `${d.field || "(general)"}: ${d.message}`);
        setSubmitErr(msgs.join(" / "));
      } else if (serverErr?.message || ex?.message) {
        setSubmitErr(serverErr?.message || ex.message);
      } else {
        setSubmitErr("สมัครสมาชิกไม่สำเร็จ");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSuccessOk = () => {
    setSuccessOpen(false);
    setTimeout(() => nav("/login"), 260);
  };

  const updateField = (k, v) => setForm((s) => ({ ...s, [k]: v }));

  const toggleSpec = (spec) => {
    const found = selectedSpecs.find((s) => s.id === spec.id);
    if (found) setSelectedSpecs((s) => s.filter((x) => x.id !== spec.id));
    else setSelectedSpecs((s) => [...s, spec]);
  };
  const openSpecDialog = () => setSpecDialogOpen(true);
  const closeSpecDialog = () => setSpecDialogOpen(false);
  const confirmSpecDialog = () => {
    setSpecDialogOpen(false);
    setFieldErr((fe) => ({ ...fe, specialties: "" }));
  };

  return (
    <ThemeProvider theme={theme}>
      {/* bg */}
      <Box
        sx={{
          position: "fixed",
          inset: 0,
          zIndex: -1,
          backgroundImage: `url('/bgbw.jpg')`,
          backgroundSize: "cover",
          backgroundPosition: "center",
        }}
      />

      <Container
        maxWidth={false}
        sx={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "center",
          px: 3,
          pt: { xs: 8, md: 10 },
        }}
      >
        <Box sx={{ width: "100%", maxWidth: 760, mx: "auto", mt: { xs: 2, sm: "-3vh", md: "0vh" } }}>
          <Paper elevation={6}>
            <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
              <Typography variant="h4" align="center">
                สมัครสมาชิก
              </Typography>

              <Typography variant="body1" align="center" sx={{ color: "text.secondary", mb: 1 }}>
                สร้างบัญชีใหม่เพื่อใช้งานระบบ นัดหมายกับแพทย์
              </Typography>

              {/* avatar + upload */}
              <Box
                sx={{
                  display: "flex",
                  justifyContent: "center",
                  alignItems: "center",
                  mb: 2,
                  position: "relative",
                }}
              >
                <Avatar
                  src={userpicPreview || undefined}
                  alt="userpic"
                  sx={{
                    width: 104,
                    height: 104,
                    border: "2px solid #e6e7ea",
                    boxShadow: "0 10px 24px rgba(8,12,20,0.06)",
                    bgcolor: "#f3f4f6",
                  }}
                />
                <Tooltip title="อัปโหลดรูปโปรไฟล์">
                  <IconButton
                    onClick={() => fileInputRef.current?.click()}
                    sx={{
                      position: "absolute",
                      right: "calc(50% - 52px)",
                      bottom: -6,
                      bgcolor: "#2b2b2b",
                      color: "#fff",
                      "&:hover": { bgcolor: "#1f1f1f" },
                      boxShadow: "0 6px 12px rgba(8,12,20,0.12)",
                    }}
                    size="small"
                  >
                    <PhotoCameraIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/jpeg,image/png,image/webp"
                  hidden
                  onChange={handleFileChange}
                />
              </Box>
              {fieldErr.userpic && (
                <Typography align="center" color="error" variant="body2" sx={{ mb: 1 }}>
                  {fieldErr.userpic}
                </Typography>
              )}

              <Box
                component="form"
                onSubmit={submit}
                encType="multipart/form-data"
                sx={{
                  mt: 1,
                  display: "grid",
                  gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr" },
                  gap: 2,
                }}
              >
                {/* role */}
                <FormControl fullWidth>
                  <InputLabel id="role-label">ประเภท</InputLabel>
                  <Select
                    labelId="role-label"
                    id="role-select"
                    label="ประเภท"
                    value={form.role}
                    onChange={(e) => updateField("role", e.target.value)}
                    sx={{ borderRadius: 2, background: "#fff" }}
                  >
                    <MenuItem value="patient">คนไข้ (Patient)</MenuItem>
                    <MenuItem value="doctor">แพทย์ (Doctor)</MenuItem>
                  </Select>
                </FormControl>

                <TextField
                  label="ชื่อ - นามสกุล"
                  value={form.full_name}
                  onChange={(e) => updateField("full_name", e.target.value)}
                  required
                  fullWidth
                  error={!!fieldErr.full_name}
                  helperText={fieldErr.full_name || ""}
                />

                <TextField
                  label="อีเมล"
                  value={form.email}
                  onChange={(e) => updateField("email", e.target.value)}
                  required
                  fullWidth
                  sx={{ gridColumn: { xs: "1 / -1", sm: "1 / 2" } }}
                  error={!!fieldErr.email}
                  helperText={fieldErr.email || ""}
                />

                <TextField
                  label="เบอร์โทร (ไม่บังคับ)"
                  value={form.phone}
                  onChange={(e) => updateField("phone", e.target.value)}
                  fullWidth
                  error={!!fieldErr.phone}
                  helperText={fieldErr.phone || ""}
                />

                <TextField
                  label="รหัสผ่าน"
                  type="password"
                  value={form.password}
                  onChange={(e) => updateField("password", e.target.value)}
                  required
                  fullWidth
                  sx={{ gridColumn: "1 / -1" }}
                  error={!!fieldErr.password}
                  helperText={fieldErr.password || ""}
                />

                {/* doctor specialties */}
                {form.role === "doctor" && (
                  <Box sx={{ gridColumn: "1 / -1", display: "flex", gap: 2, alignItems: "center", mt: 1 }}>
                    <Button variant="outlined" onClick={openSpecDialog} sx={{ textTransform: "none" }}>
                      เลือกสาขา {selectedSpecs.length ? `(${selectedSpecs.length})` : ""}
                    </Button>

                    <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                      {selectedSpecs.map((s) => (
                        <Box
                          key={s.id}
                          sx={{
                            px: 1.2,
                            py: 0.5,
                            borderRadius: 16,
                            bgcolor: "#f3f4f6",
                            display: "inline-flex",
                            alignItems: "center",
                          }}
                        >
                          <Typography variant="caption" sx={{ mr: 1 }}>
                            {s.name}
                          </Typography>
                          <IconButton size="small" onClick={() => toggleSpec(s)}>
                            ×
                          </IconButton>
                        </Box>
                      ))}
                    </Box>
                  </Box>
                )}

                <Box
                  sx={{
                    gridColumn: "1 / -1",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    mt: 1,
                    gap: 2,
                  }}
                >
                  <Box sx={{ minHeight: 24 }}>
                    {submitErr ? (
                      <Typography sx={{ color: "#bb1f1f" }}>{submitErr}</Typography>
                    ) : (
                      <Typography sx={{ color: "#6b7280" }}>กรุณากรอกข้อมูลให้ครบถ้วนและถูกต้อง</Typography>
                    )}
                  </Box>

                  <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
                    <Box sx={{ mr: 2 }}>
                      <RouterLink to="/login" style={{ color: "#374151", textDecoration: "none" }}>
                        มีบัญชีแล้ว? เข้าสู่ระบบ
                      </RouterLink>
                    </Box>

                    <ShimmerButton type="submit" disabled={loading} variant="contained">
                      {loading ? <CircularProgress size={20} color="inherit" /> : "สมัครสมาชิก"}
                    </ShimmerButton>
                  </Box>
                </Box>
              </Box>
            </Box>
          </Paper>
        </Box>
      </Container>

      {/* Specialties dialog */}
      <Dialog
        open={specDialogOpen}
        onClose={closeSpecDialog}
        TransitionComponent={Transition}
        keepMounted
        aria-labelledby="spec-dialog-title"
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle id="spec-dialog-title">เลือกสาขา (เลือกได้หลายค่า)</DialogTitle>
        <DialogContent dividers>
          <List>
            {specialties && specialties.length ? (
              specialties.map((s) => {
                const checked = !!selectedSpecs.find((x) => x.id === s.id);
                return (
                  <ListItem key={s.id} disablePadding>
                    <ListItemButton onClick={() => toggleSpec(s)}>
                      <Checkbox edge="start" checked={checked} tabIndex={-1} />
                      <ListItemText primary={s.name} />
                    </ListItemButton>
                  </ListItem>
                );
              })
            ) : (
              <Typography variant="body2" sx={{ color: "text.secondary" }}>
                ไม่พบรายการสาขา
              </Typography>
            )}
          </List>
          {fieldErr.specialties && (
            <Typography color="error" variant="body2" sx={{ mt: 1 }}>
              {fieldErr.specialties}
            </Typography>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={closeSpecDialog}>ยกเลิก</Button>
          <Button onClick={confirmSpecDialog} variant="contained">
            ตกลง
          </Button>
        </DialogActions>
      </Dialog>

      {/* success dialog */}
      <Dialog open={successOpen} TransitionComponent={Transition} keepMounted onClose={() => setSuccessOpen(false)}>
        <DialogTitle>สมัครสมาชิกสำเร็จ</DialogTitle>
        <DialogContent>
          <Typography>สมัครสมาชิกเรียบร้อยแล้ว กด OK เพื่อไปยังหน้าล็อกอิน</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleSuccessOk} variant="contained">
            OK
          </Button>
        </DialogActions>
      </Dialog>
    </ThemeProvider>
  );
}
