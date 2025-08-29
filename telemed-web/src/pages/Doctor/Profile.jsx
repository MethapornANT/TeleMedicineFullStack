// telemed-web/src/pages/Doctor/Profile.jsx
import React, { useEffect, useState, useRef, useMemo } from "react";
import {
  Box, Paper, Typography, TextField, Button, CircularProgress, Snackbar, Alert,
  Grid, Chip, Divider, Stack, Avatar, IconButton, Tooltip, Popover, List,
  ListItem, ListItemButton, ListItemText, Checkbox
} from "@mui/material";
import EditIcon from "@mui/icons-material/Edit";
import SaveIcon from "@mui/icons-material/Save";
import CloseIcon from "@mui/icons-material/Close";
import PhotoCameraIcon from "@mui/icons-material/PhotoCamera";
import api from "../../lib/api";

const API_BASE = (import.meta.env.VITE_API_URL || "http://localhost:4005").replace(/\/+$/,"");

export default function DoctorProfile() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");
  const [profile, setProfile] = useState(null);
  const [form, setForm] = useState({ full_name: "", email: "", phone: "" });
  const [editing, setEditing] = useState(false);
  const [snack, setSnack] = useState({ open:false, msg:"", severity:"success" });

  // avatar
  const [userpicFile, setUserpicFile] = useState(null);
  const [userpicPreview, setUserpicPreview] = useState("");
  const fileRef = useRef(null);

  // specialties
  const [specialties, setSpecialties] = useState([]);
  const [selectedSpecs, setSelectedSpecs] = useState([]);
  const [tempSelected, setTempSelected] = useState([]);
  const [anchorEl, setAnchorEl] = useState(null);

  const publicPicUrl = useMemo(()=> {
    const p = profile?.userpic; if (!p) return ""; return /^https?:\/\//i.test(p) ? p : `${API_BASE}${p}`;
  }, [profile?.userpic]);

  useEffect(()=> {
    let mounted = true;
    (async ()=> {
      try {
        const [specRes, profileRes] = await Promise.all([
          api.get("/specialties").catch(()=>({ data:{ data:[] } })),
          api.get("/users/me").catch(()=>({ data:{} }))
        ]);
        if (!mounted) return;
        const specList = specRes?.data?.data || [];
        setSpecialties(specList);
        const user = profileRes?.data?.user || null;
        setProfile(user);
        setForm({ full_name: user?.full_name || "", email: user?.email || "", phone: user?.phone || "" });

        // normalize specialties from server -> array of objects
        if (user && user.specialties) {
          if (Array.isArray(user.specialties) && user.specialties.length && typeof user.specialties[0] === "string") {
            const mapped = specList.filter(s => user.specialties.includes(s.id));
            setSelectedSpecs(mapped);
          } else if (Array.isArray(user.specialties)) {
            setSelectedSpecs(user.specialties);
          } else setSelectedSpecs([]);
        } else setSelectedSpecs([]);
      } catch (e) {
        console.error(e); setErr("โหลดข้อมูลไม่สำเร็จ โปรดลองใหม่");
      } finally { if (mounted) setLoading(false); }
    })();
    return ()=> mounted=false;
  }, []);

  useEffect(()=> { return ()=> { if(userpicPreview) URL.revokeObjectURL(userpicPreview); }; }, [userpicPreview]);

  const pickPic = ()=> fileRef.current?.click();
  const onPicChange = (e)=> {
    const f = e.target.files?.[0]; if (!f) return;
    const sizeMb = f.size / (1024*1024); const allowed = ["image/jpeg","image/png","image/webp"];
    if (sizeMb > 5) { setSnack({ open:true, msg:"ขนาดรูปต้องไม่เกิน 5MB", severity:"error" }); return; }
    if (!allowed.includes(f.type)) { setSnack({ open:true, msg:"รองรับเฉพาะ JPG/PNG/WebP", severity:"error" }); return; }
    setUserpicFile(f); setUserpicPreview(prev=>{ if(prev) URL.revokeObjectURL(prev); return URL.createObjectURL(f); }); setEditing(true);
  };

  const validate = (data)=> {
    const errors = [];
    if (!data.full_name || !data.full_name.trim()) errors.push("กรุณาระบุชื่อ-นามสกุล");
    if (!data.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/i.test(data.email.trim())) errors.push("รูปแบบอีเมลไม่ถูกต้อง");
    if (data.phone && !/^\d{9,10}$/.test(String(data.phone).trim())) errors.push("เบอร์ต้องเป็นตัวเลข 9-10 หลัก");
    if (!selectedSpecs || selectedSpecs.length === 0) errors.push("เลือกสาขาอย่างน้อย 1 รายการ");
    return errors;
  };

  const openSpecDropdown = (ev)=> { setTempSelected(selectedSpecs.map(s=>s.id)); setAnchorEl(ev.currentTarget); };
  const closeSpecDropdown = ()=> setAnchorEl(null);
  const popOpen = Boolean(anchorEl);
  const toggleTemp = (id)=> setTempSelected(prev => prev.includes(id) ? prev.filter(x=>x!==id) : [...prev, id]);
  const applyTemp = ()=> { const mapped = specialties.filter(s => tempSelected.includes(s.id)); setSelectedSpecs(mapped); setAnchorEl(null); setEditing(true); };

  const handleSave = async (e)=> {
    e?.preventDefault(); setErr("");
    const errors = validate(form);
    if (errors.length) { setErr(errors.join(" • ")); return; }
    setSaving(true);
    try {
      const fd = new FormData();
      fd.append("full_name", form.full_name);
      fd.append("phone", form.phone || "");
      if (userpicFile) fd.append("userpic", userpicFile);
      // send specialty_ids as JSON array (backend handles JSON string)
      fd.append("specialty_ids", JSON.stringify(selectedSpecs.map(s=>s.id)));

      const res = await api.put("/users/me", fd);
      const user = res?.data?.user || null;
      if (user) {
        setProfile(user);
        if (user.specialties && Array.isArray(user.specialties)) {
          if (user.specialties.length && typeof user.specialties[0] === "string") {
            const mapped = specialties.filter(s => user.specialties.includes(s.id));
            setSelectedSpecs(mapped);
          } else {
            setSelectedSpecs(user.specialties);
          }
        }
      } else {
        setProfile(p => ({ ...p, full_name: form.full_name, phone: form.phone || null }));
      }
      setUserpicFile(null);
      if (userpicPreview) { URL.revokeObjectURL(userpicPreview); setUserpicPreview(""); }
      setEditing(false);
      setSnack({ open:true, msg:"บันทึกสำเร็จ", severity:"success" });
    } catch (e) {
      console.error("save profile:", e);
      const payload = e?.payload ?? e?.response?.data;
      const msg = payload?.error?.message || e?.message || "บันทึกไม่สำเร็จ";
      setErr(msg); setSnack({ open:true, msg, severity:"error" });
    } finally { setSaving(false); }
  };

  const handleCancel = ()=> {
    setEditing(false);
    setForm({ full_name: profile?.full_name || "", email: profile?.email || "", phone: profile?.phone || "" });
    setUserpicFile(null); if (userpicPreview) { URL.revokeObjectURL(userpicPreview); setUserpicPreview(""); }
    setTempSelected([]); setAnchorEl(null); setErr("");
  };

  if (loading) return <Box sx={{ minHeight:"60vh", display:"grid", placeItems:"center" }}><CircularProgress /></Box>;

  return (
    <Box sx={{
      // BACKGROUND: ใช้ภาพตรงๆ ไม่จาง
      backgroundImage: "url('/bgbw.jpg')",
      backgroundRepeat: "no-repeat",
      backgroundSize: "cover",
      backgroundPosition: "center center",
      backgroundAttachment: "fixed",

      py: { xs: 4, md: 85 },

      display: "flex",
      alignItems: "flex-start",
      justifyContent: "center",
    }}>
      <Box sx={{
        width: "100%",
        maxWidth: 1160,
        px: { xs: 2, md: 4 },
        // CHANGED: ดึงการ์ดขึ้นอีกมากโดยใช้ negative mt (ปลอดภัยกว่าใช้ huge padding)
        mt: { xs: -6, md: -80 }  // <-- ปรับค่านี้เพื่อดึงขึ้นมาก/น้อยตามต้องการ
      }}>
        <Paper elevation={10} sx={{
          borderRadius: 3,
          p: { xs: 3, md: 5 },
          // ใช้ background เกือบทึบเพื่อคอนทราสต์ชัดเจนบน bg
          background: "rgba(255,255,255,0.98)",
          boxShadow: "0 40px 100px rgba(10,20,40,0.14)"
        }}>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Box>
              <Typography variant="h4" sx={{ fontWeight:800, letterSpacing: "-0.6px" }}>โปรไฟล์หมอ</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt:0.5 }}>แก้ไขข้อมูลส่วนตัวและสาขาที่เชี่ยวชาญ</Typography>
            </Box>

            <Stack direction="row" spacing={1} alignItems="center">
              {!editing ? (
                <Tooltip title="แก้ไข"><IconButton onClick={()=>setEditing(true)}><EditIcon/></IconButton></Tooltip>
              ) : (
                <Stack direction="row" spacing={1}>
                  <Tooltip title="ยกเลิก"><IconButton onClick={handleCancel}><CloseIcon/></IconButton></Tooltip>
                  <Tooltip title="บันทึก"><span><IconButton onClick={handleSave} disabled={saving}>{saving ? <CircularProgress size={20} /> : <SaveIcon/>}</IconButton></span></Tooltip>
                </Stack>
              )}
            </Stack>
          </Box>

          <Divider sx={{ my:2 }} />

          {err && <Box mb={2}><Typography color="error" variant="body2">{err}</Typography></Box>}

          <Grid container spacing={4} alignItems="center">
            <Grid item xs={12} md={4}>
              <Stack spacing={2} alignItems="center">
                <Box sx={{ position:"relative" }}>
                  <Avatar src={userpicPreview || publicPicUrl || undefined}
                    sx={{
                      width: { xs: 140, md: 180 },
                      height: { xs: 140, md: 180 },
                      boxShadow: "0 18px 40px rgba(2,12,40,0.12)",
                      border: "6px solid white",
                      bgcolor: "#f1f5f9"
                    }}>
                    {profile?.full_name?.charAt(0) || "?"}
                  </Avatar>

                  <Tooltip title="เปลี่ยนรูปโปรไฟล์">
                    <IconButton onClick={pickPic} size="small" sx={{ position:"absolute", right:-6, bottom:-6, bgcolor:"background.paper", border:"1px solid rgba(0,0,0,0.06)", "&:hover":{ bgcolor:"grey.100" } }}>
                      <PhotoCameraIcon />
                    </IconButton>
                  </Tooltip>
                </Box>

                <Typography variant="h6" sx={{ fontWeight:700, textAlign:"center" }}>{profile?.full_name}</Typography>

                <Chip label="บัญชี: หมอ" size="small" sx={{ bgcolor:"#e8f6ef", color:"#046a50", fontWeight:700 }} />

                <input ref={fileRef} type="file" accept="image/jpeg,image/png,image/webp" hidden onChange={onPicChange} />
              </Stack>
            </Grid>

            <Grid item xs={12} md={8}>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <TextField label="ชื่อ - นามสกุล" value={form.full_name} onChange={(e)=>setForm(p=>({...p, full_name:e.target.value}))} fullWidth required variant="outlined" InputProps={{ sx:{ borderRadius:2 } }} disabled={!editing} />
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField label="อีเมล" value={form.email} fullWidth disabled variant="outlined" helperText="ไม่สามารถแก้ไขได้จากที่นี่" InputProps={{ sx:{ borderRadius:2 } }} />
                </Grid>

                <Grid item xs={12} md={6}>
                  <TextField label="เบอร์โทร (ไม่บังคับ)" value={form.phone||""} onChange={(e)=>setForm(p=>({...p, phone:e.target.value}))} fullWidth variant="outlined" helperText="ตัวเลข 9-10 หลัก" InputProps={{ sx:{ borderRadius:2 } }} disabled={!editing} />
                </Grid>

                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary" sx={{ mb:1 }}>สาขาที่เชี่ยวชาญ</Typography>
                  <Box sx={{ display:"flex", gap:2, alignItems:"center", flexWrap:"wrap" }}>
                    <Button variant="outlined" onClick={openSpecDropdown} disabled={!editing} sx={{ textTransform:"none" }}>
                      เลือกสาขา {selectedSpecs?.length ? `(${selectedSpecs.length})` : ""}
                    </Button>

                    <Box sx={{ display:"flex", gap:1, flexWrap:"wrap" }}>
                      {selectedSpecs.length ? selectedSpecs.map(s=> <Chip key={s.id} label={s.name} size="small" sx={{ bgcolor:"#f3f4f6" }} />) : <Typography variant="body2" color="text.secondary">ยังไม่ได้เลือกสาขา</Typography>}
                    </Box>
                  </Box>

                  <Popover open={popOpen} anchorEl={anchorEl} onClose={closeSpecDropdown} anchorOrigin={{ vertical:"bottom", horizontal:"left" }} transformOrigin={{ vertical:"top", horizontal:"left" }} PaperProps={{ sx:{ width:320, maxHeight:360, p:1 } }}>
                    <List dense sx={{ overflowY:"auto", maxHeight:260 }}>
                      {specialties.map(s=> {
                        const checked = tempSelected.includes(s.id);
                        return (
                          <ListItem key={s.id} disablePadding>
                            <ListItemButton onClick={()=>toggleTemp(s.id)}>
                              <Checkbox edge="start" checked={checked} tabIndex={-1} />
                              <ListItemText primary={s.name} />
                            </ListItemButton>
                          </ListItem>
                        );
                      })}
                    </List>

                    <Divider sx={{ my:1 }} />
                    <Box sx={{ display:"flex", justifyContent:"flex-end", gap:1, px:1 }}>
                      <Button onClick={closeSpecDropdown} size="small" sx={{ textTransform:"none" }}>ยกเลิก</Button>
                      <Button onClick={applyTemp} variant="contained" size="small" sx={{ textTransform:"none" }}>Apply</Button>
                    </Box>
                  </Popover>
                </Grid>

                <Grid item xs={12} display="flex" justifyContent="flex-end" sx={{ mt:1 }}>
                  {!editing ? null : (
                    <Stack direction="row" spacing={2}>
                      <Button onClick={handleCancel} variant="outlined" sx={{ textTransform:"none" }}>ยกเลิก</Button>
                      <Button onClick={handleSave} variant="contained" disabled={saving} sx={{ textTransform:"none" }}>{saving ? <CircularProgress size={18} color="inherit" /> : "บันทึกทั้งหมด"}</Button>
                    </Stack>
                  )}
                </Grid>
              </Grid>
            </Grid>
          </Grid>
        </Paper>
      </Box>

      <Snackbar open={snack.open} autoHideDuration={3000} onClose={()=>setSnack(s=>({...s,open:false}))} anchorOrigin={{vertical:"bottom", horizontal:"center"}} >
        <Alert severity={snack.severity}>{snack.msg}</Alert>
      </Snackbar>
    </Box>
  );
}
