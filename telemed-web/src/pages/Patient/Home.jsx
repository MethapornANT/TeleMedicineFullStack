// src/pages/Patient/Home.jsx
import React, { useEffect, useState } from "react";
import {
  Box,
  Button,
  Container,
  TextField,
  Typography,
  Paper,
  MenuItem,
  Grid,
  Chip,
  CircularProgress,
  List,
  ListItem,
  ListItemAvatar,
  Avatar,
  ListItemText,
  Divider,
} from "@mui/material";
import api from "../../lib/api";
import { useNavigate } from "react-router-dom";

export default function PatientHome() {
  const nav = useNavigate();
  const [specialties, setSpecialties] = useState([]);
  const [q, setQ] = useState("");
  const [spec, setSpec] = useState("");
  const [loadingSpecs, setLoadingSpecs] = useState(false);

  // search state
  const [searching, setSearching] = useState(false);
  const [doctors, setDoctors] = useState([]);
  const [searchErr, setSearchErr] = useState("");

  useEffect(() => {
    (async () => {
      setLoadingSpecs(true);
      try {
        const r = await api.get("/specialties");
        setSpecialties(r?.data?.data || []);
      } catch (e) {
        console.error("load specialties", e);
      } finally {
        setLoadingSpecs(false);
      }
    })();
  }, []);

  const handleSearch = async () => {
    setSearching(true);
    setSearchErr("");
    setDoctors([]);
    try {
      // ส่ง specialty_id (backend รองรับ)
      const params = {};
      if (q) params.q = q;
      if (spec) params.specialty_id = spec;
      const r = await api.get("/doctors", { params });
      setDoctors(r?.data?.data || []);
    } catch (e) {
      console.error("search doctors error:", e);
      const msg = e?.response?.data?.error?.message || "ค้นหาไม่สำเร็จ กรุณาลองใหม่";
      setSearchErr(msg);
    } finally {
      setSearching(false);
    }
  };

  const handleChipClick = async (s) => {
    setSpec(s.id);
    setQ("");
    setSearching(true);
    setSearchErr("");
    setDoctors([]);
    try {
      const r = await api.get("/doctors", { params: { specialty_id: s.id } });
      setDoctors(r?.data?.data || []);
    } catch (e) {
      console.error("search by chip error:", e);
      const msg = e?.response?.data?.error?.message || "ค้นหาไม่สำเร็จ กรุณาลองใหม่";
      setSearchErr(msg);
    } finally {
      setSearching(false);
    }
  };

  const goBook = (doctor) => {
    const params = new URLSearchParams();
    params.set("doctorId", doctor.id);
    if (doctor.full_name) params.set("doctorName", doctor.full_name);
    nav(`/patient/book?${params.toString()}`);
  };

  const onKeyDown = (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleSearch();
    }
  };

  // --- helper: build full URL for userpic (handles absolute URL or relative /uploads/ path)
  const getUserpicUrl = (p) => {
    if (!p) return null;
    if (/^https?:\/\//i.test(p)) return p;
    // try to use axios baseURL if configured, otherwise return path as-is
    const base = api?.defaults?.baseURL || "";
    if (base) return `${base.replace(/\/$/, "")}${p}`;
    return p;
  };

  return (
    <Box sx={{ minHeight: "72vh", pt: 8, pb: 6 }}>
      <Container maxWidth="lg">
        {/* Hero / Search card */}
        <Paper
          sx={{
            p: { xs: 3, md: 4 },
            borderRadius: 2,
            boxShadow: "0 18px 40px rgba(16,24,40,0.06)",
            mb: 4,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 0.5 }}>
            ยินดีต้อนรับสู่ <Box component="span" sx={{ color: "primary.main" }}>Telemed</Box>
          </Typography>
          <Typography color="text.secondary" sx={{ mb: 3 }}>
            ค้นหาแพทย์ จองนัด และจัดการการนัดของคุณได้ง่าย ๆ
          </Typography>

          <Grid container spacing={2} alignItems="flex-start">
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="ค้นหา (ชื่อแพทย์)"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="เช่น นพ.สมชาย หรือ สมชาย"
                onKeyDown={onKeyDown}
                size="medium"
              />
            </Grid>

            <Grid item xs={12} md={4}>
              <TextField
                select
                fullWidth
                label="สาขา"
                value={spec}
                onChange={(e) => setSpec(e.target.value)}
                helperText="เลือกสาขาเพื่อค้นหาให้เฉพาะเจาะจง"
                size="medium"
              >
                <MenuItem value="">ทั้งหมด</MenuItem>
                {specialties.map((s) => (
                  <MenuItem key={s.id} value={s.id}>
                    {s.name}
                  </MenuItem>
                ))}
              </TextField>
            </Grid>

            <Grid item xs={12} md={2} sx={{ display: "flex", alignItems: "center" }}>
              <Button
                variant="contained"
                onClick={handleSearch}
                fullWidth
                disabled={searching}
                startIcon={searching ? <CircularProgress size={16} color="inherit" /> : null}
                sx={{ height: 44 }}
              >
                ค้นหา
              </Button>
            </Grid>
          </Grid>

          <Box sx={{ mt: 4 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
              สาขายอดนิยม
            </Typography>
            {loadingSpecs ? (
              <CircularProgress size={20} />
            ) : (
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                {specialties.slice(0, 8).map((s) => (
                  <Chip
                    key={s.id}
                    label={s.name}
                    onClick={() => handleChipClick(s)}
                    clickable
                    sx={{
                      cursor: "pointer",
                      borderRadius: 2,
                      background: spec === s.id ? "rgba(43,111,178,0.08)" : undefined,
                      "&:hover": { transform: "translateY(-2px)" },
                      px: 1.5,
                      py: 0.6,
                      fontWeight: 600,
                    }}
                  />
                ))}
                {!specialties.length && <Typography color="text.secondary">ยังไม่มีข้อมูลสาขา</Typography>}
              </Box>
            )}
          </Box>
        </Paper>

        {/* Results */}
        <Paper sx={{ p: 2, borderRadius: 2, boxShadow: "0 12px 28px rgba(16,24,40,0.06)" }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
            <Typography variant="h6" sx={{ fontWeight: 700 }}>
              ผลการค้นหา
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {searching ? "กำลังค้นหา..." : `${doctors.length} รายการ`}
            </Typography>
          </Box>

          <Divider sx={{ mb: 2 }} />

          {searching ? (
            <Box sx={{ py: 6, display: "flex", justifyContent: "center" }}>
              <CircularProgress />
            </Box>
          ) : searchErr ? (
            <Box sx={{ py: 4, textAlign: "center" }}>
              <Typography color="error.main">{searchErr}</Typography>
            </Box>
          ) : !doctors.length ? (
            <Box sx={{ py: 4, textAlign: "center", color: "text.secondary" }}>
              <Typography>ยังไม่มีผลลัพธ์ — ลองเปลี่ยนคำค้นหรือสาขา</Typography>
            </Box>
          ) : (
            <Box sx={{ maxHeight: 400, overflowY: 'auto' }}>
              <List disablePadding>
                {doctors.map((d) => {
                  const src = getUserpicUrl(d.userpic || d.user_pic || d.avatar || "");
                  return (
                    <React.Fragment key={d.id}>
                      <ListItem
                        sx={{
                          alignItems: "flex-start",
                          py: 2,
                          px: { xs: 1, md: 2 },
                          display: "flex",
                          gap: 2,
                        }}
                        secondaryAction={
                          <Box sx={{ display: "flex", gap: 1 }}>
                            <Button variant="outlined" size="small" onClick={() => nav(`/doctors/${d.id}`)}>
                              รายละเอียด
                            </Button>
                            <Button variant="contained" size="small" onClick={() => goBook(d)}>
                              จอง
                            </Button>
                          </Box>
                        }
                      >
                        <ListItemAvatar>
                          <Avatar
                            src={src || undefined}
                            alt={d.full_name || "Doctor"}
                            sx={{ bgcolor: src ? "transparent" : "primary.main", width: 56, height: 56 }}
                          >
                            {!src && (d.full_name ? d.full_name.charAt(0) : "D")}
                          </Avatar>
                        </ListItemAvatar>

                        <ListItemText
                          primary={
                            <Box sx={{ display: "flex", gap: 1, alignItems: "center", flexWrap: "wrap" }}>
                              <Typography sx={{ fontWeight: 700 }}>{d.full_name}</Typography>
                              {d.email && (
                                <Typography variant="caption" color="text.secondary">
                                  • {d.email}
                                </Typography>
                              )}
                              {d.phone && (
                                <Typography variant="caption" color="text.secondary">
                                  • {d.phone}
                                </Typography>
                              )}
                            </Box>
                          }
                          secondary={d.bio || ""}
                        />
                      </ListItem>
                      <Divider component="li" />
                    </React.Fragment>
                  );
                })}
              </List>
            </Box>
          )}
        </Paper>

        <Box sx={{ mt: 2 }}>
          <Typography variant="caption" color="text.secondary">
            คำแนะนำ: กดชื่อแพทย์เพื่อดูรายละเอียดหรือกด "จอง" เพื่อดำเนินการจอง (หน้าจองจะถูกสร้างแยก)
          </Typography>
        </Box>
      </Container>
    </Box>
  );
}
