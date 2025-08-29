// src/pages/Doctor/Slot.jsx
import React, { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Avatar,
  Box,
  Button,
  Chip,
  CircularProgress,
  Container,
  Divider,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import EventAvailableIcon from "@mui/icons-material/EventAvailable";
import CalendarMonthIcon from "@mui/icons-material/CalendarMonth";
import api from "../../lib/api";
import { useNavigate } from "react-router-dom";

/* helpers */
const pad2 = (n) => String(n).padStart(2, "0");
const fmtDateTH = (ymdOrIso) => {
  try {
    const d = new Date(ymdOrIso);
    return d.toLocaleDateString("th-TH", {
      weekday: "short",
      year: "numeric",
      month: "short",
      day: "2-digit",
    });
  } catch {
    return ymdOrIso;
  }
};
const todayYMD = () => {
  const d = new Date();
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
};
const addDaysYMD = (baseYmd, days) => {
  const d = baseYmd ? new Date(`${baseYmd}T00:00:00`) : new Date();
  d.setDate(d.getDate() + days);
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
};

export default function DoctorSlot() {
  const nav = useNavigate();

  // auth
  const [me, setMe] = useState(null);
  const [loadingMe, setLoadingMe] = useState(true);
  const [err, setErr] = useState("");

  // create daily slots (range of days)
  const [startDay, setStartDay] = useState(""); // YYYY-MM-DD
  const [endDay, setEndDay] = useState("");     // YYYY-MM-DD
  const [creating, setCreating] = useState(false);

  // list slots for preview
  const [fromList, setFromList] = useState(addDaysYMD(todayYMD(), 0));
  const [toList, setToList] = useState(addDaysYMD(todayYMD(), 30));
  const [loadingList, setLoadingList] = useState(false);
  const [dailySlots, setDailySlots] = useState([]);

  // --- constraints (หมอ: ห้ามเป็น "วันนี้" แต่ไม่ต้อง +2 วัน) ---
  const minStart = useMemo(() => addDaysYMD(todayYMD(), 1), []);
  const minEnd = startDay || minStart;

  // load current user (must be doctor)
  useEffect(() => {
    let stopped = false;
    (async () => {
      setLoadingMe(true);
      setErr("");
      try {
        const r = await api.get("/users/me");
        if (!stopped) setMe(r?.data?.user || r?.data);
      } catch (e) {
        if (!stopped) setErr("ไม่สามารถโหลดข้อมูลผู้ใช้ได้");
      } finally {
        if (!stopped) setLoadingMe(false);
      }
    })();
    return () => (stopped = true);
  }, []);

  const validate = () => {
    setErr("");
    if (!startDay || !endDay) {
      setErr("กรุณาเลือกทั้งวันที่เริ่มและวันที่สิ้นสุด");
      return false;
    }
    if (startDay < minStart) {
      setErr("วันเริ่มต้องไม่น้อยกว่าวันพรุ่งนี้");
      return false;
    }
    if (endDay < startDay) {
      setErr("วันสิ้นสุดต้องไม่น้อยกว่าวันเริ่ม");
      return false;
    }
    return true;
  };

  const createSlots = async (e) => {
    e.preventDefault();
    if (!validate()) return;
    setCreating(true);
    try {
      // ✅ backend ใหม่: รับ date-only (YYYY-MM-DD)
      await api.post(`/doctors/${me.id}/slots`, {
        start_time: startDay,
        end_time: endDay,
      });
      setStartDay("");
      setEndDay("");
      await fetchDailySlots(); // refresh list
      alert("สร้างวันว่างเรียบร้อย");
    } catch (error) {
      setErr(error?.message || "สร้างวันว่างไม่สำเร็จ");
    } finally {
      setCreating(false);
    }
  };

  const fetchDailySlots = async () => {
    if (!me?.id) return;
    setLoadingList(true);
    setErr("");
    setDailySlots([]);
    try {
      // ✅ backend ใหม่: GET /doctors/:id/slots?from=YYYY-MM-DD&to=YYYY-MM-DD
      const r = await api.get(`/doctors/${me.id}/slots`, {
        params: { from: fromList, to: toList },
      });
      setDailySlots(r?.data?.data || []);
    } catch (e) {
      setErr(e?.message || "โหลดวันว่างไม่สำเร็จ");
    } finally {
      setLoadingList(false);
    }
  };

  useEffect(() => {
    if (me?.id) fetchDailySlots();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me?.id]);

  if (loadingMe) {
    return (
      <Box sx={{ minHeight: "60vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  if (me && me.role !== "doctor") {
    return (
      <Container maxWidth="sm" sx={{ pt: 8 }}>
        <Alert severity="warning">หน้านี้สำหรับแพทย์เท่านั้น</Alert>
      </Container>
    );
  }

  const availableCount = dailySlots.filter((d) => d.status === "available").length;
  const bookedCount = dailySlots.filter((d) => d.status === "booked").length;

  return (
    <Box sx={{ minHeight: "80vh", pt: 6, pb: 6 }}>
      <Container maxWidth="lg">
        {/* Header */}
        <Paper sx={{ p: 3, borderRadius: 2, mb: 3 }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 2 }}>
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                จัดการวันว่างของฉัน
              </Typography>
              <Typography color="text.secondary" sx={{ mt: 0.5 }}>
                เลือกช่วง <b>วันที่</b> แล้วกด “สร้างวันว่าง” ระบบจะสร้างเป็นวันละหนึ่งช่วงให้ผู้ป่วยจอง
              </Typography>
            </Box>
            <Button variant="text" onClick={() => nav("/doctor")}>
              กลับไปแดชบอร์ด
            </Button>
          </Box>
        </Paper>

        {/* Create form */}
        <Paper sx={{ p: 3, borderRadius: 2, mb: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
            สร้างวันว่าง (รายวัน)
          </Typography>

          <Stack component="form" onSubmit={createSlots} direction={{ xs: "column", md: "row" }} spacing={2}>
            <TextField
              label="จากวันที่"
              type="date"
              InputLabelProps={{ shrink: true }}
              value={startDay}
              onChange={(e) => setStartDay(e.target.value)}
              inputProps={{ min: minStart }}
              sx={{ maxWidth: 260 }}
              required
            />
            <TextField
              label="ถึงวันที่"
              type="date"
              InputLabelProps={{ shrink: true }}
              value={endDay}
              onChange={(e) => setEndDay(e.target.value)}
              inputProps={{ min: minEnd }}
              sx={{ maxWidth: 260 }}
              required
            />
            <Button
              type="submit"
              variant="contained"
              disabled={creating}
              startIcon={creating ? <CircularProgress size={16} color="inherit" /> : <EventAvailableIcon />}
              sx={{ height: 44 }}
            >
              สร้างวันว่าง
            </Button>
          </Stack>

          {err ? <Alert severity="error" sx={{ mt: 2 }}>{err}</Alert> : null}
        </Paper>

        {/* List / Preview */}
        <Paper sx={{ p: 3, borderRadius: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700 }}>วันว่างของฉัน</Typography>
            <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
              <Chip label={`available: ${availableCount}`} color="primary" variant="outlined" />
              <Chip label={`booked: ${bookedCount}`} color="success" variant="outlined" />
            </Box>
          </Box>

          <Divider sx={{ my: 2 }} />

          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: { xs: "1fr", md: "1fr 1fr auto" },
              gap: 2,
              alignItems: "center",
              mb: 2,
            }}
          >
            <TextField
              label="จากวันที่"
              type="date"
              InputLabelProps={{ shrink: true }}
              value={fromList}
              onChange={(e) => setFromList(e.target.value)}
            />
            <TextField
              label="ถึงวันที่"
              type="date"
              InputLabelProps={{ shrink: true }}
              value={toList}
              onChange={(e) => setToList(e.target.value)}
              inputProps={{ min: fromList }}
            />
            <Button
              variant="contained"
              onClick={fetchDailySlots}
              disabled={loadingList}
              startIcon={loadingList ? <CircularProgress size={16} color="inherit" /> : <CalendarMonthIcon />}
              sx={{ height: 44 }}
            >
              ค้นหา
            </Button>
          </Box>

          {loadingList ? (
            <Box sx={{ py: 6, display: "flex", justifyContent: "center" }}>
              <CircularProgress />
            </Box>
          ) : !dailySlots.length ? (
            <Box sx={{ py: 4, textAlign: "center", color: "text.secondary" }}>
              <Typography>ยังไม่มีวันว่างในช่วงนี้</Typography>
            </Box>
          ) : (
            <List disablePadding>
              {dailySlots.map((d) => (
                <ListItem
                  key={d.id}
                  sx={{
                    px: { xs: 1, md: 2 },
                    py: 1.2,
                    mb: 1,
                    borderRadius: 1.5,
                    bgcolor: "background.paper",
                    boxShadow: "0 6px 16px rgba(16,24,40,0.06)",
                  }}
                >
                  <ListItemAvatar>
                    <Avatar><CalendarMonthIcon /></Avatar>
                  </ListItemAvatar>
                  <ListItemText
                    primary={<Typography sx={{ fontWeight: 700 }}>{fmtDateTH(d.start_time)}</Typography>}
                    secondary={
                      <Typography variant="caption" color="text.secondary">
                        สถานะ: {d.status || "available"}
                      </Typography>
                    }
                  />
                </ListItem>
              ))}
            </List>
          )}
        </Paper>
      </Container>
    </Box>
  );
}
