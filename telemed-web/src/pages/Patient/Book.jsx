// src/pages/Patient/Book.jsx
import React, { useEffect, useMemo, useState } from "react";
import {
  Avatar,
  Box,
  Button,
  CircularProgress,
  Container,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  Paper,
  TextField,
  Typography,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import CalendarMonthIcon from "@mui/icons-material/CalendarMonth";
import api from "../../lib/api";
import { useLocation, useNavigate } from "react-router-dom";

/* helpers */
const pad2 = (n) => String(n).padStart(2, "0");
const fmtDateTH = (iso) => {
  try {
    const d = new Date(iso);
    return d.toLocaleDateString("th-TH", {
      weekday: "short",
      year: "numeric",
      month: "short",
      day: "2-digit",
    });
  } catch {
    return iso;
  }
};
function todayPlus(days = 0) {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  d.setDate(d.getDate() + days);
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
}

export default function PatientBook() {
  const nav = useNavigate();
  const qs = new URLSearchParams(useLocation().search);

  const doctorId = qs.get("doctorId") || "";
  const doctorNameFromQs = qs.get("doctorName") || "";

  const [doctor, setDoctor] = useState({
    id: doctorId,
    full_name: doctorNameFromQs || "แพทย์",
    email: "",
    phone: "",
  });

  // จองได้ตั้งแต่พรุ่งนี้
  const [fromDate, setFromDate] = useState(todayPlus(1));
  const [toDate, setToDate] = useState(todayPlus(1));

  const [loading, setLoading] = useState(false);
  const [slots, setSlots] = useState([]); // daily slots
  const [error, setError] = useState("");

  const [confirming, setConfirming] = useState(false);
  const [selectedSlot, setSelectedSlot] = useState(null);
  const [booking, setBooking] = useState(false);
  const [bookResult, setBookResult] = useState({ ok: false, msg: "" });

  // keep toDate >= fromDate
  useEffect(() => {
    if (toDate < fromDate) setToDate(fromDate);
  }, [fromDate, toDate]);

  // ✅ ดึงโปรไฟล์หมอ: ใช้ /doctors (แบบหน้า Home) แล้วหา id ให้ตรง
  const fetchDoctorProfile = async () => {
    if (!doctorId) return;
    try {
      const r = await api.get("/doctors"); // ได้ id, full_name, email, phone
      const arr = r?.data?.data || [];
      const found = arr.find((x) => x.id === doctorId);
      if (found) {
        setDoctor((d) => ({
          ...d,
          full_name: found.full_name || d.full_name,
          email: found.email || "",
          phone: found.phone || "",
        }));
      }
    } catch (e) {
      console.error("โหลดข้อมูลหมอล้มเหลว", e);
    }
  };

  useEffect(() => {
    fetchDoctorProfile();
    // load slots on mount (so user doesn't have to click search)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [doctorId]);

  const fetchSlots = async () => {
    if (!doctorId) {
      setError("ไม่พบรหัสแพทย์");
      return;
    }
    setLoading(true);
    setError("");
    setSlots([]);
    try {
      const r = await api.get(`/doctors/${doctorId}/slots`, {
        params: { from: fromDate, to: toDate },
      });
      // server returns statuses normalized: available/booked/closed
      const rows = (r?.data?.data || [])
        .filter((s) => s.status === "available") // แสดงเฉพาะที่ยังว่าง
        .sort((a, b) => new Date(a.start_time) - new Date(b.start_time));
      setSlots(rows);
    } catch (e) {
      // try to read meaningful message from server
      const msg = e?.response?.data?.error?.message || e?.message || "โหลดวันว่างไม่สำเร็จ";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  // เรียก fetchSlots เมื่อ mount หรือ เมื่อ from/to/doctorId เปลี่ยน
  useEffect(() => {
    if (!doctorId) return;
    fetchSlots();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [doctorId, fromDate, toDate]);

  const backToSearch = () => nav("/patient/home");

  const openConfirm = (slot) => {
    setSelectedSlot(slot);
    setConfirming(true);
  };
  const closeConfirm = () => {
    setConfirming(false);
    setSelectedSlot(null);
    setBookResult({ ok: false, msg: "" });
  };

  const book = async () => {
    if (!selectedSlot?.id) return;
    setBooking(true);
    setBookResult({ ok: false, msg: "" });
    try {
      // chosen_date มาจาก start_time ที่เป็น "YYYY-MM-DD 00:00:00"
      const ymd = selectedSlot.start_time.slice(0, 10);
      await api.post("/appointments", {
        slot_id: selectedSlot.slot_id ?? String(selectedSlot.id).split(":")[0], // ไอดี slot แม่
        chosen_date: selectedSlot.chosen_date || selectedSlot.start_time?.slice(0, 10), // YYYY-MM-DD
      });
      setBookResult({ ok: true, msg: "จองแล้ว รอการยืนยัน" });

      // ปิด dialog และรีเฟรชรายการวันว่างทันที
      setConfirming(false);
      setSelectedSlot(null);
      await fetchSlots();
    } catch (e) {
      const msg = e?.response?.data?.error?.message || e?.message || "จองไม่สำเร็จ กรุณาลองใหม่";
      setBookResult({
        ok: false,
        msg,
      });
    } finally {
      setBooking(false);
    }
  };

  const minFrom = useMemo(() => todayPlus(1), []);
  const minTo = fromDate || minFrom;

  return (
    <Box
      sx={{
        backgroundImage: 'url("https://images.unsplash.com/photo-1587370356614-25e4f454f0a2?q=80&w=1974&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D")',
        backgroundSize: "cover",
        backgroundPosition: "center",
        backgroundAttachment: "scroll",
        pt: 6,
        pb: 6,
      }}
    >
      <Container maxWidth="lg">
        {/* Doctor header */}
        <Paper sx={{ p: 3, borderRadius: 2, mb: 3 }}>
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 2,
            }}
          >
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                จองนัดกับ {doctor.full_name}
              </Typography>
              <Typography
                variant="body2"
                color="text.secondary"
                sx={{ mt: 0.5 }}
              >
                เลือก <b>วัน</b> ที่ว่างแล้วกด “ยืนยัน” (จองได้ตั้งแต่{" "}
                {new Date(`${minFrom}T00:00:00`).toLocaleDateString("th-TH")}{" "}
                เป็นต้นไป)
              </Typography>
            </Box>
            <Button startIcon={<ArrowBackIcon />} onClick={backToSearch}>
              กลับไปค้นหา
            </Button>
          </Box>

          <Divider sx={{ my: 2 }} />

          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <Avatar sx={{ bgcolor: "primary.main" }}>
              {doctor.full_name?.charAt(0) || "D"}
            </Avatar>
            <Box sx={{ minWidth: 0 }}>
              <Typography sx={{ fontWeight: 700 }}>
                {doctor.full_name}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                อีเมล: {doctor.email || "-"} • โทร: {doctor.phone || "-"}
              </Typography>
            </Box>
          </Box>
        </Paper>

        {/* Search days */}
        <Paper sx={{ p: 3, borderRadius: 2 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
            วันที่ว่างของแพทย์ (ค้นตามช่วงวันที่)
          </Typography>

          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: { xs: "1fr", md: "1fr 1fr auto" },
              gap: 2,
              alignItems: "center",
            }}
          >
            <TextField
              label="จากวันที่"
              type="date"
              InputLabelProps={{ shrink: true }}
              value={fromDate}
              onChange={(e) => setFromDate(e.target.value)}
              inputProps={{ min: minFrom }}
            />
            <TextField
              label="ถึงวันที่"
              type="date"
              InputLabelProps={{ shrink: true }}
              value={toDate}
              onChange={(e) => setToDate(e.target.value)}
              inputProps={{ min: minTo }}
            />
            <Button
              variant="contained"
              onClick={fetchSlots}
              disabled={loading}
              startIcon={
                loading ? (
                  <CircularProgress size={16} color="inherit" />
                ) : (
                  <CalendarMonthIcon />
                )
              }
              sx={{ height: 44 }}
            >
              ค้นหา
            </Button>
          </Box>

          <Divider sx={{ my: 2 }} />

          {loading ? (
            <Box sx={{ py: 6, display: "flex", justifyContent: "center" }}>
              <CircularProgress />
            </Box>
          ) : error ? (
            <Box sx={{ py: 4, textAlign: "center" }}>
              <Typography color="error.main">{error}</Typography>
            </Box>
          ) : !slots.length ? (
            <Box sx={{ py: 4, textAlign: "center", color: "text.secondary" }}>
              <Typography>ไม่มีวันว่างในช่วงวันที่ที่เลือก</Typography>
            </Box>
          ) : (
            <Box sx={{ maxHeight: 300, overflowY: "auto" }}>
              <List disablePadding>
                {slots.map((s) => (
                  <ListItem
                    key={s.id}
                    sx={{
                      px: { xs: 1, md: 2 },
                      py: 1.5,
                      borderRadius: 1.5,
                      mb: 1,
                      boxShadow: "0 6px 16px rgba(16,24,40,0.06)",
                    }}
                    secondaryAction={
                      <Button
                        variant="contained"
                        size="small"
                        onClick={() => openConfirm(s)}
                      >
                        จองวันนี้
                      </Button>
                    }
                  >
                    <ListItemAvatar>
                      <Avatar>
                        <CalendarMonthIcon />
                      </Avatar>
                    </ListItemAvatar>
                    <ListItemText
                      primary={
                        <Typography sx={{ fontWeight: 700 }}>
                          {fmtDateTH(s.start_time)}
                        </Typography>
                      }
                      secondary={
                        <Typography variant="caption" color="text.secondary">
                          สถานะ: {s.status || "available"}
                        </Typography>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </Box>
          )}
        </Paper>
      </Container>

      {/* confirm dialog */}
      <Dialog open={confirming} onClose={closeConfirm} fullWidth maxWidth="xs">
        <DialogTitle>ยืนยันการจอง</DialogTitle>
        <DialogContent dividers>
          {selectedSlot ? (
            <Box sx={{ display: "grid", gap: 1 }}>
              <Typography>หมอ: {doctor.full_name}</Typography>
              <Typography>วันที่: {fmtDateTH(selectedSlot.start_time)}</Typography>
            </Box>
          ) : null}
          {bookResult.msg ? (
            <Typography
              sx={{ mt: 2 }}
              color={bookResult.ok ? "success.main" : "error.main"}
            >
              {bookResult.msg}
            </Typography>
          ) : null}
        </DialogContent>
        <DialogActions>
          <Button onClick={closeConfirm}>ปิด</Button>
          <Button
            variant="contained"
            onClick={book}
            disabled={booking || bookResult.ok}
          >
            {booking ? <CircularProgress size={18} /> : "ยืนยันการจอง"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
