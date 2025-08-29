// src/pages/Doctor/dashboard.jsx
import React, { useEffect, useMemo, useState } from "react";
import {
  Box, Button, Container, Paper, Typography, CircularProgress, Alert,
  Stack, Divider, Chip, Dialog, DialogTitle, DialogContent, DialogActions
} from "@mui/material";
import api from "../../lib/api";
import CheckIcon from "@mui/icons-material/Check";
import CloseIcon from "@mui/icons-material/Close";
import EventBusyIcon from "@mui/icons-material/EventBusy";

/* helpers */
const pad = (n) => String(n).padStart(2, "0");
const ymd = (d) => `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;
const thDays = ["อา","จ","อ","พ","พฤ","ศ","ส"];
const startOfMonth = (d)=> new Date(d.getFullYear(), d.getMonth(), 1, 0,0,0,0);
const endOfMonth   = (d)=> new Date(d.getFullYear(), d.getMonth()+1, 0, 23,59,59,999);
const rangeDays = (from,to)=>{ const out=[]; const s=new Date(from); s.setHours(0,0,0,0);
  const e=new Date(to); e.setHours(0,0,0,0); for(let d=new Date(s); d<=e; d.setDate(d.getDate()+1)) out.push(new Date(d)); return out; };
const Dot = ({color}) => <Box sx={{width:6,height:6,borderRadius:"50%",bgcolor:color,display:"inline-block"}}/>;

export default function DoctorDashboard() {
  const [me, setMe] = useState(null);
  const [loadingMe, setLoadingMe] = useState(true);

  const [monthCursor, setMonthCursor] = useState(()=>{ const d=new Date(); d.setDate(1); d.setHours(0,0,0,0); return d; });
  const [selectedDate, setSelectedDate] = useState(ymd(new Date()));
  const [appointments, setAppointments] = useState([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  // รายงานภาพรวมของหมอ (การ์ดแยก)
  const [summary, setSummary] = useState(null);
  const [loadingSummary, setLoadingSummary] = useState(false);

  // ยืนยันยกเลิก
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [cancelTarget, setCancelTarget] = useState(null);
  const [cancelBusy, setCancelBusy] = useState(false);

  // profile
  useEffect(() => {
    let cancel=false;
    (async ()=>{
      try {
        setLoadingMe(true);
        const r = await api.get("/users/me");
        if(!cancel) setMe(r?.data?.user || r?.data);
      } catch {
        if(!cancel) setErr("โหลดข้อมูลผู้ใช้ล้มเหลว");
      } finally { if(!cancel) setLoadingMe(false); }
    })();
    return ()=>{ cancel=true; };
  }, []);

  // appointments
  const loadAppointments = async () => {
    setLoading(true); setErr("");
    try {
      const r = await api.get("/appointments/doctor/me");
      const rows = (r?.data?.data || []).map(a => ({
        ...a,
        chosen_date: a.chosen_date ? a.chosen_date.slice(0,10) : (a.start_time ? a.start_time.slice(0,10) : null)
      }));
      setAppointments(rows);
    } catch(e) {
      setErr(e?.response?.data?.error?.message || e?.message || "โหลดตารางนัดล้มเหลว");
    } finally { setLoading(false); }
  };
  useEffect(()=>{ if(me?.role==="doctor") loadAppointments(); }, [me?.id]);

  // summary (ภาพรวม ไม่ผูกวัน)
  const loadSummary = async () => {
    try {
      setLoadingSummary(true);
      const r = await api.get("/reports/appointments"); // ไม่ส่ง date = สรุปทั้งหมดของหมอ
      setSummary(r?.data || null);
    } catch {
      setSummary(null);
    } finally { setLoadingSummary(false); }
  };
  useEffect(()=>{ if(me?.role==="doctor") loadSummary(); }, [me?.role]);

  // calendar data
  const monthDays = useMemo(() => {
    const start = startOfMonth(monthCursor);
    const end   = endOfMonth(monthCursor);
    const days  = rangeDays(start,end);
    const leading = Array.from({length: start.getDay()}, () => null);

    const confirmed = new Set(appointments.filter(a=>a.status==="confirmed" && a.chosen_date).map(a=>a.chosen_date));
    const pending   = new Set(appointments.filter(a=>a.status==="pending"   && a.chosen_date).map(a=>a.chosen_date));

    const mapped = days.map(d => ({
      ymd: ymd(d), date: d,
      hasConfirmed: confirmed.has(ymd(d)),
      hasPending: pending.has(ymd(d)),
    }));
    return [...leading, ...mapped];
  }, [monthCursor, appointments]);

  // per-day lists
  const dailyPending = useMemo(
    () => appointments.filter(a => a.chosen_date === selectedDate && a.status === "pending")
                      .sort((a,b)=> (a.created_at||"").localeCompare(b.created_at||"")),
    [appointments, selectedDate]
  );
  const dailyConfirmed = useMemo(
    () => appointments.filter(a => a.chosen_date === selectedDate && a.status === "confirmed")
                      .sort((a,b)=> (a.created_at||"").localeCompare(b.created_at||"")),
    [appointments, selectedDate]
  );
  const upcomingConfirmed = useMemo(() => {
    const today = ymd(new Date());
    return appointments.filter(a => a.status==="confirmed" && a.chosen_date >= today)
                       .sort((a,b)=> a.chosen_date.localeCompare(b.chosen_date));
  }, [appointments]);

  // update status then refresh summary
  const updateStatus = async (id, status) => {
    try {
      await api.patch(`/appointments/${id}/status`, { status });
      setAppointments(prev => prev.map(a => a.id === id ? { ...a, status } : a));
      loadSummary();
    } catch(e) {
      setErr(e?.response?.data?.error?.message || e?.message || "อัปเดตสถานะไม่สำเร็จ");
      throw e;
    }
  };

  // handlers cancel
  const onClickCancel = (appt) => {
    setCancelTarget(appt);
    setConfirmOpen(true);
  };
  const closeConfirm = () => {
    if (cancelBusy) return;
    setConfirmOpen(false);
    setCancelTarget(null);
  };
  const confirmCancel = async () => {
    if (!cancelTarget) return;
    try {
      setCancelBusy(true);
      await updateStatus(cancelTarget.id, "cancelled");
    } finally {
      setCancelBusy(false);
      setConfirmOpen(false);
      setCancelTarget(null);
    }
  };

  const prevMonth = ()=>{ const d=new Date(monthCursor); d.setMonth(d.getMonth()-1); setMonthCursor(d); };
  const nextMonth = ()=>{ const d=new Date(monthCursor); d.setMonth(d.getMonth()+1); setMonthCursor(d); };

  if (loadingMe) {
    return <Box sx={{minHeight:"60vh",display:"flex",alignItems:"center",justifyContent:"center"}}><CircularProgress/></Box>;
  }
  if (me && me.role !== "doctor") {
    return <Container maxWidth="sm" sx={{pt:8}}><Alert severity="warning">หน้านี้สำหรับแพทย์เท่านั้น</Alert></Container>;
  }

  const monthLabel = monthCursor.toLocaleDateString("th-TH", { year:"numeric", month:"long" });

  return (
    <Box sx={{ minHeight:"72vh", pt:6, pb:6, bgcolor:"#f3f4f6" }}>
      <Container maxWidth="lg">

        {/* หัวข้อกลางหน้า */}
        <Box sx={{ display:"flex", justifyContent:"center", mb:2 }}>
          <Typography variant="h5" sx={{ fontWeight:800 }} align="center">
            ปฏิทินตารางนัดของแพทย์
          </Typography>
        </Box>

        {/* การ์ด REPORT */}
        <Paper
          sx={{
            p:2.5, mb:3, maxWidth:880, mx:"auto", borderRadius:3,
            background: "linear-gradient(135deg, #1f2937 0%, #0b1220 100%)",
            color: "#fff"
          }}
          elevation={4}
        >
          <Box sx={{ textAlign:"center", mb:1 }}>
            <Typography variant="subtitle2" sx={{ opacity:0.9 }}>ภาพรวมของฉัน</Typography>
            <Typography variant="h6" sx={{ fontWeight:800 }}>สรุปนัดหมายทั้งหมด</Typography>
          </Box>

          <Box sx={{ display:"flex", justifyContent:"center", gap:1.2, flexWrap:"wrap" }}>
            {loadingSummary ? (
              <CircularProgress size={18} sx={{ color:"#fff" }}/>
            ) : summary ? (
              <>
                <Chip sx={{ color:"#0b1220", bgcolor:"#fef08a", fontWeight:700 }} label={`รวม ${summary.total ?? 0}`} />
                <Chip sx={{ bgcolor:"#86efac", color:"#0b1220", fontWeight:700 }} label={`ยืนยัน ${summary.by_status?.confirmed ?? 0}`} />
                <Chip sx={{ bgcolor:"#e5e7eb", color:"#111827" }} label={`ค้าง ${summary.by_status?.pending ?? 0}`} />
                <Chip sx={{ bgcolor:"#fecaca", color:"#111827" }} label={`ยกเลิก ${summary.by_status?.cancelled ?? 0}`} />
                <Chip sx={{ bgcolor:"#fbcfe8", color:"#111827" }} label={`ปฏิเสธ ${summary.by_status?.rejected ?? 0}`} />
                <Chip sx={{ bgcolor:"#c7d2fe", color:"#111827" }} label={`กำลังจะถึง ${summary.upcoming?.count ?? 0}`} />
              </>
            ) : (
              <Chip variant="outlined" sx={{ color:"#fff", borderColor:"rgba(255,255,255,0.4)" }} label="ไม่มีข้อมูลรายงาน"/>
            )}
          </Box>
        </Paper>

        {/* การ์ดปฏิทิน */}
        <Paper sx={{ p:2.5, borderRadius:2, mb:3, maxWidth:880, mx:"auto" }}>
          <Box sx={{ display:"flex", alignItems:"center", justifyContent:"space-between" }}>
            <Button size="small" onClick={prevMonth}>เดือนก่อนหน้า</Button>
            <Typography variant="subtitle1" sx={{ fontWeight:700 }}>{monthLabel}</Typography>
            <Button size="small" onClick={nextMonth}>เดือนถัดไป</Button>
          </Box>

          <Divider sx={{ my:1.5 }} />

          <Box sx={{ display:"grid", gridTemplateColumns:"repeat(7,1fr)", textAlign:"center", color:"text.secondary", mb:0.5 }}>
            {thDays.map(n => <Box key={n} sx={{py:0.25,fontWeight:700,fontSize:13}}>{n}</Box>)}
          </Box>

          <Box sx={{ display:"grid", gridTemplateColumns:"repeat(7,1fr)", gap:0.75 }}>
            {monthDays.map((cell, idx) =>
              cell === null ? <Box key={`x-${idx}`} /> : (
                <Paper
                  key={cell.ymd}
                  onClick={()=>setSelectedDate(cell.ymd)}
                  sx={{
                    p:0.75, cursor:"pointer", borderRadius:1.5,
                    border: selectedDate===cell.ymd ? "2px solid #1976d2" : "1px solid rgba(0,0,0,0.08)",
                    bgcolor:"background.paper", minHeight:56
                  }}
                  elevation={selectedDate===cell.ymd ? 2 : 0}
                >
                  <Box sx={{ display:"flex", alignItems:"center", justifyContent:"space-between" }}>
                    <Typography sx={{ fontWeight:700, fontSize:14 }}>{cell.date.getDate()}</Typography>
                    <Box sx={{ display:"flex", alignItems:"center", gap:0.5 }}>
                      {cell.hasConfirmed ? <Dot color="green"/> : null}
                      {cell.hasPending   ? <Dot color="gray"/> : null}
                    </Box>
                  </Box>
                </Paper>
              )
            )}
          </Box>

          <Box sx={{ display:"flex", alignItems:"center", gap:1.25, mt:1.5, justifyContent:"space-between" }}>
            <Box sx={{ display:"flex", alignItems:"center", gap:1.25 }}>
              <Chip size="small" label="จุดเขียว = มีนัดยืนยันแล้ว" />
              <Chip size="small" variant="outlined" label="จุดเทา = มีนัดรอยืนยัน" />
            </Box>
            <Button size="small" onClick={() => { loadAppointments(); loadSummary(); }}>รีเฟรช</Button>
          </Box>
        </Paper>

        {/* รายการรายวัน */}
        <Paper sx={{ p:3, borderRadius:2, mb:3, maxWidth:880, mx:"auto" }}>
          <Typography variant="h6" sx={{ fontWeight:700 }} align="center">
            วันที่เลือก: {new Date(selectedDate).toLocaleDateString("th-TH",{weekday:"long", day:"2-digit", month:"short", year:"numeric"})}
          </Typography>
          <Divider sx={{ my:2 }} />

          {loading ? (
            <Box sx={{ py:5, display:"flex", justifyContent:"center" }}><CircularProgress/></Box>
          ) : (
            <>
              <Typography variant="subtitle1" sx={{ fontWeight:700, mb:1 }}>
                รายการรอยืนยัน ({dailyPending.length})
              </Typography>
              {dailyPending.length === 0 ? (
                <Typography color="text.secondary" sx={{ mb:2 }}>ไม่มีรายการรอยืนยันในวันนี้</Typography>
              ) : (
                <Stack spacing={1.2} sx={{ mb:2 }}>
                  {dailyPending.map(a => (
                    <Paper key={a.id} sx={{ p:1.2, borderRadius:2, display:"flex", alignItems:"center", justifyContent:"space-between" }}>
                      <Box>
                        <Typography sx={{ fontWeight:700 }}>คนไข้: {a.patient_name || a.patient_id}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          สร้างเมื่อ: {a.created_at ? new Date(a.created_at).toLocaleString("th-TH") : "-"}
                        </Typography>
                      </Box>
                      <Box sx={{ display:"flex", gap:1 }}>
                        <Button size="small" variant="contained" color="success" startIcon={<CheckIcon/>}
                                onClick={()=>updateStatus(a.id,"confirmed")}>ยืนยัน</Button>
                        <Button size="small" variant="outlined" color="error" startIcon={<CloseIcon/>}
                                onClick={()=>updateStatus(a.id,"rejected")}>ปฏิเสธ</Button>
                      </Box>
                    </Paper>
                  ))}
                </Stack>
              )}

              <Divider sx={{ my:2 }} />

              <Typography variant="subtitle1" sx={{ fontWeight:700, mb:1 }}>
                นัดที่ยืนยันแล้ววันนี้ ({dailyConfirmed.length})
              </Typography>
              {dailyConfirmed.length === 0 ? (
                <Typography color="text.secondary">ไม่มีนัดยืนยันในวันนี้</Typography>
              ) : (
                <Stack spacing={1.2}>
                  {dailyConfirmed.map(a => (
                    <Paper key={a.id} sx={{ p:1.2, borderRadius:2, display:"flex", alignItems:"center", justifyContent:"space-between" }}>
                      <Box>
                        <Typography sx={{ fontWeight:700 }}>คนไข้: {a.patient_name || a.patient_id}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          วันที่: {a.chosen_date} • สถานะ: {a.status}
                        </Typography>
                      </Box>
                      <Button
                        size="small"
                        variant="outlined"
                        color="error"
                        startIcon={<EventBusyIcon/>}
                        onClick={()=>onClickCancel(a)}
                      >
                        ยกเลิกนัด
                      </Button>
                    </Paper>
                  ))}
                </Stack>
              )}
            </>
          )}
        </Paper>

        <Paper sx={{ p:3, borderRadius:2, maxWidth:880, mx:"auto" }}>
          <Typography variant="h6" sx={{ fontWeight:700 }}>ตารางนัดที่ยืนยันแล้ว (ล่วงหน้า)</Typography>
          <Divider sx={{ my:2 }} />
          {upcomingConfirmed.length === 0 ? (
            <Typography color="text.secondary">ยังไม่มีนัดล่วงหน้าที่ถูกยืนยัน</Typography>
          ) : (
            <Stack spacing={1}>
              {upcomingConfirmed.map(a => (
                <Paper key={a.id} sx={{ p:1.2, borderRadius:2 }}>
                  <Typography sx={{ fontWeight:700 }}>
                    {new Date(a.chosen_date).toLocaleDateString("th-TH")} • คนไข้: {a.patient_name || a.patient_id}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">สถานะ: {a.status}</Typography>
                </Paper>
              ))}
            </Stack>
          )}
        </Paper>

        {/* Confirm Cancel Dialog */}
        <Dialog open={confirmOpen} onClose={closeConfirm}>
          <DialogTitle>ยืนยันการยกเลิกนัด</DialogTitle>
          <DialogContent>
            <Typography>
              คุณยืนยันจะยกเลิกนัดของ{" "}
              <b>{cancelTarget?.patient_name || cancelTarget?.patient_id || "-"}</b>{" "}
              ในวันที่ <b>{cancelTarget?.chosen_date || "-"}</b> หรือไม่?
            </Typography>
            {err ? (
              <Typography color="error" variant="caption" sx={{ mt:1, display:"block" }}>{err}</Typography>
            ) : null}
          </DialogContent>
          <DialogActions>
            <Button onClick={closeConfirm} disabled={cancelBusy}>ปิด</Button>
            <Button
              variant="contained"
              color="error"
              onClick={confirmCancel}
              startIcon={cancelBusy ? null : <EventBusyIcon/>}
              disabled={cancelBusy}
            >
              {cancelBusy ? <CircularProgress size={18}/> : "ยืนยันยกเลิก"}
            </Button>
          </DialogActions>
        </Dialog>

      </Container>
    </Box>
  );
}
