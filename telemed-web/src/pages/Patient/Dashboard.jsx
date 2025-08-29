// src/pages/Patient/Dashboard.jsx
import React, { useEffect, useState } from "react";
import {
  Avatar,
  Box,
  Chip,
  CircularProgress,
  Container,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  Paper,
  Typography,
} from "@mui/material";
import ErrorOutlineIcon from "@mui/icons-material/ErrorOutline";
import EventAvailableIcon from "@mui/icons-material/EventAvailable";
import api from "../../lib/api";

function formatDateTime(ts) {
  try {
    const d = new Date(ts);
    return d.toLocaleString("th-TH", {
      weekday: "short",
      day: "2-digit",
      month: "short",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return "-";
  }
}

function statusChip(status) {
  switch ((status || "").toLowerCase()) {
    case "confirmed":
    case "upcoming":
      return <Chip label="confirmed" size="small" color="primary" />;
    case "completed":
    case "done":
      return (
        <Chip
          label="completed"
          size="small"
          sx={{ bgcolor: "#E6FFFA", color: "#065F46" }}
        />
      );
    case "cancelled":
    case "rejected": // ✅ เพิ่ม case 'rejected'
      return (
        <Chip
          label={status} // ✅ ใช้ status ที่ส่งมาเป็น label
          size="small"
          sx={{ bgcolor: "#FFF1F2", color: "#7F1D1D" }}
        />
      );
    default:
      return <Chip label={status || "unknown"} size="small" />;
  }
}

export default function Dashboard() {
  const [loading, setLoading] = useState(true);
  const [appts, setAppts] = useState([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setErr("");
      try {
        const r = await api.get("/appointments/me");
        if (!cancelled) setAppts(r?.data?.data || []);
      } catch (e) {
        console.error("fetch appointments error:", e);
        if (!cancelled) setErr("โหลดประวัติการนัดไม่สำเร็จ กรุณาลองใหม่");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // เรียงใหม่: ล่าสุดอยู่บน
  const history = (appts || [])
    .slice()
    .sort(
      (a, b) =>
        new Date(b.start_time || b.start || b.created_at) -
        new Date(a.start_time || a.start || a.created_at)
    );

  return (
    <Box
      sx={{
        display: "flex",
        alignItems: "flex-start", // Changed from "center" to "flex-start"
        justifyContent: "center",
        pb: 6,
        pt: 6, // Reduced from 6 to a lower value for less top padding
      }}
    >
      <Container maxWidth="xl">
        {/* กล่องกลางจอ กว้างขึ้น */}
        <Paper
          elevation={3}
          sx={{
            maxWidth: 1000,
            mx: "auto",
            p: { xs: 2.5, md: 3 },
            borderRadius: 3,
            boxShadow: "0 24px 60px rgba(16,24,40,0.08)",
            mt: { xs: 2, md: 4 } // Adjusted top margin to push the box up
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 2 }}>
            ประวัติการนัด
          </Typography>

          {loading ? (
            <Box sx={{ display: "flex", justifyContent: "center", py: 8 }}>
              <CircularProgress />
            </Box>
          ) : err ? (
            <Box
              sx={{
                display: "flex",
                gap: 1,
                alignItems: "center",
                color: "error.main",
                p: 2,
              }}
            >
              <ErrorOutlineIcon />
              <Typography>{err}</Typography>
            </Box>
          ) : !history.length ? (
            <Box sx={{ py: 6, textAlign: "center", color: "text.secondary" }}>
              <Typography variant="body1">ยังไม่มีประวัติการนัด</Typography>
            </Box>
          ) : (
            <List disablePadding>
              {history.map((a) => (
                <ListItem
                  key={a.id}
                  sx={{
                    mb: 1.2,
                    borderRadius: 2,
                    bgcolor: "background.paper",
                    boxShadow: "0 8px 22px rgba(16,24,40,0.06)",
                    px: { xs: 1, md: 2 },
                  }}
                  secondaryAction={statusChip(a.status)}
                >
                  <ListItemAvatar>
                    <Avatar sx={{ bgcolor: "primary.main" }}>
                      <EventAvailableIcon />
                    </Avatar>
                  </ListItemAvatar>
                  <ListItemText
                    primary={
                      <Box sx={{ display: "flex", gap: 1, alignItems: "center", flexWrap: "wrap" }}>
                        <Typography sx={{ fontWeight: 700 }}>
                          {a.title || "การปรึกษาออนไลน์"}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          • {a.doctor_name || "แพทย์"}
                        </Typography>
                      </Box>
                    }
                    secondary={
                      <Typography variant="caption" color="text.secondary">
                        {formatDateTime(a.start_time || a.start || a.created_at)}
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