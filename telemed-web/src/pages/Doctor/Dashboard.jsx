// src/pages/Doctor/slots.jsx
import React, { useEffect, useMemo, useState } from "react";
import {
  Box, Button, Container, Paper, TextField, Typography,
  CircularProgress, Alert, Stack, Divider, Chip
} from "@mui/material";
import api from "../../lib/api";
import { useNavigate } from "react-router-dom";

/* helpers */
const pad = (n) => String(n).padStart(2,"0");
const ymd = (d)=>`${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;
const startOfMonth = (d)=> new Date(d.getFullYear(), d.getMonth(), 1,0,0,0,0);
const endOfMonth   = (d)=> new Date(d.getFullYear(), d.getMonth()+1, 0,23,59,59,999);
const rangeDays = (from,to)=>{ const out=[]; const s=new Date(from); s.setHours(0,0,0,0);
  const e=new Date(to); e.setHours(0,0,0,0); for(let d=new Date(s); d<=e; d.setDate(d.getDate()+1)) out.push(new Date(d)); return out; };
const Dot = ({color}) => <Box sx={{width:8,height:8,borderRadius:"50%",bgcolor:color,display:"inline-block"}}/>;

const todayPlus = (d=0)=>{ const t=new Date(); t.setDate(t.getDate()+d); return ymd(t); };
const startOfDayISO = (ymd) => new Date(`${ymd}T00:00:00`).toISOString();
const endOfDayISO   = (ymd) => new Date(`${ymd}T23:59:59`).toISOString();

export default function DoctorSlots() {
  const nav = useNavigate();
  const [me,setMe] = useState(null);
  const [loadingMe,setLoadingMe] = useState(true);
  const [err,setErr] = useState("");

  // form state
  const [fromDate,setFromDate] = useState(todayPlus(1));
  const [toDate,setToDate]     = useState(todayPlus(1));
  const [creating,setCreating] = useState(false);
  const [summary,setSummary]   = useState("");

  // calendar
  const [monthCursor,setMonthCursor] = useState(()=>{ const d=new Date(); d.setDate(1); return d; });
  const [slots,setSlots] = useState([]);
  const [loadingSlots,setLoadingSlots] = useState(false);

  const minFrom = useMemo(()=>todayPlus(1),[]);
  const minTo   = fromDate || minFrom;

  // load profile
  useEffect(()=>{
    let cancel=false;
    (async()=>{
      setLoadingMe(true);
      try{
        const r=await api.get("/users/me");
        if(!cancel) setMe(r?.data?.user || r?.data);
      }catch(e){
        if(!cancel) setErr("โหลดข้อมูลผู้ใช้ล้มเหลว");
      }finally{ if(!cancel) setLoadingMe(false); }
    })();
    return ()=>{ cancel=true; };
  },[]);

  // load existing slots
  const loadSlots = async ()=>{
    if(!me?.id) return;
    setLoadingSlots(true);
    try{
      const from= startOfMonth(monthCursor).toISOString();
      const to  = endOfMonth(monthCursor).toISOString();
      const r= await api.get(`/doctors/${me.id}/slots?from=${from}&to=${to}`);
      setSlots(r?.data?.data || []);
    }catch(e){
      setErr(e?.response?.data?.error?.message || "โหลด slots ไม่สำเร็จ");
    }finally{ setLoadingSlots(false); }
  };
  useEffect(()=>{ if(me?.role==="doctor") loadSlots(); },[me?.id,monthCursor]);

  // validate form
  const validate=()=>{
    setErr("");
    if(!fromDate||!toDate){ setErr("กรุณาเลือกช่วงวันที่ให้ครบถ้วน"); return false; }
    if(fromDate < minFrom){ setErr("วันเริ่มต้นต้องไม่น้อยกว่าวันพรุ่งนี้"); return false; }
    if(toDate < fromDate){ setErr("วันสิ้นสุดต้องไม่น้อยกว่าวันเริ่มต้น"); return false; }
    return true;
  };

  // create slots
  const createDailySlots = async(e)=>{
    e.preventDefault();
    if(!validate()) return;
    setCreating(true); setSummary("");
    try{
      const days = rangeDays(new Date(fromDate),new Date(toDate)).map(d=>ymd(d));
      const calls = days.map(ymd=>
        api.post(`/doctors/${me.id}/slots`, {
          start_time: startOfDayISO(ymd),
          end_time: endOfDayISO(ymd)
        }).then(()=>({ok:true})).catch(()=>({ok:false}))
      );
      const results= await Promise.all(calls);
      const ok= results.filter(r=>r.ok).length;
      const fail= results.length-ok;
      setSummary(`สร้างวันว่างสำเร็จ ${ok} วัน${fail?`, ล้มเหลว ${fail} วัน`:""}`);
      loadSlots();
    }catch(err){
      setErr(err?.message || "สร้าง slot ไม่สำเร็จ");
    }finally{ setCreating(false); }
  };

  if(loadingMe){
    return <Box sx={{minHeight:"60vh",display:"flex",alignItems:"center",justifyContent:"center"}}><CircularProgress/></Box>;
  }
  if(me && me.role!=="doctor"){
    return <Container maxWidth="sm" sx={{pt:8}}><Alert severity="warning">หน้านี้สำหรับแพทย์เท่านั้น</Alert></Container>;
  }

  // calendar mapping
  const days = rangeDays(startOfMonth(monthCursor), endOfMonth(monthCursor));
  const slotsYMD = new Set(slots.map(s=>s.start_time.slice(0,10)));

  const monthLabel = monthCursor.toLocaleDateString("th-TH",{year:"numeric",month:"long"});

  return (
    <Box sx={{minHeight:"72vh",pt:6,pb:6}}>
      <Container maxWidth="md">
        {/* form create slots */}
        <Paper sx={{p:4,borderRadius:2,mb:3}}>
          <Typography variant="h5" sx={{fontWeight:700,mb:1}}>เพิ่มวันว่าง</Typography>
          <Typography color="text.secondary" sx={{mb:3}}>เลือกช่วงวันที่คุณว่าง ระบบจะสร้าง <b>slot รายวัน</b> ให้อัตโนมัติ</Typography>

          <Stack component="form" onSubmit={createDailySlots} spacing={2}>
            <TextField label="ตั้งแต่วันที่" type="date" InputLabelProps={{shrink:true}}
              value={fromDate} onChange={(e)=>setFromDate(e.target.value)} inputProps={{min:minFrom}} required/>
            <TextField label="ถึงวันที่" type="date" InputLabelProps={{shrink:true}}
              value={toDate} onChange={(e)=>setToDate(e.target.value)} inputProps={{min:minTo}} required/>

            {err && <Alert severity="error">{err}</Alert>}
            {summary && <Alert severity="success">{summary}</Alert>}

            <Box sx={{display:"flex",gap:2}}>
              <Button type="submit" variant="contained" disabled={creating}>
                {creating? <CircularProgress size={18} color="inherit"/> : "สร้างวันว่าง"}
              </Button>
              <Button variant="outlined" onClick={()=>nav("/doctor")}>กลับ</Button>
            </Box>
          </Stack>
        </Paper>

        {/* calendar view */}
        <Paper sx={{p:4,borderRadius:2}}>
          <Box sx={{display:"flex",justifyContent:"space-between",alignItems:"center",mb:2}}>
            <Button onClick={()=>setMonthCursor(new Date(monthCursor.getFullYear(),monthCursor.getMonth()-1,1))}>ก่อนหน้า</Button>
            <Typography variant="h6" sx={{fontWeight:700}}>{monthLabel}</Typography>
            <Button onClick={()=>setMonthCursor(new Date(monthCursor.getFullYear(),monthCursor.getMonth()+1,1))}>ถัดไป</Button>
          </Box>

          <Divider sx={{my:2}}/>

          {loadingSlots? (
            <Box sx={{py:5,display:"flex",justifyContent:"center"}}><CircularProgress/></Box>
          ):(
            <>
              <Box sx={{display:"grid",gridTemplateColumns:"repeat(7,1fr)",textAlign:"center",color:"text.secondary",mb:1}}>
                {["อา","จ","อ","พ","พฤ","ศ","ส"].map(n=><Box key={n} sx={{py:0.5,fontWeight:700}}>{n}</Box>)}
              </Box>
              <Box sx={{display:"grid",gridTemplateColumns:"repeat(7,1fr)",gap:1}}>
                {Array.from({length:startOfMonth(monthCursor).getDay()},()=>null).map((_,i)=><Box key={`x${i}`}/>)}
                {days.map(d=>{
                  const dYMD=ymd(d);
                  return (
                    <Paper key={dYMD} sx={{p:1.2,minHeight:72,borderRadius:2,textAlign:"left"}}>
                      <Typography sx={{fontWeight:700,fontSize:14}}>{d.getDate()}</Typography>
                      {slotsYMD.has(dYMD)? <Dot color="green"/>:null}
                    </Paper>
                  );
                })}
              </Box>
              <Box sx={{display:"flex",alignItems:"center",gap:2,mt:2}}>
                <Chip size="small" label="หมุดเขียว = มี slot แล้ว"/>
              </Box>
            </>
          )}
        </Paper>
      </Container>
    </Box>
  );
}
