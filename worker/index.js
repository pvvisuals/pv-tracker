// PV Visual Studio Tracker — Cloudflare Worker API
// Talks to a Turso (libSQL) database. See ../schema.sql for the table layout.
//
// Required secrets (wrangler secret put ...):
//   TURSO_URL          e.g. libsql://your-db-yourorg.turso.io
//   TURSO_AUTH_TOKEN   token from `turso db tokens create <db-name>`

import { createClient } from "@libsql/client/web";

const TZ = "Africa/Cairo";
const WORK_DAY_SECONDS = 8 * 3600;
const CASUAL_YEARLY = 6;
const ANNUAL_YEARLY = 21;
const SESSION_DAYS = 30;
const PBKDF2_ITER = 100000;

// ---------------------------------------------------------------- helpers

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

function err(message, status = 400) {
  return json({ error: message }, status);
}

function b64(bytes) {
  let s = "";
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s);
}
function unb64(str) {
  const bin = atob(str);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function hashSecret(plain, saltBytes) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(plain), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITER, hash: "SHA-256" },
    keyMaterial, 256
  );
  return b64(bits);
}

async function makeSecretHash(plain) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashSecret(plain, salt);
  return `${PBKDF2_ITER}:${b64(salt)}:${hash}`;
}

async function verifySecretHash(plain, stored) {
  if (!stored) return false;
  const [iterStr, saltB64, hashB64] = stored.split(":");
  const salt = unb64(saltB64);
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(plain), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: parseInt(iterStr, 10), hash: "SHA-256" },
    keyMaterial, 256
  );
  return b64(bits) === hashB64;
}

function newToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Cairo-local Y-M-D for "today", and for any Date object.
function cairoParts(date) {
  const fmt = new Intl.DateTimeFormat("en-CA", {
    timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit", weekday: "short",
  });
  const parts = fmt.formatToParts(date);
  const get = (t) => parts.find((p) => p.type === t).value;
  return { y: get("year"), m: get("month"), d: get("day"), weekday: get("weekday") };
}
function cairoDateStr(date = new Date()) {
  const p = cairoParts(date);
  return `${p.y}-${p.m}-${p.d}`;
}
function isWeekendStr(dateStr) {
  // dateStr = YYYY-MM-DD, treat as a Cairo calendar date (noon avoids DST edge issues)
  const d = new Date(dateStr + "T12:00:00Z");
  const p = cairoParts(d);
  return p.weekday === "Fri" || p.weekday === "Sat";
}
function daysInMonth(year, month) {
  return new Date(year, month, 0).getDate(); // month is 1-indexed here
}

function requireFields(body, fields) {
  for (const f of fields) {
    if (body[f] === undefined || body[f] === null || body[f] === "") {
      return f;
    }
  }
  return null;
}

// ---------------------------------------------------------------- auth

async function getAuthedEmployee(req, db) {
  const authHeader = req.headers.get("Authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return null;
  const res = await db.execute({
    sql: `SELECT e.* FROM sessions s JOIN employees e ON e.id = s.employee_id
          WHERE s.token = ? AND s.expires_at > datetime('now')`,
    args: [token],
  });
  return res.rows[0] || null;
}

function publicEmployee(e) {
  return {
    id: e.id, emp_code: e.emp_code, name: e.name, phone: e.phone,
    title: e.title, dept: e.dept, avatar_url: e.avatar_url, role: e.role,
    casual_balance: e.casual_balance, annual_balance: e.annual_balance,
  };
}

// ---------------------------------------------------------------- main

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    const db = createClient({ url: env.TURSO_URL, authToken: env.TURSO_AUTH_TOKEN });
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const method = req.method;

    let body = {};
    if (method === "POST" || method === "PATCH") {
      try { body = await req.json(); } catch { body = {}; }
    }

    try {
      // ---------- public auth routes ----------
      if (path === "/api/register" && method === "POST") return await register(db, body);
      if (path === "/api/login" && method === "POST") return await login(db, body);
      if (path === "/api/recover/step1" && method === "POST") return await recoverStep1(db, body);
      if (path === "/api/recover/step2" && method === "POST") return await recoverStep2(db, body);
      if (path === "/api/recover/step3" && method === "POST") return await recoverStep3(db, body);

      // ---------- everything below requires auth ----------
      const me = await getAuthedEmployee(req, db);
      if (!me) return err("Unauthorized", 401);

      if (path === "/api/me" && method === "GET") return json(publicEmployee(me));
      if (path === "/api/me/avatar" && method === "PATCH") return await updateAvatar(db, me, body);
      if (path === "/api/logout" && method === "POST") return await logout(req, db);

      if (path === "/api/attendance/sign-in" && method === "POST") return await signIn(db, me);
      if (path === "/api/attendance/sign-out" && method === "POST") return await signOut(db, me);
      if (path === "/api/attendance/today" && method === "GET") return await attendanceToday(db, me);

      if (path === "/api/breaks" && method === "POST") return await addBreak(db, me, body);
      if (path === "/api/breaks/today" && method === "GET") return await breaksToday(db, me);

      if (path === "/api/tasks" && method === "POST") return await addTask(db, me, body);
      if (path === "/api/tasks/today" && method === "GET") return await tasksToday(db, me);
      const taskEndMatch = path.match(/^\/api\/tasks\/(\d+)\/end$/);
      if (taskEndMatch && method === "PATCH") return await endTask(db, me, Number(taskEndMatch[1]), body);

      if (path === "/api/leave-requests" && method === "POST") return await requestLeave(db, me, body);
      if (path === "/api/leave-requests/mine" && method === "GET") return await myLeaveRequests(db, me);

      if (path === "/api/overtime-requests" && method === "POST") return await requestOvertime(db, me, body);
      if (path === "/api/overtime-requests/mine" && method === "GET") return await myOvertimeRequests(db, me);

      if (path === "/api/report/mine" && method === "GET") {
        const month = url.searchParams.get("month"); // YYYY-MM
        return await monthlyReport(db, me.id, month);
      }

      // ---------- admin only ----------
      if (path.startsWith("/api/admin/")) {
        if (me.role !== "admin") return err("Forbidden", 403);
        return await handleAdmin(db, me, path, method, body, url);
      }

      return err("Not found", 404);
    } catch (e) {
      return err("Server error: " + (e && e.message ? e.message : String(e)), 500);
    }
  },
};

// ---------------------------------------------------------------- auth handlers

async function register(db, body) {
  const missing = requireFields(body, ["name", "phone", "password", "title", "dept", "secret_q", "secret_a"]);
  if (missing) return err(`Missing field: ${missing}`);

  const existing = await db.execute({ sql: "SELECT id FROM employees WHERE phone = ?", args: [body.phone] });
  if (existing.rows.length) return err("رقم الموبايل مسجل مسبقا", 409);

  const countRes = await db.execute("SELECT COUNT(*) as c FROM employees");
  const isFirst = Number(countRes.rows[0].c) === 0;
  const empCode = String(Number(countRes.rows[0].c) + 1).padStart(2, "0");

  const passwordHash = await makeSecretHash(body.password);
  const secretAHash = await makeSecretHash(String(body.secret_a).trim().toLowerCase());

  const insert = await db.execute({
    sql: `INSERT INTO employees (emp_code, name, phone, password_hash, title, dept, secret_q, secret_a, role, casual_balance, annual_balance)
          VALUES (?,?,?,?,?,?,?,?,?,?,?) RETURNING *`,
    args: [empCode, body.name, body.phone, passwordHash, body.title, body.dept, body.secret_q, secretAHash,
           isFirst ? "admin" : "employee", CASUAL_YEARLY, ANNUAL_YEARLY],
  });

  return json({ employee: publicEmployee(insert.rows[0]) }, 201);
}

async function login(db, body) {
  const missing = requireFields(body, ["phone", "password"]);
  if (missing) return err(`Missing field: ${missing}`);

  const res = await db.execute({ sql: "SELECT * FROM employees WHERE phone = ?", args: [body.phone] });
  const emp = res.rows[0];
  if (!emp || !(await verifySecretHash(body.password, emp.password_hash))) {
    return err("رقم الموبايل او الباسورد غلط", 401);
  }

  const token = newToken();
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
  await db.execute({
    sql: "INSERT INTO sessions (token, employee_id, expires_at) VALUES (?,?,?)",
    args: [token, emp.id, expires],
  });

  return json({ token, employee: publicEmployee(emp) });
}

async function logout(req, db) {
  const authHeader = req.headers.get("Authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (token) await db.execute({ sql: "DELETE FROM sessions WHERE token = ?", args: [token] });
  return json({ ok: true });
}

async function recoverStep1(db, body) {
  const missing = requireFields(body, ["phone"]);
  if (missing) return err("ادخل رقم الموبايل");
  const res = await db.execute({ sql: "SELECT id, secret_q FROM employees WHERE phone = ?", args: [body.phone] });
  const emp = res.rows[0];
  if (!emp) return err("رقم غير موجود", 404);
  return json({ employee_id: emp.id, question: emp.secret_q });
}

async function recoverStep2(db, body) {
  const missing = requireFields(body, ["employee_id", "answer"]);
  if (missing) return err("بيانات ناقصة");
  const res = await db.execute({ sql: "SELECT secret_a FROM employees WHERE id = ?", args: [body.employee_id] });
  const emp = res.rows[0];
  if (!emp) return err("مستخدم غير موجود", 404);
  const ok = await verifySecretHash(String(body.answer).trim().toLowerCase(), emp.secret_a);
  if (!ok) return err("اجابة خاطئة", 401);
  return json({ ok: true });
}

async function recoverStep3(db, body) {
  const missing = requireFields(body, ["employee_id", "answer", "new_password"]);
  if (missing) return err("بيانات ناقصة");
  const res = await db.execute({ sql: "SELECT secret_a FROM employees WHERE id = ?", args: [body.employee_id] });
  const emp = res.rows[0];
  if (!emp) return err("مستخدم غير موجود", 404);
  const ok = await verifySecretHash(String(body.answer).trim().toLowerCase(), emp.secret_a);
  if (!ok) return err("اجابة خاطئة", 401);
  const newHash = await makeSecretHash(body.new_password);
  await db.execute({ sql: "UPDATE employees SET password_hash = ? WHERE id = ?", args: [newHash, body.employee_id] });
  return json({ ok: true });
}

async function updateAvatar(db, me, body) {
  if (!body.avatar_url) return err("Missing avatar_url");
  await db.execute({ sql: "UPDATE employees SET avatar_url = ? WHERE id = ?", args: [body.avatar_url, me.id] });
  return json({ ok: true });
}

// ---------------------------------------------------------------- attendance

async function signIn(db, me) {
  const today = cairoDateStr();
  const t = new Date().toLocaleTimeString("en-US", { timeZone: TZ, hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
  const fn = me.name.split(" ")[0];
  const res = await db.execute({
    sql: `INSERT INTO attendance (employee_id, date, action, time, first_name) VALUES (?,?,?,?,?) RETURNING *`,
    args: [me.id, today, "sign_in", t, fn],
  });
  return json({ entry: res.rows[0] }, 201);
}

async function signOut(db, me) {
  const today = cairoDateStr();
  const t = new Date().toLocaleTimeString("en-US", { timeZone: TZ, hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
  const fn = me.name.split(" ")[0];

  // figure out "worked" for this session, informational only
  const rows = await db.execute({
    sql: "SELECT * FROM attendance WHERE employee_id = ? AND date = ? ORDER BY created_at ASC",
    args: [me.id, today],
  });
  let lastIn = null;
  for (const r of rows.rows) if (r.action === "sign_in") lastIn = r;
  let worked = "";
  if (lastIn) {
    const secs = Math.max(0, Math.floor((Date.now() - new Date(lastIn.created_at + "Z").getTime()) / 1000));
    worked = formatDuration(secs);
  }

  const res = await db.execute({
    sql: `INSERT INTO attendance (employee_id, date, action, time, worked, first_name) VALUES (?,?,?,?,?,?) RETURNING *`,
    args: [me.id, today, "sign_out", t, worked, fn],
  });
  return json({ entry: res.rows[0] }, 201);
}

async function attendanceToday(db, me) {
  const today = cairoDateStr();
  const res = await db.execute({
    sql: "SELECT * FROM attendance WHERE employee_id = ? AND date = ? ORDER BY created_at ASC",
    args: [me.id, today],
  });
  return json({ entries: res.rows });
}

function formatDuration(s) {
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return [h, m, sec].map((v) => String(v).padStart(2, "0")).join(":");
}

// ---------------------------------------------------------------- breaks

async function addBreak(db, me, body) {
  const missing = requireFields(body, ["start_time", "end_time", "duration"]);
  if (missing) return err(`Missing field: ${missing}`);
  const today = cairoDateStr();
  const fn = me.name.split(" ")[0];
  const res = await db.execute({
    sql: `INSERT INTO breaks (employee_id, date, start_time, end_time, duration, first_name) VALUES (?,?,?,?,?,?) RETURNING *`,
    args: [me.id, today, body.start_time, body.end_time, body.duration, fn],
  });
  return json({ entry: res.rows[0] }, 201);
}

async function breaksToday(db, me) {
  const today = cairoDateStr();
  const res = await db.execute({
    sql: "SELECT * FROM breaks WHERE employee_id = ? AND date = ? ORDER BY created_at ASC",
    args: [me.id, today],
  });
  return json({ entries: res.rows });
}

// ---------------------------------------------------------------- tasks

async function addTask(db, me, body) {
  const missing = requireFields(body, ["project", "name"]);
  if (missing) return err(`Missing field: ${missing}`);
  const today = cairoDateStr();
  const t = new Date().toLocaleTimeString("en-US", { timeZone: TZ, hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
  const fn = me.name.split(" ")[0];
  const res = await db.execute({
    sql: `INSERT INTO tasks (employee_id, project, name, description, date, time, start_time, first_name)
          VALUES (?,?,?,?,?,?,?,?) RETURNING *`,
    args: [me.id, body.project, body.name, body.description || "", today, t, t, fn],
  });
  return json({ task: res.rows[0] }, 201);
}

async function endTask(db, me, taskId, body) {
  const rows = await db.execute({ sql: "SELECT * FROM tasks WHERE id = ? AND employee_id = ?", args: [taskId, me.id] });
  const task = rows.rows[0];
  if (!task) return err("Task not found", 404);
  const t = new Date().toLocaleTimeString("en-US", { timeZone: TZ, hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
  const dur = Math.max(0, Math.floor((Date.now() - new Date(task.created_at + "Z").getTime()) / 1000));
  await db.execute({ sql: "UPDATE tasks SET end_time = ?, duration = ? WHERE id = ?", args: [t, dur, taskId] });
  return json({ ok: true, end_time: t, duration: dur });
}

async function tasksToday(db, me) {
  const today = cairoDateStr();
  const res = await db.execute({
    sql: "SELECT * FROM tasks WHERE employee_id = ? AND date = ? ORDER BY created_at DESC",
    args: [me.id, today],
  });
  return json({ tasks: res.rows });
}

// ---------------------------------------------------------------- leave requests

async function requestLeave(db, me, body) {
  const missing = requireFields(body, ["date", "type"]);
  if (missing) return err(`Missing field: ${missing}`);
  if (!["casual", "annual"].includes(body.type)) return err("type must be casual or annual");
  if (isWeekendStr(body.date)) return err("اليوم ده اجازة اسبوعية اصلا (جمعة/سبت)");

  const existing = await db.execute({
    sql: "SELECT * FROM leave_requests WHERE employee_id = ? AND date = ?",
    args: [me.id, body.date],
  });
  if (existing.rows.length) return err("فيه طلب اجازة لليوم ده بالفعل", 409);

  const res = await db.execute({
    sql: `INSERT INTO leave_requests (employee_id, date, type, note) VALUES (?,?,?,?) RETURNING *`,
    args: [me.id, body.date, body.type, body.note || null],
  });
  return json({ request: res.rows[0] }, 201);
}

async function myLeaveRequests(db, me) {
  const res = await db.execute({
    sql: "SELECT * FROM leave_requests WHERE employee_id = ? ORDER BY date DESC",
    args: [me.id],
  });
  return json({
    requests: res.rows,
    balance: { casual: me.casual_balance, annual: me.annual_balance },
  });
}

// ---------------------------------------------------------------- overtime requests

async function requestOvertime(db, me, body) {
  const missing = requireFields(body, ["date"]);
  if (missing) return err(`Missing field: ${missing}`);
  if (isWeekendStr(body.date)) return err("اليوم ده اجازة اسبوعية");

  const existing = await db.execute({
    sql: "SELECT * FROM overtime_requests WHERE employee_id = ? AND date = ?",
    args: [me.id, body.date],
  });
  if (existing.rows.length) return err("فيه طلب اوفر تايم لليوم ده بالفعل", 409);

  const res = await db.execute({
    sql: `INSERT INTO overtime_requests (employee_id, date, note) VALUES (?,?,?) RETURNING *`,
    args: [me.id, body.date, body.note || null],
  });
  return json({ request: res.rows[0] }, 201);
}

async function myOvertimeRequests(db, me) {
  const res = await db.execute({
    sql: "SELECT * FROM overtime_requests WHERE employee_id = ? ORDER BY date DESC",
    args: [me.id],
  });
  return json({ requests: res.rows });
}

// ---------------------------------------------------------------- monthly report (core hours logic)

async function monthlyReport(db, employeeId, monthStr) {
  const now = new Date();
  let year, month;
  if (monthStr && /^\d{4}-\d{2}$/.test(monthStr)) {
    [year, month] = monthStr.split("-").map(Number);
  } else {
    const p = cairoParts(now);
    year = Number(p.y); month = Number(p.m);
  }

  const empRes = await db.execute({ sql: "SELECT * FROM employees WHERE id = ?", args: [employeeId] });
  const emp = empRes.rows[0];
  if (!emp) return err("Employee not found", 404);

  const firstDay = `${year}-${String(month).padStart(2, "0")}-01`;
  const lastDayNum = daysInMonth(year, month);
  const lastDay = `${year}-${String(month).padStart(2, "0")}-${String(lastDayNum).padStart(2, "0")}`;

  const [attRows, leaveRows, otRows] = await Promise.all([
    db.execute({
      sql: "SELECT * FROM attendance WHERE employee_id = ? AND date BETWEEN ? AND ? ORDER BY created_at ASC",
      args: [employeeId, firstDay, lastDay],
    }),
    db.execute({
      sql: "SELECT * FROM leave_requests WHERE employee_id = ? AND date BETWEEN ? AND ? AND status = 'approved'",
      args: [employeeId, firstDay, lastDay],
    }),
    db.execute({
      sql: "SELECT * FROM overtime_requests WHERE employee_id = ? AND date BETWEEN ? AND ? AND status = 'approved'",
      args: [employeeId, firstDay, lastDay],
    }),
  ]);

  const attByDate = {};
  for (const r of attRows.rows) {
    (attByDate[r.date] = attByDate[r.date] || []).push(r);
  }
  const leaveByDate = {};
  for (const r of leaveRows.rows) leaveByDate[r.date] = r;
  const otByDate = {};
  for (const r of otRows.rows) otByDate[r.date] = r;

  const todayStr = cairoDateStr();
  const days = [];
  let totalCountedSeconds = 0;
  let totalActualSeconds = 0;
  let totalOvertimeSeconds = 0;
  let absentDays = 0;
  let leaveDaysCasual = 0;
  let leaveDaysAnnual = 0;

  for (let d = 1; d <= lastDayNum; d++) {
    const dateStr = `${year}-${String(month).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
    if (dateStr > todayStr) break; // don't project future days
    if (isWeekendStr(dateStr)) {
      days.push({ date: dateStr, status: "weekend" });
      continue;
    }

    const leave = leaveByDate[dateStr];
    if (leave) {
      totalCountedSeconds += WORK_DAY_SECONDS;
      if (leave.type === "casual") leaveDaysCasual++; else leaveDaysAnnual++;
      days.push({ date: dateStr, status: "leave", leave_type: leave.type, counted_seconds: WORK_DAY_SECONDS });
      continue;
    }

    const entries = attByDate[dateStr] || [];
    let actualSeconds = 0;
    let pendingIn = null;
    for (const e of entries) {
      if (e.action === "sign_in") pendingIn = e;
      else if (e.action === "sign_out" && pendingIn) {
        const inMs = new Date(pendingIn.created_at + "Z").getTime();
        const outMs = new Date(e.created_at + "Z").getTime();
        if (outMs > inMs) actualSeconds += Math.floor((outMs - inMs) / 1000);
        pendingIn = null;
      }
    }

    if (!entries.length) {
      if (dateStr < todayStr) absentDays++;
      days.push({ date: dateStr, status: dateStr < todayStr ? "absent" : "today_pending", actual_seconds: 0, counted_seconds: 0 });
      continue;
    }

    const overtimeApproved = !!otByDate[dateStr];
    let countedSeconds, overtimeSeconds = 0;
    if (overtimeApproved) {
      countedSeconds = actualSeconds;
      overtimeSeconds = Math.max(0, actualSeconds - WORK_DAY_SECONDS);
    } else {
      countedSeconds = Math.min(actualSeconds, WORK_DAY_SECONDS);
    }

    totalActualSeconds += actualSeconds;
    totalCountedSeconds += countedSeconds;
    totalOvertimeSeconds += overtimeSeconds;

    days.push({
      date: dateStr, status: "worked",
      actual_seconds: actualSeconds, counted_seconds: countedSeconds,
      overtime_seconds: overtimeSeconds, overtime_approved: overtimeApproved,
    });
  }

  return json({
    employee: publicEmployee(emp),
    year, month,
    days,
    totals: {
      counted_seconds: totalCountedSeconds,
      counted_hours: +(totalCountedSeconds / 3600).toFixed(2),
      actual_seconds: totalActualSeconds,
      actual_hours: +(totalActualSeconds / 3600).toFixed(2),
      overtime_seconds: totalOvertimeSeconds,
      overtime_hours: +(totalOvertimeSeconds / 3600).toFixed(2),
      absent_days: absentDays,
      leave_days_casual: leaveDaysCasual,
      leave_days_annual: leaveDaysAnnual,
    },
    leave_balance: { casual: emp.casual_balance, annual: emp.annual_balance },
  });
}

// ---------------------------------------------------------------- admin

async function handleAdmin(db, admin, path, method, body, url) {
  if (path === "/api/admin/employees" && method === "GET") {
    const res = await db.execute("SELECT * FROM employees ORDER BY emp_code ASC");
    return json({ employees: res.rows.map(publicEmployee) });
  }

  if (path === "/api/admin/leave-requests" && method === "GET") {
    const status = url.searchParams.get("status") || "pending";
    const res = await db.execute({
      sql: `SELECT lr.*, e.name as employee_name, e.emp_code FROM leave_requests lr
            JOIN employees e ON e.id = lr.employee_id
            WHERE lr.status = ? ORDER BY lr.requested_at ASC`,
      args: [status],
    });
    return json({ requests: res.rows });
  }

  const leaveDecideMatch = path.match(/^\/api\/admin\/leave-requests\/(\d+)\/decide$/);
  if (leaveDecideMatch && method === "POST") {
    return await decideLeave(db, admin, Number(leaveDecideMatch[1]), body);
  }

  if (path === "/api/admin/overtime-requests" && method === "GET") {
    const status = url.searchParams.get("status") || "pending";
    const res = await db.execute({
      sql: `SELECT ot.*, e.name as employee_name, e.emp_code FROM overtime_requests ot
            JOIN employees e ON e.id = ot.employee_id
            WHERE ot.status = ? ORDER BY ot.requested_at ASC`,
      args: [status],
    });
    return json({ requests: res.rows });
  }

  const otDecideMatch = path.match(/^\/api\/admin\/overtime-requests\/(\d+)\/decide$/);
  if (otDecideMatch && method === "POST") {
    return await decideOvertime(db, admin, Number(otDecideMatch[1]), body);
  }

  const reportMatch = path === "/api/admin/report";
  if (reportMatch && method === "GET") {
    const employeeId = url.searchParams.get("employee_id");
    const month = url.searchParams.get("month");
    if (!employeeId) return err("employee_id required");
    return await monthlyReport(db, Number(employeeId), month);
  }

  if (path === "/api/admin/set-role" && method === "POST") {
    const missing = requireFields(body, ["employee_id", "role"]);
    if (missing) return err(`Missing field: ${missing}`);
    if (!["employee", "admin"].includes(body.role)) return err("invalid role");
    await db.execute({ sql: "UPDATE employees SET role = ? WHERE id = ?", args: [body.role, body.employee_id] });
    return json({ ok: true });
  }

  return err("Not found", 404);
}

async function decideLeave(db, admin, requestId, body) {
  if (!["approve", "reject"].includes(body.action)) return err("action must be approve or reject");
  const res = await db.execute({ sql: "SELECT * FROM leave_requests WHERE id = ?", args: [requestId] });
  const request = res.rows[0];
  if (!request) return err("Request not found", 404);
  if (request.status !== "pending") return err("Request already decided", 409);

  if (body.action === "approve") {
    const empRes = await db.execute({ sql: "SELECT * FROM employees WHERE id = ?", args: [request.employee_id] });
    const emp = empRes.rows[0];
    const field = request.type === "casual" ? "casual_balance" : "annual_balance";
    if (Number(emp[field]) <= 0) return err("رصيد الاجازة خلص لهذا الموظف", 409);
    await db.execute({ sql: `UPDATE employees SET ${field} = ${field} - 1 WHERE id = ?`, args: [request.employee_id] });
  }

  await db.execute({
    sql: "UPDATE leave_requests SET status = ?, decided_at = datetime('now'), decided_by = ? WHERE id = ?",
    args: [body.action === "approve" ? "approved" : "rejected", admin.id, requestId],
  });
  return json({ ok: true });
}

async function decideOvertime(db, admin, requestId, body) {
  if (!["approve", "reject"].includes(body.action)) return err("action must be approve or reject");
  const res = await db.execute({ sql: "SELECT * FROM overtime_requests WHERE id = ?", args: [requestId] });
  const request = res.rows[0];
  if (!request) return err("Request not found", 404);
  if (request.status !== "pending") return err("Request already decided", 409);

  await db.execute({
    sql: "UPDATE overtime_requests SET status = ?, decided_at = datetime('now'), decided_by = ? WHERE id = ?",
    args: [body.action === "approve" ? "approved" : "rejected", admin.id, requestId],
  });
  return json({ ok: true });
}
