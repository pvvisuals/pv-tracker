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
const ANNUAL_YEARLY = 15;
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

function calcAge(birthDateStr) {
  if (!birthDateStr) return null;
  const today = cairoParts(new Date());
  const [by, bm, bd] = birthDateStr.split("-").map(Number);
  let age = Number(today.y) - by;
  const beforeBirthdayThisYear = (Number(today.m) < bm) || (Number(today.m) === bm && Number(today.d) < bd);
  if (beforeBirthdayThisYear) age--;
  return age;
}

function hourlyRate(emp) {
  const salary = Number(emp.monthly_salary) || 0;
  const days = Number(emp.work_days_per_month) || 0;
  const dayHours = Number(emp.daily_work_hours) || 8;
  if (salary <= 0 || days <= 0 || dayHours <= 0) return 0;
  return salary / (days * dayHours);
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
    birth_date: e.birth_date || null, age: calcAge(e.birth_date),
  };
}

function adminEmployeeView(e) {
  return {
    ...publicEmployee(e),
    monthly_salary: Number(e.monthly_salary) || 0,
    work_days_per_month: Number(e.work_days_per_month) || 0,
    daily_work_hours: Number(e.daily_work_hours) || 8,
    hourly_rate: +hourlyRate(e).toFixed(2),
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
      if (path === "/api/me/profile" && method === "PATCH") return await updateProfile(db, me, body);
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

      if (path === "/api/financial-requests" && method === "POST") return await requestFinancial(db, me, body);
      if (path === "/api/financial-requests/mine" && method === "GET") return await myFinancialRequests(db, me);

      if (path === "/api/offclock-requests" && method === "POST") return await requestOffclock(db, me, body);
      if (path === "/api/offclock-requests/mine" && method === "GET") return await myOffclockRequests(db, me);

      if (path === "/api/permission-requests" && method === "POST") return await requestPermission(db, me, body);
      if (path === "/api/permission-requests/mine" && method === "GET") return await myPermissionRequests(db, me);

      if (path === "/api/official-holidays" && method === "GET") {
        return await officialHolidays(db, url.searchParams.get("month"));
      }

      if (path === "/api/report/mine" && method === "GET") {
        const month = url.searchParams.get("month"); // YYYY-MM
        return await monthlyReport(db, me.id, month);
      }

      // ---------- admin only ----------
      if (path.startsWith("/api/admin/")) {
        if (me.role !== "admin") return err("Forbidden", 403);
        return await handleAdmin(db, me, path, method, body, url, env);
      }

      return err("Not found", 404);
    } catch (e) {
      return err("Server error: " + (e && e.message ? e.message : String(e)), 500);
    }
  },
};

// ---------------------------------------------------------------- auth handlers

async function register(db, body) {
  const missing = requireFields(body, ["name", "phone", "password", "title", "dept", "secret_q", "secret_a", "birth_date"]);
  if (missing) return err(`Missing field: ${missing}`);

  const existing = await db.execute({ sql: "SELECT id FROM employees WHERE phone = ?", args: [body.phone] });
  if (existing.rows.length) return err("رقم الموبايل مسجل مسبقا", 409);

  const countRes = await db.execute("SELECT COUNT(*) as c FROM employees");
  const isFirst = Number(countRes.rows[0].c) === 0;
  const empCode = String(Number(countRes.rows[0].c) + 1).padStart(2, "0");

  const passwordHash = await makeSecretHash(body.password);
  const secretAHash = await makeSecretHash(String(body.secret_a).trim().toLowerCase());

  const insert = await db.execute({
    sql: `INSERT INTO employees (emp_code, name, phone, password_hash, title, dept, secret_q, secret_a, birth_date, role, casual_balance, annual_balance)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *`,
    args: [empCode, body.name, body.phone, passwordHash, body.title, body.dept, body.secret_q, secretAHash, body.birth_date,
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

async function updateProfile(db, me, body) {
  if (body.birth_date) {
    await db.execute({ sql: "UPDATE employees SET birth_date = ? WHERE id = ?", args: [body.birth_date, me.id] });
  }
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
    args: [me.id, body.date, body.type, body.reason || body.note || null],
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
    args: [me.id, body.date, body.reason || body.note || null],
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

// ---------------------------------------------------------------- financial requests (مستحقات مالية)

async function requestFinancial(db, me, body) {
  const missing = requireFields(body, ["amount_egp"]);
  if (missing) return err(`Missing field: ${missing}`);
  const amount = Number(body.amount_egp);
  if (!(amount > 0)) return err("المبلغ لازم يكون رقم موجب");

  const res = await db.execute({
    sql: `INSERT INTO financial_requests (employee_id, amount_egp, reason) VALUES (?,?,?) RETURNING *`,
    args: [me.id, amount, body.reason || null],
  });
  return json({ request: res.rows[0] }, 201);
}

async function myFinancialRequests(db, me) {
  const res = await db.execute({
    sql: "SELECT * FROM financial_requests WHERE employee_id = ? ORDER BY requested_at DESC",
    args: [me.id],
  });
  return json({ requests: res.rows });
}

// ---------------------------------------------------------------- off-clock hours (ساعات خارج البصمة)

async function requestOffclock(db, me, body) {
  const missing = requireFields(body, ["date", "hours"]);
  if (missing) return err(`Missing field: ${missing}`);
  const hours = Number(body.hours);
  if (!(hours > 0)) return err("عدد الساعات لازم يكون رقم موجب");

  const res = await db.execute({
    sql: `INSERT INTO offclock_requests (employee_id, date, hours, reason) VALUES (?,?,?,?) RETURNING *`,
    args: [me.id, body.date, hours, body.reason || null],
  });
  return json({ request: res.rows[0] }, 201);
}

async function myOffclockRequests(db, me) {
  const res = await db.execute({
    sql: "SELECT * FROM offclock_requests WHERE employee_id = ? ORDER BY date DESC",
    args: [me.id],
  });
  return json({ requests: res.rows });
}

// ---------------------------------------------------------------- permission / early-leave (إذن انصراف)

const PERMISSION_MONTHLY_HOURS = 2;

async function requestPermission(db, me, body) {
  const missing = requireFields(body, ["date", "hours"]);
  if (missing) return err(`Missing field: ${missing}`);
  const hours = Number(body.hours);
  if (!(hours > 0)) return err("عدد الساعات لازم يكون رقم موجب");
  if (isWeekendStr(body.date)) return err("اليوم ده اجازة اسبوعية");

  const monthPrefix = body.date.slice(0, 7); // YYYY-MM
  const used = await db.execute({
    sql: `SELECT COALESCE(SUM(hours),0) as total FROM permission_requests
          WHERE employee_id = ? AND date LIKE ? AND status IN ('pending','approved')`,
    args: [me.id, monthPrefix + "%"],
  });
  const usedHours = Number(used.rows[0].total) || 0;
  if (usedHours + hours > PERMISSION_MONTHLY_HOURS) {
    return err(`رصيد إذن الانصراف الشهري (${PERMISSION_MONTHLY_HOURS} ساعة) مش كفاية — مستخدم/معلق بالفعل ${usedHours} ساعة`, 409);
  }

  const res = await db.execute({
    sql: `INSERT INTO permission_requests (employee_id, date, hours, reason) VALUES (?,?,?,?) RETURNING *`,
    args: [me.id, body.date, hours, body.reason || null],
  });
  return json({ request: res.rows[0] }, 201);
}

async function myPermissionRequests(db, me) {
  const res = await db.execute({
    sql: "SELECT * FROM permission_requests WHERE employee_id = ? ORDER BY date DESC",
    args: [me.id],
  });
  return json({ requests: res.rows });
}

// ---------------------------------------------------------------- official holidays (read-only for employees)

async function officialHolidays(db, monthStr) {
  const month = (monthStr && /^\d{4}-\d{2}$/.test(monthStr)) ? monthStr : cairoDateStr().slice(0, 7);
  const res = await db.execute({
    sql: "SELECT * FROM official_holidays WHERE date LIKE ? ORDER BY date ASC",
    args: [month + "%"],
  });
  return json({ holidays: res.rows });
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

  const dayHours = Number(emp.daily_work_hours) || 8;
  const daySeconds = dayHours * 3600;

  const firstDay = `${year}-${String(month).padStart(2, "0")}-01`;
  const lastDayNum = daysInMonth(year, month);
  const lastDay = `${year}-${String(month).padStart(2, "0")}-${String(lastDayNum).padStart(2, "0")}`;
  const monthPrefix = `${year}-${String(month).padStart(2, "0")}`;

  const [attRows, leaveRows, otRows, holidayRows, finRows, offRows, permRows, penaltyRows] = await Promise.all([
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
    db.execute({
      sql: "SELECT * FROM official_holidays WHERE date BETWEEN ? AND ?",
      args: [firstDay, lastDay],
    }),
    db.execute({
      sql: "SELECT * FROM financial_requests WHERE employee_id = ? AND status = 'approved' AND requested_at LIKE ?",
      args: [employeeId, monthPrefix + "%"],
    }),
    db.execute({
      sql: "SELECT * FROM offclock_requests WHERE employee_id = ? AND date BETWEEN ? AND ? AND status = 'approved'",
      args: [employeeId, firstDay, lastDay],
    }),
    db.execute({
      sql: "SELECT * FROM permission_requests WHERE employee_id = ? AND date BETWEEN ? AND ? AND status = 'approved'",
      args: [employeeId, firstDay, lastDay],
    }),
    db.execute({
      sql: "SELECT * FROM penalties WHERE employee_id = ? AND date BETWEEN ? AND ?",
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
  const holidayByDate = {};
  for (const r of holidayRows.rows) holidayByDate[r.date] = r;

  const todayStr = cairoDateStr();
  const days = [];
  let totalCountedSeconds = 0;
  let totalActualSeconds = 0;
  let totalOvertimeSeconds = 0;
  let totalHolidayBonusSeconds = 0;  // extra half from doubling worked-holiday hours
  let totalHolidayOffSeconds = 0;    // auto-granted 8h on unworked holidays
  let absentDays = 0;
  let leaveDaysCasual = 0;
  let leaveDaysAnnual = 0;

  function pairAttendance(entries) {
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
    return actualSeconds;
  }

  for (let d = 1; d <= lastDayNum; d++) {
    const dateStr = `${year}-${String(month).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
    if (dateStr > todayStr) break; // don't project future days
    if (isWeekendStr(dateStr)) {
      days.push({ date: dateStr, status: "weekend" });
      continue;
    }

    const holiday = holidayByDate[dateStr];
    if (holiday) {
      const actualSeconds = pairAttendance(attByDate[dateStr] || []);
      if (actualSeconds > 0) {
        const countedSeconds = actualSeconds * 2;
        totalActualSeconds += actualSeconds;
        totalCountedSeconds += countedSeconds;
        totalHolidayBonusSeconds += actualSeconds;
        days.push({
          date: dateStr, status: "official_holiday_worked", holiday_label: holiday.label,
          actual_seconds: actualSeconds, counted_seconds: countedSeconds,
        });
      } else {
        totalCountedSeconds += daySeconds;
        totalHolidayOffSeconds += daySeconds;
        days.push({ date: dateStr, status: "official_holiday_off", holiday_label: holiday.label, counted_seconds: daySeconds });
      }
      continue;
    }

    const leave = leaveByDate[dateStr];
    if (leave) {
      totalCountedSeconds += daySeconds;
      if (leave.type === "casual") leaveDaysCasual++; else leaveDaysAnnual++;
      days.push({ date: dateStr, status: "leave", leave_type: leave.type, counted_seconds: daySeconds });
      continue;
    }

    const entries = attByDate[dateStr] || [];
    if (!entries.length) {
      if (dateStr < todayStr) absentDays++;
      days.push({ date: dateStr, status: dateStr < todayStr ? "absent" : "today_pending", actual_seconds: 0, counted_seconds: 0 });
      continue;
    }

    const actualSeconds = pairAttendance(entries);
    const overtimeApproved = !!otByDate[dateStr];
    let countedSeconds, overtimeSeconds = 0;
    if (overtimeApproved) {
      countedSeconds = actualSeconds;
      overtimeSeconds = Math.max(0, actualSeconds - daySeconds);
    } else {
      countedSeconds = Math.min(actualSeconds, daySeconds);
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

  // ---- extra hour-equivalent components (مستحقات مالية / ساعات خارج بصمة / إذن انصراف) ----
  const rate = hourlyRate(emp);
  const financialTotalEGP = finRows.rows.reduce((s, r) => s + Number(r.amount_egp), 0);
  const financialHours = rate > 0 ? financialTotalEGP / rate : 0;

  const offclockHours = offRows.rows.reduce((s, r) => s + Number(r.hours), 0);

  const permissionUsedHours = permRows.rows.reduce((s, r) => s + Number(r.hours), 0);
  const permissionBonusHours = Math.max(0, PERMISSION_MONTHLY_HOURS - permissionUsedHours);

  const penaltiesTotalEGP = penaltyRows.rows.reduce((s, r) => s + Number(r.amount_egp), 0);

  const extraSeconds = Math.round((financialHours + offclockHours + permissionBonusHours) * 3600);
  totalCountedSeconds += extraSeconds;

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
      holiday_bonus_hours: +(totalHolidayBonusSeconds / 3600).toFixed(2),
      holiday_off_hours: +(totalHolidayOffSeconds / 3600).toFixed(2),
    },
    extras: {
      hourly_rate: +rate.toFixed(2),
      financial_total_egp: +financialTotalEGP.toFixed(2),
      financial_hours: +financialHours.toFixed(2),
      offclock_hours: +offclockHours.toFixed(2),
      permission_monthly_limit: PERMISSION_MONTHLY_HOURS,
      permission_used_hours: +permissionUsedHours.toFixed(2),
      permission_bonus_hours: +permissionBonusHours.toFixed(2),
      penalties_total_egp: +penaltiesTotalEGP.toFixed(2),
    },
    leave_balance: { casual: emp.casual_balance, annual: emp.annual_balance },
  });
}

// ---------------------------------------------------------------- admin

async function handleAdmin(db, admin, path, method, body, url, env) {
  if (path === "/api/admin/employees" && method === "GET") {
    const res = await db.execute("SELECT * FROM employees ORDER BY emp_code ASC");
    return json({ employees: res.rows.map(adminEmployeeView) });
  }

  if (path === "/api/admin/leave-requests" && method === "GET") {
    const status = url.searchParams.get("status") || "pending";
    const orderBy = status === "pending" ? "lr.requested_at ASC" : "lr.decided_at DESC";
    const res = await db.execute({
      sql: `SELECT lr.*, e.name as employee_name, e.emp_code, a.name as decided_by_name FROM leave_requests lr
            JOIN employees e ON e.id = lr.employee_id
            LEFT JOIN employees a ON a.id = lr.decided_by
            WHERE lr.status = ? ORDER BY ${orderBy}`,
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
    const orderBy = status === "pending" ? "ot.requested_at ASC" : "ot.decided_at DESC";
    const res = await db.execute({
      sql: `SELECT ot.*, e.name as employee_name, e.emp_code, a.name as decided_by_name FROM overtime_requests ot
            JOIN employees e ON e.id = ot.employee_id
            LEFT JOIN employees a ON a.id = ot.decided_by
            WHERE ot.status = ? ORDER BY ${orderBy}`,
      args: [status],
    });
    return json({ requests: res.rows });
  }

  const otDecideMatch = path.match(/^\/api\/admin\/overtime-requests\/(\d+)\/decide$/);
  if (otDecideMatch && method === "POST") {
    return await decideOvertime(db, admin, Number(otDecideMatch[1]), body);
  }

  // ---------- unified approved/rejected history across all request types ----------
  if (path === "/api/admin/requests" && method === "GET") {
    return await adminAllRequests(db, url.searchParams.get("status") || "approved");
  }

  // ---------- financial requests ----------
  if (path === "/api/admin/financial-requests" && method === "GET") {
    return await adminListRequests(db, "financial_requests", url.searchParams.get("status") || "pending");
  }
  const finDecideMatch = path.match(/^\/api\/admin\/financial-requests\/(\d+)\/decide$/);
  if (finDecideMatch && method === "POST") {
    return await decideSimple(db, admin, "financial_requests", Number(finDecideMatch[1]), body);
  }

  // ---------- off-clock hour requests ----------
  if (path === "/api/admin/offclock-requests" && method === "GET") {
    return await adminListRequests(db, "offclock_requests", url.searchParams.get("status") || "pending");
  }
  const offDecideMatch = path.match(/^\/api\/admin\/offclock-requests\/(\d+)\/decide$/);
  if (offDecideMatch && method === "POST") {
    return await decideSimple(db, admin, "offclock_requests", Number(offDecideMatch[1]), body);
  }

  // ---------- permission / early-leave requests ----------
  if (path === "/api/admin/permission-requests" && method === "GET") {
    return await adminListRequests(db, "permission_requests", url.searchParams.get("status") || "pending");
  }
  const permDecideMatch = path.match(/^\/api\/admin\/permission-requests\/(\d+)\/decide$/);
  if (permDecideMatch && method === "POST") {
    return await decideSimple(db, admin, "permission_requests", Number(permDecideMatch[1]), body);
  }

  // ---------- official holidays ----------
  if (path === "/api/admin/official-holidays" && method === "GET") {
    return await officialHolidays(db, url.searchParams.get("month"));
  }
  if (path === "/api/admin/official-holidays" && method === "POST") {
    const missing = requireFields(body, ["date"]);
    if (missing) return err(`Missing field: ${missing}`);
    try {
      const res = await db.execute({
        sql: `INSERT INTO official_holidays (date, label, created_by) VALUES (?,?,?) RETURNING *`,
        args: [body.date, body.label || null, admin.id],
      });
      return json({ holiday: res.rows[0] }, 201);
    } catch (e) {
      return err("اليوم ده متسجل كإجازة رسمية بالفعل", 409);
    }
  }
  const holidayDeleteMatch = path.match(/^\/api\/admin\/official-holidays\/(\d+)$/);
  if (holidayDeleteMatch && method === "DELETE") {
    await db.execute({ sql: "DELETE FROM official_holidays WHERE id = ?", args: [Number(holidayDeleteMatch[1])] });
    return json({ ok: true });
  }

  // ---------- per-employee salary config ----------
  const salaryMatch = path.match(/^\/api\/admin\/employees\/(\d+)\/salary$/);
  if (salaryMatch && method === "POST") {
    const empId = Number(salaryMatch[1]);
    const fields = [];
    const args = [];
    if (body.monthly_salary !== undefined) { fields.push("monthly_salary = ?"); args.push(Number(body.monthly_salary) || 0); }
    if (body.work_days_per_month !== undefined) { fields.push("work_days_per_month = ?"); args.push(Number(body.work_days_per_month) || 0); }
    if (body.daily_work_hours !== undefined) { fields.push("daily_work_hours = ?"); args.push(Number(body.daily_work_hours) || 8); }
    if (body.birth_date !== undefined) { fields.push("birth_date = ?"); args.push(body.birth_date || null); }
    if (!fields.length) return err("مفيش بيانات للتحديث");
    args.push(empId);
    await db.execute({ sql: `UPDATE employees SET ${fields.join(", ")} WHERE id = ?`, args });
    const res = await db.execute({ sql: "SELECT * FROM employees WHERE id = ?", args: [empId] });
    return json({ employee: adminEmployeeView(res.rows[0]) });
  }

  // ---------- penalties (جزاءات) ----------
  if (path === "/api/admin/penalties" && method === "POST") {
    const missing = requireFields(body, ["employee_id", "amount_egp", "date"]);
    if (missing) return err(`Missing field: ${missing}`);
    const res = await db.execute({
      sql: `INSERT INTO penalties (employee_id, amount_egp, reason, date, created_by) VALUES (?,?,?,?,?) RETURNING *`,
      args: [body.employee_id, Number(body.amount_egp), body.reason || null, body.date, admin.id],
    });
    return json({ penalty: res.rows[0] }, 201);
  }
  if (path === "/api/admin/penalties" && method === "GET") {
    const employeeId = url.searchParams.get("employee_id");
    const month = url.searchParams.get("month");
    let sql = "SELECT * FROM penalties WHERE 1=1";
    const args = [];
    if (employeeId) { sql += " AND employee_id = ?"; args.push(Number(employeeId)); }
    if (month) { sql += " AND date LIKE ?"; args.push(month + "%"); }
    sql += " ORDER BY date DESC";
    const res = await db.execute({ sql, args });
    return json({ penalties: res.rows });
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
    if (body.role === "employee" && Number(body.employee_id) === admin.id) {
      return err("منقدرش تشيل صلاحية الأدمن بتاعتك انت نفسك", 400);
    }
    await db.execute({ sql: "UPDATE employees SET role = ? WHERE id = ?", args: [body.role, body.employee_id] });
    return json({ ok: true });
  }

  // ---------- full employee info (no PIN — password/answer are hashed and never included) ----------
  const fullInfoMatch = path.match(/^\/api\/admin\/employees\/(\d+)\/full$/);
  if (fullInfoMatch && method === "GET") {
    const res = await db.execute({ sql: "SELECT * FROM employees WHERE id = ?", args: [Number(fullInfoMatch[1])] });
    const emp = res.rows[0];
    if (!emp) return err("Employee not found", 404);
    return json({ employee: { ...adminEmployeeView(emp), created_at: emp.created_at, secret_q: emp.secret_q } });
  }

  function pinOk(body) {
    return !!env.ADMIN_PIN && !!body.pin && String(body.pin) === String(env.ADMIN_PIN);
  }

  // ---------- reset an employee's password (PIN required) ----------
  const resetPwMatch = path.match(/^\/api\/admin\/employees\/(\d+)\/reset-password$/);
  if (resetPwMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    if (!body.new_password) return err("ادخل باسورد جديد");
    const targetId = Number(resetPwMatch[1]);
    const newHash = await makeSecretHash(body.new_password);
    await db.execute({ sql: "UPDATE employees SET password_hash = ? WHERE id = ?", args: [newHash, targetId] });
    await db.execute({ sql: "DELETE FROM sessions WHERE employee_id = ?", args: [targetId] });
    return json({ ok: true });
  }

  // ---------- permanently delete an employee and all their data (PIN required) ----------
  const deleteEmpMatch = path.match(/^\/api\/admin\/employees\/(\d+)\/delete$/);
  if (deleteEmpMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const targetId = Number(deleteEmpMatch[1]);
    if (targetId === admin.id) return err("منقدرش تمسح حسابك انت نفسك", 400);
    const ownedTables = [
      "sessions", "attendance", "breaks", "tasks", "leave_requests", "overtime_requests",
      "financial_requests", "offclock_requests", "permission_requests", "penalties",
    ];
    for (const t of ownedTables) {
      await db.execute({ sql: `DELETE FROM ${t} WHERE employee_id = ?`, args: [targetId] });
    }
    await db.execute({ sql: "DELETE FROM employees WHERE id = ?", args: [targetId] });
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

// Generic list/decide for financial_requests, offclock_requests, permission_requests —
// they all share the same shape (employee_id, status, requested_at, decided_at, decided_by).
const REQUEST_TABLES = new Set(["financial_requests", "offclock_requests", "permission_requests"]);

async function adminListRequests(db, table, status) {
  if (!REQUEST_TABLES.has(table)) return err("invalid table", 400);
  const orderBy = status === "pending" ? "r.requested_at ASC" : "r.decided_at DESC";
  const res = await db.execute({
    sql: `SELECT r.*, e.name as employee_name, e.emp_code, a.name as decided_by_name FROM ${table} r
          JOIN employees e ON e.id = r.employee_id
          LEFT JOIN employees a ON a.id = r.decided_by
          WHERE r.status = ? ORDER BY ${orderBy}`,
    args: [status],
  });
  return json({ requests: res.rows });
}

async function decideSimple(db, admin, table, requestId, body) {
  if (!REQUEST_TABLES.has(table)) return err("invalid table", 400);
  if (!["approve", "reject"].includes(body.action)) return err("action must be approve or reject");
  const res = await db.execute({ sql: `SELECT * FROM ${table} WHERE id = ?`, args: [requestId] });
  const request = res.rows[0];
  if (!request) return err("Request not found", 404);
  if (request.status !== "pending") return err("Request already decided", 409);

  await db.execute({
    sql: `UPDATE ${table} SET status = ?, decided_at = datetime('now'), decided_by = ? WHERE id = ?`,
    args: [body.action === "approve" ? "approved" : "rejected", admin.id, requestId],
  });
  return json({ ok: true });
}

const REQUEST_KIND_META = [
  { table: "leave_requests", kind: "leave", detail: (r) => "Leave (" + (r.type === "casual" ? "Casual / عارضة" : "Annual / اعتيادية") + ")" },
  { table: "overtime_requests", kind: "overtime", detail: () => "Overtime / اوفر تايم" },
  { table: "financial_requests", kind: "financial", detail: (r) => "EGP " + r.amount_egp + " / مستحقات مالية" },
  { table: "offclock_requests", kind: "offclock", detail: (r) => r.hours + "h Off-clock / ساعات خارج البصمة" },
  { table: "permission_requests", kind: "permission", detail: (r) => r.hours + "h Permission / اذن انصراف" },
];

async function adminAllRequests(db, status) {
  const results = [];
  for (const meta of REQUEST_KIND_META) {
    const res = await db.execute({
      sql: `SELECT r.*, e.name as employee_name, e.emp_code, a.name as decided_by_name
            FROM ${meta.table} r
            JOIN employees e ON e.id = r.employee_id
            LEFT JOIN employees a ON a.id = r.decided_by
            WHERE r.status = ?`,
      args: [status],
    });
    for (const row of res.rows) {
      results.push({
        id: row.id,
        kind: meta.kind,
        employee_name: row.employee_name,
        emp_code: row.emp_code,
        date: row.date || (row.requested_at ? row.requested_at.slice(0, 10) : null),
        detail: meta.detail(row),
        reason: row.reason || row.note || null,
        status: row.status,
        requested_at: row.requested_at,
        decided_at: row.decided_at,
        decided_by_name: row.decided_by_name || null,
      });
    }
  }
  results.sort((a, b) => String(b.decided_at || b.requested_at || "").localeCompare(String(a.decided_at || a.requested_at || "")));
  return json({ requests: results });
}
