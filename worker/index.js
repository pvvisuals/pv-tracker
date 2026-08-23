// PV Visual Studio Tracker — Cloudflare Worker API
// Talks to a Turso (libSQL) database. See ../schema.sql for the table layout.
//
// Required secrets (wrangler secret put ...):
//   TURSO_URL          e.g. libsql://your-db-yourorg.turso.io
//   TURSO_AUTH_TOKEN   token from `turso db tokens create <db-name>`

import { createClient } from "@libsql/client/web";

const TZ = "Africa/Cairo";
const WORK_DAY_SECONDS = 8 * 3600;
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
function cairoHourMinute(date = new Date()) {
  const fmt = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, hour: "2-digit", minute: "2-digit", hour12: false });
  const parts = fmt.formatToParts(date);
  const get = (t) => Number(parts.find((p) => p.type === t).value);
  return { hour: get("hour"), minute: get("minute") };
}
// Casual/annual leave quotas are fixed system-wide constants (not per
// employee) — the employees.casual_balance/annual_balance columns now
// track how many days the employee has ALREADY USED, and remaining is
// always computed as quota - used. Sick leave has no quota at all.
const LEAVE_QUOTAS = { casual: 6, annual: 15 };

function leaveBalanceField(type) {
  if (type === "casual") return "casual_balance";
  if (type === "sick") return "sick_balance";
  return "annual_balance";
}
function leaveExtraField(type) {
  if (type === "casual") return "casual_extra_used";
  if (type === "annual") return "annual_extra_used";
  return null; // sick has no quota, no extra field needed
}

function isWeekendStr(dateStr) {
  // dateStr = YYYY-MM-DD, treat as a Cairo calendar date (noon avoids DST edge issues)
  const d = new Date(dateStr + "T12:00:00Z");
  const p = cairoParts(d);
  return p.weekday === "Fri" || p.weekday === "Sat";
}
// Every date from startStr to endStr inclusive that isn't a weekly off day —
// this is what actually gets deducted from a leave balance (weekends inside
// a multi-day leave span don't cost the employee anything, same as any
// other week).
function workingDaysInRange(startStr, endStr) {
  const dates = [];
  let cur = startStr;
  let guard = 0;
  while (cur <= endStr && guard < 400) {
    if (!isWeekendStr(cur)) dates.push(cur);
    cur = addDaysToDateStr(cur, 1);
    guard++;
  }
  return dates;
}
function addDaysToDateStr(dateStr, days) {
  const d = new Date(dateStr + "T12:00:00Z");
  d.setUTCDate(d.getUTCDate() + days);
  return cairoDateStr(d);
}
// Trims and collapses internal whitespace, e.g. "  PV   Tracker " -> "PV Tracker"
function normalizeText(s) {
  return String(s || "").trim().replace(/\s+/g, " ");
}
// The full_name uniqueness key is built from a lowercased name so "PV Tracker"
// and "pv tracker" collide as duplicates, while the displayed `name` column
// keeps whatever casing the admin actually typed.
function buildFullName(code, name, category, type, subCode) {
  return code + "_" + name.toLowerCase() + "_" + category + "_" + type + (subCode ? "_" + subCode : "");
}

// Fixed, auto-assigned letter shown to employees ONLY when a (code,name)
// group has more than one active variant — never admin-editable.
const VARIANT_LABEL_MAP = {
  "COM_NEW": "A",
  "COM_SUB": "B",
  "NON-COM_NEW": "C",
  "NON-COM_SUB": "D",
};
function autoSimpleLabel(category, type) {
  return VARIANT_LABEL_MAP[category + "_" + type] || "?";
}
// Egypt has used a fixed UTC+2 offset (no daylight saving) since 2014, so a
// simple fixed-offset conversion is reliable for deadline scheduling.
function cairoLocalToUtcString(dateStr, hour) {
  const [y, m, d] = dateStr.split("-").map(Number);
  const utcMs = Date.UTC(y, m - 1, d, Number(hour), 0, 0) - 2 * 3600 * 1000;
  return new Date(utcMs).toISOString().slice(0, 19).replace("T", " ");
}
function cairoDeadlineDisplay(deadlineAt) {
  if (!deadlineAt) return null;
  const d = new Date(deadlineAt + "Z");
  return d.toLocaleString("en-US", { timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit", hour: "numeric", minute: "2-digit", hour12: true });
}

// Delivery status for a single task: measured against the task's ORIGINAL
// start time is implicit (the deadline itself doesn't move when set later),
// comparing either the actual completion instant or "now" against the
// stored deadline.
// Counts qualifying (non-weekend, non-holiday, non-approved-leave) calendar
// dates strictly AFTER fromDateStr through toDateStr inclusive. Used so the
// "days remaining/overdue" countdown only counts real working days, the
// same way leave balances already do.
function countWorkingDaysStrictlyAfter(fromDateStr, toDateStr, isNonWorkingFn) {
  if (toDateStr <= fromDateStr) {
    // counting backwards (overdue direction): dates after toDateStr through fromDateStr
    let count = 0;
    let cur = addDaysToDateStr(toDateStr, 1);
    let guard = 0;
    while (cur <= fromDateStr && guard < 400) {
      if (!isNonWorkingFn(cur)) count++;
      cur = addDaysToDateStr(cur, 1);
      guard++;
    }
    return count;
  }
  let count = 0;
  let cur = addDaysToDateStr(fromDateStr, 1);
  let guard = 0;
  while (cur <= toDateStr && guard < 400) {
    if (!isNonWorkingFn(cur)) count++;
    cur = addDaysToDateStr(cur, 1);
    guard++;
  }
  return count;
}

// A "delivery evaluation context" — pre-fetches every official holiday and
// every employee's approved leave covering the relevant span ONCE, then
// hands back a fast isNonWorkingDay(employeeId, dateStr) lookup so we never
// run a query per task.
async function buildDeliveryContext(db, employeeIds, fromDateStr, toDateStr) {
  const [holidayRows, leaveRows] = await Promise.all([
    db.execute({ sql: "SELECT date FROM official_holidays WHERE date BETWEEN ? AND ?", args: [fromDateStr, toDateStr] }),
    employeeIds.length
      ? db.execute({
          sql: `SELECT employee_id, date, end_date FROM leave_requests WHERE status = 'approved'
                AND COALESCE(end_date, date) >= ? AND date <= ? AND employee_id IN (${employeeIds.map(() => "?").join(",")})`,
          args: [fromDateStr, toDateStr, ...employeeIds],
        })
      : Promise.resolve({ rows: [] }),
  ]);
  const holidaySet = new Set(holidayRows.rows.map((r) => r.date));
  const leaveByEmployee = {}; // employeeId -> Set of dateStr
  for (const r of leaveRows.rows) {
    if (!leaveByEmployee[r.employee_id]) leaveByEmployee[r.employee_id] = new Set();
    const end = r.end_date || r.date;
    let cur = r.date;
    let guard = 0;
    while (cur <= end && guard < 400) {
      leaveByEmployee[r.employee_id].add(cur);
      cur = addDaysToDateStr(cur, 1);
      guard++;
    }
  }
  return function isNonWorkingDay(employeeId, dateStr) {
    if (isWeekendStr(dateStr)) return true;
    if (holidaySet.has(dateStr)) return true;
    if (leaveByEmployee[employeeId] && leaveByEmployee[employeeId].has(dateStr)) return true;
    return false;
  };
}

const DELIVERY_BUFFER_SECONDS = 6 * 3600; // ±6h "counts as on-time" window around the deadline

function computeDeliveryStatus(task, actualEndMs, nowMs, isNonWorkingDay) {
  if (!task.deadline_at) return { status: "no_deadline" };
  const deadlineMs = new Date(task.deadline_at + "Z").getTime();
  const deadlineDateStr = task.deadline_at.slice(0, 10);
  const isCompleted = !!task.end_time;
  const deadlineOnNonWorkingDay = isNonWorkingDay(task.employee_id, deadlineDateStr);

  if (isCompleted) {
    if (actualEndMs === null) return { status: "no_deadline" };
    const deltaSeconds = Math.floor((actualEndMs - deadlineMs) / 1000); // negative = early
    let status;
    if (deltaSeconds < -DELIVERY_BUFFER_SECONDS) status = "on_time";
    else if (deltaSeconds > DELIVERY_BUFFER_SECONDS) status = "late";
    else status = "on_time_buffer"; // within the 6h window either side — yellow
    return {
      status, deadline_at: task.deadline_at, deadline_display: cairoDeadlineDisplay(task.deadline_at),
      delta_seconds: deltaSeconds, delay_seconds: Math.max(0, deltaSeconds), deadline_on_non_working_day: deadlineOnNonWorkingDay,
    };
  }

  const todayStr = new Date(nowMs).toISOString().slice(0, 10); // fine at day granularity for this purpose
  if (nowMs <= deadlineMs) {
    const workingDays = countWorkingDaysStrictlyAfter(todayStr, deadlineDateStr, (d) => isNonWorkingDay(task.employee_id, d));
    return {
      status: "in_progress", deadline_at: task.deadline_at, deadline_display: cairoDeadlineDisplay(task.deadline_at),
      remaining_seconds: Math.floor((deadlineMs - nowMs) / 1000), remaining_working_days: workingDays, deadline_on_non_working_day: deadlineOnNonWorkingDay,
    };
  }
  const workingDaysOver = countWorkingDaysStrictlyAfter(todayStr, deadlineDateStr, (d) => isNonWorkingDay(task.employee_id, d));
  return {
    status: "overdue", deadline_at: task.deadline_at, deadline_display: cairoDeadlineDisplay(task.deadline_at),
    overdue_seconds: Math.floor((nowMs - deadlineMs) / 1000), overdue_working_days: workingDaysOver, deadline_on_non_working_day: deadlineOnNonWorkingDay,
  };
}

// Attaches a `delivery` object to every task, using each task's segments
// (already attached) to find the actual completion instant for finished
// tasks. Now async: it pre-fetches holidays/leave once for the whole batch
// so the "days remaining" countdown reflects real working days.
async function attachDeliveryStatus(db, tasks) {
  const nowMs = Date.now();
  const relevantTasks = tasks.filter((t) => t.deadline_at);
  if (!relevantTasks.length) return tasks.map((t) => ({ ...t, delivery: { status: "no_deadline" } }));

  const employeeIds = [...new Set(relevantTasks.map((t) => t.employee_id))];
  let minDate = new Date(nowMs).toISOString().slice(0, 10);
  let maxDate = minDate;
  for (const t of relevantTasks) {
    const dDate = t.deadline_at.slice(0, 10);
    if (dDate < minDate) minDate = dDate;
    if (dDate > maxDate) maxDate = dDate;
  }
  const isNonWorkingDay = await buildDeliveryContext(db, employeeIds, minDate, maxDate);

  return tasks.map((t) => {
    let actualEndMs = null;
    if (t.end_time && t.segments && t.segments.length) {
      const last = t.segments[t.segments.length - 1];
      if (last.ended_at) actualEndMs = new Date(last.ended_at + "Z").getTime();
    }
    return { ...t, delivery: computeDeliveryStatus(t, actualEndMs, nowMs, isNonWorkingDay) };
  });
}

function taskProjectDisplay(proj) {
  return proj.code + " - " + proj.name + (proj.simple_label ? " (" + proj.simple_label + ")" : "");
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

function isBirthdayToday(birthDateStr) {
  if (!birthDateStr) return false;
  const today = cairoParts(new Date());
  const [, bm, bd] = birthDateStr.split("-").map(Number);
  return Number(today.m) === bm && Number(today.d) === bd;
}

function daysUntilBirthday(birthDateStr) {
  if (!birthDateStr) return null;
  const today = cairoParts(new Date());
  const [, bm, bd] = birthDateStr.split("-").map(Number);
  const todayYmd = `${today.y}-${String(today.m).padStart(2,"0")}-${String(today.d).padStart(2,"0")}`;
  let nextYear = Number(today.y);
  let candidate = `${nextYear}-${String(bm).padStart(2,"0")}-${String(bd).padStart(2,"0")}`;
  if (candidate < todayYmd) { nextYear += 1; candidate = `${nextYear}-${String(bm).padStart(2,"0")}-${String(bd).padStart(2,"0")}`; }
  const todayMs = new Date(todayYmd + "T12:00:00Z").getTime();
  const candMs = new Date(candidate + "T12:00:00Z").getTime();
  return Math.round((candMs - todayMs) / 86400000);
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
  const casualSystemUsed = Number(e.casual_balance) || 0;
  const annualSystemUsed = Number(e.annual_balance) || 0;
  const casualExtraUsed = Number(e.casual_extra_used) || 0;
  const annualExtraUsed = Number(e.annual_extra_used) || 0;
  return {
    id: e.id, emp_code: e.emp_code, name: e.name, phone: e.phone,
    title: e.title, dept: e.dept, avatar_url: e.avatar_url, role: e.role,
    // Combined total used (system-tracked + manual pre-system adjustment) —
    // this is what every existing "remaining = quota - used" calculation
    // and display already reads, so it stays accurate everywhere for free.
    casual_balance: casualSystemUsed + casualExtraUsed,
    annual_balance: annualSystemUsed + annualExtraUsed,
    sick_balance: e.sick_balance,
    // Raw breakdown, only for the Salary Settings admin form.
    casual_system_used: casualSystemUsed, annual_system_used: annualSystemUsed,
    casual_extra_used: casualExtraUsed, annual_extra_used: annualExtraUsed,
    birth_date: e.birth_date || null, age: calcAge(e.birth_date),
    is_probation: !!e.is_probation,
    is_birthday_today: isBirthdayToday(e.birth_date),
  };
}

function adminEmployeeView(e) {
  return {
    ...publicEmployee(e),
    monthly_salary: Number(e.monthly_salary) || 0,
    work_days_per_month: Number(e.work_days_per_month) || 0,
    daily_work_hours: Number(e.daily_work_hours) || 8,
    hourly_rate: +hourlyRate(e).toFixed(2),
    is_active: !!e.is_active,
    deactivated_at: e.deactivated_at || null,
    deactivated_by_name: e.deactivated_by_name || null,
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
    if (method === "POST" || method === "PATCH" || method === "DELETE") {
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
      if (path === "/api/breaks/start" && method === "POST") return await startBreak(db, me);
      const breakEndMatch = path.match(/^\/api\/breaks\/(\d+)\/end$/);
      if (breakEndMatch && method === "PATCH") return await endBreak(db, me, Number(breakEndMatch[1]));
      if (path === "/api/breaks/today" && method === "GET") return await breaksToday(db, me);

      if (path === "/api/tasks" && method === "POST") return await addTask(db, me, body);
      if (path === "/api/tasks/today" && method === "GET") return await tasksToday(db, me);
      if (path === "/api/tasks/list" && method === "GET") return await tasksByDate(db, me, url.searchParams.get("date") || cairoDateStr());
      if (path === "/api/tasks/list-by-month" && method === "GET") return await tasksByMonth(db, me, url.searchParams.get("month"));
      if (path === "/api/tasks/active" && method === "GET") return await activeTasks(db, me);
      if (path === "/api/tasks/paused" && method === "GET") return await pausedTasksList(db, me);
      const taskEndMatch = path.match(/^\/api\/tasks\/(\d+)\/end$/);
      if (taskEndMatch && method === "PATCH") return await endTask(db, me, Number(taskEndMatch[1]), body);
      const taskPauseMatch = path.match(/^\/api\/tasks\/(\d+)\/pause$/);
      if (taskPauseMatch && method === "PATCH") return await pauseTask(db, me, Number(taskPauseMatch[1]));
      const taskResumeMatch = path.match(/^\/api\/tasks\/(\d+)\/resume$/);
      if (taskResumeMatch && method === "PATCH") return await resumeTask(db, me, Number(taskResumeMatch[1]));
      const taskLongPauseMatch = path.match(/^\/api\/tasks\/(\d+)\/long-pause$/);
      if (taskLongPauseMatch && method === "PATCH") return await longPauseTask(db, me, Number(taskLongPauseMatch[1]), body);
      const taskDeadlineReqMatch = path.match(/^\/api\/tasks\/(\d+)\/request-deadline-change$/);
      if (taskDeadlineReqMatch && method === "POST") return await requestDeadlineChange(db, me, Number(taskDeadlineReqMatch[1]), body, "manual");
      if (path === "/api/deadline-requests/mine" && method === "GET") return await myDeadlineRequests(db, me, url.searchParams.get("month"));
      const attachUploadMatch = path.match(/^\/api\/requests\/(leave|financial|offclock|permission)\/(\d+)\/attachment$/);
      if (attachUploadMatch && method === "POST") return await uploadRequestAttachment(db, me, attachUploadMatch[1], Number(attachUploadMatch[2]), body);
      const attachListMatch = path.match(/^\/api\/requests\/(leave|financial|offclock|permission)\/(\d+)\/attachments$/);
      if (attachListMatch && method === "GET") return await listMyRequestAttachments(db, me, attachListMatch[1], Number(attachListMatch[2]));
      const attachByIdMatch = path.match(/^\/api\/attachments\/(\d+)$/);
      if (attachByIdMatch && method === "GET") return await getAttachmentById(db, me, Number(attachByIdMatch[1]));
      if (attachByIdMatch && method === "DELETE") return await deleteAttachmentById(db, me, Number(attachByIdMatch[1]));
      const ownReqMatch = path.match(/^\/api\/requests\/(leave|financial|offclock|permission)\/(\d+)$/);
      if (ownReqMatch && method === "PATCH") return await editOwnPendingRequest(db, me, ownReqMatch[1], Number(ownReqMatch[2]), body);
      if (ownReqMatch && method === "DELETE") return await deleteOwnPendingRequest(db, me, ownReqMatch[1], Number(ownReqMatch[2]));
      const taskEditMatch = path.match(/^\/api\/tasks\/(\d+)$/);
      if (taskEditMatch && method === "PATCH") return await editTask(db, me, Number(taskEditMatch[1]), body, env);

      if (path === "/api/projects" && method === "GET") return await listProjects(db);

      if (path === "/api/leave-requests" && method === "POST") return await requestLeave(db, me, body);
      if (path === "/api/leave-requests/mine" && method === "GET") return await myLeaveRequests(db, me, url.searchParams.get("month"));

      if (path === "/api/financial-requests" && method === "POST") return await requestFinancial(db, me, body);
      if (path === "/api/financial-requests/mine" && method === "GET") return await myFinancialRequests(db, me, url.searchParams.get("month"));

      if (path === "/api/offclock-requests" && method === "POST") return await requestOffclock(db, me, body);
      if (path === "/api/offclock-requests/mine" && method === "GET") return await myOffclockRequests(db, me, url.searchParams.get("month"));

      if (path === "/api/permission-requests" && method === "POST") return await requestPermission(db, me, body);
      if (path === "/api/permission-requests/mine" && method === "GET") return await myPermissionRequests(db, me, url.searchParams.get("month"));

      if (path === "/api/official-holidays" && method === "GET") {
        return await officialHolidays(db, url.searchParams.get("month"));
      }
      if (path === "/api/penalties/mine" && method === "GET") return await myPenalties(db, me, url.searchParams.get("month"));
      if (path === "/api/bonuses/mine" && method === "GET") return await myBonuses(db, me, url.searchParams.get("month"));
      if (path === "/api/late-arrivals/mine" && method === "GET") return await myLateArrivals(db, me, url.searchParams.get("month"));
      if (path === "/api/notices/mine" && method === "GET") return await myNotices(db, me, url.searchParams.get("month"));

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
  const missing = requireFields(body, ["emp_code", "name", "phone", "password", "title", "dept", "secret_q", "secret_a", "birth_date"]);
  if (missing) return err(`Missing field: ${missing}`);

  const empCode = String(body.emp_code).trim();
  if (!empCode) return err("لازم تدخل رقم كود موظف");

  const existingPhone = await db.execute({ sql: "SELECT id FROM employees WHERE phone = ?", args: [body.phone] });
  if (existingPhone.rows.length) return err("رقم الموبايل مسجل مسبقا", 409);

  const existingCode = await db.execute({ sql: "SELECT id FROM employees WHERE emp_code = ?", args: [empCode] });
  if (existingCode.rows.length) return err("كود الموظف ده مستخدم بالفعل — اختار كود تاني", 409);

  const countRes = await db.execute("SELECT COUNT(*) as c FROM employees");
  const isFirst = Number(countRes.rows[0].c) === 0;

  const passwordHash = await makeSecretHash(body.password);
  const secretAHash = await makeSecretHash(String(body.secret_a).trim().toLowerCase());

  const insert = await db.execute({
    sql: `INSERT INTO employees (emp_code, name, phone, password_hash, title, dept, secret_q, secret_a, birth_date, role, casual_balance, annual_balance, sick_balance)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *`,
    args: [empCode, body.name, body.phone, passwordHash, body.title, body.dept, body.secret_q, secretAHash, body.birth_date,
           isFirst ? "admin" : "employee", 0, 0, 0],
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
  if (!emp.is_active) return err("الحساب ده متعطل، تواصل مع الإدارة", 403);

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
  const now = new Date();
  const t = now.toLocaleTimeString("en-US", { timeZone: TZ, hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
  const fn = me.name.split(" ")[0];
  const res = await db.execute({
    sql: `INSERT INTO attendance (employee_id, date, action, time, first_name) VALUES (?,?,?,?,?) RETURNING *`,
    args: [me.id, today, "sign_in", t, fn],
  });

  // Late-arrival check: after 11:10 AM Cairo time — log it for admin review
  // (they decide penalize vs excuse; nothing is deducted automatically).
  const { hour, minute } = cairoHourMinute(now);
  const minutesSinceMidnight = hour * 60 + minute;
  let lateArrival = null;
  if (minutesSinceMidnight > 11 * 60 + 10) {
    const existing = await db.execute({
      sql: "SELECT * FROM late_arrivals WHERE employee_id = ? AND date = ?",
      args: [me.id, today],
    });
    if (!existing.rows.length) {
      const laRes = await db.execute({
        sql: `INSERT INTO late_arrivals (employee_id, date, arrival_time) VALUES (?,?,?) RETURNING *`,
        args: [me.id, today, t],
      });
      lateArrival = laRes.rows[0];
    } else {
      lateArrival = existing.rows[0];
    }
  }

  return json({ entry: res.rows[0], late_arrival: lateArrival }, 201);
}

async function signOut(db, me) {
  const todayForCheck = cairoDateStr();
  const [openTaskRes, openBreakRes] = await Promise.all([
    db.execute({ sql: "SELECT name FROM tasks WHERE employee_id = ? AND end_time IS NULL AND paused = 0", args: [me.id] }),
    db.execute({ sql: "SELECT id FROM breaks WHERE employee_id = ? AND date = ? AND end_time IS NULL", args: [me.id, todayForCheck] }),
  ]);
  const openItems = [];
  if (openBreakRes.rows.length) openItems.push("استراحة شغالة");
  for (const t of openTaskRes.rows) openItems.push("تاسك شغال: " + t.name);
  if (openItems.length) {
    return err("لازم تقفل الحاجات دي الأول قبل ما تسجل انصراف: " + openItems.join("، "), 409);
  }

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
  const yesterday = addDaysToDateStr(today, -1);
  const res = await db.execute({
    sql: "SELECT * FROM attendance WHERE employee_id = ? AND date IN (?, ?) ORDER BY created_at ASC",
    args: [me.id, yesterday, today],
  });

  let pendingIn = null;
  for (const r of res.rows) {
    if (r.action === "sign_in") pendingIn = r;
    else if (r.action === "sign_out") pendingIn = null;
  }
  const openFromYesterday = (pendingIn && pendingIn.date !== today) ? pendingIn : null;

  const todayRows = res.rows.filter((r) => r.date === today);
  return json({ entries: todayRows, open_session: openFromYesterday });
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

async function isCurrentlySignedIn(db, employeeId) {
  const today = cairoDateStr();
  const yesterday = addDaysToDateStr(today, -1);
  const res = await db.execute({
    sql: "SELECT * FROM attendance WHERE employee_id = ? AND date IN (?, ?) ORDER BY created_at ASC",
    args: [employeeId, yesterday, today],
  });
  let pendingIn = null;
  for (const r of res.rows) {
    if (r.action === "sign_in") pendingIn = r;
    else if (r.action === "sign_out") pendingIn = null;
  }
  return !!pendingIn;
}

async function startBreak(db, me) {
  if (!(await isCurrentlySignedIn(db, me.id))) {
    return err("لازم تسجل حضور الأول قبل ما تبدأ استراحة", 400);
  }
  const today = cairoDateStr();

  // Guard against duplicate opens (e.g. a retried click after a network
  // hiccup) — if there's already an unfinished break today, just return it
  // instead of creating a second one that would never get closed properly.
  const openRes = await db.execute({
    sql: "SELECT * FROM breaks WHERE employee_id = ? AND date = ? AND end_time IS NULL ORDER BY created_at DESC LIMIT 1",
    args: [me.id, today],
  });
  if (openRes.rows.length) {
    return json({ entry: openRes.rows[0] }, 200);
  }

  const t = new Date().toLocaleTimeString("en-US", { timeZone: TZ, hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
  const fn = me.name.split(" ")[0];
  const res = await db.execute({
    sql: `INSERT INTO breaks (employee_id, date, start_time, first_name) VALUES (?,?,?,?) RETURNING *`,
    args: [me.id, today, t, fn],
  });
  return json({ entry: res.rows[0] }, 201);
}

async function endBreak(db, me, breakId) {
  const rows = await db.execute({ sql: "SELECT * FROM breaks WHERE id = ? AND employee_id = ?", args: [breakId, me.id] });
  const brk = rows.rows[0];
  if (!brk) return err("Break not found", 404);
  if (brk.end_time) return err("Break already ended", 409);
  const t = new Date().toLocaleTimeString("en-US", { timeZone: TZ, hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
  const dur = Math.max(0, Math.floor((Date.now() - new Date(brk.created_at + "Z").getTime()) / 1000));
  await db.execute({ sql: "UPDATE breaks SET end_time = ?, duration = ? WHERE id = ?", args: [t, dur, breakId] });
  return json({ ok: true, entry: { ...brk, end_time: t, duration: dur } });
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
  const missing = requireFields(body, ["project_id", "name"]);
  if (missing) return err(`Missing field: ${missing}`);
  const projRes = await db.execute({ sql: "SELECT * FROM projects WHERE id = ? AND active = 1", args: [body.project_id] });
  const proj = projRes.rows[0];
  if (!proj) return err("المشروع ده مش موجود أو مش متاح حالياً", 400);

  const today = cairoDateStr();
  const t = new Date().toLocaleTimeString("en-US", { timeZone: TZ, hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
  const fn = me.name.split(" ")[0];
  const displayName = taskProjectDisplay(proj);
  const res = await db.execute({
    sql: `INSERT INTO tasks (employee_id, project, project_id, name, description, date, time, start_time, first_name)
          VALUES (?,?,?,?,?,?,?,?,?) RETURNING *`,
    args: [me.id, displayName, proj.id, body.name, body.description || "", today, t, t, fn],
  });
  const task = res.rows[0];
  await db.execute({
    sql: `INSERT INTO task_segments (task_id, employee_id, date, start_display) VALUES (?,?,?,?)`,
    args: [task.id, me.id, today, t],
  });
  return json({ task }, 201);
}

async function editTask(db, me, taskId, body, env) {
  if (!pinOkShared(env, body)) return err("كود الأمان غلط", 403);
  const rows = await db.execute({ sql: "SELECT * FROM tasks WHERE id = ?", args: [taskId] });
  const task = rows.rows[0];
  if (!task) return err("Task not found", 404);
  if (task.employee_id !== me.id && me.role !== "admin") return err("Forbidden", 403);

  const fields = [];
  const args = [];
  if (body.name !== undefined) { fields.push("name = ?"); args.push(body.name); }
  if (body.description !== undefined) { fields.push("description = ?"); args.push(body.description); }
  if (body.project_id !== undefined) {
    const projRes = await db.execute({ sql: "SELECT * FROM projects WHERE id = ?", args: [body.project_id] });
    const proj = projRes.rows[0];
    if (!proj) return err("المشروع ده مش موجود", 400);
    fields.push("project_id = ?"); args.push(proj.id);
    fields.push("project = ?"); args.push(taskProjectDisplay(proj));
  }
  if (!fields.length) return err("مفيش حاجة للتعديل");
  args.push(taskId);
  await db.execute({ sql: `UPDATE tasks SET ${fields.join(", ")} WHERE id = ?`, args });
  const updated = await db.execute({ sql: "SELECT * FROM tasks WHERE id = ?", args: [taskId] });
  return json({ task: (await attachDeliveryStatus(db, await attachSegments(db, updated.rows)))[0] });
}

async function pauseTask(db, me, taskId) {
  const rows = await db.execute({ sql: "SELECT * FROM tasks WHERE id = ? AND employee_id = ?", args: [taskId, me.id] });
  const task = rows.rows[0];
  if (!task) return err("Task not found", 404);
  if (task.end_time) return err("التاسك ده خلص بالفعل", 400);
  if (task.paused) return err("التاسك ده متوقف بالفعل", 400);

  const t = new Date().toLocaleTimeString("en-US", { timeZone: TZ, hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
  const segRes = await db.execute({ sql: "SELECT * FROM task_segments WHERE task_id = ? AND ended_at IS NULL ORDER BY id DESC LIMIT 1", args: [taskId] });
  if (segRes.rows[0]) {
    await db.execute({ sql: "UPDATE task_segments SET end_display = ?, ended_at = datetime('now') WHERE id = ?", args: [t, segRes.rows[0].id] });
  }
  await db.execute({ sql: "UPDATE tasks SET paused = 1 WHERE id = ?", args: [taskId] });
  const updated = await db.execute({ sql: "SELECT * FROM tasks WHERE id = ?", args: [taskId] });
  return json({ task: (await attachDeliveryStatus(db, await attachSegments(db, updated.rows)))[0] });
}

// "Long pause" — same effect as a regular pause, plus it automatically
// files a deadline-change request (since a long pause usually means the
// current deadline won't be met and needs the admin's attention).
async function longPauseTask(db, me, taskId, body) {
  const pauseResult = await pauseTask(db, me, taskId);
  if (pauseResult.status && pauseResult.status !== 200 && pauseResult.status !== 201) return pauseResult;
  await requestDeadlineChange(db, me, taskId, body, "long_pause");
  return pauseResult;
}

// Files (or re-files) a deadline-change request for a task — stays pending
// until the admin sets a new deadline (approve) or declines it.
async function requestDeadlineChange(db, me, taskId, body, source) {
  const rows = await db.execute({ sql: "SELECT * FROM tasks WHERE id = ? AND employee_id = ?", args: [taskId, me.id] });
  const task = rows.rows[0];
  if (!task) return err("Task not found", 404);
  const existing = await db.execute({
    sql: "SELECT * FROM task_deadline_requests WHERE task_id = ? AND status = 'pending'",
    args: [taskId],
  });
  if (existing.rows.length) return err("فيه طلب تغيير معاد لسه معلق للتاسك ده بالفعل", 409);
  const res = await db.execute({
    sql: `INSERT INTO task_deadline_requests (task_id, employee_id, reason, source) VALUES (?,?,?,?) RETURNING *`,
    args: [taskId, me.id, (body && body.reason) || (source === "long_pause" ? "وقوف طويل — محتاج تأجيل المعاد" : null), source],
  });
  return json({ request: res.rows[0] }, 201);
}

async function myDeadlineRequests(db, me, monthStr) {
  const res = await db.execute({
    sql: `SELECT tdr.*, t.name as task_name, t.project as project_display FROM task_deadline_requests tdr
          JOIN tasks t ON t.id = tdr.task_id
          WHERE tdr.employee_id = ? AND tdr.requested_at LIKE ? ORDER BY tdr.requested_at DESC`,
    args: [me.id, monthLikePattern(monthStr)],
  });
  return json({ requests: res.rows });
}

const REQUEST_ATTACHMENT_TABLE = { leave: "leave_requests", financial: "financial_requests", offclock: "offclock_requests", permission: "permission_requests" };

// Employee can edit or delete their OWN request — but only while it's still
// 'pending' (untouched by admin). Works uniformly for any request type, so
// a future request type gets this for free by adding one line to the map.
async function deleteOwnPendingRequest(db, me, reqType, reqId) {
  const table = REQUEST_ATTACHMENT_TABLE[reqType];
  if (!table) return err("Invalid request type", 400);
  const cur = await db.execute({ sql: `SELECT * FROM ${table} WHERE id = ? AND employee_id = ?`, args: [reqId, me.id] });
  if (!cur.rows[0]) return err("Request not found", 404);
  if (cur.rows[0].status !== "pending") return err("الطلب ده اتقرر فيه بالفعل، مينفعش تحذفه", 409);
  await db.execute({ sql: "DELETE FROM request_attachments WHERE request_type = ? AND request_id = ?", args: [reqType, reqId] });
  await db.execute({ sql: `DELETE FROM ${table} WHERE id = ?`, args: [reqId] });
  return json({ ok: true });
}

async function editOwnPendingRequest(db, me, reqType, reqId, body) {
  const table = REQUEST_ATTACHMENT_TABLE[reqType];
  if (!table) return err("Invalid request type", 400);
  const cur = await db.execute({ sql: `SELECT * FROM ${table} WHERE id = ? AND employee_id = ?`, args: [reqId, me.id] });
  const existing = cur.rows[0];
  if (!existing) return err("Request not found", 404);
  if (existing.status !== "pending") return err("الطلب ده اتقرر فيه بالفعل، مينفعش تعدله", 409);

  if (reqType === "leave") {
    const type = body.type || existing.type;
    if (!["casual", "annual", "sick"].includes(type)) return err("type must be casual, annual, or sick");
    const date = body.date || existing.date;
    const endDate = body.end_date || (body.date ? date : existing.end_date) || date;
    if (endDate < date) return err("تاريخ النهاية لازم يكون بعد أو يساوي تاريخ البداية");
    const workingDays = workingDaysInRange(date, endDate);
    if (!workingDays.length) return err("الفترة دي كلها جمعة/سبت — مفيش يوم عمل فعلي فيها");
    const overlap = await db.execute({
      sql: `SELECT * FROM leave_requests WHERE employee_id = ? AND id != ? AND status != 'rejected'
            AND date <= ? AND COALESCE(end_date, date) >= ?`,
      args: [me.id, reqId, endDate, date],
    });
    if (overlap.rows.length) return err("فيه طلب إجازة بيتداخل مع الفترة دي بالفعل", 409);
    await db.execute({
      sql: "UPDATE leave_requests SET date = ?, end_date = ?, type = ?, reason = ? WHERE id = ?",
      args: [date, endDate === date ? null : endDate, type, body.reason !== undefined ? body.reason : existing.reason, reqId],
    });
  } else if (reqType === "financial") {
    const amount = body.amount_egp !== undefined ? Number(body.amount_egp) : Number(existing.amount_egp);
    if (!(amount > 0)) return err("المبلغ لازم يكون رقم موجب");
    await db.execute({
      sql: "UPDATE financial_requests SET amount_egp = ?, reason = ? WHERE id = ?",
      args: [amount, body.reason !== undefined ? body.reason : existing.reason, reqId],
    });
  } else if (reqType === "offclock" || reqType === "permission") {
    const date = body.date || existing.date;
    const hours = body.hours !== undefined ? Number(body.hours) : Number(existing.hours);
    if (!(hours > 0)) return err("عدد الساعات لازم يكون رقم موجب");
    await db.execute({
      sql: `UPDATE ${table} SET date = ?, hours = ?, reason = ? WHERE id = ?`,
      args: [date, hours, body.reason !== undefined ? body.reason : existing.reason, reqId],
    });
  }
  const updated = await db.execute({ sql: `SELECT * FROM ${table} WHERE id = ?`, args: [reqId] });
  return json({ request: updated.rows[0] });
}
const MAX_ATTACHMENT_BASE64_CHARS = 4 * 1024 * 1024; // ~3MB actual file size

// Employee attaches a file to their OWN request — works uniformly for any
// request type via the shared request_attachments table, so any future
// request type gets attachment support for free.
const MAX_ATTACHMENTS_PER_REQUEST = 6;

async function uploadRequestAttachment(db, me, reqType, reqId, body) {
  const table = REQUEST_ATTACHMENT_TABLE[reqType];
  const missing = requireFields(body, ["filename", "mimetype", "data_base64"]);
  if (missing) return err(`Missing field: ${missing}`);
  if (body.data_base64.length > MAX_ATTACHMENT_BASE64_CHARS) return err("الملف كبير جداً — الحد الأقصى تقريباً 3 ميجا", 413);
  const own = await db.execute({ sql: `SELECT id FROM ${table} WHERE id = ? AND employee_id = ?`, args: [reqId, me.id] });
  if (!own.rows[0]) return err("Request not found", 404);
  const countRes = await db.execute({ sql: "SELECT COUNT(*) as c FROM request_attachments WHERE request_type = ? AND request_id = ?", args: [reqType, reqId] });
  if (Number(countRes.rows[0].c) >= MAX_ATTACHMENTS_PER_REQUEST) return err(`أقصى عدد مرفقات للطلب الواحد ${MAX_ATTACHMENTS_PER_REQUEST}`, 409);
  const res = await db.execute({
    sql: `INSERT INTO request_attachments (request_type, request_id, filename, mimetype, data_base64, uploaded_by) VALUES (?,?,?,?,?,?) RETURNING id, filename, mimetype, uploaded_at`,
    args: [reqType, reqId, body.filename, body.mimetype, body.data_base64, me.id],
  });
  return json({ attachment: res.rows[0] }, 201);
}

async function listMyRequestAttachments(db, me, reqType, reqId) {
  const table = REQUEST_ATTACHMENT_TABLE[reqType];
  const own = await db.execute({ sql: `SELECT id FROM ${table} WHERE id = ? AND employee_id = ?`, args: [reqId, me.id] });
  if (!own.rows[0]) return err("Request not found", 404);
  const res = await db.execute({ sql: "SELECT id, filename, mimetype, uploaded_at FROM request_attachments WHERE request_type = ? AND request_id = ? ORDER BY id ASC", args: [reqType, reqId] });
  return json({ attachments: res.rows });
}

async function listAdminRequestAttachments(db, reqType, reqId) {
  const res = await db.execute({ sql: "SELECT id, filename, mimetype, uploaded_at FROM request_attachments WHERE request_type = ? AND request_id = ? ORDER BY id ASC", args: [reqType, reqId] });
  return json({ attachments: res.rows });
}

// Fetching/deleting one specific attachment by its own id — works whether
// the request has one attachment or several.
async function getAttachmentById(db, me, attId) {
  const res = await db.execute({ sql: "SELECT * FROM request_attachments WHERE id = ?", args: [attId] });
  const att = res.rows[0];
  if (!att) return err("مفيش مرفق بالرقم ده", 404);
  if (me.role !== "admin") {
    const table = REQUEST_ATTACHMENT_TABLE[att.request_type];
    const own = await db.execute({ sql: `SELECT id FROM ${table} WHERE id = ? AND employee_id = ?`, args: [att.request_id, me.id] });
    if (!own.rows[0]) return err("Not authorized", 403);
  }
  return json({ attachment: att });
}

async function deleteAttachmentById(db, me, attId) {
  const res = await db.execute({ sql: "SELECT * FROM request_attachments WHERE id = ?", args: [attId] });
  const att = res.rows[0];
  if (!att) return err("مفيش مرفق بالرقم ده", 404);
  const table = REQUEST_ATTACHMENT_TABLE[att.request_type];
  const own = await db.execute({ sql: `SELECT * FROM ${table} WHERE id = ? AND employee_id = ?`, args: [att.request_id, me.id] });
  if (!own.rows[0]) return err("Not authorized", 403);
  if (own.rows[0].status !== "pending") return err("الطلب ده اتقرر فيه بالفعل، مينفعش تعدل مرفقاته", 409);
  await db.execute({ sql: "DELETE FROM request_attachments WHERE id = ?", args: [attId] });
  return json({ ok: true });
}

async function resumeTask(db, me, taskId) {
  const rows = await db.execute({ sql: "SELECT * FROM tasks WHERE id = ? AND employee_id = ?", args: [taskId, me.id] });
  const task = rows.rows[0];
  if (!task) return err("Task not found", 404);
  if (task.end_time) return err("التاسك ده خلص بالفعل", 400);
  if (!task.paused) return err("التاسك ده مش متوقف", 400);

  const today = cairoDateStr();
  const t = new Date().toLocaleTimeString("en-US", { timeZone: TZ, hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
  await db.execute({
    sql: `INSERT INTO task_segments (task_id, employee_id, date, start_display) VALUES (?,?,?,?)`,
    args: [taskId, me.id, today, t],
  });
  await db.execute({ sql: "UPDATE tasks SET paused = 0 WHERE id = ?", args: [taskId] });
  const updated = await db.execute({ sql: "SELECT * FROM tasks WHERE id = ?", args: [taskId] });
  return json({ task: (await attachDeliveryStatus(db, await attachSegments(db, updated.rows)))[0] });
}

async function endTask(db, me, taskId, body) {
  const rows = await db.execute({ sql: "SELECT * FROM tasks WHERE id = ? AND employee_id = ?", args: [taskId, me.id] });
  const task = rows.rows[0];
  if (!task) return err("Task not found", 404);
  const t = new Date().toLocaleTimeString("en-US", { timeZone: TZ, hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });

  const openSegRes = await db.execute({ sql: "SELECT * FROM task_segments WHERE task_id = ? AND ended_at IS NULL ORDER BY id DESC LIMIT 1", args: [taskId] });
  if (openSegRes.rows[0]) {
    await db.execute({ sql: "UPDATE task_segments SET end_display = ?, ended_at = datetime('now') WHERE id = ?", args: [t, openSegRes.rows[0].id] });
  }

  // Total duration = sum of every segment's actual elapsed time (pauses
  // don't count), not just "now minus original start".
  const allSegs = await db.execute({ sql: "SELECT * FROM task_segments WHERE task_id = ?", args: [taskId] });
  let totalSecs = 0;
  for (const s of allSegs.rows) {
    const startMs = new Date(s.created_at + "Z").getTime();
    const endMs = s.ended_at ? new Date(s.ended_at + "Z").getTime() : Date.now();
    if (endMs > startMs) totalSecs += Math.floor((endMs - startMs) / 1000);
  }

  await db.execute({ sql: "UPDATE tasks SET end_time = ?, duration = ?, paused = 0 WHERE id = ?", args: [t, totalSecs, taskId] });
  return json({ ok: true, end_time: t, duration: totalSecs });
}

// Batches segment history (start/pause/resume/end timestamps) onto a list
// of task rows, so the UI can show the full multi-day timeline.
async function attachSegments(db, tasks) {
  if (!tasks.length) return tasks;
  const ids = tasks.map((t) => t.id);
  const placeholders = ids.map(() => "?").join(",");
  const segRes = await db.execute({ sql: `SELECT * FROM task_segments WHERE task_id IN (${placeholders}) ORDER BY id ASC`, args: ids });
  const byTask = {};
  for (const s of segRes.rows) { (byTask[s.task_id] = byTask[s.task_id] || []).push(s); }
  return tasks.map((t) => ({ ...t, segments: byTask[t.id] || [] }));
}

async function tasksToday(db, me) {
  const today = cairoDateStr();
  const res = await db.execute({
    sql: "SELECT * FROM tasks WHERE employee_id = ? AND date = ? ORDER BY created_at ASC",
    args: [me.id, today],
  });
  return json({ tasks: await attachDeliveryStatus(db, await attachSegments(db, res.rows)) });
}

async function tasksByDate(db, me, dateStr) {
  const res = await db.execute({
    sql: "SELECT * FROM tasks WHERE employee_id = ? AND date = ? ORDER BY created_at ASC",
    args: [me.id, dateStr],
  });
  return json({ tasks: await attachDeliveryStatus(db, await attachSegments(db, res.rows)) });
}

async function tasksByMonth(db, me, monthStr) {
  const isAll = monthStr === "all";
  let sql = "SELECT * FROM tasks WHERE employee_id = ?";
  const args = [me.id];
  if (!isAll) { sql += " AND date LIKE ?"; args.push(monthLikePattern(monthStr)); }
  sql += " ORDER BY created_at ASC";
  const res = await db.execute({ sql, args });
  return json({ tasks: await attachDeliveryStatus(db, await attachSegments(db, res.rows)) });
}

// Currently-being-worked tasks (not paused, not ended) — shown regardless
// of which day they started, so a multi-day task never disappears.
async function activeTasks(db, me) {
  const res = await db.execute({
    sql: "SELECT * FROM tasks WHERE employee_id = ? AND end_time IS NULL AND paused = 0 ORDER BY created_at ASC",
    args: [me.id],
  });
  return json({ tasks: await attachDeliveryStatus(db, await attachSegments(db, res.rows)) });
}

// Paused tasks — set aside, not finished, shown regardless of day so the
// employee can resume any of them whenever they get back to it.
async function pausedTasksList(db, me) {
  const res = await db.execute({
    sql: "SELECT * FROM tasks WHERE employee_id = ? AND end_time IS NULL AND paused = 1 ORDER BY created_at ASC",
    args: [me.id],
  });
  return json({ tasks: await attachDeliveryStatus(db, await attachSegments(db, res.rows)) });
}

// Employee-facing project catalog — deduplicated by (code, name); if a group
// has more than one ACTIVE variant, the frontend must show the friendly
// simple_label picker so the exact variant is unambiguous. Single-variant
// groups resolve automatically with no extra step.
async function listProjects(db) {
  const res = await db.execute("SELECT * FROM projects WHERE active = 1 ORDER BY code ASC, name COLLATE NOCASE ASC");
  const groups = {};
  for (const r of res.rows) {
    const key = r.code + "||" + r.name.trim().toLowerCase();
    if (!groups[key]) groups[key] = { code: r.code, name: r.name, variants: [] };
    groups[key].variants.push({ id: r.id, simple_label: r.simple_label });
  }
  return json({ projects: Object.values(groups) });
}

// ---------------------------------------------------------------- leave requests

async function requestLeave(db, me, body) {
  if (me.is_probation) return err("لسه في فترة الاختبار — الإجازات مش متاحة حالياً", 403);
  const missing = requireFields(body, ["date", "type"]);
  if (missing) return err(`Missing field: ${missing}`);
  if (!["casual", "annual", "sick"].includes(body.type)) return err("type must be casual, annual, or sick");

  const endDate = body.end_date || body.date;
  if (endDate < body.date) return err("تاريخ النهاية لازم يكون بعد أو يساوي تاريخ البداية");
  const workingDays = workingDaysInRange(body.date, endDate);
  if (!workingDays.length) return err("الفترة دي كلها جمعة/سبت — مفيش يوم عمل فعلي فيها");

  // No overlap with any existing (pending/approved) request across the
  // WHOLE span, not just the exact start date.
  const existing = await db.execute({
    sql: `SELECT * FROM leave_requests WHERE employee_id = ? AND status != 'rejected'
          AND date <= ? AND COALESCE(end_date, date) >= ?`,
    args: [me.id, endDate, body.date],
  });
  if (existing.rows.length) return err("فيه طلب إجازة بيتداخل مع الفترة دي بالفعل", 409);

  const res = await db.execute({
    sql: `INSERT INTO leave_requests (employee_id, date, end_date, type, note) VALUES (?,?,?,?,?) RETURNING *`,
    args: [me.id, body.date, body.end_date || null, body.type, body.reason || body.note || null],
  });
  return json({ request: res.rows[0], working_days: workingDays.length }, 201);
}

async function myLeaveRequests(db, me, monthStr) {
  const month = monthLikePattern(monthStr);
  const res = await db.execute({
    sql: "SELECT *, (SELECT COUNT(*) FROM request_attachments ra WHERE ra.request_type='leave' AND ra.request_id=leave_requests.id) as has_attachment FROM leave_requests WHERE employee_id = ? AND date LIKE ? ORDER BY date DESC",
    args: [me.id, month],
  });
  return json({
    requests: res.rows,
    balance: { casual: me.casual_balance, annual: me.annual_balance, sick: me.sick_balance },
  });
}

// ---------------------------------------------------------------- overtime requests

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

async function myFinancialRequests(db, me, monthStr) {
  const month = monthLikePattern(monthStr);
  const res = await db.execute({
    sql: "SELECT *, (SELECT COUNT(*) FROM request_attachments ra WHERE ra.request_type='financial' AND ra.request_id=financial_requests.id) as has_attachment FROM financial_requests WHERE employee_id = ? AND requested_at LIKE ? ORDER BY requested_at DESC",
    args: [me.id, month],
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

async function myOffclockRequests(db, me, monthStr) {
  const month = monthLikePattern(monthStr);
  const res = await db.execute({
    sql: "SELECT *, (SELECT COUNT(*) FROM request_attachments ra WHERE ra.request_type='offclock' AND ra.request_id=offclock_requests.id) as has_attachment FROM offclock_requests WHERE employee_id = ? AND date LIKE ? ORDER BY date DESC",
    args: [me.id, month],
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

async function myPermissionRequests(db, me, monthStr) {
  const month = monthLikePattern(monthStr);
  const res = await db.execute({
    sql: "SELECT *, (SELECT COUNT(*) FROM request_attachments ra WHERE ra.request_type='permission' AND ra.request_id=permission_requests.id) as has_attachment FROM permission_requests WHERE employee_id = ? AND date LIKE ? ORDER BY date DESC",
    args: [me.id, month],
  });
  return json({ requests: res.rows });
}

// ---------------------------------------------------------------- official holidays (read-only for employees)

// Every "month filter" list/report in the system accepts monthStr === "all"
// to mean "don't filter by month at all" — this builds the matching LIKE
// pattern (or a default of the current month when nothing valid was given).
function monthLikePattern(monthStr) {
  if (monthStr === "all") return "%";
  const month = (monthStr && /^\d{4}-\d{2}$/.test(monthStr)) ? monthStr : cairoDateStr().slice(0, 7);
  return month + "%";
}

async function officialHolidays(db, monthStr) {
  const res = await db.execute({
    sql: "SELECT * FROM official_holidays WHERE date LIKE ? ORDER BY date ASC",
    args: [monthLikePattern(monthStr)],
  });
  return json({ holidays: res.rows });
}

async function myPenalties(db, me, monthStr) {
  const month = monthLikePattern(monthStr);
  const res = await db.execute({
    sql: `SELECT p.*, a.name as deleted_by_name FROM penalties p
          LEFT JOIN employees a ON a.id = p.deleted_by
          WHERE p.employee_id = ? AND p.date LIKE ? ORDER BY p.date DESC`,
    args: [me.id, month],
  });
  return json({ penalties: res.rows });
}

async function myNotices(db, me, monthStr) {
  const month = monthLikePattern(monthStr);
  const res = await db.execute({
    sql: `SELECT n.*, a.name as deleted_by_name FROM notices n
          LEFT JOIN employees a ON a.id = n.deleted_by
          WHERE n.employee_id = ? AND n.date LIKE ? ORDER BY n.date DESC`,
    args: [me.id, month],
  });
  return json({ notices: res.rows });
}

async function myLateArrivals(db, me, monthStr) {
  const month = monthLikePattern(monthStr);
  const res = await db.execute({
    sql: "SELECT * FROM late_arrivals WHERE employee_id = ? AND date LIKE ? ORDER BY date DESC",
    args: [me.id, month],
  });
  return json({ late_arrivals: res.rows });
}

async function myBonuses(db, me, monthStr) {
  const month = monthLikePattern(monthStr);
  const res = await db.execute({
    sql: `SELECT b.*, a.name as deleted_by_name FROM bonuses b
          LEFT JOIN employees a ON a.id = b.deleted_by
          WHERE b.employee_id = ? AND b.date LIKE ? ORDER BY b.date DESC`,
    args: [me.id, month],
  });
  const rate = hourlyRate(me);
  const bonuses = res.rows.map((b) => ({ ...b, hours_equivalent: rate > 0 ? +(Number(b.amount_egp) / rate).toFixed(2) : 0 }));
  return json({ bonuses });
}

// ---------------------------------------------------------------- monthly report (core hours logic)

async function monthlyReport(db, employeeId, monthStr) {
  const isAllMonths = monthStr === "all";
  const now = new Date();
  let year, month;
  if (!isAllMonths) {
    if (monthStr && /^\d{4}-\d{2}$/.test(monthStr)) {
      [year, month] = monthStr.split("-").map(Number);
    } else {
      const p = cairoParts(now);
      year = Number(p.y); month = Number(p.m);
    }
  }

  const empRes = await db.execute({ sql: "SELECT * FROM employees WHERE id = ?", args: [employeeId] });
  const emp = empRes.rows[0];
  if (!emp) return err("Employee not found", 404);

  const dayHours = Number(emp.daily_work_hours) || 8;
  const daySeconds = dayHours * 3600;

  let firstDay, lastDay, monthPrefix;
  if (isAllMonths) {
    // Full history: from the day the employee was registered through today.
    firstDay = (emp.created_at || cairoDateStr()).slice(0, 10);
    lastDay = cairoDateStr();
    monthPrefix = null; // no single-month prefix makes sense in "all" mode
  } else {
    firstDay = `${year}-${String(month).padStart(2, "0")}-01`;
    const lastDayNum = daysInMonth(year, month);
    lastDay = `${year}-${String(month).padStart(2, "0")}-${String(lastDayNum).padStart(2, "0")}`;
    monthPrefix = `${year}-${String(month).padStart(2, "0")}`;
  }

  const [attRows, leaveRows, otRows, holidayRows, finRows, offRows, permRows, penaltyRows, projectRows, breakRows, bonusRows, lateRows, deadlineTaskRows, dayTaskRows] = await Promise.all([
    db.execute({
      sql: "SELECT * FROM attendance WHERE employee_id = ? AND date BETWEEN ? AND ? ORDER BY created_at ASC",
      args: [employeeId, firstDay, addDaysToDateStr(lastDay, 1)],
    }),
    db.execute({
      sql: "SELECT * FROM leave_requests WHERE employee_id = ? AND COALESCE(end_date, date) >= ? AND date <= ? AND status = 'approved'",
      args: [employeeId, firstDay, lastDay],
    }),
    db.execute({
      sql: `SELECT DISTINCT ts.date FROM task_segments ts
            JOIN tasks t ON t.id = ts.task_id
            JOIN projects p ON p.id = t.project_id
            WHERE t.employee_id = ? AND ts.date BETWEEN ? AND ? AND p.overtime_enabled = 1`,
      args: [employeeId, firstDay, lastDay],
    }),
    db.execute({
      sql: "SELECT * FROM official_holidays WHERE date BETWEEN ? AND ?",
      args: [firstDay, lastDay],
    }),
    db.execute({
      sql: "SELECT * FROM financial_requests WHERE employee_id = ? AND status = 'approved' AND requested_at LIKE ?",
      args: [employeeId, isAllMonths ? "%" : monthPrefix + "%"],
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
      sql: "SELECT * FROM penalties WHERE employee_id = ? AND date BETWEEN ? AND ? AND deleted_at IS NULL",
      args: [employeeId, firstDay, lastDay],
    }),
    db.execute({
      sql: `SELECT p.code, p.name, p.category, p.type, p.sub_code, p.simple_label,
                   SUM(COALESCE(t.duration,0)) as total_seconds, COUNT(*) as task_count
            FROM tasks t JOIN projects p ON p.id = t.project_id
            WHERE t.employee_id = ? AND t.date BETWEEN ? AND ?
            GROUP BY p.code, p.name, p.category, p.type, p.sub_code ORDER BY total_seconds DESC`,
      args: [employeeId, firstDay, lastDay],
    }),
    db.execute({
      sql: "SELECT * FROM breaks WHERE employee_id = ? AND date BETWEEN ? AND ?",
      args: [employeeId, firstDay, lastDay],
    }),
    db.execute({
      sql: "SELECT * FROM bonuses WHERE employee_id = ? AND date BETWEEN ? AND ? AND deleted_at IS NULL",
      args: [employeeId, firstDay, lastDay],
    }),
    db.execute({
      sql: "SELECT * FROM late_arrivals WHERE employee_id = ? AND date BETWEEN ? AND ?",
      args: [employeeId, firstDay, lastDay],
    }),
    db.execute({
      sql: "SELECT * FROM tasks WHERE employee_id = ? AND date BETWEEN ? AND ? AND deadline_at IS NOT NULL AND end_time IS NOT NULL",
      args: [employeeId, firstDay, lastDay],
    }),
    db.execute({
      sql: `SELECT DISTINCT t.*, p.code as p_code, p.name as p_name, p.category, p.type, p.sub_code, p.simple_label,
                   ts.date as segment_date
            FROM tasks t
            JOIN task_segments ts ON ts.task_id = t.id
            LEFT JOIN projects p ON p.id = t.project_id
            WHERE t.employee_id = ? AND ts.date BETWEEN ? AND ?`,
      args: [employeeId, firstDay, lastDay],
    }),
  ]);

  const leaveByDate = {};
  for (const r of leaveRows.rows) {
    const rangeEnd = r.end_date || r.date;
    let cur = r.date > firstDay ? r.date : firstDay;
    const stop = rangeEnd < lastDay ? rangeEnd : lastDay;
    let guard = 0;
    while (cur <= stop && guard < 400) {
      leaveByDate[cur] = r;
      cur = addDaysToDateStr(cur, 1);
      guard++;
    }
  }
  const otDates = new Set(otRows.rows.map((r) => r.date));
  const holidayByDate = {};
  for (const r of holidayRows.rows) holidayByDate[r.date] = r;
  const breakSecondsByDate = {};
  for (const b of breakRows.rows) {
    if (b.duration) breakSecondsByDate[b.date] = (breakSecondsByDate[b.date] || 0) + Number(b.duration);
  }

  const todayStr = cairoDateStr();
  const days = [];
  let totalCountedSeconds = 0;
  let totalActualSeconds = 0;
  let totalOvertimeSeconds = 0;
  let totalHolidayBonusSeconds = 0;  // extra half from doubling worked-holiday hours
  let totalHolidayOffSeconds = 0;    // auto-granted 8h on unworked holidays
  let totalWeekendBonusSeconds = 0;  // extra half from doubling worked-weekend hours
  let requiredSeconds = 0;           // baseline hours the employee was expected to work this month so far
  let totalUncountedOvertimeSeconds = 0; // worked past required, but no overtime-enabled project that day
  let totalRegularWorkSeconds = 0;   // capped (<=8h/day) portion of ordinary worked days
  let totalLeaveCreditSeconds = 0;   // auto 8h/day credit for approved leave
  let absentDays = 0;
  let leaveDaysCasual = 0;
  let leaveDaysAnnual = 0;
  let leaveDaysSick = 0;

  // Pair sign_in/sign_out chronologically across the WHOLE fetched range (not
  // grouped by calendar date) so a shift that crosses midnight still counts
  // as one session, attributed to the date the employee SIGNED IN — not the
  // date they happened to sign out.
  const sessionsByDate = {};   // sign-in date -> total actual seconds worked that day
  const daysWithSignIn = new Set();
  const timesByDate = {};      // sign-in date -> { in_time, out_time } (first sign-in / last sign-out shown that day)
  {
    let pendingIn = null;
    for (const e of attRows.rows) {
      if (e.action === "sign_in") {
        pendingIn = e;
        daysWithSignIn.add(e.date);
        if (!timesByDate[e.date]) timesByDate[e.date] = {};
        if (!timesByDate[e.date].in_time) timesByDate[e.date].in_time = e.time;
      } else if (e.action === "sign_out" && pendingIn) {
        const inMs = new Date(pendingIn.created_at + "Z").getTime();
        const outMs = new Date(e.created_at + "Z").getTime();
        if (outMs > inMs) {
          const secs = Math.floor((outMs - inMs) / 1000);
          sessionsByDate[pendingIn.date] = (sessionsByDate[pendingIn.date] || 0) + secs;
        }
        if (!timesByDate[pendingIn.date]) timesByDate[pendingIn.date] = {};
        timesByDate[pendingIn.date].out_time = e.time;
        pendingIn = null;
      }
    }
  }

  // "Required hours" is a pure calendar figure for the WHOLE month — total
  // days minus weekly-off days minus official holidays — known in advance
  // and completely independent of attendance/leave/absence, so it doesn't
  // wait for the month (or even today) to happen, and it updates instantly
  // whenever an official holiday is added/removed.
  for (let dateStr = firstDay; dateStr <= lastDay; dateStr = addDaysToDateStr(dateStr, 1)) {
    if (isWeekendStr(dateStr)) continue;
    if (holidayByDate[dateStr]) continue;
    requiredSeconds += daySeconds;
  }

  for (let dateStr = firstDay; dateStr <= lastDay; dateStr = addDaysToDateStr(dateStr, 1)) {
    if (dateStr > todayStr) break; // don't project future days

    const breakSecs = breakSecondsByDate[dateStr] || 0;
    const times = timesByDate[dateStr] || {};

    if (isWeekendStr(dateStr)) {
      // Weekly off day — completely neutral: not required, and not counted
      // either unless the employee actually worked it (then doubled).
      const actualSeconds = sessionsByDate[dateStr] || 0;
      if (actualSeconds > 0) {
        const countedSeconds = actualSeconds * 2;
        totalActualSeconds += actualSeconds;
        totalCountedSeconds += countedSeconds;
        totalWeekendBonusSeconds += actualSeconds;
        days.push({ date: dateStr, status: "weekend_worked", actual_seconds: actualSeconds, counted_seconds: countedSeconds,
          sign_in_time: times.in_time || null, sign_out_time: times.out_time || null, break_seconds: breakSecs });
      } else {
        days.push({ date: dateStr, status: "weekend", counted_seconds: 0, break_seconds: breakSecs });
      }
      continue;
    }

    const holiday = holidayByDate[dateStr];
    if (holiday) {
      // Official holiday — same neutral treatment as a weekly off day: not
      // required, not counted unless actually worked (then doubled).
      const actualSeconds = sessionsByDate[dateStr] || 0;
      if (actualSeconds > 0) {
        const countedSeconds = actualSeconds * 2;
        totalActualSeconds += actualSeconds;
        totalCountedSeconds += countedSeconds;
        totalHolidayBonusSeconds += actualSeconds;
        days.push({
          date: dateStr, status: "official_holiday_worked", holiday_label: holiday.label,
          actual_seconds: actualSeconds, counted_seconds: countedSeconds,
          sign_in_time: times.in_time || null, sign_out_time: times.out_time || null, break_seconds: breakSecs,
        });
      } else {
        days.push({ date: dateStr, status: "official_holiday_off", holiday_label: holiday.label, counted_seconds: 0, break_seconds: breakSecs });
      }
      continue;
    }

    const leave = leaveByDate[dateStr];
    if (leave) {
      // Approved leave — required already includes this day via the
      // calendar-only pre-pass above; the employee just gets full credit
      // on the counted side, so the net effect for this day is zero.
      totalCountedSeconds += daySeconds;
      totalLeaveCreditSeconds += daySeconds;
      if (leave.type === "casual") leaveDaysCasual++; else if (leave.type === "sick") leaveDaysSick++; else leaveDaysAnnual++;
      days.push({ date: dateStr, status: "leave", leave_type: leave.type, counted_seconds: daySeconds, break_seconds: breakSecs });
      continue;
    }

    // A regular required work day (already counted in the pre-pass above).

    if (!daysWithSignIn.has(dateStr)) {
      if (dateStr < todayStr) absentDays++;
      days.push({ date: dateStr, status: dateStr < todayStr ? "absent" : "today_pending", actual_seconds: 0, counted_seconds: 0, break_seconds: breakSecs });
      continue;
    }

    const actualSeconds = sessionsByDate[dateStr] || 0;
    const overtimeApproved = otDates.has(dateStr);
    let countedSeconds, overtimeSeconds = 0, uncountedOvertimeSeconds = 0;
    if (overtimeApproved) {
      countedSeconds = actualSeconds;
      overtimeSeconds = Math.max(0, actualSeconds - daySeconds);
    } else {
      countedSeconds = Math.min(actualSeconds, daySeconds);
      uncountedOvertimeSeconds = Math.max(0, actualSeconds - daySeconds);
    }

    totalActualSeconds += actualSeconds;
    totalCountedSeconds += countedSeconds;
    totalOvertimeSeconds += overtimeSeconds;
    totalUncountedOvertimeSeconds += uncountedOvertimeSeconds;
    totalRegularWorkSeconds += Math.min(countedSeconds, daySeconds);

    days.push({
      date: dateStr, status: "worked",
      actual_seconds: actualSeconds, counted_seconds: countedSeconds,
      overtime_seconds: overtimeSeconds, overtime_approved: overtimeApproved,
      uncounted_overtime_seconds: uncountedOvertimeSeconds,
      sign_in_time: times.in_time || null, sign_out_time: times.out_time || null, break_seconds: breakSecs,
    });
  }

  // ---- extra hour-equivalent components (مستحقات مالية / ساعات خارج بصمة / إذن انصراف) ----
  const rate = hourlyRate(emp);
  const financialTotalEGP = finRows.rows.reduce((s, r) => s + Number(r.amount_egp), 0);
  const financialHours = rate > 0 ? financialTotalEGP / rate : 0;

  const offclockHours = offRows.rows.reduce((s, r) => s + Number(r.hours), 0);

  const permissionUsedHours = permRows.rows.reduce((s, r) => s + Number(r.hours), 0);
  let permissionBonusHours;
  if (isAllMonths) {
    // The 2h cap is a PER-MONTH allowance — summing every month's unused
    // portion (including months with zero requests, which still earn the
    // full bonus) instead of applying one flat cap across the whole history.
    const usedByMonth = {};
    for (const r of permRows.rows) {
      const mk = r.date.slice(0, 7);
      usedByMonth[mk] = (usedByMonth[mk] || 0) + Number(r.hours);
    }
    permissionBonusHours = 0;
    let my = Number(firstDay.slice(0, 4)), mm = Number(firstDay.slice(5, 7));
    const endY = Number(lastDay.slice(0, 4)), endM = Number(lastDay.slice(5, 7));
    while (my < endY || (my === endY && mm <= endM)) {
      const mk = `${my}-${String(mm).padStart(2, "0")}`;
      permissionBonusHours += Math.max(0, PERMISSION_MONTHLY_HOURS - (usedByMonth[mk] || 0));
      mm++; if (mm > 12) { mm = 1; my++; }
    }
  } else {
    permissionBonusHours = Math.max(0, PERMISSION_MONTHLY_HOURS - permissionUsedHours);
  }

  const penaltiesTotalEGP = penaltyRows.rows.reduce((s, r) => s + Number(r.amount_egp), 0);
  const bonusesTotalEGP = bonusRows.rows.reduce((s, r) => s + Number(r.amount_egp), 0);
  const bonusesHoursEquivalent = rate > 0 ? bonusesTotalEGP / rate : 0;

  const extraSeconds = Math.round((financialHours + offclockHours + permissionBonusHours) * 3600);
  totalCountedSeconds += extraSeconds;

  const requiredHours = +(requiredSeconds / 3600).toFixed(2);
  const countedHoursFinal = +(totalCountedSeconds / 3600).toFixed(2);
  const hoursDiff = +(countedHoursFinal - requiredHours).toFixed(2);
  const baseSalary = Number(emp.monthly_salary) || 0;
  const salaryAdjustment = +(hoursDiff * rate).toFixed(2);
  const finalSalary = +(baseSalary + salaryAdjustment + bonusesTotalEGP - penaltiesTotalEGP).toFixed(2);

  // Attach each day's worked tasks (grouped by which day they had an active
  // segment on, so a multi-day task shows up under every day it was
  // actually worked) — used to fill the "what did they work on" column
  // next to each day's attendance details.
  const dayTasksWithSegments = await attachSegments(db, dayTaskRows.rows);
  const tasksByDate = {};
  for (const t of dayTasksWithSegments) {
    const dk = t.segment_date;
    if (!tasksByDate[dk]) tasksByDate[dk] = [];
    tasksByDate[dk].push({
      id: t.id, name: t.name, description: t.description,
      project: (t.p_code ? (t.p_code + " - " + t.p_name) : (t.project || "")),
      project_type: t.p_code ? (t.category + " / " + t.type + (t.sub_code ? " " + t.sub_code : "") + (t.simple_label ? " (" + t.simple_label + ")" : "")) : null,
      start_time: t.start_time, end_time: t.end_time, paused: !!t.paused,
      segments: t.segments,
    });
  }
  for (const d of days) {
    d.tasks = tasksByDate[d.date] || [];
  }

  return json({
    employee: publicEmployee(emp),
    year: isAllMonths ? null : year,
    month: isAllMonths ? "all" : month,
    range: { start: firstDay, end: lastDay },
    days,
    totals: {
      counted_seconds: totalCountedSeconds,
      counted_hours: countedHoursFinal,
      actual_seconds: totalActualSeconds,
      actual_hours: +(totalActualSeconds / 3600).toFixed(2),
      regular_work_hours: +(totalRegularWorkSeconds / 3600).toFixed(2),
      leave_credit_hours: +(totalLeaveCreditSeconds / 3600).toFixed(2),
      overtime_seconds: totalOvertimeSeconds,
      overtime_hours: +(totalOvertimeSeconds / 3600).toFixed(2),
      uncounted_overtime_hours: +(totalUncountedOvertimeSeconds / 3600).toFixed(2),
      absent_days: absentDays,
      absent_hours_deducted: +(absentDays * dayHours).toFixed(2),
      leave_days_casual: leaveDaysCasual,
      leave_days_annual: leaveDaysAnnual,
      leave_days_sick: leaveDaysSick,
      holiday_bonus_hours: +(totalHolidayBonusSeconds / 3600).toFixed(2),
      holiday_actual_hours: +(totalHolidayBonusSeconds / 3600).toFixed(2),
      holiday_counted_hours: +((totalHolidayBonusSeconds * 2) / 3600).toFixed(2),
      holiday_off_hours: +(totalHolidayOffSeconds / 3600).toFixed(2),
      weekend_bonus_hours: +(totalWeekendBonusSeconds / 3600).toFixed(2),
      weekend_actual_hours: +(totalWeekendBonusSeconds / 3600).toFixed(2),
      weekend_counted_hours: +((totalWeekendBonusSeconds * 2) / 3600).toFixed(2),
      required_hours: requiredHours,
    },
    late_arrivals: {
      count: lateRows.rows.length,
      list: lateRows.rows.map((l) => ({ date: l.date, arrival_time: l.arrival_time, status: l.status })),
    },
    deliveries: await (async () => {
      const withSegments = await attachSegments(db, deadlineTaskRows.rows);
      const withStatus = await attachDeliveryStatus(db, withSegments);
      let onTime = 0, onTimeBuffer = 0, late = 0;
      const list = withStatus.map((t) => {
        if (t.delivery.status === "on_time") onTime++;
        else if (t.delivery.status === "on_time_buffer") onTimeBuffer++;
        else if (t.delivery.status === "late") late++;
        return {
          task_name: t.name, project: t.project, date: t.date,
          status: t.delivery.status, deadline_display: t.delivery.deadline_display,
          delay_seconds: t.delivery.delay_seconds || 0,
        };
      });
      return { total: withStatus.length, on_time: onTime, on_time_buffer: onTimeBuffer, late, list };
    })(),
    extras: {
      hourly_rate: +rate.toFixed(2),
      financial_total_egp: +financialTotalEGP.toFixed(2),
      financial_hours: +financialHours.toFixed(2),
      offclock_hours: +offclockHours.toFixed(2),
      permission_monthly_limit: PERMISSION_MONTHLY_HOURS,
      permission_used_hours: +permissionUsedHours.toFixed(2),
      permission_bonus_hours: +permissionBonusHours.toFixed(2),
      penalties_total_egp: +penaltiesTotalEGP.toFixed(2),
      bonuses_total_egp: +bonusesTotalEGP.toFixed(2),
      bonuses_hours_equivalent: +bonusesHoursEquivalent.toFixed(2),
    },
    salary: {
      base_salary: baseSalary,
      work_days_per_month: Number(emp.work_days_per_month) || 0,
      daily_work_hours: dayHours,
      hourly_rate: +rate.toFixed(2),
      required_hours: requiredHours,
      counted_hours: countedHoursFinal,
      hours_diff: hoursDiff,
      salary_adjustment: salaryAdjustment,
      penalties_total_egp: +penaltiesTotalEGP.toFixed(2),
      bonuses_total_egp: +bonusesTotalEGP.toFixed(2),
      final_salary: finalSalary,
    },
    leave_balance: { casual: emp.casual_balance, annual: emp.annual_balance, sick: emp.sick_balance },
    project_hours: buildProjectHoursByType(projectRows.rows),
  });
}

// Groups flat (code,name,category,type,sub_code,total_seconds) rows into
// project -> type-variant hierarchy, so "how many hours on this project
// overall" and "how many hours on each type of it" are both available.
function buildProjectHoursByType(rows) {
  const byProject = {};
  for (const r of rows) {
    const key = r.code + " - " + r.name;
    if (!byProject[key]) byProject[key] = { project: key, total_seconds: 0, types: {} };
    byProject[key].total_seconds += Number(r.total_seconds) || 0;
    const typeLabel = r.category + " / " + r.type + (r.sub_code ? " " + r.sub_code : "") + (r.simple_label ? " (" + r.simple_label + ")" : "");
    if (!byProject[key].types[typeLabel]) byProject[key].types[typeLabel] = { type: typeLabel, seconds: 0, task_count: 0 };
    byProject[key].types[typeLabel].seconds += Number(r.total_seconds) || 0;
    byProject[key].types[typeLabel].task_count += Number(r.task_count) || 0;
  }
  return Object.values(byProject)
    .map((p) => ({
      project: p.project,
      hours: +(p.total_seconds / 3600).toFixed(2),
      types: Object.values(p.types)
        .map((t) => ({ type: t.type, hours: +(t.seconds / 3600).toFixed(2), task_count: t.task_count }))
        .sort((a, b) => b.hours - a.hours),
    }))
    .sort((a, b) => b.hours - a.hours);
}

// Company-wide project hours — sums task time across ALL employees for the
// given month, with a per-employee breakdown inside each project.
// Project cost & profitability — labor cost is computed per employee
// (hours worked on the project × that employee's own hourly rate), summed
// per project group (code+name). External expenses add on top; the
// project's set price minus (labor + external expenses) = profit/loss.
// mode "total" ignores the month entirely (all-time); mode "monthly" scopes
// tasks and expenses to the given month.
async function profitLossReport(db, monthStr) {
  const month = monthLikePattern(monthStr);
  const res = await db.execute({
    sql: `SELECT ct.*, c.name as created_by_name FROM company_transactions ct
          LEFT JOIN employees c ON c.id = ct.created_by
          WHERE ct.date LIKE ? ORDER BY ct.date DESC, ct.id DESC`,
    args: [month],
  });
  let totalIncome = 0, totalExpense = 0;
  for (const r of res.rows) {
    if (r.type === "income") totalIncome += Number(r.amount_egp);
    else totalExpense += Number(r.amount_egp);
  }
  const net = +(totalIncome - totalExpense).toFixed(2);
  return json({
    month: monthStr === "all" ? "all" : month.replace("%", ""),
    total_income_egp: +totalIncome.toFixed(2),
    total_expense_egp: +totalExpense.toFixed(2),
    net_profit_loss_egp: net,
    transactions: res.rows,
  });
}

async function projectCostReportData(db, isMonthly, firstDay, lastDay) {
  let taskSql = `SELECT p.code, p.name, p.category, p.type, p.sub_code, p.simple_label,
                        t.employee_id, e.name as employee_name, e.emp_code,
                        e.monthly_salary, e.work_days_per_month, e.daily_work_hours,
                        SUM(COALESCE(t.duration,0)) as total_seconds
                 FROM tasks t
                 JOIN employees e ON e.id = t.employee_id
                 JOIN projects p ON p.id = t.project_id`;
  const taskArgs = [];
  if (isMonthly) { taskSql += " WHERE t.date BETWEEN ? AND ?"; taskArgs.push(firstDay, lastDay); }
  taskSql += " GROUP BY p.code, p.name, p.category, p.type, p.sub_code, t.employee_id";
  const taskRows = await db.execute({ sql: taskSql, args: taskArgs });

  let expSql = "SELECT * FROM project_expenses";
  const expArgs = [];
  if (isMonthly) { expSql += " WHERE date BETWEEN ? AND ?"; expArgs.push(firstDay, lastDay); }
  const [expRows, costRows] = await Promise.all([
    db.execute({ sql: expSql, args: expArgs }),
    db.execute("SELECT * FROM project_costs"),
  ]);

  const byProject = {};
  const key = (code, name) => code + "||" + name.trim().toLowerCase();
  const ensure = (code, name) => {
    const k = key(code, name);
    if (!byProject[k]) byProject[k] = { project_code: code, project_name: name, labor_cost_egp: 0, employees: [], external_expenses_egp: 0, expenses: [], price_egp: 0, types: {} };
    return byProject[k];
  };

  for (const r of taskRows.rows) {
    const g = ensure(r.code, r.name);
    const rate = hourlyRate({ monthly_salary: r.monthly_salary, work_days_per_month: r.work_days_per_month, daily_work_hours: r.daily_work_hours });
    const hours = +((Number(r.total_seconds) || 0) / 3600).toFixed(2);
    const cost = +(hours * rate).toFixed(2);
    g.labor_cost_egp += cost;
    const empEntry = { employee_id: r.employee_id, emp_code: r.emp_code, name: r.employee_name, hours, hourly_rate: +rate.toFixed(2), cost_egp: cost };
    g.employees.push(empEntry);

    // Same figures, broken down by this specific variant (category/type/sub_code).
    const typeLabel = r.category + " / " + r.type + (r.sub_code ? " " + r.sub_code : "") + (r.simple_label ? " (" + r.simple_label + ")" : "");
    if (!g.types[typeLabel]) g.types[typeLabel] = { type: typeLabel, labor_cost_egp: 0, employees: [] };
    g.types[typeLabel].labor_cost_egp += cost;
    g.types[typeLabel].employees.push(empEntry);
  }
  for (const r of expRows.rows) {
    const g = ensure(r.project_code, r.project_name);
    g.external_expenses_egp += Number(r.amount_egp);
    g.expenses.push({ id: r.id, amount_egp: Number(r.amount_egp), description: r.description, date: r.date });
  }
  for (const r of costRows.rows) {
    const g = ensure(r.project_code, r.project_name);
    g.price_egp = Number(r.cost_egp);
  }

  return Object.values(byProject).map((g) => {
    const laborCost = +g.labor_cost_egp.toFixed(2);
    const externalExp = +g.external_expenses_egp.toFixed(2);
    const actualCost = +(laborCost + externalExp).toFixed(2);
    const profitLoss = +(g.price_egp - actualCost).toFixed(2);
    // Per-type view: same shared price/expenses (a project has one price
    // regardless of internal classification), but labor cost narrowed to
    // just that one variant — useful to compare which type is carrying the
    // work, not a literal split of the client's payment.
    const types = Object.values(g.types).map((ty) => {
      const tyLaborCost = +ty.labor_cost_egp.toFixed(2);
      const tyActualCost = +(tyLaborCost + externalExp).toFixed(2);
      return {
        type: ty.type,
        labor_cost_egp: tyLaborCost,
        external_expenses_egp: externalExp,
        actual_cost_egp: tyActualCost,
        price_egp: g.price_egp,
        profit_loss_egp: +(g.price_egp - tyActualCost).toFixed(2),
        employees: ty.employees.sort((a, b) => b.cost_egp - a.cost_egp),
      };
    }).sort((a, b) => b.labor_cost_egp - a.labor_cost_egp);
    return {
      project_code: g.project_code, project_name: g.project_name,
      price_egp: g.price_egp,
      labor_cost_egp: laborCost,
      external_expenses_egp: externalExp,
      actual_cost_egp: actualCost,
      profit_loss_egp: profitLoss,
      employees: g.employees.sort((a, b) => b.cost_egp - a.cost_egp),
      expenses: g.expenses.sort((a, b) => (a.date < b.date ? 1 : -1)),
      types,
    };
  }).sort((a, b) => a.project_code.localeCompare(b.project_code));
}

async function projectCostReport(db, mode, monthStr) {
  const isMonthly = mode === "monthly";
  let firstDay = null, lastDay = null, year = null, month = null;
  if (isMonthly) {
    const now = new Date();
    if (monthStr && /^\d{4}-\d{2}$/.test(monthStr)) {
      [year, month] = monthStr.split("-").map(Number);
    } else {
      const p = cairoParts(now);
      year = Number(p.y); month = Number(p.m);
    }
    firstDay = `${year}-${String(month).padStart(2, "0")}-01`;
    const lastDayNum = daysInMonth(year, month);
    lastDay = `${year}-${String(month).padStart(2, "0")}-${String(lastDayNum).padStart(2, "0")}`;
  }
  const projects = await projectCostReportData(db, isMonthly, firstDay, lastDay);
  return json({ mode: isMonthly ? "monthly" : "total", year, month, projects });
}

async function clientFinancialReport(db, clientCode, monthStr) {
  if (!clientCode) return err("client_code required");
  const clientRes = await db.execute({ sql: "SELECT * FROM clients WHERE client_code = ?", args: [clientCode] });
  const client = clientRes.rows[0] || { client_code: clientCode, client_name: null };

  // Reuse the all-time cost report, then narrow to this client's projects
  // (matched by the code prefix — the first 2 digits are the client code).
  const full = await projectCostReportData(db, false, null, null);
  const clientProjects = full.filter((p) => String(p.project_code).slice(0, 2) === clientCode);

  const isAll = monthStr === "all" || !monthStr;
  let monthFirst = null, monthLast = null;
  if (!isAll) {
    const [y, m] = monthStr.split("-").map(Number);
    monthFirst = `${y}-${String(m).padStart(2, "0")}-01`;
    monthLast = `${y}-${String(m).padStart(2, "0")}-${String(daysInMonth(y, m)).padStart(2, "0")}`;
  }

  // Pull each project's own row (for its delivered_at / active status) to
  // know delivery counts and to compute the "delivered within this month"
  // percentage of total client value.
  const projRows = await db.execute({
    sql: "SELECT DISTINCT code, name, active, delivered_at FROM projects WHERE substr(code,1,2) = ?",
    args: [clientCode],
  });
  const statusByKey = {};
  for (const r of projRows.rows) {
    const k = r.code + "||" + r.name.trim().toLowerCase();
    if (!statusByKey[k]) statusByKey[k] = { active: !!r.active, delivered_at: r.delivered_at };
    else if (r.delivered_at) statusByKey[k].delivered_at = r.delivered_at; // any variant delivered counts as delivered
  }

  let totalPrice = 0, totalLabor = 0, totalExternal = 0, totalActual = 0, deliveredCount = 0;
  let deliveredInMonthValue = 0;
  const projects = clientProjects.map((p) => {
    const k = p.project_code + "||" + p.project_name.trim().toLowerCase();
    const st = statusByKey[k] || {};
    const isDelivered = !!st.delivered_at;
    totalPrice += p.price_egp || 0;
    totalLabor += p.labor_cost_egp || 0;
    totalExternal += p.external_expenses_egp || 0;
    totalActual += p.actual_cost_egp || 0;
    if (isDelivered) deliveredCount++;
    if (isDelivered && !isAll && st.delivered_at.slice(0, 10) >= monthFirst && st.delivered_at.slice(0, 10) <= monthLast) {
      deliveredInMonthValue += p.price_egp || 0;
    }
    return {
      project_code: p.project_code, project_name: p.project_name,
      price_egp: p.price_egp, labor_cost_egp: p.labor_cost_egp, external_expenses_egp: p.external_expenses_egp,
      actual_cost_egp: p.actual_cost_egp, profit_loss_egp: p.profit_loss_egp,
      active: st.active !== undefined ? st.active : true, delivered_at: st.delivered_at || null,
    };
  }).sort((a, b) => a.project_code.localeCompare(b.project_code));

  return json({
    client, month: isAll ? "all" : monthStr,
    projects,
    totals: {
      project_count: projects.length, delivered_count: deliveredCount,
      total_price_egp: +totalPrice.toFixed(2), total_labor_cost_egp: +totalLabor.toFixed(2),
      total_external_expenses_egp: +totalExternal.toFixed(2), total_actual_cost_egp: +totalActual.toFixed(2),
      total_profit_loss_egp: +(totalPrice - totalActual).toFixed(2),
    },
    month_delivered_value_egp: isAll ? null : +deliveredInMonthValue.toFixed(2),
    month_delivered_percentage: (!isAll && totalPrice > 0) ? +((deliveredInMonthValue / totalPrice) * 100).toFixed(1) : null,
  });
}

async function projectsReport(db, monthStr) {
  const isAll = monthStr === "all";
  let year, month, firstDay, lastDay;
  if (!isAll) {
    const now = new Date();
    if (monthStr && /^\d{4}-\d{2}$/.test(monthStr)) {
      [year, month] = monthStr.split("-").map(Number);
    } else {
      const p = cairoParts(now);
      year = Number(p.y); month = Number(p.m);
    }
    firstDay = `${year}-${String(month).padStart(2, "0")}-01`;
    const lastDayNum = daysInMonth(year, month);
    lastDay = `${year}-${String(month).padStart(2, "0")}-${String(lastDayNum).padStart(2, "0")}`;
  }

  let sql = `SELECT p.code, p.name, p.category, p.type, p.sub_code, p.simple_label,
                 t.employee_id, e.name as employee_name, e.emp_code,
                 SUM(COALESCE(t.duration,0)) as total_seconds, COUNT(*) as task_count
          FROM tasks t
          JOIN employees e ON e.id = t.employee_id
          JOIN projects p ON p.id = t.project_id`;
  const args = [];
  if (!isAll) { sql += " WHERE t.date BETWEEN ? AND ?"; args.push(firstDay, lastDay); }
  sql += " GROUP BY p.code, p.name, p.category, p.type, p.sub_code, t.employee_id ORDER BY p.code ASC, p.name COLLATE NOCASE ASC, total_seconds DESC";
  const res = await db.execute({ sql, args });

  const byProject = {};
  for (const r of res.rows) {
    const projKey = r.code + " - " + r.name;
    if (!byProject[projKey]) byProject[projKey] = { project: projKey, total_seconds: 0, variants: {} };
    byProject[projKey].total_seconds += Number(r.total_seconds) || 0;

    const typeLabel = r.category + " / " + r.type + (r.sub_code ? " " + r.sub_code : "") + (r.simple_label ? " (" + r.simple_label + ")" : "");
    const variants = byProject[projKey].variants;
    if (!variants[typeLabel]) variants[typeLabel] = { type: typeLabel, total_seconds: 0, employees: [] };
    variants[typeLabel].total_seconds += Number(r.total_seconds) || 0;
    variants[typeLabel].employees.push({
      employee_id: r.employee_id, emp_code: r.emp_code, name: r.employee_name,
      hours: +((Number(r.total_seconds) || 0) / 3600).toFixed(2),
      task_count: Number(r.task_count) || 0,
    });
  }

  const projects = Object.values(byProject)
    .map((p) => ({
      project: p.project,
      hours: +(p.total_seconds / 3600).toFixed(2),
      types: Object.values(p.variants)
        .map((v) => ({ type: v.type, hours: +(v.total_seconds / 3600).toFixed(2), employees: v.employees }))
        .sort((a, b) => b.hours - a.hours),
    }))
    .sort((a, b) => b.hours - a.hours);

  return json({ year, month, projects });
}

// ---------------------------------------------------------------- admin

function pinOkShared(env, body) {
  return !!env.ADMIN_PIN && !!body.pin && String(body.pin) === String(env.ADMIN_PIN);
}

async function handleAdmin(db, admin, path, method, body, url, env) {
  if (path === "/api/admin/employees" && method === "GET") {
    const res = await db.execute("SELECT * FROM employees WHERE is_active = 1 ORDER BY emp_code ASC");
    return json({ employees: res.rows.map(adminEmployeeView) });
  }

  if (path === "/api/admin/employees/status" && method === "GET") {
    return await adminEmployeesStatus(db);
  }

  if (path === "/api/admin/birthdays" && method === "GET") {
    return await adminBirthdays(db);
  }

  if (path === "/api/admin/tasks-by-day" && method === "GET") {
    return await adminTasksByDay(db, url.searchParams.get("employee_id"), url.searchParams.get("date"));
  }

  if (path === "/api/admin/tasks-by-month" && method === "GET") {
    return await adminTasksByMonth(db, url.searchParams.get("employee_id"), url.searchParams.get("month"));
  }

  if (path === "/api/admin/check-deadline-conflict" && method === "GET") {
    const empId = url.searchParams.get("employee_id");
    const dateStr = url.searchParams.get("date");
    if (!empId || !dateStr) return err("employee_id و date مطلوبين");
    const reasons = [];
    if (isWeekendStr(dateStr)) reasons.push("اليوم ده إجازة أسبوعية (جمعة/سبت)");
    const holRes = await db.execute({ sql: "SELECT * FROM official_holidays WHERE date = ?", args: [dateStr] });
    if (holRes.rows[0]) reasons.push("اليوم ده إجازة رسمية: " + (holRes.rows[0].name || ""));
    const leaveRes = await db.execute({
      sql: "SELECT * FROM leave_requests WHERE employee_id = ? AND status = 'approved' AND date <= ? AND COALESCE(end_date, date) >= ?",
      args: [Number(empId), dateStr, dateStr],
    });
    if (leaveRes.rows[0]) reasons.push("الموظف في إجازة معتمدة (" + (leaveRes.rows[0].type === "casual" ? "عارضة" : "اعتيادية") + ") في اليوم ده");
    return json({ has_conflict: reasons.length > 0, reasons });
  }

  const setDeadlineMatch = path.match(/^\/api\/admin\/tasks\/(\d+)\/deadline$/);
  if (setDeadlineMatch && method === "PATCH") {
    const missing = requireFields(body, ["deadline_date", "deadline_hour"]);
    if (missing) return err(`Missing field: ${missing}`);
    const taskId = Number(setDeadlineMatch[1]);
    const deadlineAt = cairoLocalToUtcString(body.deadline_date, body.deadline_hour);
    await db.execute({
      sql: "UPDATE tasks SET deadline_at = ?, deadline_set_by = ?, deadline_set_at = datetime('now') WHERE id = ?",
      args: [deadlineAt, admin.id, taskId],
    });
    const updated = await db.execute({ sql: "SELECT * FROM tasks WHERE id = ?", args: [taskId] });
    if (!updated.rows[0]) return err("Task not found", 404);
    return json({ task: (await attachDeliveryStatus(db, await attachSegments(db, updated.rows)))[0] });
  }

  const adminAttachListMatch = path.match(/^\/api\/admin\/requests\/(leave|financial|offclock|permission)\/(\d+)\/attachments$/);
  if (adminAttachListMatch && method === "GET") return await listAdminRequestAttachments(db, adminAttachListMatch[1], Number(adminAttachListMatch[2]));

  if (path === "/api/admin/deadline-requests" && method === "GET") {
    const status = url.searchParams.get("status") || "pending";
    const month = url.searchParams.get("month");
    const employeeId = url.searchParams.get("employee_id");
    let sql = `SELECT tdr.*, e.name as employee_name, e.emp_code, t.name as task_name, t.project as project_display, t.date as task_date,
                      a.name as decided_by_name
               FROM task_deadline_requests tdr
               JOIN employees e ON e.id = tdr.employee_id
               JOIN tasks t ON t.id = tdr.task_id
               LEFT JOIN employees a ON a.id = tdr.decided_by
               WHERE tdr.status = ?`;
    const args = [status];
    if (month) { sql += " AND tdr.requested_at LIKE ?"; args.push(monthLikePattern(month)); }
    if (employeeId && employeeId !== "all") { sql += " AND tdr.employee_id = ?"; args.push(Number(employeeId)); }
    sql += " ORDER BY tdr.requested_at DESC";
    const res = await db.execute({ sql, args });
    return json({ requests: res.rows });
  }

  const decideDeadlineMatch = path.match(/^\/api\/admin\/deadline-requests\/(\d+)\/decide$/);
  if (decideDeadlineMatch && method === "POST") {
    if (!["approve", "reject"].includes(body.action)) return err("action must be approve or reject");
    const reqId = Number(decideDeadlineMatch[1]);
    const cur = await db.execute({ sql: "SELECT * FROM task_deadline_requests WHERE id = ?", args: [reqId] });
    const request = cur.rows[0];
    if (!request) return err("Request not found", 404);
    if (request.status !== "pending") return err("Request already decided", 409);

    let newDeadlineAt = null;
    if (body.action === "approve") {
      const missing = requireFields(body, ["deadline_date", "deadline_hour"]);
      if (missing) return err(`Missing field: ${missing}`);
      newDeadlineAt = cairoLocalToUtcString(body.deadline_date, body.deadline_hour);
      await db.execute({
        sql: "UPDATE tasks SET deadline_at = ?, deadline_set_by = ?, deadline_set_at = datetime('now') WHERE id = ?",
        args: [newDeadlineAt, admin.id, request.task_id],
      });
    }
    await db.execute({
      sql: "UPDATE task_deadline_requests SET status = ?, new_deadline_at = ?, decided_by = ?, decided_at = datetime('now') WHERE id = ?",
      args: [body.action === "approve" ? "approved" : "rejected", newDeadlineAt, admin.id, reqId],
    });
    return json({ ok: true });
  }

  if (path === "/api/admin/leave-requests" && method === "GET") {
    const status = url.searchParams.get("status") || "pending";
    const month = monthLikePattern(url.searchParams.get("month"));
    const orderBy = status === "pending" ? "lr.requested_at ASC" : "lr.decided_at DESC";
    const res = await db.execute({
      sql: `SELECT lr.*, e.name as employee_name, e.emp_code, a.name as decided_by_name,
                   (SELECT COUNT(*) FROM request_attachments ra WHERE ra.request_type='leave' AND ra.request_id=lr.id) as has_attachment
            FROM leave_requests lr
            JOIN employees e ON e.id = lr.employee_id
            LEFT JOIN employees a ON a.id = lr.decided_by
            WHERE lr.status = ? AND lr.date LIKE ? ORDER BY ${orderBy}`,
      args: [status, month],
    });
    return json({ requests: res.rows });
  }

  const leaveDecideMatch = path.match(/^\/api\/admin\/leave-requests\/(\d+)\/decide$/);
  if (leaveDecideMatch && method === "POST") {
    return await decideLeave(db, admin, Number(leaveDecideMatch[1]), body);
  }

  // ---------- unified approved/rejected history across all request types ----------
  if (path === "/api/admin/requests" && method === "GET") {
    return await adminAllRequests(db, url.searchParams.get("status") || "approved");
  }

  // ---------- financial requests ----------
  if (path === "/api/admin/financial-requests" && method === "GET") {
    return await adminListRequests(db, "financial_requests", url.searchParams.get("status") || "pending", url.searchParams.get("month"));
  }
  const finDecideMatch = path.match(/^\/api\/admin\/financial-requests\/(\d+)\/decide$/);
  if (finDecideMatch && method === "POST") {
    return await decideSimple(db, admin, "financial_requests", Number(finDecideMatch[1]), body);
  }

  // ---------- off-clock hour requests ----------
  if (path === "/api/admin/offclock-requests" && method === "GET") {
    return await adminListRequests(db, "offclock_requests", url.searchParams.get("status") || "pending", url.searchParams.get("month"));
  }
  const offDecideMatch = path.match(/^\/api\/admin\/offclock-requests\/(\d+)\/decide$/);
  if (offDecideMatch && method === "POST") {
    return await decideSimple(db, admin, "offclock_requests", Number(offDecideMatch[1]), body);
  }

  // ---------- permission / early-leave requests ----------
  if (path === "/api/admin/permission-requests" && method === "GET") {
    return await adminListRequests(db, "permission_requests", url.searchParams.get("status") || "pending", url.searchParams.get("month"));
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
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
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
    if (body.casual_extra_used !== undefined) { fields.push("casual_extra_used = ?"); args.push(Number(body.casual_extra_used) || 0); }
    if (body.annual_extra_used !== undefined) { fields.push("annual_extra_used = ?"); args.push(Number(body.annual_extra_used) || 0); }
    if (body.sick_balance !== undefined) { fields.push("sick_balance = ?"); args.push(Number(body.sick_balance) || 0); }
    if (!fields.length) return err("مفيش بيانات للتحديث");
    args.push(empId);
    await db.execute({ sql: `UPDATE employees SET ${fields.join(", ")} WHERE id = ?`, args });
    const res = await db.execute({ sql: "SELECT * FROM employees WHERE id = ?", args: [empId] });
    return json({ employee: adminEmployeeView(res.rows[0]) });
  }

  // ---------- penalties (جزاءات) ----------
  if (path === "/api/admin/penalties" && method === "POST") {
    const missing = requireFields(body, ["employee_id", "days", "date"]);
    if (missing) return err(`Missing field: ${missing}`);
    const days = Number(body.days);
    if (!(days > 0)) return err("عدد الأيام لازم يكون رقم موجب");
    const empRes = await db.execute({ sql: "SELECT * FROM employees WHERE id = ?", args: [body.employee_id] });
    const emp = empRes.rows[0];
    if (!emp) return err("Employee not found", 404);
    const amountEGP = days * 8 * hourlyRate(emp);
    const res = await db.execute({
      sql: `INSERT INTO penalties (employee_id, amount_egp, days, reason, date, created_by) VALUES (?,?,?,?,?,?) RETURNING *`,
      args: [body.employee_id, amountEGP, days, body.reason || null, body.date, admin.id],
    });
    return json({ penalty: res.rows[0] }, 201);
  }
  if (path === "/api/admin/penalties" && method === "GET") {
    const employeeId = url.searchParams.get("employee_id");
    const month = monthLikePattern(url.searchParams.get("month"));
    let sql = `SELECT p.*, e.name as employee_name, e.emp_code, c.name as created_by_name, d.name as deleted_by_name FROM penalties p
               JOIN employees e ON e.id = p.employee_id
               LEFT JOIN employees c ON c.id = p.created_by
               LEFT JOIN employees d ON d.id = p.deleted_by
               WHERE p.date LIKE ?`;
    const args = [month];
    if (employeeId) { sql += " AND p.employee_id = ?"; args.push(Number(employeeId)); }
    sql += " ORDER BY p.date DESC";
    const res = await db.execute({ sql, args });
    return json({ penalties: res.rows });
  }
  const penaltyDeleteMatch = path.match(/^\/api\/admin\/penalties\/(\d+)\/delete$/);
  if (penaltyDeleteMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const pid = Number(penaltyDeleteMatch[1]);
    const res = await db.execute({ sql: "SELECT * FROM penalties WHERE id = ?", args: [pid] });
    if (!res.rows[0]) return err("Penalty not found", 404);
    if (res.rows[0].deleted_at) return err("الجزاء ده اتحذف بالفعل", 409);
    await db.execute({
      sql: "UPDATE penalties SET deleted_at = datetime('now'), deleted_by = ? WHERE id = ?",
      args: [admin.id, pid],
    });
    return json({ ok: true });
  }

  // ---------- bonuses (مكافآت) — same pattern as penalties, but entered in
  // EGP directly (not days) and ADDS to the final salary instead of subtracting ----------
  if (path === "/api/admin/bonuses" && method === "POST") {
    const missing = requireFields(body, ["employee_id", "amount_egp", "date"]);
    if (missing) return err(`Missing field: ${missing}`);
    const amount = Number(body.amount_egp);
    if (!(amount > 0)) return err("قيمة المكافأة لازم تكون رقم موجب");
    const empRes = await db.execute({ sql: "SELECT * FROM employees WHERE id = ?", args: [body.employee_id] });
    const emp = empRes.rows[0];
    if (!emp) return err("Employee not found", 404);
    const res = await db.execute({
      sql: `INSERT INTO bonuses (employee_id, amount_egp, reason, date, created_by) VALUES (?,?,?,?,?) RETURNING *`,
      args: [body.employee_id, amount, body.reason || null, body.date, admin.id],
    });
    return json({ bonus: res.rows[0] }, 201);
  }
  if (path === "/api/admin/bonuses" && method === "GET") {
    const employeeId = url.searchParams.get("employee_id");
    const month = monthLikePattern(url.searchParams.get("month"));
    let sql = `SELECT b.*, e.name as employee_name, e.emp_code, c.name as created_by_name, d.name as deleted_by_name FROM bonuses b
               JOIN employees e ON e.id = b.employee_id
               LEFT JOIN employees c ON c.id = b.created_by
               LEFT JOIN employees d ON d.id = b.deleted_by
               WHERE b.date LIKE ?`;
    const args = [month];
    if (employeeId) { sql += " AND b.employee_id = ?"; args.push(Number(employeeId)); }
    sql += " ORDER BY b.date DESC";
    const res = await db.execute({ sql, args });
    return json({ bonuses: res.rows });
  }
  const bonusDeleteMatch = path.match(/^\/api\/admin\/bonuses\/(\d+)\/delete$/);
  if (bonusDeleteMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const bid = Number(bonusDeleteMatch[1]);
    const res = await db.execute({ sql: "SELECT * FROM bonuses WHERE id = ?", args: [bid] });
    if (!res.rows[0]) return err("Bonus not found", 404);
    if (res.rows[0].deleted_at) return err("المكافأة دي اتحذفت بالفعل", 409);
    await db.execute({
      sql: "UPDATE bonuses SET deleted_at = datetime('now'), deleted_by = ? WHERE id = ?",
      args: [admin.id, bid],
    });
    return json({ ok: true });
  }
  const bonusEditMatch = path.match(/^\/api\/admin\/bonuses\/(\d+)$/);
  if (bonusEditMatch && method === "PATCH") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const bid = Number(bonusEditMatch[1]);
    const cur = await db.execute({ sql: "SELECT * FROM bonuses WHERE id = ?", args: [bid] });
    if (!cur.rows[0]) return err("Bonus not found", 404);
    if (cur.rows[0].deleted_at) return err("المكافأة دي اتحذفت بالفعل", 409);
    const amount = body.amount_egp !== undefined ? Number(body.amount_egp) : Number(cur.rows[0].amount_egp);
    if (!(amount > 0)) return err("قيمة المكافأة لازم تكون رقم موجب");
    const date = body.date || cur.rows[0].date;
    const reason = body.reason !== undefined ? body.reason : cur.rows[0].reason;
    await db.execute({
      sql: "UPDATE bonuses SET amount_egp = ?, date = ?, reason = ? WHERE id = ?",
      args: [amount, date, reason, bid],
    });
    const updated = await db.execute({ sql: "SELECT * FROM bonuses WHERE id = ?", args: [bid] });
    return json({ bonus: updated.rows[0] });
  }

  // ---------- late arrivals (تأخير) — admin reviews each: excuse or penalize ----------
  if (path === "/api/admin/late-arrivals" && method === "GET") {
    const employeeId = url.searchParams.get("employee_id");
    const status = url.searchParams.get("status"); // optional filter
    const month = monthLikePattern(url.searchParams.get("month"));
    let sql = `SELECT la.*, e.name as employee_name, e.emp_code, a.name as decided_by_name FROM late_arrivals la
               JOIN employees e ON e.id = la.employee_id
               LEFT JOIN employees a ON a.id = la.decided_by
               WHERE la.date LIKE ?`;
    const args = [month];
    if (employeeId) { sql += " AND la.employee_id = ?"; args.push(Number(employeeId)); }
    if (status) { sql += " AND la.status = ?"; args.push(status); }
    sql += " ORDER BY la.date DESC";
    const res = await db.execute({ sql, args });
    return json({ late_arrivals: res.rows });
  }
  const lateExcuseMatch = path.match(/^\/api\/admin\/late-arrivals\/(\d+)\/excuse$/);
  if (lateExcuseMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const laId = Number(lateExcuseMatch[1]);
    const cur = await db.execute({ sql: "SELECT * FROM late_arrivals WHERE id = ?", args: [laId] });
    if (!cur.rows[0]) return err("Late arrival record not found", 404);
    if (cur.rows[0].status !== "pending") return err("القرار اتاخد بالفعل على التأخيرة دي", 409);
    await db.execute({
      sql: "UPDATE late_arrivals SET status = 'excused', decided_by = ?, decided_at = datetime('now') WHERE id = ?",
      args: [admin.id, laId],
    });
    return json({ ok: true });
  }
  const latePenalizeMatch = path.match(/^\/api\/admin\/late-arrivals\/(\d+)\/penalize$/);
  if (latePenalizeMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const laId = Number(latePenalizeMatch[1]);
    const cur = await db.execute({ sql: "SELECT * FROM late_arrivals WHERE id = ?", args: [laId] });
    const la = cur.rows[0];
    if (!la) return err("Late arrival record not found", 404);
    if (la.status !== "pending") return err("القرار اتاخد بالفعل على التأخيرة دي", 409);
    const days = Number(body.days);
    if (!(days > 0)) return err("عدد الأيام/الساعات لازم يكون رقم موجب");
    const empRes = await db.execute({ sql: "SELECT * FROM employees WHERE id = ?", args: [la.employee_id] });
    const emp = empRes.rows[0];
    const amountEGP = days * 8 * hourlyRate(emp);
    const penRes = await db.execute({
      sql: `INSERT INTO penalties (employee_id, amount_egp, days, reason, date, created_by) VALUES (?,?,?,?,?,?) RETURNING *`,
      args: [la.employee_id, amountEGP, days, "تأخير — وصل الساعة " + la.arrival_time, la.date, admin.id],
    });
    await db.execute({
      sql: "UPDATE late_arrivals SET status = 'penalized', penalty_id = ?, decided_by = ?, decided_at = datetime('now') WHERE id = ?",
      args: [penRes.rows[0].id, admin.id, laId],
    });
    return json({ ok: true, penalty: penRes.rows[0] });
  }
  const lateEditMatch = path.match(/^\/api\/admin\/late-arrivals\/(\d+)\/reset$/);
  if (lateEditMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const laId = Number(lateEditMatch[1]);
    const cur = await db.execute({ sql: "SELECT * FROM late_arrivals WHERE id = ?", args: [laId] });
    const la = cur.rows[0];
    if (!la) return err("Late arrival record not found", 404);
    if (la.status === "pending") return err("التأخيرة دي أصلاً معلقة، مفيش قرار نلغيه", 409);
    if (la.penalty_id) {
      await db.execute({
        sql: "UPDATE penalties SET deleted_at = datetime('now'), deleted_by = ? WHERE id = ?",
        args: [admin.id, la.penalty_id],
      });
    }
    await db.execute({
      sql: "UPDATE late_arrivals SET status = 'pending', penalty_id = NULL, decided_by = NULL, decided_at = NULL WHERE id = ?",
      args: [laId],
    });
    return json({ ok: true });
  }

  // ---------- notices (لفت نظر) — same idea as penalties, informational only ----------
  if (path === "/api/admin/notices" && method === "POST") {
    const missing = requireFields(body, ["employee_id", "date"]);
    if (missing) return err(`Missing field: ${missing}`);
    const res = await db.execute({
      sql: `INSERT INTO notices (employee_id, reason, date, created_by) VALUES (?,?,?,?) RETURNING *`,
      args: [body.employee_id, body.reason || null, body.date, admin.id],
    });
    return json({ notice: res.rows[0] }, 201);
  }
  if (path === "/api/admin/notices" && method === "GET") {
    const employeeId = url.searchParams.get("employee_id");
    const month = monthLikePattern(url.searchParams.get("month"));
    let sql = `SELECT n.*, e.name as employee_name, e.emp_code, c.name as created_by_name, d.name as deleted_by_name FROM notices n
               JOIN employees e ON e.id = n.employee_id
               LEFT JOIN employees c ON c.id = n.created_by
               LEFT JOIN employees d ON d.id = n.deleted_by
               WHERE n.date LIKE ?`;
    const args = [month];
    if (employeeId) { sql += " AND n.employee_id = ?"; args.push(Number(employeeId)); }
    sql += " ORDER BY n.date DESC";
    const res = await db.execute({ sql, args });
    return json({ notices: res.rows });
  }
  const noticeDeleteMatch = path.match(/^\/api\/admin\/notices\/(\d+)\/delete$/);
  if (noticeDeleteMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const nid = Number(noticeDeleteMatch[1]);
    const res = await db.execute({ sql: "SELECT * FROM notices WHERE id = ?", args: [nid] });
    if (!res.rows[0]) return err("Notice not found", 404);
    if (res.rows[0].deleted_at) return err("لفت النظر ده اتحذف بالفعل", 409);
    await db.execute({
      sql: "UPDATE notices SET deleted_at = datetime('now'), deleted_by = ? WHERE id = ?",
      args: [admin.id, nid],
    });
    return json({ ok: true });
  }

  // ---------- shared projects list (admin manages, everyone can read via /api/projects) ----------
  if (path === "/api/admin/projects" && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const missing = requireFields(body, ["code", "name", "category", "type"]);
    if (missing) return err(`Missing field: ${missing}`);
    if (!["COM", "NON-COM"].includes(body.category)) return err("Category لازم يكون COM أو NON-COM");
    if (!["NEW", "SUB"].includes(body.type)) return err("Type لازم يكون NEW أو SUB");
    if (body.type === "SUB" && !body.sub_code) return err("لازم تدخل كود فرعي للـ SUB");
    const code = normalizeText(body.code);
    const name = normalizeText(body.name);
    const subCode = body.type === "SUB" ? normalizeText(body.sub_code) : null;
    const fullName = buildFullName(code, name, body.category, body.type, subCode);
    try {
      const res = await db.execute({
        sql: `INSERT INTO projects (code, name, category, type, sub_code, simple_label, overtime_enabled, full_name, created_by)
              VALUES (?,?,?,?,?,?,?,?,?) RETURNING *`,
        args: [code, name, body.category, body.type, subCode, autoSimpleLabel(body.category, body.type), body.overtime_enabled ? 1 : 0, fullName, admin.id],
      });
      return json({ project: res.rows[0] }, 201);
    } catch (e) {
      return err("المشروع ده متسجل قبل كده بنفس الكود والاسم والتصنيف", 409);
    }
  }
  if (path === "/api/admin/projects" && method === "GET") {
    const res = await db.execute("SELECT * FROM projects ORDER BY code ASC, name COLLATE NOCASE ASC, category ASC, type ASC");
    return json({ projects: res.rows });
  }

  // ---------- edit an existing project variant (any field, incl. the overtime checkbox) ----------
  const projectEditMatch = path.match(/^\/api\/admin\/projects\/(\d+)$/);
  if (projectEditMatch && method === "PATCH") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const pid = Number(projectEditMatch[1]);
    const cur = await db.execute({ sql: "SELECT * FROM projects WHERE id = ?", args: [pid] });
    const proj = cur.rows[0];
    if (!proj) return err("Project not found", 404);

    const code = body.code !== undefined ? normalizeText(body.code) : proj.code;
    const name = body.name !== undefined ? normalizeText(body.name) : proj.name;
    const category = body.category !== undefined ? body.category : proj.category;
    const type = body.type !== undefined ? body.type : proj.type;
    if (!["COM", "NON-COM"].includes(category)) return err("Category لازم يكون COM أو NON-COM");
    if (!["NEW", "SUB"].includes(type)) return err("Type لازم يكون NEW أو SUB");
    const subCode = type === "SUB" ? normalizeText(body.sub_code !== undefined ? body.sub_code : proj.sub_code) : null;
    if (type === "SUB" && !subCode) return err("لازم تدخل كود فرعي للـ SUB");
    const simpleLabel = autoSimpleLabel(category, type);
    const overtimeEnabled = body.overtime_enabled !== undefined ? (body.overtime_enabled ? 1 : 0) : proj.overtime_enabled;
    const fullName = buildFullName(code, name, category, type, subCode);

    try {
      await db.execute({
        sql: `UPDATE projects SET code=?, name=?, category=?, type=?, sub_code=?, simple_label=?, overtime_enabled=?, full_name=? WHERE id=?`,
        args: [code, name, category, type, subCode, simpleLabel, overtimeEnabled, fullName, pid],
      });
      const updated = await db.execute({ sql: "SELECT * FROM projects WHERE id = ?", args: [pid] });
      return json({ project: updated.rows[0] });
    } catch (e) {
      return err("في مشروع تاني متسجل بنفس الكود والاسم والتصنيف", 409);
    }
  }

  // ---------- pause: stop offering to employees, keep all history, reversible ----------
  const projectPauseMatch = path.match(/^\/api\/admin\/projects\/(\d+)\/pause$/);
  if (projectPauseMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    await db.execute({ sql: "UPDATE projects SET active = 0 WHERE id = ?", args: [Number(projectPauseMatch[1])] });
    return json({ ok: true });
  }
  const projectReactivateMatch = path.match(/^\/api\/admin\/projects\/(\d+)\/reactivate$/);
  if (projectReactivateMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    await db.execute({ sql: "UPDATE projects SET active = 1 WHERE id = ?", args: [Number(projectReactivateMatch[1])] });
    return json({ ok: true });
  }
  const projectDeliveredMatch = path.match(/^\/api\/admin\/projects\/(\d+)\/deliver$/);
  if (projectDeliveredMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    await db.execute({ sql: "UPDATE projects SET delivered_at = datetime('now'), delivered_by = ? WHERE id = ?", args: [admin.id, Number(projectDeliveredMatch[1])] });
    return json({ ok: true });
  }
  const projectUndoDeliveredMatch = path.match(/^\/api\/admin\/projects\/(\d+)\/undo-deliver$/);
  if (projectUndoDeliveredMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    await db.execute({ sql: "UPDATE projects SET delivered_at = NULL, delivered_by = NULL WHERE id = ?", args: [Number(projectUndoDeliveredMatch[1])] });
    return json({ ok: true });
  }

  // ---------- permanent delete: irreversible, blocked if any task references it ----------
  const projectDeleteMatch = path.match(/^\/api\/admin\/projects\/(\d+)$/);
  if (projectDeleteMatch && method === "DELETE") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const pid = Number(projectDeleteMatch[1]);
    const taskCount = await db.execute({ sql: "SELECT COUNT(*) as c FROM tasks WHERE project_id = ?", args: [pid] });
    if (Number(taskCount.rows[0].c) > 0) {
      return err("المشروع ده عليه تاسكات مسجلة — استخدم 'إيقاف' بدل الحذف النهائي عشان التاريخ يفضل موجود", 409);
    }
    await db.execute({ sql: "DELETE FROM projects WHERE id = ?", args: [pid] });
    return json({ ok: true });
  }

  const reportMatch = path === "/api/admin/report";
  if (reportMatch && method === "GET") {
    const employeeId = url.searchParams.get("employee_id");
    const month = url.searchParams.get("month");
    if (!employeeId) return err("employee_id required");
    return await monthlyReport(db, Number(employeeId), month);
  }

  if (path === "/api/admin/projects-report" && method === "GET") {
    return await projectsReport(db, url.searchParams.get("month"));
  }

  // ---------- clients registry (client_code = first 2 digits of project codes) ----------
  if (path === "/api/admin/clients" && method === "GET") {
    const res = await db.execute("SELECT * FROM clients ORDER BY client_code ASC");
    return json({ clients: res.rows });
  }
  if (path === "/api/admin/clients/check-code" && method === "GET") {
    const code = String(url.searchParams.get("code") || "").trim();
    if (!/^\d{2}$/.test(code)) return json({ exists: false });
    const res = await db.execute({ sql: "SELECT * FROM clients WHERE client_code = ?", args: [code] });
    return json({ exists: !!res.rows[0], client: res.rows[0] || null });
  }
  if (path === "/api/admin/client-types" && method === "GET") {
    const builtIn = ["Designer", "Developer", "Marketing Agency"];
    const res = await db.execute("SELECT DISTINCT client_type FROM clients WHERE client_type IS NOT NULL AND client_type != ''");
    const custom = res.rows.map((r) => r.client_type).filter((t) => !builtIn.includes(t));
    return json({ types: [...builtIn, ...custom] });
  }
  if (path === "/api/admin/client-governorates" && method === "GET") {
    const res = await db.execute("SELECT DISTINCT governorate FROM clients WHERE governorate IS NOT NULL AND governorate != '' ORDER BY governorate ASC");
    return json({ governorates: res.rows.map((r) => r.governorate) });
  }
  if (path === "/api/admin/clients" && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const missing = requireFields(body, ["client_code", "client_name"]);
    if (missing) return err(`Missing field: ${missing}`);
    const code = String(body.client_code).trim();
    if (!/^\d{2}$/.test(code)) return err("كود الكلاينت لازم يكون رقمين بالظبط (مثال: 01)");
    // Same code can already exist (e.g. a project using it was added first)
    // — upsert instead of failing, so "whichever gets entered first,
    // client or project, doesn't matter" holds true.
    const existing = await db.execute({ sql: "SELECT id FROM clients WHERE client_code = ?", args: [code] });
    const fields = {
      client_name: body.client_name.trim(),
      client_type: body.client_type || null,
      entity_type: body.entity_type || null,
      address: body.address || null,
      governorate: body.governorate || null,
      city_area: body.city_area || null,
      instagram_url: body.instagram_url || null,
      facebook_url: body.facebook_url || null,
      website_url: body.website_url || null,
      phone: body.phone || null,
      contact_person_name: body.contact_person_name || null,
      contact_person_title: body.contact_person_title || null,
      rating: body.rating ? Number(body.rating) : null,
    };
    if (existing.rows[0]) {
      const setClauses = Object.keys(fields).map((k) => `${k} = ?`).join(", ");
      await db.execute({
        sql: `UPDATE clients SET ${setClauses}, updated_by = ?, updated_at = datetime('now') WHERE id = ?`,
        args: [...Object.values(fields), admin.id, existing.rows[0].id],
      });
      const updated = await db.execute({ sql: "SELECT * FROM clients WHERE id = ?", args: [existing.rows[0].id] });
      return json({ client: updated.rows[0] });
    }
    const res = await db.execute({
      sql: `INSERT INTO clients (client_code, client_name, client_type, entity_type, address, instagram_url, facebook_url, website_url, phone, contact_person_name, contact_person_title, rating, created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *`,
      args: [code, fields.client_name, fields.client_type, fields.entity_type, fields.address, fields.instagram_url, fields.facebook_url, fields.website_url, fields.phone, fields.contact_person_name, fields.contact_person_title, fields.rating, admin.id],
    });
    return json({ client: res.rows[0] }, 201);
  }
  const clientEditMatch = path.match(/^\/api\/admin\/clients\/(\d+)$/);
  if (clientEditMatch && method === "PATCH") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    if (!body.client_name) return err("اكتب اسم العميل");
    const fields = {
      client_name: body.client_name.trim(),
      client_type: body.client_type || null,
      entity_type: body.entity_type || null,
      address: body.address || null,
      governorate: body.governorate || null,
      city_area: body.city_area || null,
      instagram_url: body.instagram_url || null,
      facebook_url: body.facebook_url || null,
      website_url: body.website_url || null,
      phone: body.phone || null,
      contact_person_name: body.contact_person_name || null,
      contact_person_title: body.contact_person_title || null,
      rating: body.rating ? Number(body.rating) : null,
    };
    const setClauses = Object.keys(fields).map((k) => `${k} = ?`).join(", ");
    await db.execute({
      sql: `UPDATE clients SET ${setClauses}, updated_by = ?, updated_at = datetime('now') WHERE id = ?`,
      args: [...Object.values(fields), admin.id, Number(clientEditMatch[1])],
    });
    return json({ ok: true });
  }
  if (clientEditMatch && method === "DELETE") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    await db.execute({ sql: "DELETE FROM clients WHERE id = ?", args: [Number(clientEditMatch[1])] });
    return json({ ok: true });
  }

  // ---------- project cost & profitability (admin-only, hidden from employees) ----------
  if (path === "/api/admin/project-costs" && method === "GET") {
    const res = await db.execute("SELECT * FROM project_costs ORDER BY project_code ASC, project_name COLLATE NOCASE ASC");
    return json({ costs: res.rows });
  }
  if (path === "/api/admin/project-costs" && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const missing = requireFields(body, ["project_code", "project_name", "cost_egp"]);
    if (missing) return err(`Missing field: ${missing}`);
    const cost = Number(body.cost_egp);
    if (!(cost >= 0)) return err("تكلفة المشروع لازم تكون رقم موجب أو صفر");
    await db.execute({
      sql: `INSERT INTO project_costs (project_code, project_name, cost_egp, details, updated_by, updated_at)
            VALUES (?,?,?,?,?,datetime('now'))
            ON CONFLICT(project_code, project_name) DO UPDATE SET cost_egp = excluded.cost_egp, details = excluded.details, updated_by = excluded.updated_by, updated_at = datetime('now')`,
      args: [body.project_code, body.project_name, cost, body.details || null, admin.id],
    });
    return json({ ok: true });
  }

  // ---------- project payment schedule (installments) ----------
  if (path === "/api/admin/project-payments" && method === "GET") {
    const code = url.searchParams.get("project_code");
    const name = url.searchParams.get("project_name");
    if (!code || !name) return err("project_code و project_name مطلوبين");
    const res = await db.execute({
      sql: "SELECT * FROM project_payments WHERE project_code = ? AND project_name = ? ORDER BY COALESCE(planned_date, date('now')) ASC, id ASC",
      args: [code, name],
    });
    return json({ payments: res.rows });
  }
  if (path === "/api/admin/project-payments" && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const missing = requireFields(body, ["project_code", "project_name", "amount_egp"]);
    if (missing) return err(`Missing field: ${missing}`);
    const amount = Number(body.amount_egp);
    if (!(amount > 0)) return err("قيمة الدفعة لازم تكون رقم موجب");
    const res = await db.execute({
      sql: `INSERT INTO project_payments (project_code, project_name, amount_egp, planned_date, created_by) VALUES (?,?,?,?,?) RETURNING *`,
      args: [body.project_code, body.project_name, amount, body.planned_date || null, admin.id],
    });
    return json({ payment: res.rows[0] }, 201);
  }
  const payMarkPaidMatch = path.match(/^\/api\/admin\/project-payments\/(\d+)\/mark-paid$/);
  if (payMarkPaidMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const missing = requireFields(body, ["paid_date"]);
    if (missing) return err(`Missing field: ${missing}`);
    const pid = Number(payMarkPaidMatch[1]);
    const cur = await db.execute({ sql: "SELECT * FROM project_payments WHERE id = ?", args: [pid] });
    const payment = cur.rows[0];
    if (!payment) return err("Payment not found", 404);
    if (payment.paid) return err("الدفعة دي متسجلة كمدفوعة بالفعل", 409);
    const txRes = await db.execute({
      sql: `INSERT INTO company_transactions (type, amount_egp, date, description, project_code, project_name, created_by)
            VALUES ('income',?,?,?,?,?,?) RETURNING *`,
      args: [payment.amount_egp, body.paid_date, "دفعة مشروع " + payment.project_code + " - " + payment.project_name, payment.project_code, payment.project_name, admin.id],
    });
    await db.execute({
      sql: "UPDATE project_payments SET paid = 1, paid_date = ?, transaction_id = ? WHERE id = ?",
      args: [body.paid_date, txRes.rows[0].id, pid],
    });
    return json({ ok: true, transaction: txRes.rows[0] });
  }
  const payDeleteMatch = path.match(/^\/api\/admin\/project-payments\/(\d+)$/);
  if (payDeleteMatch && method === "DELETE") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const pid = Number(payDeleteMatch[1]);
    const cur = await db.execute({ sql: "SELECT * FROM project_payments WHERE id = ?", args: [pid] });
    const payment = cur.rows[0];
    if (payment && payment.transaction_id) {
      await db.execute({ sql: "DELETE FROM company_transactions WHERE id = ?", args: [payment.transaction_id] });
    }
    await db.execute({ sql: "DELETE FROM project_payments WHERE id = ?", args: [pid] });
    return json({ ok: true });
  }

  if (path === "/api/admin/project-expenses" && method === "GET") {
    const code = url.searchParams.get("project_code");
    const name = url.searchParams.get("project_name");
    let sql = `SELECT pe.*, c.name as created_by_name FROM project_expenses pe
               LEFT JOIN employees c ON c.id = pe.created_by WHERE 1=1`;
    const args = [];
    if (code) { sql += " AND pe.project_code = ?"; args.push(code); }
    if (name) { sql += " AND pe.project_name = ?"; args.push(name); }
    sql += " ORDER BY pe.date DESC";
    const res = await db.execute({ sql, args });
    return json({ expenses: res.rows });
  }
  if (path === "/api/admin/project-expenses" && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const missing = requireFields(body, ["project_code", "project_name", "amount_egp", "date"]);
    if (missing) return err(`Missing field: ${missing}`);
    const amount = Number(body.amount_egp);
    if (!(amount > 0)) return err("قيمة المصروف لازم تكون رقم موجب");
    const res = await db.execute({
      sql: `INSERT INTO project_expenses (project_code, project_name, amount_egp, description, date, created_by) VALUES (?,?,?,?,?,?) RETURNING *`,
      args: [body.project_code, body.project_name, amount, body.description || null, body.date, admin.id],
    });
    return json({ expense: res.rows[0] }, 201);
  }
  const projExpenseDeleteMatch = path.match(/^\/api\/admin\/project-expenses\/(\d+)$/);
  if (projExpenseDeleteMatch && method === "DELETE") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    await db.execute({ sql: "DELETE FROM project_expenses WHERE id = ?", args: [Number(projExpenseDeleteMatch[1])] });
    return json({ ok: true });
  }

  if (path === "/api/admin/project-cost-report" && method === "GET") {
    return await projectCostReport(db, url.searchParams.get("mode"), url.searchParams.get("month"));
  }
  if (path === "/api/admin/client-financial-report" && method === "GET") {
    return await clientFinancialReport(db, url.searchParams.get("client_code"), url.searchParams.get("month"));
  }

  // ---------- company income & expenses (profit/loss) ----------
  if (path === "/api/admin/company-transactions" && method === "GET") {
    const month = monthLikePattern(url.searchParams.get("month"));
    const res = await db.execute({
      sql: `SELECT ct.*, c.name as created_by_name FROM company_transactions ct
            LEFT JOIN employees c ON c.id = ct.created_by
            WHERE ct.date LIKE ? ORDER BY ct.date DESC, ct.id DESC`,
      args: [month],
    });
    return json({ transactions: res.rows });
  }
  if (path === "/api/admin/company-transactions" && method === "POST") {
    const missing = requireFields(body, ["type", "amount_egp", "date"]);
    if (missing) return err(`Missing field: ${missing}`);
    if (!["income", "expense"].includes(body.type)) return err("النوع لازم يكون income أو expense");
    const amount = Number(body.amount_egp);
    if (!(amount > 0)) return err("القيمة لازم تكون رقم موجب");
    const res = await db.execute({
      sql: `INSERT INTO company_transactions (type, amount_egp, date, description, project_code, project_name, created_by)
            VALUES (?,?,?,?,?,?,?) RETURNING *`,
      args: [body.type, amount, body.date, body.description || null,
             body.type === "income" ? (body.project_code || null) : null,
             body.type === "income" ? (body.project_name || null) : null,
             admin.id],
    });
    return json({ transaction: res.rows[0] }, 201);
  }
  const companyTxDeleteMatch = path.match(/^\/api\/admin\/company-transactions\/(\d+)$/);
  if (companyTxDeleteMatch && method === "DELETE") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    await db.execute({ sql: "DELETE FROM company_transactions WHERE id = ?", args: [Number(companyTxDeleteMatch[1])] });
    return json({ ok: true });
  }
  if (path === "/api/admin/profit-loss-report" && method === "GET") {
    return await profitLossReport(db, url.searchParams.get("month"));
  }

  // ---------- petty cash / عهدة — fully standalone, never affects company totals ----------
  if (path === "/api/admin/petty-cash" && method === "GET") {
    const monthParam = url.searchParams.get("month");
    let sql = `SELECT pc.*, c.name as created_by_name FROM petty_cash pc
               LEFT JOIN employees c ON c.id = pc.created_by WHERE 1=1`;
    const args = [];
    if (monthParam && monthParam !== "all") { sql += " AND pc.date LIKE ?"; args.push(monthLikePattern(monthParam)); }
    sql += " ORDER BY pc.date DESC, pc.id DESC";
    const res = await db.execute({ sql, args });
    const allRes = await db.execute("SELECT type, amount_egp FROM petty_cash");
    let balance = 0;
    for (const r of allRes.rows) balance += (r.type === "fund" ? Number(r.amount_egp) : -Number(r.amount_egp));
    return json({ entries: res.rows, balance: +balance.toFixed(2) });
  }
  if (path === "/api/admin/petty-cash" && method === "POST") {
    const missing = requireFields(body, ["type", "amount_egp", "date"]);
    if (missing) return err(`Missing field: ${missing}`);
    if (!["fund", "expense"].includes(body.type)) return err("النوع لازم يكون fund أو expense");
    const amount = Number(body.amount_egp);
    if (!(amount > 0)) return err("القيمة لازم تكون رقم موجب");
    // No cap here on purpose: if an expense pushes the balance below zero,
    // that negative balance means the admin paid out of their own pocket
    // and the company owes them that amount back — it's tracked, not blocked.
    const res = await db.execute({
      sql: `INSERT INTO petty_cash (type, amount_egp, date, description, created_by) VALUES (?,?,?,?,?) RETURNING *`,
      args: [body.type, amount, body.date, body.description || null, admin.id],
    });
    return json({ entry: res.rows[0] }, 201);
  }
  const pettyCashDeleteMatch = path.match(/^\/api\/admin\/petty-cash\/(\d+)$/);
  if (pettyCashDeleteMatch && method === "DELETE") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const pcId = Number(pettyCashDeleteMatch[1]);
    const cur = await db.execute({ sql: "SELECT * FROM petty_cash WHERE id = ?", args: [pcId] });
    if (cur.rows[0] && cur.rows[0].linked_transaction_id) {
      await db.execute({ sql: "DELETE FROM company_transactions WHERE id = ?", args: [cur.rows[0].linked_transaction_id] });
    }
    await db.execute({ sql: "DELETE FROM petty_cash WHERE id = ?", args: [pcId] });
    return json({ ok: true });
  }

  // Link/unlink a petty-cash EXPENSE to Company Expenses — mirrors the same
  // details and uses the ORIGINAL registration date, not the linking date.
  const pcLinkMatch = path.match(/^\/api\/admin\/petty-cash\/(\d+)\/link-company-expense$/);
  if (pcLinkMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const pcId = Number(pcLinkMatch[1]);
    const cur = await db.execute({ sql: "SELECT * FROM petty_cash WHERE id = ?", args: [pcId] });
    const entry = cur.rows[0];
    if (!entry) return err("Entry not found", 404);
    if (entry.type !== "expense") return err("الربط ده متاح بس لمصروفات العهدة");
    if (entry.linked_transaction_id) return err("المصروف ده متضاف بالفعل لمصروفات الشركة", 409);
    const txRes = await db.execute({
      sql: `INSERT INTO company_transactions (type, amount_egp, date, description, created_by) VALUES ('expense',?,?,?,?) RETURNING id`,
      args: [entry.amount_egp, entry.date, (entry.description || "") + " (من العهدة)", admin.id],
    });
    await db.execute({ sql: "UPDATE petty_cash SET linked_transaction_id = ? WHERE id = ?", args: [txRes.rows[0].id, pcId] });
    return json({ ok: true });
  }
  const pcUnlinkMatch = path.match(/^\/api\/admin\/petty-cash\/(\d+)\/unlink-company-expense$/);
  if (pcUnlinkMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const pcId = Number(pcUnlinkMatch[1]);
    const cur = await db.execute({ sql: "SELECT * FROM petty_cash WHERE id = ?", args: [pcId] });
    const entry = cur.rows[0];
    if (!entry || !entry.linked_transaction_id) return err("مفيش ربط لإلغائه", 404);
    await db.execute({ sql: "DELETE FROM company_transactions WHERE id = ?", args: [entry.linked_transaction_id] });
    await db.execute({ sql: "UPDATE petty_cash SET linked_transaction_id = NULL WHERE id = ?", args: [pcId] });
    return json({ ok: true });
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

  // ---------- probation -> permanent (unlocks leave requests) — PIN required ----------
  if (path === "/api/admin/set-probation" && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const missing = requireFields(body, ["employee_id"]);
    if (missing) return err(`Missing field: ${missing}`);
    const isProbation = body.is_probation ? 1 : 0;
    await db.execute({ sql: "UPDATE employees SET is_probation = ? WHERE id = ?", args: [isProbation, body.employee_id] });
    return json({ ok: true });
  }

  // ---------- full employee info (no PIN — password/answer are hashed and never included) ----------
  const fullInfoMatch = path.match(/^\/api\/admin\/employees\/(\d+)\/full$/);
  if (fullInfoMatch && method === "GET") {
    const empId = Number(fullInfoMatch[1]);
    const res = await db.execute({ sql: "SELECT * FROM employees WHERE id = ?", args: [empId] });
    const emp = res.rows[0];
    if (!emp) return err("Employee not found", 404);

    const [penRes, notRes, bonRes] = await Promise.all([
      db.execute({
        sql: `SELECT p.*, c.name as created_by_name, d.name as deleted_by_name FROM penalties p
              LEFT JOIN employees c ON c.id = p.created_by
              LEFT JOIN employees d ON d.id = p.deleted_by
              WHERE p.employee_id = ? ORDER BY p.date DESC`,
        args: [empId],
      }),
      db.execute({
        sql: `SELECT n.*, c.name as created_by_name, d.name as deleted_by_name FROM notices n
              LEFT JOIN employees c ON c.id = n.created_by
              LEFT JOIN employees d ON d.id = n.deleted_by
              WHERE n.employee_id = ? ORDER BY n.date DESC`,
        args: [empId],
      }),
      db.execute({
        sql: `SELECT b.*, c.name as created_by_name, d.name as deleted_by_name FROM bonuses b
              LEFT JOIN employees c ON c.id = b.created_by
              LEFT JOIN employees d ON d.id = b.deleted_by
              WHERE b.employee_id = ? ORDER BY b.date DESC`,
        args: [empId],
      }),
    ]);
    const activePenalties = penRes.rows.filter((p) => !p.deleted_at);
    const activeNotices = notRes.rows.filter((n) => !n.deleted_at);
    const activeBonuses = bonRes.rows.filter((b) => !b.deleted_at);

    return json({
      employee: { ...adminEmployeeView(emp), created_at: emp.created_at, secret_q: emp.secret_q },
      penalties: penRes.rows,
      penalties_active_count: activePenalties.length,
      notices: notRes.rows,
      notices_active_count: activeNotices.length,
      bonuses: bonRes.rows,
      bonuses_active_count: activeBonuses.length,
    });
  }

  function pinOk(body) {
    return pinOkShared(env, body);
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

  // ---------- deactivate an employee (PIN required) — replaces permanent delete.
  // The employees row is NEVER removed, so every historical report (project
  // cost, project hours, monthly reports) that joins against it stays
  // accurate forever. The employee just can't log in or appear in active
  // lists anymore.
  const deactivateEmpMatch = path.match(/^\/api\/admin\/employees\/(\d+)\/deactivate$/);
  if (deactivateEmpMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const targetId = Number(deactivateEmpMatch[1]);
    if (targetId === admin.id) return err("منقدرش تعطّل حسابك انت نفسك", 400);
    const cur = await db.execute({ sql: "SELECT * FROM employees WHERE id = ?", args: [targetId] });
    if (!cur.rows[0]) return err("Employee not found", 404);
    if (!cur.rows[0].is_active) return err("الموظف ده متعطل بالفعل", 409);
    await db.execute({
      sql: "UPDATE employees SET is_active = 0, deactivated_at = datetime('now'), deactivated_by = ? WHERE id = ?",
      args: [admin.id, targetId],
    });
    await db.execute({ sql: "DELETE FROM sessions WHERE employee_id = ?", args: [targetId] });
    return json({ ok: true });
  }

  const reactivateEmpMatch = path.match(/^\/api\/admin\/employees\/(\d+)\/reactivate$/);
  if (reactivateEmpMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const targetId = Number(reactivateEmpMatch[1]);
    const cur = await db.execute({ sql: "SELECT * FROM employees WHERE id = ?", args: [targetId] });
    if (!cur.rows[0]) return err("Employee not found", 404);
    if (cur.rows[0].is_active) return err("الموظف ده أصلاً شغال", 409);
    await db.execute({
      sql: "UPDATE employees SET is_active = 1, deactivated_at = NULL, deactivated_by = NULL WHERE id = ?",
      args: [targetId],
    });
    return json({ ok: true });
  }

  // ---------- repair tool: recompute casual_balance/annual_balance/sick_balance
  // for EVERY employee directly from their actual approved leave_requests,
  // instead of trusting whatever number is currently stored. Never touches
  // casual_extra_used/annual_extra_used (the manual pre-system adjustment).
  if (path === "/api/admin/recompute-leave-balances" && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    const empRes = await db.execute("SELECT id FROM employees");
    const results = [];
    for (const emp of empRes.rows) {
      const leaveRes = await db.execute({
        sql: "SELECT type, date, end_date FROM leave_requests WHERE employee_id = ? AND status = 'approved'",
        args: [emp.id],
      });
      let casual = 0, annual = 0, sick = 0;
      for (const r of leaveRes.rows) {
        const days = workingDaysInRange(r.date, r.end_date || r.date).length;
        if (r.type === "casual") casual += days;
        else if (r.type === "sick") sick += days;
        else annual += days;
      }
      await db.execute({
        sql: "UPDATE employees SET casual_balance = ?, annual_balance = ?, sick_balance = ? WHERE id = ?",
        args: [casual, annual, sick, emp.id],
      });
      results.push({ employee_id: emp.id, casual_used: casual, annual_used: annual, sick_used: sick });
    }
    return json({ ok: true, recomputed: results });
  }

  if (path === "/api/admin/deactivated-employees" && method === "GET") {
    const search = (url.searchParams.get("search") || "").trim();
    let sql = `SELECT e.*, a.name as deactivated_by_name FROM employees e
               LEFT JOIN employees a ON a.id = e.deactivated_by
               WHERE e.is_active = 0`;
    const args = [];
    if (search) { sql += " AND (e.name LIKE ? OR e.emp_code LIKE ?)"; args.push("%" + search + "%", "%" + search + "%"); }
    sql += " ORDER BY e.deactivated_at DESC";
    const res = await db.execute({ sql, args });
    return json({ employees: res.rows.map(adminEmployeeView) });
  }

  // ---------- reverse an already-decided request: approved<->rejected (PIN required) ----------
  const redecideMatch = path.match(/^\/api\/admin\/requests\/(leave|overtime|financial|offclock|permission)\/(\d+)\/redecide$/);
  if (redecideMatch && method === "POST") {
    if (!pinOk(body)) return err("كود الأمان غلط", 403);
    if (!["approve", "reject"].includes(body.action)) return err("action must be approve or reject");
    return await redecideRequest(db, admin, redecideMatch[1], Number(redecideMatch[2]), body.action);
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
    const field = leaveBalanceField(request.type);
    const extraField = leaveExtraField(request.type);
    const days = workingDaysInRange(request.date, request.end_date || request.date).length;
    const quota = LEAVE_QUOTAS[request.type]; // undefined for sick — no cap
    if (quota !== undefined) {
      const usedSoFar = (Number(emp[field]) || 0) + (extraField ? (Number(emp[extraField]) || 0) : 0);
      const remaining = quota - usedSoFar;
      if (remaining < days) return err(`رصيد الإجازة مش كفاية (متبقي ${remaining} من ${quota}، مطلوب ${days})`, 409);
    }
    await db.execute({ sql: `UPDATE employees SET ${field} = ${field} + ? WHERE id = ?`, args: [days, request.employee_id] });
  }

  await db.execute({
    sql: "UPDATE leave_requests SET status = ?, decided_at = datetime('now'), decided_by = ? WHERE id = ?",
    args: [body.action === "approve" ? "approved" : "rejected", admin.id, requestId],
  });
  return json({ ok: true });
}

const REQUEST_TABLE_BY_KIND = {
  leave: "leave_requests", financial: "financial_requests",
  offclock: "offclock_requests", permission: "permission_requests",
};

// Reverses an ALREADY-decided request (approved<->rejected). Only leave
// requests have a persisted side effect (the balance counter) that needs
// correcting — every other kind is computed fresh from the status column
// each time a report or list is fetched, so just flipping the status is
// enough to make it correct everywhere (admin lists, employee view, reports).
async function redecideRequest(db, admin, kind, requestId, action) {
  const table = REQUEST_TABLE_BY_KIND[kind];
  if (!table) return err("invalid kind", 400);
  const newStatus = action === "approve" ? "approved" : "rejected";

  const res = await db.execute({ sql: `SELECT * FROM ${table} WHERE id = ?`, args: [requestId] });
  const request = res.rows[0];
  if (!request) return err("Request not found", 404);
  if (request.status === "pending") return err("الطلب لسه معلق — استخدم زرار الموافقة/الرفض العادي", 400);
  if (request.status === newStatus) return json({ ok: true, unchanged: true });

  if (kind === "leave") {
    const field = leaveBalanceField(request.type);
    const extraField = leaveExtraField(request.type);
    const days = workingDaysInRange(request.date, request.end_date || request.date).length;
    const quota = LEAVE_QUOTAS[request.type]; // undefined for sick — no cap
    if (request.status === "approved" && newStatus === "rejected") {
      // was approved (days already counted as used) → now reversed to rejected: undo the usage
      await db.execute({ sql: `UPDATE employees SET ${field} = MAX(0, ${field} - ?) WHERE id = ?`, args: [days, request.employee_id] });
    } else if (request.status === "rejected" && newStatus === "approved") {
      // was rejected (no usage counted) → now approved: count the usage, but check quota first
      const empRes = await db.execute({ sql: "SELECT * FROM employees WHERE id = ?", args: [request.employee_id] });
      const emp = empRes.rows[0];
      if (quota !== undefined) {
        const usedSoFar = (Number(emp[field]) || 0) + (extraField ? (Number(emp[extraField]) || 0) : 0);
        const remaining = quota - usedSoFar;
        if (remaining < days) return err(`رصيد الإجازة مش كفاية (متبقي ${remaining} من ${quota}، مطلوب ${days})`, 409);
      }
      await db.execute({ sql: `UPDATE employees SET ${field} = ${field} + ? WHERE id = ?`, args: [days, request.employee_id] });
    }
  }

  await db.execute({
    sql: `UPDATE ${table} SET status = ?, decided_at = datetime('now'), decided_by = ? WHERE id = ?`,
    args: [newStatus, admin.id, requestId],
  });
  return json({ ok: true });
}

// Generic list/decide for financial_requests, offclock_requests, permission_requests —
// they all share the same shape (employee_id, status, requested_at, decided_at, decided_by).
const REQUEST_TABLES = new Set(["financial_requests", "offclock_requests", "permission_requests"]);

// Admin-only "who worked on what, on a given day" — shows the FULL project
// classification (code, name, category, type, sub_code) since this view is
// for the admin, unlike the employee-facing simplified code+name+letter.
async function adminTasksByDay(db, employeeId, dateStr) {
  const date = (dateStr && /^\d{4}-\d{2}-\d{2}$/.test(dateStr)) ? dateStr : cairoDateStr();
  let sql = `SELECT DISTINCT t.*, e.name as employee_name, e.emp_code,
                    p.code as p_code, p.name as p_name, p.category, p.type, p.sub_code, p.simple_label
             FROM tasks t
             JOIN employees e ON e.id = t.employee_id
             JOIN task_segments ts ON ts.task_id = t.id
             LEFT JOIN projects p ON p.id = t.project_id
             WHERE ts.date = ?`;
  const args = [date];
  if (employeeId && employeeId !== "all") { sql += " AND t.employee_id = ?"; args.push(Number(employeeId)); }
  sql += " ORDER BY e.emp_code ASC, t.created_at ASC";
  const res = await db.execute({ sql, args });
  return json({ date, tasks: await attachDeliveryStatus(db, await attachSegments(db, res.rows)) });
}

// For the "Deadlines & Delivery Status" admin section — every task in the
// given month (or all-time), full project detail, per-task delivery status.
async function adminTasksByMonth(db, employeeId, monthStr) {
  const isAll = monthStr === "all";
  let sql = `SELECT t.*, e.name as employee_name, e.emp_code,
                    p.code as p_code, p.name as p_name, p.category, p.type, p.sub_code, p.simple_label
             FROM tasks t
             JOIN employees e ON e.id = t.employee_id
             LEFT JOIN projects p ON p.id = t.project_id
             WHERE 1=1`;
  const args = [];
  if (!isAll) { sql += " AND t.date LIKE ?"; args.push(monthLikePattern(monthStr)); }
  if (employeeId && employeeId !== "all") { sql += " AND t.employee_id = ?"; args.push(Number(employeeId)); }
  sql += " ORDER BY e.emp_code ASC, t.created_at ASC";
  const res = await db.execute({ sql, args });
  return json({ tasks: await attachDeliveryStatus(db, await attachSegments(db, res.rows)) });
}

async function adminBirthdays(db) {
  const res = await db.execute("SELECT id, emp_code, name, birth_date FROM employees WHERE birth_date IS NOT NULL AND is_active = 1 ORDER BY emp_code ASC");
  const list = res.rows.map((e) => ({
    id: e.id, emp_code: e.emp_code, name: e.name, birth_date: e.birth_date,
    is_today: isBirthdayToday(e.birth_date),
    days_until: daysUntilBirthday(e.birth_date),
  }));
  list.sort((a, b) => a.days_until - b.days_until);
  return json({ birthdays: list });
}

async function adminEmployeesStatus(db) {
  const today = cairoDateStr();
  const yesterday = addDaysToDateStr(today, -1);

  const [attRes, brkRes, empRes] = await Promise.all([
    db.execute({ sql: "SELECT * FROM attendance WHERE date IN (?, ?) ORDER BY employee_id ASC, created_at ASC", args: [yesterday, today] }),
    db.execute({ sql: "SELECT * FROM breaks WHERE date = ? ORDER BY employee_id ASC, created_at ASC", args: [today] }),
    db.execute("SELECT id, emp_code, name FROM employees WHERE is_active = 1 ORDER BY emp_code ASC"),
  ]);

  const attByEmp = {};
  for (const r of attRes.rows) (attByEmp[r.employee_id] = attByEmp[r.employee_id] || []).push(r);
  const brkByEmp = {};
  for (const r of brkRes.rows) (brkByEmp[r.employee_id] = brkByEmp[r.employee_id] || []).push(r);

  const statuses = empRes.rows.map((emp) => {
    const attRows = attByEmp[emp.id] || [];
    const brkRows = brkByEmp[emp.id] || [];

    let openBreak = null;
    for (const b of brkRows) if (!b.end_time) openBreak = b;

    let pendingIn = null;
    for (const a of attRows) {
      if (a.action === "sign_in") pendingIn = a;
      else if (a.action === "sign_out") pendingIn = null;
    }

    let lastSignOutToday = null;
    for (let i = attRows.length - 1; i >= 0; i--) {
      if (attRows[i].action === "sign_out" && attRows[i].date === today) { lastSignOutToday = attRows[i]; break; }
    }

    const base = { id: emp.id, emp_code: emp.emp_code, name: emp.name };

    if (openBreak) {
      return { ...base, status: "break", since: openBreak.created_at, break_start_time: openBreak.start_time };
    }
    if (pendingIn) {
      return { ...base, status: "signed_in", since: pendingIn.created_at, sign_in_time: pendingIn.time };
    }
    if (lastSignOutToday) {
      let totalSecs = 0, pin = null;
      for (const a of attRows) {
        if (a.action === "sign_in") pin = a;
        else if (a.action === "sign_out" && pin) {
          const inMs = new Date(pin.created_at + "Z").getTime();
          const outMs = new Date(a.created_at + "Z").getTime();
          if (outMs > inMs) totalSecs += Math.floor((outMs - inMs) / 1000);
          pin = null;
        }
      }
      return { ...base, status: "signed_out", sign_out_time: lastSignOutToday.time, worked_seconds: totalSecs };
    }
    return { ...base, status: "not_signed_in" };
  });

  return json({ statuses });
}

const REQUEST_TABLE_TO_TYPE = { financial_requests: "financial", offclock_requests: "offclock", permission_requests: "permission", leave_requests: "leave" };

async function adminListRequests(db, table, status, monthStr) {
  if (!REQUEST_TABLES.has(table)) return err("invalid table", 400);
  const month = monthLikePattern(monthStr);
  const dateCol = table === "financial_requests" ? "r.requested_at" : "r.date";
  const orderBy = status === "pending" ? "r.requested_at ASC" : "r.decided_at DESC";
  const reqType = REQUEST_TABLE_TO_TYPE[table];
  const res = await db.execute({
    sql: `SELECT r.*, e.name as employee_name, e.emp_code, a.name as decided_by_name,
                 (SELECT COUNT(*) FROM request_attachments ra WHERE ra.request_type = ? AND ra.request_id = r.id) as has_attachment
          FROM ${table} r
          JOIN employees e ON e.id = r.employee_id
          LEFT JOIN employees a ON a.id = r.decided_by
          WHERE r.status = ? AND ${dateCol} LIKE ? ORDER BY ${orderBy}`,
    args: [reqType, status, month],
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
