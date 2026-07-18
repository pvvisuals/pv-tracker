# PV Visual Studio Tracker — Turso + Cloudflare Worker migration

## What changed
- The frontend (`index.html`) no longer talks to Supabase directly. It now calls a Cloudflare
  Worker (`worker/`), which is the only thing that talks to the database.
- Database moved to **Turso** (SQLite). Schema: `worker/schema.sql`.
- Passwords and secret-question answers are now hashed (PBKDF2), not stored as plain text.
- Login now returns a session **token** (stored in `localStorage.pv_token`) used as
  `Authorization: Bearer <token>` on every request.
- New: leave requests (casual/annual), overtime requests, an admin approval tab, and a
  monthly hours report that implements the hour-calculation rules you specified.

## 1. Create the Turso database
```bash
turso db create pv-tracker
turso db shell pv-tracker < worker/schema.sql
turso db tokens create pv-tracker      # save this token
turso db show pv-tracker --url         # save this URL (libsql://...)
```

## 2. Deploy the Worker
```bash
cd worker
npm install
wrangler secret put TURSO_URL          # paste the libsql:// URL
wrangler secret put TURSO_AUTH_TOKEN   # paste the token
wrangler deploy
```
Wrangler will print your Worker URL, e.g. `https://pv-tracker-api.yoursubdomain.workers.dev`.

## 3. Point the frontend at your Worker
Open `index.html`, find this line near the top of the `<script>` block:
```js
var API_BASE = "https://pv-tracker-api.YOUR-SUBDOMAIN.workers.dev";
```
Replace it with the URL from step 2, then host `index.html` anywhere static
(Cloudflare Pages, GitHub Pages, or just open it locally for testing).

## First admin
The **first person who registers** automatically gets `role = admin`. You can promote
anyone else later via `POST /api/admin/set-role {employee_id, role}` (as an existing admin).

## Business rules implemented in the Worker (`worker/src/index.js`)
- Work day = 8 hours. Friday & Saturday are excluded entirely from hour calculations
  (not counted as work, not counted as absence).
- **Leave**: an employee (or admin) submits a leave request for a specific date and type
  (`casual` or `annual`). It stays `pending` until an admin approves/rejects it.
  On approval, 1 day is deducted from that balance (6 casual / 21 annual per year) and the
  day is automatically counted as 8 worked hours — no sign-in required.
- **Overtime**: similar request/approval flow, per date.
  - If overtime is **approved** for a day and the person worked more than 8 hours,
    all of the actual time counts (the excess over 8h is reported separately as
    `overtime_hours`).
  - If overtime is **not approved**, the day is capped at 8 counted hours no matter how
    long the person was actually signed in.
  - Either way, `actual_seconds` (real sign-in→sign-out time) is always reported alongside
    `counted_seconds`, so nothing is hidden.
- **Breaks** are informational only — they're logged and shown in the UI, and highlighted
  in red in the day's log if a single break exceeds 30 minutes, but they are **never**
  subtracted from worked hours.
- Monthly report: `GET /api/report/mine?month=YYYY-MM` (employee) or
  `GET /api/admin/report?employee_id=&month=YYYY-MM` (admin) returns a day-by-day
  breakdown plus totals (counted hours, actual hours, overtime hours, absent days,
  leave days taken by type) and the employee's remaining leave balance.

## Known simplifications / things to revisit
- Leave balances reset is not automated (no "new year" job yet) — reset manually per
  employee via SQL or add a small cron Worker later if needed.
- CORS is currently open (`Access-Control-Allow-Origin: *`) for ease of testing; restrict
  it to your actual frontend origin in `worker/src/index.js` before going fully live.
- All Cairo-timezone logic uses `Intl.DateTimeFormat` with `Africa/Cairo`, so it's correct
  regardless of DST changes.
