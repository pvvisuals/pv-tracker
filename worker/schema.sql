-- PV Visual Studio Tracker — Turso (SQLite) schema
-- Run with: turso db shell <db-name> < schema.sql

CREATE TABLE IF NOT EXISTS employees (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  emp_code      TEXT,
  name          TEXT NOT NULL,
  phone         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,      -- PBKDF2 hash, format: iterations:saltB64:hashB64
  title         TEXT,
  dept          TEXT,
  secret_q      TEXT,
  secret_a      TEXT,               -- lowercased answer, hashed same way as password
  avatar_url    TEXT,
  role          TEXT NOT NULL DEFAULT 'employee', -- 'employee' | 'admin'
  casual_balance  INTEGER NOT NULL DEFAULT 6,      -- days left this year
  annual_balance  INTEGER NOT NULL DEFAULT 21,     -- days left this year
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,
  employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_employee ON sessions(employee_id);

CREATE TABLE IF NOT EXISTS attendance (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  date        TEXT NOT NULL,   -- YYYY-MM-DD
  action      TEXT NOT NULL,   -- 'sign_in' | 'sign_out'
  time        TEXT NOT NULL,   -- display string, e.g. "09:03:11 AM"
  first_name  TEXT,
  worked      TEXT,            -- display string set on sign_out (informational only)
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_attendance_emp_date ON attendance(employee_id, date);

CREATE TABLE IF NOT EXISTS breaks (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  date        TEXT NOT NULL,
  start_time  TEXT,
  end_time    TEXT,
  duration    INTEGER,        -- seconds — monitoring only, never deducted from hours
  first_name  TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_breaks_emp_date ON breaks(employee_id, date);

CREATE TABLE IF NOT EXISTS tasks (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  project     TEXT,
  name        TEXT,
  description TEXT,
  date        TEXT,
  time        TEXT,
  start_time  TEXT,
  end_time    TEXT,
  duration    INTEGER,
  first_name  TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tasks_emp_date ON tasks(employee_id, date);

CREATE TABLE IF NOT EXISTS leave_requests (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  date        TEXT NOT NULL,          -- day being requested off, YYYY-MM-DD
  type        TEXT NOT NULL,          -- 'casual' | 'annual'
  status      TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'approved' | 'rejected'
  note        TEXT,
  requested_at TEXT NOT NULL DEFAULT (datetime('now')),
  decided_at  TEXT,
  decided_by  INTEGER REFERENCES employees(id)
);
CREATE INDEX IF NOT EXISTS idx_leave_emp ON leave_requests(employee_id);
CREATE INDEX IF NOT EXISTS idx_leave_status ON leave_requests(status);
-- one request per employee per day
CREATE UNIQUE INDEX IF NOT EXISTS uq_leave_emp_date ON leave_requests(employee_id, date);

CREATE TABLE IF NOT EXISTS overtime_requests (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  date        TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'pending',
  note        TEXT,
  requested_at TEXT NOT NULL DEFAULT (datetime('now')),
  decided_at  TEXT,
  decided_by  INTEGER REFERENCES employees(id)
);
CREATE INDEX IF NOT EXISTS idx_ot_emp ON overtime_requests(employee_id);
CREATE INDEX IF NOT EXISTS idx_ot_status ON overtime_requests(status);
CREATE UNIQUE INDEX IF NOT EXISTS uq_ot_emp_date ON overtime_requests(employee_id, date);
