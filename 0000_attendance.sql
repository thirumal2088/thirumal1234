CREATE TABLE IF NOT EXISTS staff (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  work TEXT NOT NULL DEFAULT '',
  regular_time TEXT NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS punches (
  staff_id INTEGER NOT NULL REFERENCES staff(id),
  day TEXT NOT NULL,
  time_in TEXT NOT NULL,
  time_out TEXT,
  PRIMARY KEY (staff_id, day)
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS kiosk (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  token_hash TEXT NOT NULL
);
