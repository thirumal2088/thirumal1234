CREATE TABLE IF NOT EXISTS staff_photos (
  staff_id INTEGER PRIMARY KEY REFERENCES staff(id),
  jpeg TEXT NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS staff_advances (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  staff_id INTEGER NOT NULL REFERENCES staff(id),
  day TEXT NOT NULL,
  paise INTEGER NOT NULL CHECK (paise > 0),
  reason TEXT NOT NULL DEFAULT '',
  voice TEXT,
  voice_type TEXT,
  request_id TEXT NOT NULL UNIQUE
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS staff_advances_staff ON staff_advances(staff_id, id DESC);
