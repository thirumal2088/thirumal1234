ALTER TABLE staff ADD COLUMN regular_out TEXT;
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS staff_schedules (
  staff_id INTEGER NOT NULL REFERENCES staff(id),
  effective_day TEXT NOT NULL,
  time_in TEXT NOT NULL,
  time_out TEXT NOT NULL,
  PRIMARY KEY (staff_id, effective_day)
);
