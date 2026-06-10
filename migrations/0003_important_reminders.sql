ALTER TABLE reminders ADD COLUMN important INTEGER NOT NULL DEFAULT 0;
ALTER TABLE reminders ADD COLUMN resend_interval_minutes INTEGER NOT NULL DEFAULT 30;
ALTER TABLE reminders ADD COLUMN confirmation_token TEXT NOT NULL DEFAULT '';
ALTER TABLE reminders ADD COLUMN confirmed_at TEXT;

CREATE INDEX IF NOT EXISTS idx_reminders_confirmation_token ON reminders(confirmation_token);
