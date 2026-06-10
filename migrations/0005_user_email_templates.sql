CREATE TABLE IF NOT EXISTS user_email_templates (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  email_language TEXT NOT NULL DEFAULT 'zh' CHECK (email_language IN ('zh', 'en')),
  email_template TEXT NOT NULL DEFAULT 'letter' CHECK (email_template IN ('letter', 'card', 'custom')),
  custom_email_html TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
