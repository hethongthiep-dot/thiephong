-- Thiệp Cưới Online Hoàn Chỉnh — schema libsql
-- Chạy bằng: npm run migrate (hoặc server tự chạy khi khởi động)

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS invitations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL UNIQUE,
  owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  groom TEXT NOT NULL DEFAULT '',
  bride TEXT NOT NULL DEFAULT '',
  template_id TEXT NOT NULL DEFAULT 'sage',
  event_date TEXT DEFAULT '',
  event_time TEXT DEFAULT '',
  venue TEXT DEFAULT '',
  address TEXT DEFAULT '',
  greeting TEXT DEFAULT '',
  groom_parents TEXT DEFAULT '{}',
  bride_parents TEXT DEFAULT '{}',
  events TEXT DEFAULT '[]',
  schedule TEXT DEFAULT '[]',
  dress_code TEXT DEFAULT '[]',
  gift TEXT DEFAULT '{}',
  music_track TEXT DEFAULT 'canon',
  data TEXT DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_invitations_slug ON invitations(slug);
CREATE INDEX IF NOT EXISTS idx_invitations_owner ON invitations(owner_id);

CREATE TABLE IF NOT EXISTS photos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invitation_id INTEGER NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,
  kind TEXT NOT NULL DEFAULT 'album',
  data_url TEXT NOT NULL,
  caption TEXT DEFAULT '',
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_photos_invitation ON photos(invitation_id);

CREATE TABLE IF NOT EXISTS wishes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invitation_id INTEGER NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,
  name TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_wishes_invitation ON wishes(invitation_id);

CREATE TABLE IF NOT EXISTS rsvps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invitation_id INTEGER NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,
  name TEXT NOT NULL DEFAULT '',
  attending INTEGER NOT NULL DEFAULT 1,
  guests INTEGER NOT NULL DEFAULT 1,
  phone TEXT DEFAULT '',
  meal TEXT DEFAULT '',
  dietary TEXT DEFAULT '[]',
  transport TEXT DEFAULT '',
  lodging TEXT DEFAULT '',
  song_request TEXT DEFAULT '',
  adults INTEGER NOT NULL DEFAULT 1,
  children INTEGER NOT NULL DEFAULT 0,
  note TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_rsvps_invitation ON rsvps(invitation_id);
