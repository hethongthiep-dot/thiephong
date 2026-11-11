'use strict';
/**
 * Thiệp Cưới Online Hoàn Chỉnh — server
 * Node.js + Express + libsql (@libsql/client).
 * - DB local mặc định: file:./data/wedding.db
 * - DB cloud (Turso): đặt TURSO_DATABASE_URL + TURSO_AUTH_TOKEN
 * - Frontend: public/index.html (bản tĩnh của web hoàn chỉnh)
 * - API: /api/auth/*, /api/invitations/*, /api/photos, /api/wishes, /api/rsvps
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { createClient } = require('@libsql/client');

const PORT = parseInt(process.env.PORT || '3000', 10);
const SESSION_DAYS = 30;
const IS_PROD = process.env.NODE_ENV === 'production';

// ---------------------------------------------------------------- DB setup
function makeDb() {
  if (process.env.TURSO_DATABASE_URL) {
    console.log('[db] Turso cloud:', process.env.TURSO_DATABASE_URL);
    return createClient({
      url: process.env.TURSO_DATABASE_URL,
      authToken: process.env.TURSO_AUTH_TOKEN || undefined,
    });
  }
  const dataDir = path.join(__dirname, 'data');
  fs.mkdirSync(dataDir, { recursive: true });
  const file = path.join(dataDir, 'wedding.db');
  console.log('[db] local file:', file);
  return createClient({ url: 'file:' + file });
}
const db = makeDb();

async function migrate() {
  const sql = fs.readFileSync(path.join(__dirname, 'db', 'schema.sql'), 'utf8')
    .split('\n')
    .filter((line) => !line.trim().startsWith('--'))
    .join('\n');
  const statements = sql
    .split(/;\s*\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  for (const stmt of statements) {
    await db.execute(stmt);
  }
  // Keep databases created by older versions compatible with the richer
  // action-based frontend. SQLite does not add columns for an existing table
  // when CREATE TABLE IF NOT EXISTS is re-run.
  for (const stmt of [
    "ALTER TABLE invitations ADD COLUMN data TEXT DEFAULT '{}'",
    "ALTER TABLE photos ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE rsvps ADD COLUMN adults INTEGER NOT NULL DEFAULT 1",
    "ALTER TABLE rsvps ADD COLUMN children INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE rsvps ADD COLUMN note TEXT DEFAULT ''",
  ]) {
    try {
      await db.execute(stmt);
    } catch (e) {
      if (!/duplicate column|already exists/i.test(String(e))) throw e;
    }
  }
  console.log('[db] migrate ok');
}

// ---------------------------------------------------------------- helpers
function slugify(text) {
  return (text || '')
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/đ/g, 'd')
    .replace(/Đ/g, 'D')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'thiep-cuoi';
}
function makeSlug(groom, bride) {
  const base = slugify(`${groom || ''}-va-${bride || ''}`.replace(/-va-$/, '-va-co-dau'));
  return base === 'va' ? 'thiep-cuoi' : base;
}
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}
function newToken() {
  return crypto.randomBytes(32).toString('hex');
}
function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function setSessionCookie(res, token) {
  const attrs = [
    `session=${token}`,
    'HttpOnly',
    'Path=/',
    'SameSite=Lax',
    `Max-Age=${SESSION_DAYS * 24 * 3600}`,
  ];
  if (IS_PROD) attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');
}

async function authUser(req) {
  const token = parseCookies(req).session;
  return authUserByToken(token);
}

async function authUserByToken(token) {
  if (!token) return null;
  const row = await db.execute({
    sql: 'SELECT s.user_id, s.expires_at, u.id, u.name, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?',
    args: [token],
  });
  if (row.rows.length === 0) return null;
  const s = row.rows[0];
  if (new Date(s.expires_at) < new Date()) {
    await db.execute({ sql: 'DELETE FROM sessions WHERE id = ?', args: [token] });
    return null;
  }
  return { id: s.id, name: s.name, email: s.email };
}
async function requireAuth(req, res, next) {
  const user = await authUser(req);
  if (!user) return res.status(401).json({ error: 'Chưa đăng nhập' });
  req.user = user;
  next();
}
async function isSiteOwner(user) {
  // Tài khoản đăng ký đầu tiên = chủ web, được nhận thiệp cũ chưa có chủ.
  const row = await db.execute('SELECT MIN(id) AS first_id FROM users');
  return !!(row.rows[0] && Number(row.rows[0].first_id) === Number(user.id));
}
async function findInvitationBySlug(slug) {
  const row = await db.execute({
    sql: 'SELECT * FROM invitations WHERE slug = ?',
    args: [slug],
  });
  return row.rows[0] || null;
}
async function findInvitationById(id) {
  const row = await db.execute({
    sql: 'SELECT * FROM invitations WHERE id = ?',
    args: [id],
  });
  return row.rows[0] || null;
}
function publicInvitation(inv) {
  if (!inv) return null;
  return {
    id: inv.id,
    slug: inv.slug,
    groom: inv.groom,
    bride: inv.bride,
    templateId: inv.template_id,
    eventDate: inv.event_date,
    eventTime: inv.event_time,
    venue: inv.venue,
    address: inv.address,
    greeting: inv.greeting,
    groomParents: safeJson(inv.groom_parents, {}),
    brideParents: safeJson(inv.bride_parents, {}),
    events: safeJson(inv.events, []),
    schedule: safeJson(inv.schedule, []),
    dressCode: safeJson(inv.dress_code, []),
    gift: safeJson(inv.gift, {}),
    musicTrack: inv.music_track,
    createdAt: inv.created_at,
  };
}
function safeJson(text, fallback) {
  try { return JSON.parse(text || ''); } catch { return fallback; }
}
function canManage(inv, user) {
  return inv.owner_id !== null && Number(inv.owner_id) === Number(user.id);
}

function actionInvitation(inv) {
  if (!inv) return null;
  const stored = safeJson(inv.data, null);
  const data = stored && typeof stored === 'object' ? stored : {
    inviteText: inv.greeting || '',
    event1: {
      title: 'Lễ Thành Hôn & Tiệc Cưới',
      date: inv.event_date || '',
      time: inv.event_time || '',
      venue: inv.venue || '',
      address: inv.address || '',
    },
    event2: { enabled: false },
    groomFather: safeJson(inv.groom_parents, {}).father || '',
    brideFather: safeJson(inv.bride_parents, {}).father || '',
    schedule: safeJson(inv.schedule, []),
    dressColors: safeJson(inv.dress_code, []),
    giftGroom: safeJson(inv.gift, {}),
    musicTrack: inv.music_track || 'canon',
  };
  return {
    id: Number(inv.id),
    slug: inv.slug,
    groomName: inv.groom,
    brideName: inv.bride,
    templateId: inv.template_id,
    data: JSON.stringify(data),
    createdAt: inv.created_at,
    updatedAt: inv.updated_at,
  };
}

function actionPhoto(row) {
  return {
    id: Number(row.id),
    url: row.data_url,
    caption: row.caption || '',
    kind: row.kind || 'album',
    sortOrder: Number(row.sort_order || 0),
  };
}

function actionWish(row) {
  return {
    id: Number(row.id),
    guestName: row.name || 'Khách',
    message: row.message || '',
    createdAt: row.created_at,
  };
}

function actionRsvp(row) {
  return {
    id: Number(row.id),
    guestName: row.name || 'Khách',
    phone: row.phone || '',
    attending: !!Number(row.attending),
    guestCount: Number(row.guests || 1),
    adults: Number(row.adults || 1),
    children: Number(row.children || 0),
    meal: row.meal || '',
    diet: safeJson(row.dietary, []),
    transport: row.transport || '',
    lodging: row.lodging || '',
    songRequest: row.song_request || '',
    note: row.note || '',
    createdAt: row.created_at,
  };
}

async function requireActionUser(args) {
  const user = await authUserByToken(args && args.sessionToken);
  if (!user) throw new Error('Bạn cần đăng nhập để dùng tính năng này.');
  return user;
}

async function actionInvitationById(id) {
  return findInvitationById(id);
}

async function actionInvitationBySlug(slug) {
  return findInvitationBySlug(slug);
}

function actionDataFields(data) {
  const d = data && typeof data === 'object' ? data : {};
  const e = d.event1 || {};
  return {
    eventDate: e.date || '',
    eventTime: e.time || '',
    venue: e.venue || '',
    address: e.address || '',
    greeting: d.inviteText || '',
    groomParents: { father: d.groomFather || '', mother: d.groomMother || '', order: d.groomOrder || '' },
    brideParents: { father: d.brideFather || '', mother: d.brideMother || '', order: d.brideOrder || '' },
    events: [d.event1 || {}, d.event2 || {}],
    schedule: d.schedule || [],
    dressCode: d.dressColors || [],
    gift: d.giftGroom || {},
    musicTrack: d.musicTrack || 'canon',
  };
}

async function createActionSession(userId) {
  const token = newToken();
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
  await db.execute({
    sql: 'INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)',
    args: [token, userId, expires],
  });
  return token;
}

async function handleAction(action, args, req, res) {
  const a = args || {};
  switch (action) {
    case 'me': {
      const user = await authUserByToken(a.sessionToken);
      return { user };
    }
    case 'register': {
      const name = String(a.name || '').trim();
      const email = String(a.email || '').trim().toLowerCase();
      const password = String(a.password || '');
      if (!name) throw new Error('Bạn nhập tên hiển thị nhé.');
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Email chưa đúng định dạng, bạn kiểm tra lại nhé.');
      if (password.length < 6) throw new Error('Mật khẩu cần ít nhất 6 ký tự nhé.');
      const exists = await db.execute({ sql: 'SELECT id FROM users WHERE email = ?', args: [email] });
      if (exists.rows.length) throw new Error('Email này đã có tài khoản — bạn bấm Đăng nhập nhé.');
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = hashPassword(password, salt);
      const inserted = await db.execute({
        sql: 'INSERT INTO users (name, email, password_hash, password_salt) VALUES (?, ?, ?, ?)',
        args: [name, email, hash, salt],
      });
      const user = { id: Number(inserted.lastInsertRowid), name, email };
      const token = await createActionSession(user.id);
      setSessionCookie(res, token);
      return { token, user };
    }
    case 'login': {
      const email = String(a.email || '').trim().toLowerCase();
      const row = await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [email] });
      const found = row.rows[0];
      if (!found || hashPassword(String(a.password || ''), found.password_salt) !== found.password_hash) {
        throw new Error('Email hoặc mật khẩu chưa đúng, bạn kiểm tra lại nhé.');
      }
      const user = { id: Number(found.id), name: found.name, email: found.email };
      const token = await createActionSession(user.id);
      setSessionCookie(res, token);
      return { token, user };
    }
    case 'logout': {
      if (a.sessionToken) await db.execute({ sql: 'DELETE FROM sessions WHERE id = ?', args: [a.sessionToken] });
      clearSessionCookie(res);
      return { ok: true };
    }
    case 'listInvitations': {
      const user = await requireActionUser(a);
      const owner = await isSiteOwner(user);
      const rows = await db.execute({
        sql: 'SELECT * FROM invitations WHERE owner_id = ? OR (? = 1 AND owner_id IS NULL) ORDER BY updated_at DESC',
        args: [user.id, owner ? 1 : 0],
      });
      const invitations = [];
      for (const inv of rows.rows) {
        const base = actionInvitation(inv);
        const [wishes, rsvps, photos] = await Promise.all([
          db.execute({ sql: 'SELECT COUNT(*) AS count FROM wishes WHERE invitation_id = ?', args: [inv.id] }),
          db.execute({ sql: 'SELECT COUNT(*) AS count, COALESCE(SUM(CASE WHEN attending = 1 THEN 1 ELSE 0 END), 0) AS attending FROM rsvps WHERE invitation_id = ?', args: [inv.id] }),
          db.execute({ sql: 'SELECT COUNT(*) AS count FROM photos WHERE invitation_id = ?', args: [inv.id] }),
        ]);
        invitations.push({
          ...base,
          legacy: inv.owner_id === null,
          wishCount: Number(wishes.rows[0].count || 0),
          rsvpCount: Number(rsvps.rows[0].count || 0),
          attendingCount: Number(rsvps.rows[0].attending || 0),
          photoCount: Number(photos.rows[0].count || 0),
        });
      }
      return { invitations };
    }
    case 'createInvitation': {
      const user = await requireActionUser(a);
      const groom = String(a.groomName || '').trim();
      const bride = String(a.brideName || '').trim();
      if (!groom || !bride) throw new Error('Bạn nhập đủ tên cô dâu và chú rể nhé.');
      let slug = makeSlug(groom, bride);
      let n = 2;
      while (await findInvitationBySlug(slug)) slug = `${makeSlug(groom, bride)}-${n++}`;
      const data = safeJson(a.data, {});
      const f = actionDataFields(data);
      const result = await db.execute({
        sql: `INSERT INTO invitations (slug, owner_id, groom, bride, template_id, event_date, event_time, venue, address, greeting, groom_parents, bride_parents, events, schedule, dress_code, gift, music_track, data)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [slug, user.id, groom, bride, a.templateId || 'sage', f.eventDate, f.eventTime, f.venue, f.address, f.greeting, JSON.stringify(f.groomParents), JSON.stringify(f.brideParents), JSON.stringify(f.events), JSON.stringify(f.schedule), JSON.stringify(f.dressCode), JSON.stringify(f.gift), f.musicTrack, JSON.stringify(data)],
      });
      return { invitation: actionInvitation(await findInvitationById(Number(result.lastInsertRowid))) };
    }
    case 'updateInvitation': {
      const user = await requireActionUser(a);
      const inv = await actionInvitationById(a.id);
      if (!inv || !canManage(inv, user)) throw new Error(!inv ? 'Không tìm thấy thiệp này.' : 'Thiệp này thuộc về tài khoản khác.');
      const data = safeJson(a.data, {});
      const f = actionDataFields(data);
      let slug = inv.slug;
      if (a.regenerateSlug) {
        slug = makeSlug(a.groomName, a.brideName);
        let n = 2;
        while (true) {
          const hit = await findInvitationBySlug(slug);
          if (!hit || Number(hit.id) === Number(a.id)) break;
          slug = `${makeSlug(a.groomName, a.brideName)}-${n++}`;
        }
      }
      await db.execute({
        sql: `UPDATE invitations SET slug = ?, groom = ?, bride = ?, template_id = ?, event_date = ?, event_time = ?, venue = ?, address = ?, greeting = ?, groom_parents = ?, bride_parents = ?, events = ?, schedule = ?, dress_code = ?, gift = ?, music_track = ?, data = ?, updated_at = datetime('now') WHERE id = ?`,
        args: [slug, a.groomName, a.brideName, a.templateId || 'sage', f.eventDate, f.eventTime, f.venue, f.address, f.greeting, JSON.stringify(f.groomParents), JSON.stringify(f.brideParents), JSON.stringify(f.events), JSON.stringify(f.schedule), JSON.stringify(f.dressCode), JSON.stringify(f.gift), f.musicTrack, JSON.stringify(data), a.id],
      });
      return { invitation: actionInvitation(await actionInvitationById(a.id)) };
    }
    case 'deleteInvitation': {
      const user = await requireActionUser(a);
      const inv = await actionInvitationById(a.id);
      if (!inv || !canManage(inv, user)) throw new Error('Bạn không có quyền xóa thiệp này.');
      await db.execute({ sql: 'DELETE FROM invitations WHERE id = ?', args: [a.id] });
      return { ok: true };
    }
    case 'claimInvitation': {
      const user = await requireActionUser(a);
      const inv = await actionInvitationById(a.id);
      if (!inv) throw new Error('Không tìm thấy thiệp này.');
      if (inv.owner_id !== null) throw new Error('Thiệp này đã thuộc về tài khoản khác.');
      if (!(await isSiteOwner(user))) throw new Error('Chỉ tài khoản chủ web mới nhận được thiệp cũ này.');
      await db.execute({ sql: 'UPDATE invitations SET owner_id = ? WHERE id = ?', args: [user.id, a.id] });
      return { ok: true };
    }
    case 'getInvitationBySlug': {
      const inv = await actionInvitationBySlug(a.slug);
      if (!inv) return { found: false, invitation: null, photos: [], wishes: [] };
      const [photos, wishes] = await Promise.all([
        db.execute({ sql: 'SELECT * FROM photos WHERE invitation_id = ? ORDER BY sort_order ASC, id ASC', args: [inv.id] }),
        db.execute({ sql: 'SELECT * FROM wishes WHERE invitation_id = ? ORDER BY id DESC LIMIT 200', args: [inv.id] }),
      ]);
      return { found: true, invitation: actionInvitation(inv), photos: photos.rows.map(actionPhoto), wishes: wishes.rows.map(actionWish) };
    }
    case 'listPhotos': {
      const rows = await db.execute({ sql: 'SELECT * FROM photos WHERE invitation_id = ? ORDER BY sort_order ASC, id ASC', args: [a.invitationId] });
      return { photos: rows.rows.map(actionPhoto) };
    }
    case 'uploadPhoto': {
      const user = await requireActionUser(a);
      const inv = await actionInvitationById(a.invitationId);
      if (!inv || !canManage(inv, user)) throw new Error('Bạn không có quyền sửa thiệp này.');
      const count = await db.execute({ sql: 'SELECT COUNT(*) AS count FROM photos WHERE invitation_id = ?', args: [a.invitationId] });
      const url = `data:${a.mimeType};base64,${a.dataBase64}`;
      const result = await db.execute({ sql: 'INSERT INTO photos (invitation_id, kind, data_url, caption, sort_order) VALUES (?, ?, ?, ?, ?)', args: [a.invitationId, a.kind || 'album', url, a.caption || '', Number(count.rows[0].count || 0)] });
      const row = await db.execute({ sql: 'SELECT * FROM photos WHERE id = ?', args: [result.lastInsertRowid] });
      return { photo: actionPhoto(row.rows[0]) };
    }
    case 'setPhotoKind':
    case 'updatePhotoCaption':
    case 'deletePhoto': {
      const user = await requireActionUser(a);
      const photo = await db.execute({ sql: 'SELECT * FROM photos WHERE id = ?', args: [a.photoId] });
      const row = photo.rows[0];
      const inv = row ? await actionInvitationById(row.invitation_id) : null;
      if (!row || !inv || !canManage(inv, user)) throw new Error('Bạn không có quyền sửa ảnh này.');
      if (action === 'setPhotoKind') await db.execute({ sql: 'UPDATE photos SET kind = ? WHERE id = ?', args: [a.kind, a.photoId] });
      else if (action === 'updatePhotoCaption') await db.execute({ sql: 'UPDATE photos SET caption = ? WHERE id = ?', args: [a.caption || '', a.photoId] });
      else await db.execute({ sql: 'DELETE FROM photos WHERE id = ?', args: [a.photoId] });
      return { ok: true };
    }
    case 'addWish': {
      const inv = await actionInvitationBySlug(a.slug);
      if (!inv) throw new Error('Không tìm thấy thiệp này.');
      const result = await db.execute({ sql: 'INSERT INTO wishes (invitation_id, name, message) VALUES (?, ?, ?)', args: [inv.id, String(a.guestName || 'Khách').trim(), String(a.message || '')] });
      const row = await db.execute({ sql: 'SELECT * FROM wishes WHERE id = ?', args: [result.lastInsertRowid] });
      return { wish: actionWish(row.rows[0]) };
    }
    case 'addRsvp': {
      const inv = await actionInvitationBySlug(a.slug);
      if (!inv) throw new Error('Không tìm thấy thiệp này.');
      const guests = Number(a.guestCount || 1);
      const result = await db.execute({
        sql: 'INSERT INTO rsvps (invitation_id, name, attending, guests, phone, meal, dietary, transport, lodging, song_request, adults, children, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        args: [inv.id, String(a.guestName || 'Khách').trim(), a.attending ? 1 : 0, guests, a.phone || '', a.meal || '', JSON.stringify(a.diet || []), a.transport || '', a.lodging || '', a.songRequest || '', Number(a.adults == null ? 1 : a.adults), Number(a.children || 0), a.note || ''],
      });
      return { ok: true, id: Number(result.lastInsertRowid) };
    }
    case 'listResponses': {
      const user = await requireActionUser(a);
      const inv = await actionInvitationById(a.invitationId);
      if (!inv || !canManage(inv, user)) throw new Error('Bạn không có quyền xem phản hồi của thiệp này.');
      const [wishes, rsvps] = await Promise.all([
        db.execute({ sql: 'SELECT * FROM wishes WHERE invitation_id = ? ORDER BY id DESC LIMIT 500', args: [a.invitationId] }),
        db.execute({ sql: 'SELECT * FROM rsvps WHERE invitation_id = ? ORDER BY id DESC LIMIT 500', args: [a.invitationId] }),
      ]);
      const wishRows = wishes.rows.map(actionWish);
      const rsvpRows = rsvps.rows.map(actionRsvp);
      const attending = rsvpRows.filter((x) => x.attending);
      return { wishes: wishRows, rsvps: rsvpRows, totals: { attendingParties: attending.length, declinedParties: rsvpRows.length - attending.length, attendingGuests: attending.reduce((sum, x) => sum + x.guestCount, 0) } };
    }
    case 'deleteWish':
    case 'deleteRsvp': {
      const user = await requireActionUser(a);
      const id = action === 'deleteWish' ? a.wishId : a.rsvpId;
      const table = action === 'deleteWish' ? 'wishes' : 'rsvps';
      const row = await db.execute({ sql: `SELECT * FROM ${table} WHERE id = ?`, args: [id] });
      const item = row.rows[0];
      const inv = item ? await actionInvitationById(item.invitation_id) : null;
      if (!item || !inv || !canManage(inv, user)) throw new Error('Bạn không có quyền xóa phản hồi này.');
      await db.execute({ sql: `DELETE FROM ${table} WHERE id = ?`, args: [id] });
      return { ok: true };
    }
    default:
      throw new Error(`Hành động không hỗ trợ: ${action}`);
  }
}

// ---------------------------------------------------------------- app
const app = express();
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));

// ---------------- Auth ----------------
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) return res.status(400).json({ error: 'Thiếu tên, email hoặc mật khẩu' });
    if (String(password).length < 6) return res.status(400).json({ error: 'Mật khẩu ít nhất 6 ký tự' });
    const emailNorm = String(email).trim().toLowerCase();
    const exists = await db.execute({ sql: 'SELECT id FROM users WHERE email = ?', args: [emailNorm] });
    if (exists.rows.length) return res.status(409).json({ error: 'Email này đã đăng ký' });
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(String(password), salt);
    const r = await db.execute({
      sql: 'INSERT INTO users (name, email, password_hash, password_salt) VALUES (?, ?, ?, ?)',
      args: [String(name).trim(), emailNorm, hash, salt],
    });
    const userId = Number(r.lastInsertRowid);
    const token = newToken();
    const expires = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
    await db.execute({ sql: 'INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)', args: [token, userId, expires] });
    setSessionCookie(res, token);
    res.json({ user: { id: userId, name: String(name).trim(), email: emailNorm } });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Thiếu email hoặc mật khẩu' });
    const row = await db.execute({
      sql: 'SELECT * FROM users WHERE email = ?',
      args: [String(email).trim().toLowerCase()],
    });
    const user = row.rows[0];
    if (!user || hashPassword(String(password), user.password_salt) !== user.password_hash) {
      return res.status(401).json({ error: 'Email hoặc mật khẩu không đúng' });
    }
    const token = newToken();
    const expires = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
    await db.execute({ sql: 'INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)', args: [token, user.id, expires] });
    setSessionCookie(res, token);
    res.json({ user: { id: user.id, name: user.name, email: user.email } });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

app.post('/api/auth/logout', async (req, res) => {
  const token = parseCookies(req).session;
  if (token) await db.execute({ sql: 'DELETE FROM sessions WHERE id = ?', args: [token] });
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get('/api/auth/me', async (req, res) => {
  const user = await authUser(req);
  if (!user) return res.json({ user: null });
  res.json({ user });
});

// ---------------- Invitations ----------------
// List MY invitations (logged in only)
app.get('/api/invitations', requireAuth, async (req, res) => {
  try {
    const row = await db.execute({
      sql: 'SELECT * FROM invitations WHERE owner_id = ? ORDER BY created_at DESC',
      args: [req.user.id],
    });
    res.json({ invitations: row.rows.map(publicInvitation) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// Get one invitation by slug (public — guest view)
app.get('/api/invitations/:slug', async (req, res) => {
  try {
    const inv = await findInvitationBySlug(req.params.slug);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    res.json({ invitation: publicInvitation(inv) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// Create (logged in only)
app.post('/api/invitations', requireAuth, async (req, res) => {
  try {
    const b = req.body || {};
    if (!b.groom || !b.bride) return res.status(400).json({ error: 'Thiếu tên chú rể / cô dâu' });
    let slug = makeSlug(b.groom, b.bride);
    let n = 2;
    while (await findInvitationBySlug(slug)) slug = `${makeSlug(b.groom, b.bride)}-${n++}`;
    const r = await db.execute({
      sql: `INSERT INTO invitations (slug, owner_id, groom, bride, template_id, event_date, event_time, venue, address, greeting, groom_parents, bride_parents, events, schedule, dress_code, gift, music_track)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        slug, req.user.id, b.groom, b.bride, b.templateId || 'sage',
        b.eventDate || '', b.eventTime || '', b.venue || '', b.address || '',
        b.greeting || '', JSON.stringify(b.groomParents || {}), JSON.stringify(b.brideParents || {}),
        JSON.stringify(b.events || []), JSON.stringify(b.schedule || []),
        JSON.stringify(b.dressCode || []), JSON.stringify(b.gift || {}), b.musicTrack || 'canon',
      ],
    });
    const inv = await findInvitationById(Number(r.lastInsertRowid));
    res.status(201).json({ invitation: publicInvitation(inv) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// Update (owner only; slug never changes)
app.put('/api/invitations/:id', requireAuth, async (req, res) => {
  try {
    const inv = await findInvitationById(req.params.id);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    if (!canManage(inv, req.user)) return res.status(403).json({ error: 'Thiệp này thuộc về tài khoản khác' });
    const b = req.body || {};
    const fields = {
      groom: b.groom, bride: b.bride, template_id: b.templateId,
      event_date: b.eventDate, event_time: b.eventTime, venue: b.venue,
      address: b.address, greeting: b.greeting, music_track: b.musicTrack,
    };
    const sets = [];
    const args = [];
    for (const [k, v] of Object.entries(fields)) {
      if (v !== undefined) { sets.push(`${k} = ?`); args.push(v); }
    }
    for (const [key, col] of [['groomParents', 'groom_parents'], ['brideParents', 'bride_parents'], ['events', 'events'], ['schedule', 'schedule'], ['dressCode', 'dress_code'], ['gift', 'gift']]) {
      if (b[key] !== undefined) { sets.push(`${col} = ?`); args.push(JSON.stringify(b[key])); }
    }
    if (sets.length) {
      sets.push("updated_at = datetime('now')");
      await db.execute({ sql: `UPDATE invitations SET ${sets.join(', ')} WHERE id = ?`, args: [...args, inv.id] });
    }
    res.json({ invitation: publicInvitation(await findInvitationById(inv.id)) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// Delete (owner only)
app.delete('/api/invitations/:id', requireAuth, async (req, res) => {
  try {
    const inv = await findInvitationById(req.params.id);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    if (!canManage(inv, req.user)) return res.status(403).json({ error: 'Thiệp này thuộc về tài khoản khác' });
    await db.execute({ sql: 'DELETE FROM invitations WHERE id = ?', args: [inv.id] });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// Claim an ownerless invitation (only the first registered account = site owner)
app.post('/api/invitations/:id/claim', requireAuth, async (req, res) => {
  try {
    const inv = await findInvitationById(req.params.id);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    if (inv.owner_id !== null) return res.status(409).json({ error: 'Thiệp này đã thuộc về tài khoản khác' });
    if (!(await isSiteOwner(req.user))) return res.status(403).json({ error: 'Chỉ tài khoản chủ web (đăng ký đầu tiên) mới nhận được thiệp cũ' });
    await db.execute({ sql: 'UPDATE invitations SET owner_id = ? WHERE id = ?', args: [req.user.id, inv.id] });
    res.json({ invitation: publicInvitation(await findInvitationById(inv.id)) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// ---------------- Photos ----------------
app.get('/api/invitations/:slug/photos', async (req, res) => {
  try {
    const inv = await findInvitationBySlug(req.params.slug);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    const row = await db.execute({
      sql: 'SELECT id, kind, data_url, caption, created_at FROM photos WHERE invitation_id = ? ORDER BY created_at ASC',
      args: [inv.id],
    });
    res.json({ photos: row.rows.map((p) => ({ id: p.id, kind: p.kind, dataUrl: p.data_url, caption: p.caption, createdAt: p.created_at })) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

app.post('/api/invitations/:slug/photos', requireAuth, async (req, res) => {
  try {
    const inv = await findInvitationBySlug(req.params.slug);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    if (!canManage(inv, req.user)) return res.status(403).json({ error: 'Thiệp này thuộc về tài khoản khác' });
    const { dataUrl, kind, caption } = req.body || {};
    if (!dataUrl || typeof dataUrl !== 'string' || !dataUrl.startsWith('data:image/')) {
      return res.status(400).json({ error: 'Ảnh phải là data URL (data:image/...)' });
    }
    const r = await db.execute({
      sql: 'INSERT INTO photos (invitation_id, kind, data_url, caption) VALUES (?, ?, ?, ?)',
      args: [inv.id, kind || 'album', dataUrl, caption || ''],
    });
    res.status(201).json({ photo: { id: Number(r.lastInsertRowid), kind: kind || 'album', dataUrl, caption: caption || '' } });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

app.patch('/api/photos/:id/caption', requireAuth, async (req, res) => {
  try {
    const row = await db.execute({ sql: 'SELECT * FROM photos WHERE id = ?', args: [req.params.id] });
    const photo = row.rows[0];
    if (!photo) return res.status(404).json({ error: 'Không tìm thấy ảnh' });
    const inv = await findInvitationById(photo.invitation_id);
    if (!canManage(inv, req.user)) return res.status(403).json({ error: 'Thiệp này thuộc về tài khoản khác' });
    await db.execute({ sql: 'UPDATE photos SET caption = ? WHERE id = ?', args: [req.body.caption || '', photo.id] });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

app.delete('/api/photos/:id', requireAuth, async (req, res) => {
  try {
    const row = await db.execute({ sql: 'SELECT * FROM photos WHERE id = ?', args: [req.params.id] });
    const photo = row.rows[0];
    if (!photo) return res.status(404).json({ error: 'Không tìm thấy ảnh' });
    const inv = await findInvitationById(photo.invitation_id);
    if (!canManage(inv, req.user)) return res.status(403).json({ error: 'Thiệp này thuộc về tài khoản khác' });
    await db.execute({ sql: 'DELETE FROM photos WHERE id = ?', args: [photo.id] });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// ---------------- Wishes (public) ----------------
app.get('/api/invitations/:slug/wishes', async (req, res) => {
  try {
    const inv = await findInvitationBySlug(req.params.slug);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    const row = await db.execute({
      sql: 'SELECT id, name, message, created_at FROM wishes WHERE invitation_id = ? ORDER BY created_at DESC',
      args: [inv.id],
    });
    res.json({ wishes: row.rows.map((w) => ({ id: w.id, name: w.name, message: w.message, createdAt: w.created_at })) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

app.post('/api/invitations/:slug/wishes', async (req, res) => {
  try {
    const inv = await findInvitationBySlug(req.params.slug);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    const { name, message } = req.body || {};
    if (!message) return res.status(400).json({ error: 'Thiếu lời chúc' });
    const r = await db.execute({
      sql: 'INSERT INTO wishes (invitation_id, name, message) VALUES (?, ?, ?)',
      args: [inv.id, String(name || 'Khách').trim(), String(message)],
    });
    res.status(201).json({ wish: { id: Number(r.lastInsertRowid), name: String(name || 'Khách').trim(), message: String(message) } });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// ---------------- RSVPs ----------------
// Public totals (guest view)
app.get('/api/invitations/:slug/rsvps/totals', async (req, res) => {
  try {
    const inv = await findInvitationBySlug(req.params.slug);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    const row = await db.execute({
      sql: `SELECT COUNT(*) AS total,
              COALESCE(SUM(CASE WHEN attending = 1 THEN 1 ELSE 0 END), 0) AS attending_households,
              COALESCE(SUM(CASE WHEN attending = 1 THEN guests ELSE 0 END), 0) AS attending_guests
            FROM rsvps WHERE invitation_id = ?`,
      args: [inv.id],
    });
    res.json({ totals: row.rows[0] });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// Owner-only full list
app.get('/api/invitations/:id/rsvps', requireAuth, async (req, res) => {
  try {
    const inv = await findInvitationById(req.params.id);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    if (!canManage(inv, req.user)) return res.status(403).json({ error: 'Thiệp này thuộc về tài khoản khác' });
    const row = await db.execute({
      sql: 'SELECT * FROM rsvps WHERE invitation_id = ? ORDER BY created_at DESC',
      args: [inv.id],
    });
    res.json({ rsvps: row.rows });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// Add RSVP (public — guest)
app.post('/api/invitations/:slug/rsvps', async (req, res) => {
  try {
    const inv = await findInvitationBySlug(req.params.slug);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    const b = req.body || {};
    if (!b.name) return res.status(400).json({ error: 'Thiếu tên khách' });
    const attending = b.attending === false || b.attending === 0 ? 0 : 1;
    const r = await db.execute({
      sql: `INSERT INTO rsvps (invitation_id, name, attending, guests, phone, meal, dietary, transport, lodging, song_request)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        inv.id, String(b.name).trim(), attending, parseInt(b.guests, 10) || 1,
        b.phone || '', b.meal || '', JSON.stringify(b.dietary || []),
        b.transport || '', b.lodging || '', b.songRequest || '',
      ],
    });
    res.status(201).json({ rsvp: { id: Number(r.lastInsertRowid), name: String(b.name).trim(), attending, guests: parseInt(b.guests, 10) || 1 } });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// ---------------- Frontend actions adapter ----------------
// The attached UI is delivered as a single static bundle and talks to a
// small action endpoint. Keep this adapter alongside the REST API so both
// clients remain supported.
app.post('/actions', async (req, res) => {
  try {
    const body = req.body || {};
    const data = await handleAction(body.action, body.args || {}, req, res);
    res.json({ data });
  } catch (e) {
    console.error('[actions]', bodyAction(req.body), e);
    res.json({ error: String(e && e.message ? e.message : e) });
  }
});

function bodyAction(body) {
  return body && body.action ? body.action : 'unknown';
}

// ---------------- Health + static ----------------
app.get('/api/health', async (req, res) => {
  try {
    await db.execute('SELECT 1');
    res.json({ ok: true, db: process.env.TURSO_DATABASE_URL ? 'turso' : 'local' });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) return res.status(404).json({ error: 'Không tìm thấy API' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------------------------------------------------------------- boot
async function start() {
  await migrate();
  app.listen(PORT, () => {
    console.log(`[server] Thiệp Cưới Online Hoàn Chỉnh chạy tại http://localhost:${PORT}`);
  });
}
if (require.main === module) {
  start().catch((e) => { console.error(e); process.exit(1); });
}
module.exports = { app, db, migrate };
