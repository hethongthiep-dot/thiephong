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
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const ALLOWED_IMAGE_MIMES = new Set([
  'image/jpeg',
  'image/jpg',
  'image/png',
  'image/webp',
  'image/gif',
]);
const MAX_PHOTO_BASE64_LEN = 12 * 1024 * 1024; // ~9MB binary image max
const MAX_PHOTOS_PER_INVITATION = 60;

// ---------------------------------------------------------------- logging & input helpers
function sanitizeLog(val) {
  return String(val == null ? '' : val).replace(/[\r\n\0]+/g, ' ').slice(0, 300);
}
function sanitizeText(val, maxLen = 500) {
  return String(val == null ? '' : val).replace(/\0/g, '').trim().slice(0, maxLen);
}

// Bounded in-memory rate limiter (chống spam/brute-force và chống OOM)
const rateBuckets = new Map();
const MAX_RATE_BUCKETS = 5000;
function getClientIp(req) {
  if (!req) return 'unknown';
  const xff = req.headers && req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    return xff.split(',')[0].trim().slice(0, 64);
  }
  return String((req.socket && req.socket.remoteAddress) || req.ip || 'unknown').slice(0, 64);
}
function checkRateLimit(req, scope, limit, windowMs) {
  const now = Date.now();
  if (rateBuckets.size > MAX_RATE_BUCKETS) {
    for (const [k, v] of rateBuckets.entries()) {
      if (v.resetAt <= now) rateBuckets.delete(k);
    }
    if (rateBuckets.size > MAX_RATE_BUCKETS) rateBuckets.clear();
  }
  const key = `${scope}:${getClientIp(req)}`;
  const entry = rateBuckets.get(key);
  if (!entry || entry.resetAt <= now) {
    rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  entry.count += 1;
  return entry.count <= limit;
}

// ---------------------------------------------------------------- DB setup
function makeDb() {
  if (process.env.TURSO_DATABASE_URL) {
    console.log('[ENGINE] [db] Turso cloud:', sanitizeLog(process.env.TURSO_DATABASE_URL));
    return createClient({
      url: process.env.TURSO_DATABASE_URL,
      authToken: process.env.TURSO_AUTH_TOKEN || undefined,
    });
  }
  const file = process.env.LOCAL_DB_PATH
    ? path.resolve(process.env.LOCAL_DB_PATH)
    : path.join(__dirname, 'data', 'wedding.db');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  console.log('[ENGINE] [db] local file:', sanitizeLog(file));
  return createClient({ url: 'file:' + file });
}
const db = makeDb();

async function cleanupExpiredSessions() {
  try {
    await db.execute("DELETE FROM sessions WHERE expires_at < datetime('now')");
  } catch (err) {
    console.error('[ENGINE] [db] cleanupExpiredSessions error:', sanitizeLog(err.message || err));
  }
}

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
  await cleanupExpiredSessions();
  console.log('[ENGINE] [db] migrate ok');
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
function verifyPassword(password, salt, expectedHashHex) {
  if (!password || !salt || !expectedHashHex) return false;
  try {
    const actualBuf = Buffer.from(hashPassword(String(password), String(salt)), 'hex');
    const expectedBuf = Buffer.from(String(expectedHashHex), 'hex');
    if (actualBuf.length === 0 || actualBuf.length !== expectedBuf.length) return false;
    return crypto.timingSafeEqual(actualBuf, expectedBuf);
  } catch (err) {
    console.error('[ENGINE] [auth] verifyPassword error:', sanitizeLog(err.message || err));
    return false;
  }
}
function newToken() {
  return crypto.randomBytes(32).toString('hex');
}
function signSessionToken(rawToken) {
  if (!rawToken || !SESSION_SECRET) return rawToken;
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(rawToken).digest('hex');
  return `${rawToken}.${sig}`;
}
function extractSessionToken(tokenOrSigned) {
  if (!tokenOrSigned || typeof tokenOrSigned !== 'string') return '';
  const trimmed = tokenOrSigned.trim();
  const dotIdx = trimmed.indexOf('.');
  if (dotIdx === -1) {
    return trimmed;
  }
  const raw = trimmed.slice(0, dotIdx);
  const sig = trimmed.slice(dotIdx + 1);
  if (!SESSION_SECRET) return raw;
  try {
    const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(raw).digest('hex');
    const sigBuf = Buffer.from(sig, 'hex');
    const expBuf = Buffer.from(expectedSig, 'hex');
    if (sigBuf.length === 0 || sigBuf.length !== expBuf.length) return '';
    return crypto.timingSafeEqual(sigBuf, expBuf) ? raw : '';
  } catch (err) {
    console.error('[ENGINE] [auth] extractSessionToken error:', sanitizeLog(err.message || err));
    return '';
  }
}
function parseCookies(req) {
  const out = {};
  const header = (req && req.headers && req.headers.cookie) || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) {
      const k = part.slice(0, i).trim();
      const v = part.slice(i + 1).trim();
      try {
        out[k] = decodeURIComponent(v);
      } catch (_err) {
        out[k] = v;
      }
    }
  }
  return out;
}
function setSessionCookie(res, rawToken) {
  const cookieVal = signSessionToken(rawToken);
  const attrs = [
    `session=${cookieVal}`,
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

async function authUserByToken(tokenInput) {
  const token = extractSessionToken(tokenInput);
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
  try {
    return JSON.parse(text || '');
  } catch (_err) {
    return fallback;
  }
}
function canManage(inv, user) {
  return inv.owner_id !== null && Number(inv.owner_id) === Number(user.id);
}
function hasValidImageMagicBytes(buf, mime) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return false;
  if (mime === 'image/jpeg' || mime === 'image/jpg') {
    return buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
  }
  if (mime === 'image/png') {
    return buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47;
  }
  if (mime === 'image/gif') {
    const hdr = buf.subarray(0, 6).toString('ascii');
    return hdr === 'GIF87a' || hdr === 'GIF89a';
  }
  if (mime === 'image/webp') {
    return buf.subarray(0, 4).toString('ascii') === 'RIFF' && buf.subarray(8, 12).toString('ascii') === 'WEBP';
  }
  return false;
}
function validateDataUrlImage(dataUrl) {
  if (!dataUrl || typeof dataUrl !== 'string') {
    return { ok: false, error: 'Dữ liệu ảnh không hợp lệ.' };
  }
  if (dataUrl.length > MAX_PHOTO_BASE64_LEN) {
    return { ok: false, error: 'Ảnh quá lớn (tối đa ~9MB mỗi ảnh).' };
  }
  const match = dataUrl.match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,([A-Za-z0-9+/=\s]+)$/);
  if (!match) {
    return { ok: false, error: 'Định dạng ảnh phải là data URL base64 hợp lệ.' };
  }
  const mime = match[1].toLowerCase();
  if (!ALLOWED_IMAGE_MIMES.has(mime)) {
    return { ok: false, error: 'Chỉ hỗ trợ ảnh JPEG, PNG, WEBP hoặc GIF.' };
  }
  const cleanedBase64 = match[2].replace(/\s+/g, '');
  const buf = Buffer.from(cleanedBase64, 'base64');
  if (!hasValidImageMagicBytes(buf, mime)) {
    return { ok: false, error: 'Nội dung tệp ảnh không khớp với định dạng khai báo.' };
  }
  return { ok: true, dataUrl: `data:${mime};base64,${cleanedBase64}` };
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
  const id = Number(row.id);
  return {
    id,
    url: `/api/photos/${id}/raw`,
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

async function resolveActionUser(args, req) {
  const tokenFromArgs = args && args.sessionToken;
  if (tokenFromArgs) {
    const u = await authUserByToken(tokenFromArgs);
    if (u) return u;
  }
  return authUser(req);
}

async function requireActionUser(args, req) {
  const user = await resolveActionUser(args, req);
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
      const user = await resolveActionUser(a, req);
      return { user };
    }
    case 'register': {
      if (!checkRateLimit(req, 'auth', 15, 60000)) {
        throw new Error('Bạn thao tác quá nhanh, vui lòng thử lại sau 1 phút nhé.');
      }
      const name = sanitizeText(a.name, 120);
      const email = sanitizeText(a.email, 180).toLowerCase();
      const password = String(a.password || '');
      if (!name) throw new Error('Bạn nhập tên hiển thị nhé.');
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Email chưa đúng định dạng, bạn kiểm tra lại nhé.');
      if (password.length < 6 || password.length > 200) throw new Error('Mật khẩu cần từ 6 đến 200 ký tự nhé.');
      const exists = await db.execute({ sql: 'SELECT id FROM users WHERE email = ?', args: [email] });
      if (exists.rows.length) throw new Error('Email này đã có tài khoản — bạn bấm Đăng nhập nhé.');
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = hashPassword(password, salt);
      const inserted = await db.execute({
        sql: 'INSERT INTO users (name, email, password_hash, password_salt) VALUES (?, ?, ?, ?)',
        args: [name, email, hash, salt],
      });
      const user = { id: Number(inserted.lastInsertRowid), name, email };
      const rawToken = await createActionSession(user.id);
      setSessionCookie(res, rawToken);
      return { token: signSessionToken(rawToken), user };
    }
    case 'login': {
      if (!checkRateLimit(req, 'auth', 15, 60000)) {
        throw new Error('Bạn đăng nhập thử quá nhiều lần, vui lòng đợi 1 phút nhé.');
      }
      const email = sanitizeText(a.email, 180).toLowerCase();
      const row = await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [email] });
      const found = row.rows[0];
      if (!found || !verifyPassword(String(a.password || ''), found.password_salt, found.password_hash)) {
        throw new Error('Email hoặc mật khẩu chưa đúng, bạn kiểm tra lại nhé.');
      }
      const user = { id: Number(found.id), name: found.name, email: found.email };
      const rawToken = await createActionSession(user.id);
      setSessionCookie(res, rawToken);
      return { token: signSessionToken(rawToken), user };
    }
    case 'logout': {
      const rawToken = extractSessionToken(a.sessionToken || parseCookies(req).session);
      if (rawToken) await db.execute({ sql: 'DELETE FROM sessions WHERE id = ?', args: [rawToken] });
      clearSessionCookie(res);
      return { ok: true };
    }
    case 'listInvitations': {
      const user = await requireActionUser(a, req);
      const owner = await isSiteOwner(user);
      const rows = await db.execute({
        sql: `SELECT i.*,
                (SELECT COUNT(*) FROM wishes w WHERE w.invitation_id = i.id) AS wish_count,
                (SELECT COUNT(*) FROM rsvps r WHERE r.invitation_id = i.id) AS rsvp_count,
                (SELECT COALESCE(SUM(CASE WHEN r.attending = 1 THEN 1 ELSE 0 END), 0) FROM rsvps r WHERE r.invitation_id = i.id) AS attending_count,
                (SELECT COUNT(*) FROM photos p WHERE p.invitation_id = i.id) AS photo_count
              FROM invitations i
              WHERE i.owner_id = ? OR (? = 1 AND i.owner_id IS NULL)
              ORDER BY i.updated_at DESC`,
        args: [user.id, owner ? 1 : 0],
      });
      const invitations = rows.rows.map((inv) => ({
        ...actionInvitation(inv),
        legacy: inv.owner_id === null,
        wishCount: Number(inv.wish_count || 0),
        rsvpCount: Number(inv.rsvp_count || 0),
        attendingCount: Number(inv.attending_count || 0),
        photoCount: Number(inv.photo_count || 0),
      }));
      return { invitations };
    }
    case 'createInvitation': {
      const user = await requireActionUser(a, req);
      const groom = sanitizeText(a.groomName, 120);
      const bride = sanitizeText(a.brideName, 120);
      if (!groom || !bride) throw new Error('Bạn nhập đủ tên cô dâu và chú rể nhé.');
      let slug = makeSlug(groom, bride);
      let n = 2;
      while (await findInvitationBySlug(slug)) slug = `${makeSlug(groom, bride)}-${n++}`;
      const data = safeJson(a.data, {});
      const f = actionDataFields(data);
      const result = await db.execute({
        sql: `INSERT INTO invitations (slug, owner_id, groom, bride, template_id, event_date, event_time, venue, address, greeting, groom_parents, bride_parents, events, schedule, dress_code, gift, music_track, data)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [slug, user.id, groom, bride, sanitizeText(a.templateId || 'sage', 60), f.eventDate, f.eventTime, f.venue, f.address, f.greeting, JSON.stringify(f.groomParents), JSON.stringify(f.brideParents), JSON.stringify(f.events), JSON.stringify(f.schedule), JSON.stringify(f.dressCode), JSON.stringify(f.gift), f.musicTrack, JSON.stringify(data)],
      });
      return { invitation: actionInvitation(await findInvitationById(Number(result.lastInsertRowid))) };
    }
    case 'updateInvitation': {
      const user = await requireActionUser(a, req);
      const inv = await actionInvitationById(a.id);
      if (!inv || !canManage(inv, user)) throw new Error(!inv ? 'Không tìm thấy thiệp này.' : 'Thiệp này thuộc về tài khoản khác.');
      const groom = sanitizeText(a.groomName, 120) || inv.groom;
      const bride = sanitizeText(a.brideName, 120) || inv.bride;
      const data = safeJson(a.data, {});
      const f = actionDataFields(data);
      let slug = inv.slug;
      if (a.regenerateSlug) {
        slug = makeSlug(groom, bride);
        let n = 2;
        while (true) {
          const hit = await findInvitationBySlug(slug);
          if (!hit || Number(hit.id) === Number(a.id)) break;
          slug = `${makeSlug(groom, bride)}-${n++}`;
        }
      }
      await db.execute({
        sql: `UPDATE invitations SET slug = ?, groom = ?, bride = ?, template_id = ?, event_date = ?, event_time = ?, venue = ?, address = ?, greeting = ?, groom_parents = ?, bride_parents = ?, events = ?, schedule = ?, dress_code = ?, gift = ?, music_track = ?, data = ?, updated_at = datetime('now') WHERE id = ?`,
        args: [slug, groom, bride, sanitizeText(a.templateId || 'sage', 60), f.eventDate, f.eventTime, f.venue, f.address, f.greeting, JSON.stringify(f.groomParents), JSON.stringify(f.brideParents), JSON.stringify(f.events), JSON.stringify(f.schedule), JSON.stringify(f.dressCode), JSON.stringify(f.gift), f.musicTrack, JSON.stringify(data), a.id],
      });
      return { invitation: actionInvitation(await actionInvitationById(a.id)) };
    }
    case 'deleteInvitation': {
      const user = await requireActionUser(a, req);
      const inv = await actionInvitationById(a.id);
      if (!inv || !canManage(inv, user)) throw new Error('Bạn không có quyền xóa thiệp này.');
      await db.execute({ sql: 'DELETE FROM invitations WHERE id = ?', args: [a.id] });
      return { ok: true };
    }
    case 'claimInvitation': {
      const user = await requireActionUser(a, req);
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
        db.execute({ sql: 'SELECT id, kind, caption, sort_order FROM photos WHERE invitation_id = ? ORDER BY sort_order ASC, id ASC', args: [inv.id] }),
        db.execute({ sql: 'SELECT id, name, message, created_at FROM wishes WHERE invitation_id = ? ORDER BY id DESC LIMIT 200', args: [inv.id] }),
      ]);
      return { found: true, invitation: actionInvitation(inv), photos: photos.rows.map(actionPhoto), wishes: wishes.rows.map(actionWish) };
    }
    case 'listPhotos': {
      const rows = await db.execute({ sql: 'SELECT id, kind, caption, sort_order FROM photos WHERE invitation_id = ? ORDER BY sort_order ASC, id ASC', args: [a.invitationId] });
      return { photos: rows.rows.map(actionPhoto) };
    }
    case 'uploadPhoto': {
      const user = await requireActionUser(a, req);
      const inv = await actionInvitationById(a.invitationId);
      if (!inv || !canManage(inv, user)) throw new Error('Bạn không có quyền sửa thiệp này.');
      const count = await db.execute({ sql: 'SELECT COUNT(*) AS count FROM photos WHERE invitation_id = ?', args: [a.invitationId] });
      const currentCount = Number(count.rows[0].count || 0);
      if (currentCount >= MAX_PHOTOS_PER_INVITATION) {
        throw new Error(`Mỗi thiệp hỗ trợ tối đa ${MAX_PHOTOS_PER_INVITATION} ảnh.`);
      }
      const rawUrl = `data:${String(a.mimeType || '').trim()};base64,${String(a.dataBase64 || '').trim()}`;
      const check = validateDataUrlImage(rawUrl);
      if (!check.ok) throw new Error(check.error);
      const kind = sanitizeText(a.kind || 'album', 30) || 'album';
      const caption = sanitizeText(a.caption || '', 300);
      const result = await db.execute({
        sql: 'INSERT INTO photos (invitation_id, kind, data_url, caption, sort_order) VALUES (?, ?, ?, ?, ?)',
        args: [a.invitationId, kind, check.dataUrl, caption, currentCount],
      });
      const row = await db.execute({ sql: 'SELECT id, kind, caption, sort_order FROM photos WHERE id = ?', args: [result.lastInsertRowid] });
      return { photo: actionPhoto(row.rows[0]) };
    }
    case 'setPhotoKind':
    case 'updatePhotoCaption':
    case 'deletePhoto': {
      const user = await requireActionUser(a, req);
      const photo = await db.execute({ sql: 'SELECT * FROM photos WHERE id = ?', args: [a.photoId] });
      const row = photo.rows[0];
      const inv = row ? await actionInvitationById(row.invitation_id) : null;
      if (!row || !inv || !canManage(inv, user)) throw new Error('Bạn không có quyền sửa ảnh này.');
      if (action === 'setPhotoKind') await db.execute({ sql: 'UPDATE photos SET kind = ? WHERE id = ?', args: [sanitizeText(a.kind, 30), a.photoId] });
      else if (action === 'updatePhotoCaption') await db.execute({ sql: 'UPDATE photos SET caption = ? WHERE id = ?', args: [sanitizeText(a.caption || '', 300), a.photoId] });
      else await db.execute({ sql: 'DELETE FROM photos WHERE id = ?', args: [a.photoId] });
      return { ok: true };
    }
    case 'reorderPhotos': {
      const user = await requireActionUser(a, req);
      const inv = await actionInvitationById(a.invitationId);
      if (!inv || !canManage(inv, user)) throw new Error('Bạn không có quyền sửa thiệp này.');
      const ids = Array.isArray(a.photoIds) ? a.photoIds.map((x) => parseInt(x, 10)).filter((x) => Number.isFinite(x) && x > 0) : [];
      for (let i = 0; i < ids.length; i += 1) {
        await db.execute({
          sql: 'UPDATE photos SET sort_order = ? WHERE id = ? AND invitation_id = ?',
          args: [i, ids[i], inv.id],
        });
      }
      return { ok: true };
    }
    case 'addWish': {
      if (!checkRateLimit(req, 'wish', 20, 60000)) {
        throw new Error('Bạn gửi lời chúc quá nhanh, vui lòng đợi ít giây nhé.');
      }
      const inv = await actionInvitationBySlug(a.slug);
      if (!inv) throw new Error('Không tìm thấy thiệp này.');
      const guestName = sanitizeText(a.guestName || 'Khách', 120) || 'Khách';
      const message = sanitizeText(a.message || '', 2000);
      if (!message) throw new Error('Bạn nhập lời chúc trước khi gửi nhé.');
      const result = await db.execute({ sql: 'INSERT INTO wishes (invitation_id, name, message) VALUES (?, ?, ?)', args: [inv.id, guestName, message] });
      const row = await db.execute({ sql: 'SELECT * FROM wishes WHERE id = ?', args: [result.lastInsertRowid] });
      return { wish: actionWish(row.rows[0]) };
    }
    case 'addRsvp': {
      if (!checkRateLimit(req, 'rsvp', 20, 60000)) {
        throw new Error('Bạn gửi xác nhận quá nhanh, vui lòng đợi ít giây nhé.');
      }
      const inv = await actionInvitationBySlug(a.slug);
      if (!inv) throw new Error('Không tìm thấy thiệp này.');
      const guestName = sanitizeText(a.guestName || 'Khách', 120) || 'Khách';
      const guests = Math.min(50, Math.max(1, parseInt(a.guestCount, 10) || 1));
      const adults = Math.min(50, Math.max(0, parseInt(a.adults == null ? 1 : a.adults, 10) || 0));
      const children = Math.min(50, Math.max(0, parseInt(a.children || 0, 10) || 0));
      const result = await db.execute({
        sql: 'INSERT INTO rsvps (invitation_id, name, attending, guests, phone, meal, dietary, transport, lodging, song_request, adults, children, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        args: [
          inv.id,
          guestName,
          a.attending ? 1 : 0,
          guests,
          sanitizeText(a.phone || '', 40),
          sanitizeText(a.meal || '', 100),
          JSON.stringify(Array.isArray(a.diet) ? a.diet.slice(0, 20) : []),
          sanitizeText(a.transport || '', 100),
          sanitizeText(a.lodging || '', 100),
          sanitizeText(a.songRequest || '', 200),
          adults,
          children,
          sanitizeText(a.note || '', 1000),
        ],
      });
      return { ok: true, id: Number(result.lastInsertRowid) };
    }
    case 'listResponses': {
      const user = await requireActionUser(a, req);
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
      const user = await requireActionUser(a, req);
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
      throw new Error(`Hành động không hỗ trợ: ${sanitizeText(action, 60)}`);
  }
}

// ---------------------------------------------------------------- app
const app = express();
app.disable('x-powered-by');

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https://img.vietqr.io https:; media-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none';"
  );
  next();
});

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// ---------------- Auth ----------------
app.post('/api/auth/register', async (req, res) => {
  try {
    if (!checkRateLimit(req, 'auth', 15, 60000)) {
      return res.status(429).json({ error: 'Thao tác quá nhanh, vui lòng thử lại sau 1 phút' });
    }
    const { name, email, password } = req.body || {};
    const nameClean = sanitizeText(name, 120);
    const emailNorm = sanitizeText(email, 180).toLowerCase();
    if (!nameClean || !emailNorm || !password) return res.status(400).json({ error: 'Thiếu tên, email hoặc mật khẩu' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNorm)) return res.status(400).json({ error: 'Email không hợp lệ' });
    if (String(password).length < 6 || String(password).length > 200) return res.status(400).json({ error: 'Mật khẩu từ 6 đến 200 ký tự' });
    const exists = await db.execute({ sql: 'SELECT id FROM users WHERE email = ?', args: [emailNorm] });
    if (exists.rows.length) return res.status(409).json({ error: 'Email này đã đăng ký' });
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(String(password), salt);
    const r = await db.execute({
      sql: 'INSERT INTO users (name, email, password_hash, password_salt) VALUES (?, ?, ?, ?)',
      args: [nameClean, emailNorm, hash, salt],
    });
    const userId = Number(r.lastInsertRowid);
    const token = await createActionSession(userId);
    setSessionCookie(res, token);
    res.json({ user: { id: userId, name: nameClean, email: emailNorm } });
  } catch (e) { console.error('[ENGINE] [auth/register]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    if (!checkRateLimit(req, 'auth', 15, 60000)) {
      return res.status(429).json({ error: 'Thao tác quá nhanh, vui lòng thử lại sau 1 phút' });
    }
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Thiếu email hoặc mật khẩu' });
    const row = await db.execute({
      sql: 'SELECT * FROM users WHERE email = ?',
      args: [sanitizeText(email, 180).toLowerCase()],
    });
    const user = row.rows[0];
    if (!user || !verifyPassword(String(password), user.password_salt, user.password_hash)) {
      return res.status(401).json({ error: 'Email hoặc mật khẩu không đúng' });
    }
    const token = await createActionSession(user.id);
    setSessionCookie(res, token);
    res.json({ user: { id: user.id, name: user.name, email: user.email } });
  } catch (e) { console.error('[ENGINE] [auth/login]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

app.post('/api/auth/logout', async (req, res) => {
  try {
    const rawToken = extractSessionToken(parseCookies(req).session);
    if (rawToken) await db.execute({ sql: 'DELETE FROM sessions WHERE id = ?', args: [rawToken] });
    clearSessionCookie(res);
    res.json({ ok: true });
  } catch (e) { console.error('[ENGINE] [auth/logout]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

app.get('/api/auth/me', async (req, res) => {
  try {
    const user = await authUser(req);
    if (!user) return res.json({ user: null });
    res.json({ user });
  } catch (e) { console.error('[ENGINE] [auth/me]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
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
  } catch (e) { console.error('[ENGINE] [invitations/list]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// Get one invitation by slug (public — guest view)
app.get('/api/invitations/:slug', async (req, res) => {
  try {
    const inv = await findInvitationBySlug(req.params.slug);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    res.json({ invitation: publicInvitation(inv) });
  } catch (e) { console.error('[ENGINE] [invitations/get]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// Create (logged in only)
app.post('/api/invitations', requireAuth, async (req, res) => {
  try {
    const b = req.body || {};
    const groom = sanitizeText(b.groom, 120);
    const bride = sanitizeText(b.bride, 120);
    if (!groom || !bride) return res.status(400).json({ error: 'Thiếu tên chú rể / cô dâu' });
    let slug = makeSlug(groom, bride);
    let n = 2;
    while (await findInvitationBySlug(slug)) slug = `${makeSlug(groom, bride)}-${n++}`;
    const r = await db.execute({
      sql: `INSERT INTO invitations (slug, owner_id, groom, bride, template_id, event_date, event_time, venue, address, greeting, groom_parents, bride_parents, events, schedule, dress_code, gift, music_track)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        slug, req.user.id, groom, bride, sanitizeText(b.templateId || 'sage', 60),
        sanitizeText(b.eventDate || '', 40), sanitizeText(b.eventTime || '', 40), sanitizeText(b.venue || '', 200), sanitizeText(b.address || '', 300),
        sanitizeText(b.greeting || '', 2000), JSON.stringify(b.groomParents || {}), JSON.stringify(b.brideParents || {}),
        JSON.stringify(b.events || []), JSON.stringify(b.schedule || []),
        JSON.stringify(b.dressCode || []), JSON.stringify(b.gift || {}), sanitizeText(b.musicTrack || 'canon', 60),
      ],
    });
    const inv = await findInvitationById(Number(r.lastInsertRowid));
    res.status(201).json({ invitation: publicInvitation(inv) });
  } catch (e) { console.error('[ENGINE] [invitations/create]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// Update (owner only; slug never changes)
app.put('/api/invitations/:id', requireAuth, async (req, res) => {
  try {
    const inv = await findInvitationById(req.params.id);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    if (!canManage(inv, req.user)) return res.status(403).json({ error: 'Thiệp này thuộc về tài khoản khác' });
    const b = req.body || {};
    const fields = {
      groom: b.groom !== undefined ? sanitizeText(b.groom, 120) : undefined,
      bride: b.bride !== undefined ? sanitizeText(b.bride, 120) : undefined,
      template_id: b.templateId !== undefined ? sanitizeText(b.templateId, 60) : undefined,
      event_date: b.eventDate !== undefined ? sanitizeText(b.eventDate, 40) : undefined,
      event_time: b.eventTime !== undefined ? sanitizeText(b.eventTime, 40) : undefined,
      venue: b.venue !== undefined ? sanitizeText(b.venue, 200) : undefined,
      address: b.address !== undefined ? sanitizeText(b.address, 300) : undefined,
      greeting: b.greeting !== undefined ? sanitizeText(b.greeting, 2000) : undefined,
      music_track: b.musicTrack !== undefined ? sanitizeText(b.musicTrack, 60) : undefined,
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
      // Đồng bộ luôn sang cột JSON `data` để frontend bundle hiển thị nhất quán
      const currentData = safeJson(inv.data, null);
      if (currentData && typeof currentData === 'object') {
        const nextData = { ...currentData };
        if (b.greeting !== undefined) nextData.inviteText = fields.greeting;
        if (b.musicTrack !== undefined) nextData.musicTrack = fields.music_track;
        if (b.schedule !== undefined) nextData.schedule = b.schedule;
        if (b.dressCode !== undefined) nextData.dressColors = b.dressCode;
        if (b.gift !== undefined) nextData.giftGroom = b.gift;
        if (b.eventDate !== undefined || b.eventTime !== undefined || b.venue !== undefined || b.address !== undefined) {
          nextData.event1 = {
            ...(nextData.event1 || {}),
            ...(b.eventDate !== undefined ? { date: fields.event_date } : {}),
            ...(b.eventTime !== undefined ? { time: fields.event_time } : {}),
            ...(b.venue !== undefined ? { venue: fields.venue } : {}),
            ...(b.address !== undefined ? { address: fields.address } : {}),
          };
        }
        sets.push('data = ?');
        args.push(JSON.stringify(nextData));
      }
      sets.push("updated_at = datetime('now')");
      await db.execute({ sql: `UPDATE invitations SET ${sets.join(', ')} WHERE id = ?`, args: [...args, inv.id] });
    }
    res.json({ invitation: publicInvitation(await findInvitationById(inv.id)) });
  } catch (e) { console.error('[ENGINE] [invitations/update]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// Delete (owner only)
app.delete('/api/invitations/:id', requireAuth, async (req, res) => {
  try {
    const inv = await findInvitationById(req.params.id);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    if (!canManage(inv, req.user)) return res.status(403).json({ error: 'Thiệp này thuộc về tài khoản khác' });
    await db.execute({ sql: 'DELETE FROM invitations WHERE id = ?', args: [inv.id] });
    res.json({ ok: true });
  } catch (e) { console.error('[ENGINE] [invitations/delete]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
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
  } catch (e) { console.error('[ENGINE] [invitations/claim]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// ---------------- Photos ----------------
app.get('/api/photos/:id/raw', async (req, res) => {
  try {
    const photoId = parseInt(req.params.id, 10);
    if (!Number.isFinite(photoId) || photoId <= 0) {
      return res.status(400).json({ error: 'ID ảnh không hợp lệ' });
    }
    const row = await db.execute({
      sql: 'SELECT id, data_url FROM photos WHERE id = ?',
      args: [photoId],
    });
    const photo = row.rows[0];
    if (!photo || typeof photo.data_url !== 'string') {
      return res.status(404).json({ error: 'Không tìm thấy ảnh' });
    }
    const match = photo.data_url.match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,([A-Za-z0-9+/=\s]+)$/);
    if (!match) {
      return res.status(404).json({ error: 'Dữ liệu ảnh không hợp lệ' });
    }
    const mime = match[1].toLowerCase();
    if (!ALLOWED_IMAGE_MIMES.has(mime)) {
      return res.status(415).json({ error: 'Định dạng ảnh không được hỗ trợ' });
    }
    const buf = Buffer.from(match[2], 'base64');
    const etag = `"photo-${photoId}-${buf.length}"`;
    res.setHeader('ETag', etag);
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    if (req.headers['if-none-match'] === etag) {
      return res.status(304).end();
    }
    res.setHeader('Content-Type', mime);
    res.setHeader('Content-Length', buf.length);
    res.send(buf);
  } catch (e) { console.error('[ENGINE] [photos/raw]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

app.get('/api/invitations/:slug/photos', async (req, res) => {
  try {
    const inv = await findInvitationBySlug(req.params.slug);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    const includeData = req.query && req.query.includeData === '1';
    const sql = includeData
      ? 'SELECT id, kind, data_url, caption, created_at FROM photos WHERE invitation_id = ? ORDER BY sort_order ASC, id ASC'
      : 'SELECT id, kind, caption, created_at FROM photos WHERE invitation_id = ? ORDER BY sort_order ASC, id ASC';
    const row = await db.execute({ sql, args: [inv.id] });
    res.json({
      photos: row.rows.map((p) => ({
        id: Number(p.id),
        kind: p.kind,
        url: `/api/photos/${Number(p.id)}/raw`,
        ...(includeData ? { dataUrl: p.data_url } : {}),
        caption: p.caption,
        createdAt: p.created_at,
      })),
    });
  } catch (e) { console.error('[ENGINE] [photos/list]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

app.post('/api/invitations/:slug/photos', requireAuth, async (req, res) => {
  try {
    const inv = await findInvitationBySlug(req.params.slug);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    if (!canManage(inv, req.user)) return res.status(403).json({ error: 'Thiệp này thuộc về tài khoản khác' });
    const { dataUrl, kind, caption } = req.body || {};
    const check = validateDataUrlImage(dataUrl);
    if (!check.ok) {
      return res.status(400).json({ error: check.error });
    }
    const count = await db.execute({ sql: 'SELECT COUNT(*) AS count FROM photos WHERE invitation_id = ?', args: [inv.id] });
    if (Number(count.rows[0].count || 0) >= MAX_PHOTOS_PER_INVITATION) {
      return res.status(400).json({ error: `Mỗi thiệp hỗ trợ tối đa ${MAX_PHOTOS_PER_INVITATION} ảnh` });
    }
    const cleanKind = sanitizeText(kind || 'album', 30) || 'album';
    const cleanCaption = sanitizeText(caption || '', 300);
    const r = await db.execute({
      sql: 'INSERT INTO photos (invitation_id, kind, data_url, caption) VALUES (?, ?, ?, ?)',
      args: [inv.id, cleanKind, check.dataUrl, cleanCaption],
    });
    const photoId = Number(r.lastInsertRowid);
    res.status(201).json({ photo: { id: photoId, kind: cleanKind, url: `/api/photos/${photoId}/raw`, caption: cleanCaption } });
  } catch (e) { console.error('[ENGINE] [photos/create]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

app.patch('/api/photos/:id/caption', requireAuth, async (req, res) => {
  try {
    const row = await db.execute({ sql: 'SELECT * FROM photos WHERE id = ?', args: [req.params.id] });
    const photo = row.rows[0];
    if (!photo) return res.status(404).json({ error: 'Không tìm thấy ảnh' });
    const inv = await findInvitationById(photo.invitation_id);
    if (!canManage(inv, req.user)) return res.status(403).json({ error: 'Thiệp này thuộc về tài khoản khác' });
    await db.execute({ sql: 'UPDATE photos SET caption = ? WHERE id = ?', args: [sanitizeText(req.body && req.body.caption, 300), photo.id] });
    res.json({ ok: true });
  } catch (e) { console.error('[ENGINE] [photos/caption]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
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
  } catch (e) { console.error('[ENGINE] [photos/delete]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// ---------------- Wishes (public) ----------------
app.get('/api/invitations/:slug/wishes', async (req, res) => {
  try {
    const inv = await findInvitationBySlug(req.params.slug);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    const row = await db.execute({
      sql: 'SELECT id, name, message, created_at FROM wishes WHERE invitation_id = ? ORDER BY created_at DESC LIMIT 200',
      args: [inv.id],
    });
    res.json({ wishes: row.rows.map((w) => ({ id: w.id, name: w.name, message: w.message, createdAt: w.created_at })) });
  } catch (e) { console.error('[ENGINE] [wishes/list]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

app.post('/api/invitations/:slug/wishes', async (req, res) => {
  try {
    if (!checkRateLimit(req, 'wish', 20, 60000)) {
      return res.status(429).json({ error: 'Bạn gửi lời chúc quá nhanh, vui lòng đợi ít giây' });
    }
    const inv = await findInvitationBySlug(req.params.slug);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    const { name, message } = req.body || {};
    const cleanName = sanitizeText(name || 'Khách', 120) || 'Khách';
    const cleanMsg = sanitizeText(message, 2000);
    if (!cleanMsg) return res.status(400).json({ error: 'Thiếu lời chúc' });
    const r = await db.execute({
      sql: 'INSERT INTO wishes (invitation_id, name, message) VALUES (?, ?, ?)',
      args: [inv.id, cleanName, cleanMsg],
    });
    res.status(201).json({ wish: { id: Number(r.lastInsertRowid), name: cleanName, message: cleanMsg } });
  } catch (e) { console.error('[ENGINE] [wishes/create]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
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
  } catch (e) { console.error('[ENGINE] [rsvps/totals]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// Owner-only full list
app.get('/api/invitations/:id/rsvps', requireAuth, async (req, res) => {
  try {
    const inv = await findInvitationById(req.params.id);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    if (!canManage(inv, req.user)) return res.status(403).json({ error: 'Thiệp này thuộc về tài khoản khác' });
    const row = await db.execute({
      sql: 'SELECT * FROM rsvps WHERE invitation_id = ? ORDER BY created_at DESC LIMIT 500',
      args: [inv.id],
    });
    res.json({ rsvps: row.rows });
  } catch (e) { console.error('[ENGINE] [rsvps/list]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
});

// Add RSVP (public — guest)
app.post('/api/invitations/:slug/rsvps', async (req, res) => {
  try {
    if (!checkRateLimit(req, 'rsvp', 20, 60000)) {
      return res.status(429).json({ error: 'Bạn gửi xác nhận quá nhanh, vui lòng đợi ít giây' });
    }
    const inv = await findInvitationBySlug(req.params.slug);
    if (!inv) return res.status(404).json({ error: 'Không tìm thấy thiệp' });
    const b = req.body || {};
    const cleanName = sanitizeText(b.name, 120);
    if (!cleanName) return res.status(400).json({ error: 'Thiếu tên khách' });
    const attending = b.attending === false || b.attending === 0 ? 0 : 1;
    const guests = Math.min(50, Math.max(1, parseInt(b.guests, 10) || 1));
    const r = await db.execute({
      sql: `INSERT INTO rsvps (invitation_id, name, attending, guests, phone, meal, dietary, transport, lodging, song_request)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        inv.id, cleanName, attending, guests,
        sanitizeText(b.phone || '', 40), sanitizeText(b.meal || '', 100), JSON.stringify(Array.isArray(b.dietary) ? b.dietary.slice(0, 20) : []),
        sanitizeText(b.transport || '', 100), sanitizeText(b.lodging || '', 100), sanitizeText(b.songRequest || '', 200),
      ],
    });
    res.status(201).json({ rsvp: { id: Number(r.lastInsertRowid), name: cleanName, attending, guests } });
  } catch (e) { console.error('[ENGINE] [rsvps/create]', sanitizeLog(e.message || e)); res.status(500).json({ error: 'Lỗi máy chủ' }); }
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
    console.error('[ENGINE] [actions]', sanitizeLog(bodyAction(req.body)), sanitizeLog(e && e.message ? e.message : e));
    res.json({ error: String(e && e.message ? e.message : 'Lỗi xử lý yêu cầu') });
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
  } catch (e) {
    console.error('[ENGINE] [health]', sanitizeLog(e && e.message ? e.message : e));
    res.status(500).json({ ok: false, error: 'DB_UNAVAILABLE' });
  }
});

app.use(express.static(path.join(__dirname, 'public'), { maxAge: IS_PROD ? '1h' : 0 }));
app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) return res.status(404).json({ error: 'Không tìm thấy API' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------------------------------------------------------------- boot
async function start() {
  await migrate();
  app.listen(PORT, () => {
    console.log(`[ENGINE] [server] Thiệp Cưới Online Hoàn Chỉnh chạy tại http://localhost:${PORT}`);
  });
}
if (require.main === module) {
  start().catch((e) => { console.error('[ENGINE] [fatal]', sanitizeLog(e && e.message ? e.message : e)); process.exit(1); });
}
module.exports = { app, db, migrate };
