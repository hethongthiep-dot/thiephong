'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const assert = require('node:assert/strict');
const { describe, it, before, after } = require('node:test');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'thiep-cuoi-test-'));
process.env.LOCAL_DB_PATH = path.join(tmpDir, 'test.db');
process.env.SESSION_SECRET = 'test-hmac-secret-key-for-unit-tests-only';
delete process.env.TURSO_DATABASE_URL;
delete process.env.TURSO_AUTH_TOKEN;

const { app, db, migrate } = require('../server');

// 1x1 transparent PNG in base64
const TINY_PNG_BASE64 =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';

describe('Thiệp Cưới Cloud API & Security', () => {
  let server;
  let baseUrl;

  before(async () => {
    await migrate();
    server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
    if (db && typeof db.close === 'function') {
      try {
        db.close();
      } catch (_err) {
        // ignore close errors during test teardown
      }
    }
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_err) {
      // ignore Windows file lock on temp db cleanup
    }
  });

  async function callAction(action, args = {}, cookie = '') {
    const headers = { 'content-type': 'application/json' };
    if (cookie) headers.cookie = cookie;
    const res = await fetch(`${baseUrl}/actions`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ action, args }),
    });
    const body = await res.json();
    const setCookie = res.headers.get('set-cookie') || '';
    return { status: res.status, headers: res.headers, body, setCookie };
  }

  it('phục vụ static assets và HTTP Security Headers chuẩn', async () => {
    const res = await fetch(`${baseUrl}/`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.equal(res.headers.get('x-powered-by'), null);
    assert.ok(res.headers.get('content-security-policy')?.includes("default-src 'self'"));

    const html = await res.text();
    assert.ok(html.includes('/app.css'));
    assert.ok(html.includes('/app.js'));

    const [cssRes, jsRes, healthRes] = await Promise.all([
      fetch(`${baseUrl}/app.css`),
      fetch(`${baseUrl}/app.js`),
      fetch(`${baseUrl}/api/health`),
    ]);
    assert.equal(cssRes.status, 200);
    assert.equal(jsRes.status, 200);
    assert.equal(healthRes.status, 200);
    const health = await healthRes.json();
    assert.equal(health.ok, true);
    assert.equal(health.db, 'local');

    // Kiểm tra 6 tranh minh họa mẫu thiệp được phục vụ đầy đủ
    for (const artName of ['royal', 'traditional', 'garden', 'romantic', 'midnight', 'ocean']) {
      const artRes = await fetch(`${baseUrl}/illustrations/${artName}.jpg`);
      assert.equal(artRes.status, 200, `Missing illustration ${artName}`);
      assert.equal(artRes.headers.get('content-type'), 'image/jpeg');
    }
  });

  it('luồng Auth: đăng ký, ký session HMAC, đăng nhập sai/đúng, fallback cookie và đăng xuất', async () => {
    const reg = await callAction('register', {
      name: 'Chủ Web',
      email: 'owner@example.com',
      password: 'password123',
    });
    assert.ok(!reg.body.error, reg.body.error);
    assert.equal(reg.body.data.user.email, 'owner@example.com');
    assert.ok(reg.body.data.token.includes('.')); // signed HMAC token
    assert.ok(reg.setCookie.includes('HttpOnly'));

    const sessionCookie = reg.setCookie.split(';')[0];

    // Xác thực qua sessionToken
    const meByToken = await callAction('me', { sessionToken: reg.body.data.token });
    assert.equal(meByToken.body.data.user.email, 'owner@example.com');

    // Xác thực fallback qua HttpOnly cookie khi không truyền sessionToken
    const meByCookie = await callAction('me', {}, sessionCookie);
    assert.equal(meByCookie.body.data.user.email, 'owner@example.com');

    // Token giả mạo chữ ký phải bị từ chối
    const tampered = await callAction('me', { sessionToken: `${reg.body.data.token}dead` });
    assert.equal(tampered.body.data.user, null);

    // Sai mật khẩu
    const badLogin = await callAction('login', {
      email: 'owner@example.com',
      password: 'wrong-password',
    });
    assert.ok(badLogin.body.error);

    // Đăng xuất xóa session
    const logout = await callAction('logout', { sessionToken: reg.body.data.token });
    assert.equal(logout.body.data.ok, true);
    const meAfterLogout = await callAction('me', { sessionToken: reg.body.data.token });
    assert.equal(meAfterLogout.body.data.user, null);
  });

  it('luồng Thiệp, Phân quyền, Ảnh binary endpoint, Lời chúc và RSVP', async () => {
    // User 1 (site owner) & User 2
    const u1 = await callAction('login', { email: 'owner@example.com', password: 'password123' });
    const t1 = u1.body.data.token;
    const u2 = await callAction('register', {
      name: 'Khách Tạo Thiệp',
      email: 'guest2@example.com',
      password: 'password123',
    });
    const t2 = u2.body.data.token;

    // Tạo thiệp cũ chưa có chủ (owner_id IS NULL) để test claimInvitation
    const legacyRes = await db.execute({
      sql: "INSERT INTO invitations (slug, owner_id, groom, bride) VALUES (?, NULL, ?, ?)",
      args: ['thiep-cu-test', 'An', 'Binh'],
    });
    const legacyId = Number(legacyRes.lastInsertRowid);

    // User 2 không được nhận thiệp cũ
    const u2Claim = await callAction('claimInvitation', { sessionToken: t2, id: legacyId });
    assert.ok(u2Claim.body.error);

    // User 1 (đăng ký đầu tiên) được nhận thiệp cũ
    const u1Claim = await callAction('claimInvitation', { sessionToken: t1, id: legacyId });
    assert.equal(u1Claim.body.data.ok, true);

    // User 2 tạo thiệp mới
    const created = await callAction('createInvitation', {
      sessionToken: t2,
      groomName: 'Minh Tuấn',
      brideName: 'Thu Hằng',
      templateId: 'burgundy',
      data: JSON.stringify({
        inviteText: 'Kính mời chung vui',
        event1: { date: '2026-12-20', time: '18:00', venue: 'White Palace', address: 'TP.HCM' },
      }),
    });
    assert.ok(!created.body.error, created.body.error);
    const inv = created.body.data.invitation;
    assert.equal(inv.slug, 'minh-tuan-va-thu-hang');

    // Chặn upload ảnh giả mạo XSS (SVG / HTML) và giả mạo magic bytes
    const badSvg = await callAction('uploadPhoto', {
      sessionToken: t2,
      invitationId: inv.id,
      mimeType: 'image/svg+xml',
      dataBase64: Buffer.from('<svg onload="alert(1)"></svg>').toString('base64'),
    });
    assert.ok(badSvg.body.error);

    const fakePng = await callAction('uploadPhoto', {
      sessionToken: t2,
      invitationId: inv.id,
      mimeType: 'image/png',
      dataBase64: Buffer.from('<html><script>alert(1)</script></html>').toString('base64'),
    });
    assert.ok(fakePng.body.error);

    // Upload ảnh PNG hợp lệ
    const uploaded = await callAction('uploadPhoto', {
      sessionToken: t2,
      invitationId: inv.id,
      mimeType: 'image/png',
      dataBase64: TINY_PNG_BASE64,
      caption: 'Ảnh cưới 1',
      kind: 'hero',
    });
    assert.ok(!uploaded.body.error, uploaded.body.error);
    const photo = uploaded.body.data.photo;
    assert.equal(photo.url, `/api/photos/${photo.id}/raw`);

    // Upload thêm ảnh thứ 2 và test reorderPhotos
    const uploaded2 = await callAction('uploadPhoto', {
      sessionToken: t2,
      invitationId: inv.id,
      mimeType: 'image/png',
      dataBase64: TINY_PNG_BASE64,
      caption: 'Ảnh cưới 2',
      kind: 'album',
    });
    assert.ok(!uploaded2.body.error, uploaded2.body.error);
    const photo2 = uploaded2.body.data.photo;

    const reordered = await callAction('reorderPhotos', {
      sessionToken: t2,
      invitationId: inv.id,
      photoIds: [photo2.id, photo.id],
    });
    assert.equal(reordered.body.data.ok, true);

    // getInvitationBySlug trả URL gọn nhẹ theo đúng thứ tự mới, không nhồi data:image vào JSON
    const guestView = await callAction('getInvitationBySlug', { slug: inv.slug });
    assert.equal(guestView.body.data.found, true);
    assert.equal(guestView.body.data.photos.length, 2);
    assert.equal(guestView.body.data.photos[0].id, photo2.id);
    assert.equal(guestView.body.data.photos[0].url, `/api/photos/${photo2.id}/raw`);
    assert.ok(!JSON.stringify(guestView.body).includes('data:image'));

    // Endpoint /api/photos/:id/raw trả binary ảnh thật kèm Cache-Control + ETag / 304 Not Modified
    const rawRes = await fetch(`${baseUrl}/api/photos/${photo.id}/raw`);
    assert.equal(rawRes.status, 200);
    assert.equal(rawRes.headers.get('content-type'), 'image/png');
    assert.ok(rawRes.headers.get('cache-control')?.includes('immutable'));
    const etag = rawRes.headers.get('etag');
    assert.ok(etag);
    const rawBuf = Buffer.from(await rawRes.arrayBuffer());
    assert.deepEqual(rawBuf, Buffer.from(TINY_PNG_BASE64, 'base64'));

    const notModifiedRes = await fetch(`${baseUrl}/api/photos/${photo.id}/raw`, {
      headers: { 'if-none-match': etag },
    });
    assert.equal(notModifiedRes.status, 304);

    // Khách gửi lời chúc & RSVP
    const wish = await callAction('addWish', {
      slug: inv.slug,
      guestName: 'Anh Nam',
      message: 'Chúc hai bạn trăm năm hạnh phúc!',
    });
    assert.equal(wish.body.data.wish.guestName, 'Anh Nam');

    const rsvp = await callAction('addRsvp', {
      slug: inv.slug,
      guestName: 'Chị Lan',
      attending: true,
      guestCount: 2,
      adults: 2,
      children: 0,
    });
    assert.equal(rsvp.body.data.ok, true);

    // User 1 không được xem danh sách RSVP của thiệp thuộc User 2
    const u1Responses = await callAction('listResponses', { sessionToken: t1, invitationId: inv.id });
    assert.ok(u1Responses.body.error);

    // User 2 xem được đầy đủ lời chúc và RSVP + kiểm tra listInvitations đếm đúng
    const u2Responses = await callAction('listResponses', { sessionToken: t2, invitationId: inv.id });
    assert.equal(u2Responses.body.data.wishes.length, 1);
    assert.equal(u2Responses.body.data.totals.attendingGuests, 2);

    const listU2 = await callAction('listInvitations', { sessionToken: t2 });
    assert.equal(listU2.body.data.invitations.length, 1);
    assert.equal(listU2.body.data.invitations[0].wishCount, 1);
    assert.equal(listU2.body.data.invitations[0].rsvpCount, 1);
    assert.equal(listU2.body.data.invitations[0].photoCount, 2);

    // Kiểm tra REST API PUT /api/invitations/:id đồng bộ sang cột data
    const u2Cookie = u2.setCookie.split(';')[0];
    const putRes = await fetch(`${baseUrl}/api/invitations/${inv.id}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: u2Cookie },
      body: JSON.stringify({ venue: 'GEM Center' }),
    });
    assert.equal(putRes.status, 200);
    const afterPut = await callAction('getInvitationBySlug', { slug: inv.slug });
    const parsedData = JSON.parse(afterPut.body.data.invitation.data);
    assert.equal(parsedData.event1.venue, 'GEM Center');
  });
});
