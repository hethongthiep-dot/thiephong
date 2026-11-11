'use strict';
// Vercel serverless entry: tái sử dụng đúng app Express trong server.js.
// Lưu ý: trên Vercel không có ổ đĩa bền — bắt buộc dùng Turso cloud
// (đặt TURSO_DATABASE_URL + TURSO_AUTH_TOKEN trong Project Settings).
const { app, migrate } = require('../server');

let migrated = false;
module.exports = async (req, res) => {
  if (!migrated) {
    await migrate();
    migrated = true;
  }
  return app(req, res);
};
