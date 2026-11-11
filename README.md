# Thiệp Cưới Online Hoàn Chỉnh — Dự án cloud (libsql)

Web thiệp cưới online hoàn chỉnh, đóng gói thành một dự án Node.js deploy được lên cloud.

**Có gì trong web:**
- Tài khoản riêng: đăng ký / đăng nhập (mật khẩu băm PBKDF2, phiên 30 ngày). Chỉ tài khoản đã đăng nhập mới tạo và quản lý thiệp; mỗi tài khoản chỉ thấy thiệp, ảnh, lời chúc và RSVP của chính mình.
- Thiệp cưới: tên chú rể / cô dâu, link theo tên hai bạn không dấu (ví dụ `/minh-tuan-va-thu-hang`), mẫu thiệp (60.150 mẫu), ngày giờ, địa điểm, hai họ, lễ Vu Quy, lịch trình, dress code, mừng cưới VietQR, nhạc nền Canon in D.
- Ảnh theo thiệp (kèm chú thích), sổ lời chúc, RSVP (số hộ / số khách tham dự).
- Khách không cần đăng nhập vẫn mở thiệp theo link và gửi lời chúc / RSVP.
- Hiệu ứng chạy mặc định: hoa rơi, pháo hoa, pháo hoa trái tim, bướm, sân khấu FX, 6 con chuột cùng vẽ thiệp.

**Cơ sở dữ liệu:** libsql — chạy local bằng file `data/wedding.db`, hoặc chuyển sang Turso cloud chỉ bằng 2 biến môi trường.

## Chạy nhanh trên máy

```bash
npm install
npm start
# Mở http://localhost:3000
```

Chạy ở chế độ theo dõi thay đổi (dev):

```bash
npm run dev
```

Chạy riêng phần migrate (tạo bảng):

```bash
npm run migrate
```

## Chuyển sang Turso cloud

1. Tạo tài khoản và database tại https://turso.tech (miễn phí).
2. Lấy URL và token:
   ```bash
   turso db create thiep-cuoi
   turso db show thiep-cuoi --url
   turso db tokens create thiep-cuoi
   ```
3. Tạo file `.env` (copy từ `.env.example`) và điền:
   ```env
   TURSO_DATABASE_URL=libsql://thiep-cuoi-<ten-ban>.turso.io
   TURSO_AUTH_TOKEN=eyJhbGciOi...
   SESSION_SECRET=doi-thanh-chuoi-ngau-nhien-dai
   PORT=3000
   ```
4. Chạy lại `npm start` — server tự tạo bảng trên Turso lần đầu chạy.

Không đặt `TURSO_*` thì app dùng DB local `data/wedding.db` (thư mục `data/` đã nằm trong `.gitignore`).

## Tài khoản đầu tiên và thiệp cũ

- **Đăng ký tài khoản đầu tiên** trên web sau khi deploy — tài khoản này là **chủ web**.
- Thiệp cũ tạo trước khi có tài khoản (chưa có chủ, ví dụ thiệp `ghy & gfyj`) chỉ hiển thị với tài khoản chủ web. Sau khi đăng nhập bằng tài khoản đầu tiên, bấm **"Nhận làm thiệp của tôi"** trên thiệp cũ để gắn nó vào tài khoản của bạn. Các tài khoản đăng ký sau không thấy và không chạm được vào thiệp cũ (kể cả số tài khoản mừng cưới trong đó).

## Deploy lên Fly.io

```bash
flyctl auth login
flyctl launch --no-deploy   # chọn region sin (Singapore), không tạo Postgres
flyctl secrets set TURSO_DATABASE_URL="libsql://..." TURSO_AUTH_TOKEN="..." SESSION_SECRET="chuoi-ngau-nhien-dai"
flyctl deploy
flyctl open
```

File `fly.toml` đã có sẵn. Nếu không dùng Turso mà muốn DB local bền vững trên Fly, bỏ comment khối `[[mounts]]` trong `fly.toml` và tạo volume:

```bash
flyctl volumes create thiep_cuoi_data --size 1
```

## Deploy lên Render

1. Đẩy code lên GitHub.
2. Trên Render chọn **New → Blueprint**, chọn repo (file `render.yaml` đã có sẵn).
3. Vào **Environment** của service, thêm `TURSO_DATABASE_URL` và `TURSO_AUTH_TOKEN`.
4. Deploy — Render tự chạy `npm ci` rồi `node server.js`.

Lưu ý: gói Free của Render dùng ổ đĩa tạm — **bắt buộc dùng Turso** nếu không muốn mất dữ liệu khi service khởi động lại.

## Deploy lên Railway

1. Đẩy code lên GitHub, trên Railway chọn **New Project → Deploy from GitHub repo**.
2. Railway tự nhận diện Node.js, chạy `npm start` (cổng lấy từ biến `PORT` của Railway).
3. Vào **Variables**, thêm `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`, `SESSION_SECRET`.
4. Railway cấp domain `*.up.railway.app` — mở domain đó là dùng được.

Tương tự Render, Railway không giữ ổ đĩa bền theo mặc định — **dùng Turso** để dữ liệu không mất.

## Deploy lên Vercel (tùy chọn)

File `vercel.json` + `api/index.js` đã có sẵn (API chạy dạng serverless, giao diện tĩnh từ `public/`). **Bắt buộc dùng Turso** vì Vercel không có ổ đĩa bền. Thêm 3 biến `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`, `SESSION_SECRET` trong Project Settings → Environment Variables rồi deploy.

## API

Frontend hiện tại gọi `POST /actions` để giữ đúng giao diện bundle đã gửi. Đây là
adapter nội bộ trên cùng Express app, chuyển action sang LibSQL; các REST endpoint
bên dưới vẫn được giữ để tương thích.

| Phương thức | Đường dẫn | Ghi chú |
|---|---|---|
| POST | `/api/auth/register` | `{name, email, password}` |
| POST | `/api/auth/login` | `{email, password}` → cookie phiên 30 ngày |
| POST | `/api/auth/logout` | |
| GET | `/api/auth/me` | Tài khoản hiện tại hoặc `null` |
| GET | `/api/invitations` | Thiệp của tôi (cần đăng nhập) |
| GET | `/api/invitations/:slug` | Xem thiệp công khai (khách) |
| POST | `/api/invitations` | Tạo thiệp (cần đăng nhập) |
| PUT | `/api/invitations/:id` | Sửa thiệp (chủ thiệp) |
| DELETE | `/api/invitations/:id` | Xóa thiệp (chủ thiệp) |
| POST | `/api/invitations/:id/claim` | Nhận thiệp cũ chưa có chủ (chủ web) |
| GET/POST | `/api/invitations/:slug/photos` | Xem / tải ảnh lên (data URL) |
| PATCH | `/api/photos/:id/caption` | Sửa chú thích ảnh |
| DELETE | `/api/photos/:id` | Xóa ảnh |
| GET/POST | `/api/invitations/:slug/wishes` | Lời chúc (khách gửi được) |
| GET | `/api/invitations/:slug/rsvps/totals` | Tổng RSVP công khai |
| GET | `/api/invitations/:id/rsvps` | Danh sách RSVP (chủ thiệp) |
| POST | `/api/invitations/:slug/rsvps` | Gửi RSVP (khách) |
| GET | `/api/health` | Kiểm tra server + DB |

## Cấu trúc thư mục

```
thiep-cuoi-cloud-project/
├── server.js            # Express + API + migrate khi khởi động
├── api/index.js         # Entry serverless cho Vercel
├── db/schema.sql        # users, sessions, invitations, photos, wishes, rsvps
├── scripts/migrate.js   # npm run migrate
├── public/index.html    # Bundle giao diện mới (dữ liệu đi qua backend, không dùng DB offline)
├── Dockerfile           # node:20-alpine
├── fly.toml             # Fly.io
├── render.yaml          # Render Blueprint
├── vercel.json          # Vercel
├── .env.example
└── package.json
```
