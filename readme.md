# X509 Management  (MVC)

Golang backend sử dụng **Echo Framework** theo kiến trúc MVC, quản lý toàn bộ vòng đời của X.509 Certificate: từ khi user tạo CSR, upload lên server, cho đến khi Admin ký và phát hành certificate.

---

## Mục lục

1. [Kiến trúc tổng quan](#1-kiến-trúc-tổng-quan)
2. [Luồng nghiệp vụ chính: CSR → Ký](#2-luồng-nghiệp-vụ-chính-csr--ký)
3. [API Endpoints](#3-api-endpoints)
4. [Hướng dẫn Khởi tạo Database](#4-hướng-dẫn-khởi-tạo-database)
5. [Hướng dẫn Chạy Server](#5-hướng-dẫn-chạy-server)
6. [TODO: Những việc cần implement](#6-todo-những-việc-cần-implement)

---

## 1. Kiến trúc tổng quan

```
client (Postman / Frontend)
        │
        ▼
   Echo HTTP Router  (/router/router.go)
        │
        ▼
   Controller  (/controllers/)
        │
        ▼
   Service     (/services/)        ← business logic, crypto
        │
        ▼
   Repository  (/repositories/)   ← GORM / MySQL
        │
        ▼
   MySQL Database
```

**Các bảng chính trong Database:**

| Bảng              | Mô tả                                              |
|-------------------|----------------------------------------------------|
| `users`           | Tài khoản customer (người yêu cầu certificate)     |
| `csrs`            | CSR do user submit, lưu PEM + trạng thái lifecycle |
| `certificates`    | Certificate đã được ký, lưu PEM + metadata         |
| `refresh_tokens`  | Token xoay vòng cho cả customer lẫn admin          |

---

## 2. Luồng nghiệp vụ chính: CSR → Ký

Đây là luồng **cốt lõi** cần implement. Toàn bộ các bước diễn ra theo thứ tự sau:

```
┌─────────────────────────────────────────────────────────────────────┐
│  PHÍA USER (Customer)                                               │
│                                                                     │
│  Bước 1. Đăng ký / Đăng nhập  →  lấy JWT access token             │
│                                                                     │
│  Bước 2. Tạo CSR ở phía client (ngoài scope của server):           │
│    • Tự sinh cặp khóa (RSA 2048 / ECDSA P-256 / Ed25519)           │
│    • Điền Subject: CN, O, OU, C, ...                                │
│    • Ký CSR bằng private key (tạo file .csr / .pem)                │
│    • Lưu private key ở local — KHÔNG bao giờ gửi lên server        │
│                                                                     │
│  Bước 3. Upload CSR lên server                                      │
│    POST /customer/csrs                                              │
│    Body: { "pem": "-----BEGIN CERTIFICATE REQUEST-----\n..." }      │
│    → Server parse, validate, lưu vào bảng csrs (status=pending)    │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                │  (Admin nhận thông báo có CSR mới)
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHÍA ADMIN                                                         │
│                                                                     │
│  Bước 4. Đăng nhập Admin  →  lấy Admin JWT                         │
│                                                                     │
│  Bước 5. Xem danh sách CSR đang chờ                                 │
│    GET /admin/csrs?status=pending                                   │
│                                                                     │
│  Bước 6. Duyệt hoặc Từ chối CSR                                     │
│    POST /admin/csrs/:id/approve  →  status = approved              │
│    POST /admin/csrs/:id/reject   →  status = rejected              │
│                                                                     │
│  Bước 7. Ký Certificate (sau khi approve)                           │
│    • Dùng CA private key đã được cấu hình sẵn trên server           │
│    • Server đọc CSR PEM, ký bằng CA key, tạo Certificate PEM        │
│    • Lưu vào bảng certificates, liên kết với CSR                    │
│    • Cập nhật csrs.status = issued                                  │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  USER LẤY CERTIFICATE                                               │
│                                                                     │
│  Bước 8. User lấy certificate đã được ký                            │
│    GET /customer/csrs/:id  →  xem trạng thái CSR của mình          │
│    GET /customer/certificates/:id  →  tải về Certificate PEM        │
└─────────────────────────────────────────────────────────────────────┘
```

### Trạng thái CSR (State Machine)

```
  [submit]       [admin approve]      [ký xong]
   pending  ──►   approved    ──►     issued
      │
      │ [admin reject]
      ▼
   rejected
```

---

## 3. API Endpoints

> **Lưu ý**: Tất cả các route protected đều cần header `Authorization: Bearer <access_token>`.

### 3.1 Public — Không cần xác thực

| Method | Path             | Mô tả                              |
|--------|------------------|------------------------------------|
| GET    | `/health`        | Health check                       |
| POST   | `/auth/register` | Đăng ký tài khoản customer         |
| POST   | `/auth/login`    | Đăng nhập customer, lấy JWT        |
| POST   | `/auth/refresh`  | Làm mới access token (cookie)      |
| POST   | `/admin/login`   | Đăng nhập admin, lấy Admin JWT     |
| POST   | `/admin/refresh` | Làm mới admin access token         |

---

### 3.2 Customer — Cần JWT của customer (`/customer/*`)

#### Auth

| Method | Path                | Mô tả                     |
|--------|---------------------|---------------------------|
| POST   | `/customer/logout`  | Đăng xuất, hủy token      |

#### CSR

| Method | Path                   | Mô tả                                                |
|--------|------------------------|------------------------------------------------------|
| POST   | `/customer/csrs`       | **Upload CSR** — gửi PEM lên để admin ký             |
| GET    | `/customer/csrs`       | Xem danh sách CSR của bản thân                       |
| GET    | `/customer/csrs/:id`   | Xem chi tiết 1 CSR (bao gồm trạng thái hiện tại)    |

**Request body mẫu cho `POST /customer/csrs`:**
```json
{
  "pem": "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...==\n-----END CERTIFICATE REQUEST-----"
}
```

**Response mẫu:**
```json
{
  "id": 7,
  "subject": "CN=alice.example.com",
  "key_algorithm": "RSA",
  "signature_algorithm": "SHA256WithRSA",
  "dns_names": ["alice.example.com"],
  "status": "pending",
  "created_at": "2026-04-12T00:00:00Z"
}
```

#### Certificate

| Method | Path                          | Mô tả                                   |
|--------|-------------------------------|-----------------------------------------|
| GET    | `/customer/certificates`      | Xem danh sách certificate đã được cấp  |
| GET    | `/customer/certificates/:id`  | Lấy PEM của certificate cụ thể         |

---

### 3.3 Admin — Cần JWT của admin (`/admin/*`)

#### Auth & Quản lý tài khoản

| Method | Path                      | Mô tả                        |
|--------|---------------------------|------------------------------|
| POST   | `/admin/logout`           | Đăng xuất admin              |
| POST   | `/admin/change-password`  | Đổi mật khẩu admin           |

#### Quản lý CSR

| Method | Path                        | Mô tả                                                 |
|--------|-----------------------------|-------------------------------------------------------|
| GET    | `/admin/csrs`               | Lấy toàn bộ CSR (filter theo `?status=pending`, v.v.) |
| GET    | `/admin/csrs/:id`           | Xem chi tiết CSR                                      |
| POST   | `/admin/csrs/:id/approve`   | **Duyệt CSR** — chuyển status sang `approved`         |
| POST   | `/admin/csrs/:id/reject`    | **Từ chối CSR** — chuyển status sang `rejected`       |

**Request body mẫu cho `/approve` hoặc `/reject`:**
```json
{
  "notes": "Thông tin hợp lệ, đã xác minh domain."
}
```

#### Quản lý Certificate

| Method | Path                             | Mô tả                                           |
|--------|----------------------------------|-------------------------------------------------|
| GET    | `/admin/certificates`            | Xem toàn bộ certificate trong hệ thống          |
| GET    | `/admin/certificates/:id`        | Xem chi tiết 1 certificate                      |
| POST   | `/admin/certificates`            | Ký và phát hành certificate từ CSR đã approve   |
| POST   | `/admin/certificates/:id/revoke` | Thu hồi certificate                             |
| DELETE | `/admin/certificates/:id`        | Xóa certificate khỏi hệ thống                  |
| GET    | `/admin/certificates/expiring`   | Danh sách certificate sắp hết hạn               |
| POST   | `/admin/certificates/validate`   | Xác thực 1 certificate PEM                      |

---

## 4. Hướng dẫn Khởi tạo Database

1. **Khởi động MySQL** và tạo database:
   ```sql
   CREATE DATABASE IF NOT EXISTS x509;
   ```

2. **Chạy migration** để GORM tự tạo các bảng (`users`, `csrs`, `certificates`, `refresh_tokens`):
   ```bash
   go run cmd/migration/main.go
   ```

---

## 5. Hướng dẫn Chạy Server

```bash
go run cmd/app/main.go
```

Server khởi chạy tại `http://localhost:8080`. Sử dụng **Postman** để test:
1. Đăng ký/đăng nhập qua `/auth/login` để lấy JWT.
2. Dùng JWT để gọi các API protected.

---

## 6. TODO: Những việc cần implement

Hiện tại các route customer/admin đang được **commented out** trong `router/router.go` và logic nghiệp vụ đang **panic** với `TODO: implement`. Dưới đây là danh sách các module cần hoàn thiện theo thứ tự ưu tiên:

### 🔴 Ưu tiên cao — Core của luồng CSR

#### `repositories/csr_repository.go`
- [ ] `Create(csr *models.CSR) error` — lưu CSR mới vào DB
- [ ] `FindByID(id uint) (*models.CSR, error)` — tìm theo ID
- [ ] `FindByRequesterID(userID uint) ([]models.CSR, error)` — CSR của 1 user
- [ ] `FindPending() ([]models.CSR, error)` — lọc CSR đang chờ
- [ ] `FindAll(filter CSRFilter) ([]models.CSR, error)` — toàn bộ CSR, có filter
- [ ] `Update(csr *models.CSR) error` — cập nhật status, notes, approver

#### `services/csr_service.go`
- [ ] `SubmitCSR(requesterID uint, pemBlock string) (*models.CSR, error)`
  - Parse và validate PEM block (dùng `crypto/x509`)
  - Trích xuất Subject, KeyAlgorithm, DNSNames, IPAddresses
  - Lưu vào DB qua repository
- [ ] `GetCSRs(requesterID *uint) ([]models.CSR, error)` — có thể filter theo user
- [ ] `GetCSR(id uint, requesterID *uint) (*models.CSR, error)` — kiểm tra quyền sở hữu
- [ ] `ApproveCSR(csrID uint, adminID uint, notes string) error`
- [ ] `RejectCSR(csrID uint, adminID uint, notes string) error`

#### `controllers/csr_controller.go`
- [ ] `SubmitCSR(c echo.Context) error` — bind request, gọi service, trả JSON
- [ ] `GetCSRs(c echo.Context) error`
- [ ] `GetCSR(c echo.Context) error`
- [ ] `ApproveCSR(c echo.Context) error`
- [ ] `RejectCSR(c echo.Context) error`

---

### 🔴 Ưu tiên cao — Ký Certificate

#### `services/signer.go`
- [ ] `SignCSR(csr *models.CSR, caKey crypto.PrivateKey, caCert *x509.Certificate) (*x509.Certificate, error)`
  - Đọc CSR PEM → `x509.ParseCertificateRequest`
  - Verify chữ ký tự ký của CSR (`csr.CheckSignature()`)
  - Lập template (`x509.Certificate`) từ thông tin CSR
  - Ký bằng `x509.CreateCertificate(rand.Reader, &template, caCert, publicKey, caKey)`
  - Trả về PEM

#### `repositories/certificate_repository.go`
- [ ] `Create`, `FindByID`, `FindAll`, `FindBySubject`, `FindByIssuer`
- [ ] `FindExpired`, `FindRevoked`, `Update`, `Delete`

#### `services/certificate_service.go`
- [ ] `IssueCertificate(csrID uint) (*models.Certificate, error)` — ký và lưu
- [ ] `RevokeCertificate(certID uint) error`
- [ ] `ValidateCertificate(pemBlock string) (bool, error)`
- [ ] `GetExpiringCertificates(within time.Duration) ([]models.Certificate, error)`

#### `controllers/certificate_controller.go`
- [ ] `ImportCertificate`, `GetCertificates`, `GetCertificate`
- [ ] `RevokeCertificate`, `DeleteCertificate`, `ValidateCertificate`
- [ ] `GetExpiringCertificates`

---

### 🟡 Ưu tiên trung — Utility & Infrastructure

#### `services/converter.go`
- [ ] `ToModel(cert *x509.Certificate) *models.Certificate` — chuyển Go struct sang DB model
- [ ] `ToX509(m *models.Certificate) (*x509.Certificate, error)` — ngược lại
- [ ] `PEMEncode(cert *x509.Certificate) string`
- [ ] `PEMDecode(pem string) (*x509.Certificate, error)`
- [ ] `Fingerprint(cert *x509.Certificate) string` — SHA-256 fingerprint

#### `services/validator.go`
- [ ] Kiểm tra certificate chain
- [ ] Kiểm tra thời hạn, revocation status

#### `repositories/db_repository.go`
- [ ] Bọc transaction an toàn: tự động rollback nếu lỗi

---

### 🟢 Bước cuối — Bật lại các Routes

Sau khi implement xong service/controller/repository, mở comment trong `router/router.go`:

```go
// Uncomment toàn bộ khối customer và admin routes
customer := e.Group("/customer")
customer.Use(jwtMiddlewareFunc)
// ...

admin := e.Group("/admin")
admin.Use(adminJwtMiddlewareFunc)
// ...
```

---

## Ghi chú bảo mật

- **Private key của user KHÔNG BAO GIỜ được gửi lên server.** Server chỉ nhận CSR (public key + thông tin + chữ ký tự ký).
- **CA private key** phải được lưu an toàn phía server (env variable, secret manager — không commit lên git).
- Tất cả API protected phải xác thực JWT và kiểm tra quyền sở hữu (user chỉ thấy CSR/cert của chính họ).
