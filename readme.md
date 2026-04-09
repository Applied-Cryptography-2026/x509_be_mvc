# X509 Management  (MVC)

Golang (Echo Framework) áp dụng kiến trúc MVC 

## 1. Hướng dẫn Khởi tạo Cơ sở dữ liệu (GORM)

Để ứng dụng tự động thiết lập các bảng trong database (AutoMigrate), hãy làm theo 2 bước:

1. **Chuẩn bị MySQL**:
   - Khởi động MySQL
   - Mở Terminal MySQL hoặc MySQL Workbench chạy lệnh: `CREATE DATABASE IF NOT EXISTS x509;`
2. **Chạy Migration**:
   - Từ thư mục gốc của dự án, gõ lệnh sau để GORM tự động tạo bảng vào Database `x509` (gồm users, csrs, certificates, refresh_tokens):
   ```bash
   go run cmd/migration/main.go
   ```

## 2. Hướng dẫn Chạy chương trình

Sau khi kết nối Database thành công, bật Server API (chạy ở cổng 8080):

```bash
go run cmd/app/main.go
```
- API sẽ chạy và lắng nghe tại `http://localhost:8080`.
-  Postman để test API (hãy test Đăng ký và Đăng nhập `/auth/login` để lấy JWT trước nhé).

---

## 3. TODO List

 Phần thao tác nghiệp vụ (Business Logic) hiện tại đã được đánh dấu `TODO: implement` và đang báo `panic`. Dưới đây là danh sách những module cần được lập trình ruột lõi:

### Tính năng về CSR (Yêu cầu cấp chứng chỉ)
- **`CSRRepository`**: Cần viết code truy vấn SQL/GORM cho: `FindAll`, `FindByID`, `FindPending`, `FindByRequesterID`, `Create`, `Update`.
- **`CSRService` & `CSRController`**: Cụ thể hoá logic xử lý request:
  - Khách hàng Gửi yêu cầu CSR (`SubmitCSR`).
  - Lấy danh sách cá nhân / hoặc toàn bộ hệ thống (`GetCSRs`, `GetCSR`).
  - Admin Duyệt hoặc Từ chối CSR (`ApproveCSR`, `RejectCSR`).

### Tính năng về Certificate (Chứng chỉ số)
- **`CertificateRepository`**: Viết mã GORM thao tác: `FindAll`, `FindByID`, `FindBySubject`, `FindByIssuer`, `FindExpired`, `FindRevoked`, `Create`, `Update`, `Delete`.
- **`CertificateService` & `CertificateController`**:
  - Xem danh sách Chứng chỉ (`GetCertificates`, `GetCertificate`).
  - Hành động Dành cho Admin: Ký mới/Nhập chứng chỉ (`ImportCertificate`), Thu hồi (`RevokeCertificate`), Xoá (`DeleteCertificate`), Xác thực bằng Code (`ValidateCertificate`).

### Các Utilities thuật toán (Dịch vụ hỗ trợ mã hoá)
- **`Converter`** (`services/converter.go`): Cần phục hồi các hàm chuyển đổi qua lại giữa struct Go `models.Certificate` và cấu trúc x509 tiêu chuẩn của Package Crypto (`ToModel`, `ToX509`, `keyUsageStrings`, v.v..).
- **`Signer`, `Validator`, `PEM`, `Fingerprint`**: Xử lý logic đọc PEM block, trích xuất mã SHA-256 (Fingerprint), và ký chứng chỉ bằng khoá (CA Signer).
- **`DBRepository`**: Tính năng bọc Transaction an toàn (Database Rollback nếu lệnh lỗi) hiện đang chờ code.
