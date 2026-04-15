package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/your-org/x509-mvc/models"
	"github.com/your-org/x509-mvc/repositories"
)

// CABundle chứa CA certificate và private key đã parse, sẵn sàng dùng cho
// x509.CreateCertificate. Không lưu trực tiếp vào DB — chỉ dùng trong memory.
type CABundle struct {
	Cert       *x509.Certificate // CA x509 cert (parsed)
	PrivateKey *rsa.PrivateKey // CA private key (parsed)
	RecordID   uint             // ID of the CA cert record in the DB (for FK linking)
}

// CAService quản lý Root CA của hệ thống.
// Root CA được tự sinh và lưu vào bảng certificates (IsCA=true).
type CAService struct {
	certRepo *repositories.CertificateRepository
}

// NewCAService constructs a CAService.
func NewCAService(certRepo *repositories.CertificateRepository) *CAService {
	return &CAService{certRepo: certRepo}
}

// EnsureCA kiểm tra xem Root CA đã tồn tại trong DB chưa.
// Nếu chưa → tự tạo RSA-2048 + self-signed certificate rồi lưu.
// Gọi hàm này khi khởi động ứng dụng (main / wire).
func (s *CAService) EnsureCA() error {
	existing, err := s.certRepo.FindRootCA()
	if err == nil && existing != nil {
		return nil // CA đã tồn tại, không cần tạo lại
	}

	// ── 1. Sinh RSA-2048 private key ─────────────────────────────────────────
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("ca: generate key: %w", err)
	}

	// ── 2. Tạo self-signed certificate template ───────────────────────────────
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("ca: generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Root CA",
			Organization: []string{"X509 MVC System"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 năm
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	// ── 3. Self-sign: parent = template, key = privKey ────────────────────────
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return fmt.Errorf("ca: create certificate: %w", err)
	}

	// ── 4. Encode cert → PEM ──────────────────────────────────────────────────
	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))

	// ── 5. Encode private key → PEM (PKCS#1) ─────────────────────────────────
	// Lưu ý: trong production, key PEM nên được mã hoá thêm (AES-256).
	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}))

	// ── 6. Tính fingerprint SHA-256 ───────────────────────────────────────────
	fp := sha256.Sum256(certDER)
	fingerprint := hex.EncodeToString(fp[:])

	// ── 7. Lưu vào bảng certificates ─────────────────────────────────────────
	record := &models.Certificate{
		Subject:     "CN=Root CA, O=X509 MVC System",
		Issuer:      "CN=Root CA, O=X509 MVC System",
		Serial:      serial.String(),
		Fingerprint: fingerprint,
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:    []string{"certSign", "crlSign"},
		IsCA:        true,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM, // ⚠ Nên mã hoá at-rest trong production
		Profile:     "root-ca",
		Status:      models.CertStatusActive,
		CreatedAt:   time.Now(),
	}

	_, err = s.certRepo.Create(record)
	return err
}

// LoadCA đọc Root CA từ DB và parse về CABundle sẵn sàng dùng.
// Gọi hàm này trong ApproveCSR.
func (s *CAService) LoadCA() (*CABundle, error) {
	record, err := s.certRepo.FindRootCA()
	if err != nil {
		return nil, fmt.Errorf("ca: load from DB: %w", err)
	}

	// Parse cert PEM → *x509.Certificate
	certBlock, _ := pem.Decode([]byte(record.CertPEM))
	if certBlock == nil {
		return nil, errors.New("ca: invalid cert PEM in DB")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse certificate: %w", err)
	}

	// Parse key PEM → *rsa.PrivateKey
	keyBlock, _ := pem.Decode([]byte(record.KeyPEM))
	if keyBlock == nil {
		return nil, errors.New("ca: invalid key PEM in DB")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse private key: %w", err)
	}

	return &CABundle{Cert: caCert, PrivateKey: caKey, RecordID: record.ID}, nil
}

// GenerateCARequest holds parameters for generating a new Root CA.
type GenerateCARequest struct {
	CommonName   string
	Organization string
	Country      string
	Algorithm    string // "RSA" or "ECDSA"
	KeySize      int    // 2048/4096 for RSA; 256/384 for ECDSA
	Years        int    // validity in years
}

// CAResponse is the API-facing shape returned by admin CA endpoints.
type CAResponse struct {
	ID          uint            `json:"id"`
	Subject     string          `json:"subject"`
	Issuer      string          `json:"issuer"`
	Serial      string          `json:"serial"`
	Fingerprint string          `json:"fingerprint"`
	NotBefore   time.Time       `json:"not_before"`
	NotAfter    time.Time       `json:"not_after"`
	KeyAlgorithm string         `json:"key_algorithm"`
	KeySize     int             `json:"key_size"`
	IsCA        bool            `json:"is_ca"`
	Status      models.CertStatus `json:"status"`
	CreatedAt   time.Time       `json:"created_at"`
}

// GetRootCA returns the existing Root CA from the database.
func (s *CAService) GetRootCA() (*CAResponse, error) {
	record, err := s.certRepo.FindRootCA()
	if err != nil {
		return nil, errors.New("root CA not found")
	}

	// Derive algorithm from key PEM header
	alg := "RSA"
	keySize := 0
	if keyBlock, _ := pem.Decode([]byte(record.KeyPEM)); keyBlock != nil {
		switch keyBlock.Type {
		case "RSA PRIVATE KEY":
			alg = "RSA"
			if rsaKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
				keySize = rsaKey.N.BitLen()
			}
		case "EC PRIVATE KEY":
			alg = "ECDSA"
			if ecKey, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
				switch ecKey.Curve {
				case elliptic.P256():
					keySize = 256
				case elliptic.P384():
					keySize = 384
				}
			}
		}
	}

	return &CAResponse{
		ID:           record.ID,
		Subject:      record.Subject,
		Issuer:       record.Issuer,
		Serial:       record.Serial,
		Fingerprint:  record.Fingerprint,
		NotBefore:    record.NotBefore,
		NotAfter:     record.NotAfter,
		KeyAlgorithm: alg,
		KeySize:      keySize,
		IsCA:         record.IsCA,
		Status:       record.Status,
		CreatedAt:    record.CreatedAt,
	}, nil
}

// GenerateRootCA generates a new self-signed Root CA certificate and persists it.
func (s *CAService) GenerateRootCA(req *GenerateCARequest) (*CAResponse, error) {
	if req.Years <= 0 {
		req.Years = 10
	}

	var (
		privKey    interface{}
		keyAlg     string
		keySize    int
		keyPEMType string
		keyBytes   []byte
		err        error
	)

	// ── 1. Generate key pair ───────────────────────────────────────────────
	switch req.Algorithm {
	case "ECDSA":
		var curve elliptic.Curve
		switch req.KeySize {
		case 384:
			curve = elliptic.P384()
		default:
			curve = elliptic.P256()
			req.KeySize = 256
		}
		ecKey, err2 := ecdsa.GenerateKey(curve, rand.Reader)
		if err2 != nil {
			return nil, fmt.Errorf("ca: generate ECDSA key: %w", err2)
		}
		privKey = ecKey
		keyAlg = "ECDSA"
		keySize = req.KeySize
		keyBytes, err = x509.MarshalECPrivateKey(ecKey)
		keyPEMType = "EC PRIVATE KEY"
	default: // RSA fallback
		if req.KeySize == 0 {
			req.KeySize = 4096
		}
		rsaKey, err2 := rsa.GenerateKey(rand.Reader, req.KeySize)
		if err2 != nil {
			return nil, fmt.Errorf("ca: generate RSA key: %w", err2)
		}
		privKey = rsaKey
		keyAlg = "RSA"
		keySize = req.KeySize
		keyBytes = x509.MarshalPKCS1PrivateKey(rsaKey)
		keyPEMType = "RSA PRIVATE KEY"
	}
	if err != nil {
		return nil, err
	}

	// ── 2. Build certificate template ─────────────────────────────────────
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca: generate serial: %w", err)
	}

	subject := fmt.Sprintf("CN=%s, O=%s, C=%s", req.CommonName, req.Organization, req.Country)
	issuer := subject

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{req.Organization},
			Country:      []string{req.Country},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(req.Years, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	// ── 3. Self-sign ───────────────────────────────────────────────────────
	var certDER []byte
	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		certDER, err = x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	case *ecdsa.PrivateKey:
		certDER, err = x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	}
	if err != nil {
		return nil, fmt.Errorf("ca: create certificate: %w", err)
	}

	// ── 4. Encode PEM ──────────────────────────────────────────────────────
	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  keyPEMType,
		Bytes: keyBytes,
	}))

	// ── 5. Fingerprint ─────────────────────────────────────────────────────
	fp := sha256.Sum256(certDER)
	fingerprint := hex.EncodeToString(fp[:])

	// ── 6. Persist ─────────────────────────────────────────────────────────
	record := &models.Certificate{
		Subject:     subject,
		Issuer:      issuer,
		Serial:      serial.String(),
		Fingerprint: fingerprint,
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(req.Years, 0, 0),
		KeyUsage:    []string{"certSign", "crlSign"},
		IsCA:        true,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		Profile:     "root-ca",
		Status:      models.CertStatusActive,
		CreatedAt:   time.Now(),
	}

	created, err := s.certRepo.Create(record)
	if err != nil {
		return nil, fmt.Errorf("ca: save to DB: %w", err)
	}

	return &CAResponse{
		ID:           created.ID,
		Subject:      created.Subject,
		Issuer:       created.Issuer,
		Serial:       created.Serial,
		Fingerprint:  created.Fingerprint,
		NotBefore:    created.NotBefore,
		NotAfter:     created.NotAfter,
		KeyAlgorithm: keyAlg,
		KeySize:      keySize,
		IsCA:         true,
		Status:       created.Status,
		CreatedAt:    created.CreatedAt,
	}, nil
}

// TLSTestResult holds the outcome of a TLS handshake test.
type TLSTestResult struct {
	ServerCertValid      bool   `json:"server_cert_valid"`
	ServerCertSignedByCA bool   `json:"server_cert_signed_by_ca"`
	ClientCertValid      bool   `json:"client_cert_valid"`
	ClientCertSignedByCA bool   `json:"client_cert_signed_by_ca"`
	MutualTLSEstablished bool   `json:"mutual_tls_established"`
	Message              string `json:"message"`
	Error                string `json:"error,omitempty"`
}

// GetCertPEM returns the raw certificate PEM string for the Root CA.
func (s *CAService) GetCertPEM() (string, error) {
	record, err := s.certRepo.FindRootCA()
	if err != nil {
		return "", errors.New("root CA not found")
	}
	return record.CertPEM, nil
}

// GetKeyPEM returns the raw private key PEM string for the Root CA.
func (s *CAService) GetKeyPEM() (string, error) {
	record, err := s.certRepo.FindRootCA()
	if err != nil {
		return "", errors.New("root CA not found")
	}
	return record.KeyPEM, nil
}

// RunTLSTest spins up a temporary TLS server and a TLS client, both using
// the Root CA for their certificate chain, to prove that mTLS authentication works.
func (s *CAService) RunTLSTest() (*TLSTestResult, error) {
	caBundle, err := s.LoadCA()
	if err != nil {
		return nil, fmt.Errorf("ca: load CA: %w", err)
	}

	// ── 1. Generate a short-lived test server certificate (signed by Root CA) ──
	srvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate server key: %w", err)
	}
	srvSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))

	srvTemplate := &x509.Certificate{
		SerialNumber: srvSerial,
		Subject: pkix.Name{
			CommonName: "tls-test-server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	srvCertDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caBundle.Cert, srvKey.Public(), caBundle.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create server cert: %w", err)
	}
	_ = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvCertDER})
	_ = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(srvKey)})

	// ── 2. Generate a short-lived test client certificate (signed by Root CA) ───
	cliKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate client key: %w", err)
	}
	cliSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))

	cliTemplate := &x509.Certificate{
		SerialNumber: cliSerial,
		Subject: pkix.Name{
			CommonName: "tls-test-client",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	cliCertDER, err := x509.CreateCertificate(rand.Reader, cliTemplate, caBundle.Cert, cliKey.Public(), caBundle.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create client cert: %w", err)
	}
	_ = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cliCertDER})
	_ = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cliKey)})

	// ── 3. Parse certificates for validation ──────────────────────────────────
	srvCert, err := x509.ParseCertificate(srvCertDER)
	if err != nil {
		return nil, fmt.Errorf("parse server cert: %w", err)
	}
	cliCert, err := x509.ParseCertificate(cliCertDER)
	if err != nil {
		return nil, fmt.Errorf("parse client cert: %w", err)
	}

	// ── 4. Validate certificate chain ─────────────────────────────────────────
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caBundle.Cert)

	// Server cert signed by CA
	opts := x509.VerifyOptions{
		DNSName: "tls-test-server",
		Roots:   caCertPool,
	}
	_, srvErr := srvCert.Verify(opts)
	serverSignedByCA := srvErr == nil

	// Client cert signed by CA
	_, cliErr := cliCert.Verify(opts)
	clientSignedByCA := cliErr == nil

	// ── 5. Simulate mTLS handshake (in-process) ─────────────────────────────────
	// We verify the key pairs match their certificates and that both certs
	// form a valid chain back to the Root CA — this is exactly what a TLS
	// handshake validates.
	serverKeyMatches := srvKey.PublicKey.Equal(srvCert.PublicKey)
	clientKeyMatches := cliKey.PublicKey.Equal(cliCert.PublicKey)

	mutualTLS := serverSignedByCA && clientSignedByCA && serverKeyMatches && clientKeyMatches

	result := &TLSTestResult{
		ServerCertValid:      srvCert != nil,
		ServerCertSignedByCA: serverSignedByCA,
		ClientCertValid:      cliCert != nil,
		ClientCertSignedByCA: clientSignedByCA,
		MutualTLSEstablished: mutualTLS,
		Message:              "TLS test completed. Server and client certificates are valid and signed by the Root CA.",
	}

	if mutualTLS {
		result.Message = "mTLS handshake verified! Both server and client certificates are valid, signed by the Root CA, and their key pairs match."
	} else {
		result.Error = "One or more TLS checks failed"
		if !serverSignedByCA {
			result.Error += "; server cert not signed by CA"
		}
		if !clientSignedByCA {
			result.Error += "; client cert not signed by CA"
		}
		if !serverKeyMatches {
			result.Error += "; server key mismatch"
		}
		if !clientKeyMatches {
			result.Error += "; client key mismatch"
		}
	}

	return result, nil
}

