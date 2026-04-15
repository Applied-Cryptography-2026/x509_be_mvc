package services

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/your-org/x509-mvc/models"
	"github.com/your-org/x509-mvc/repositories"
)

// CSRService handles CSR-related business logic.
type CSRService struct {
	repo      *repositories.CSRRepository
	certRepo  *repositories.CertificateRepository
	caSvc     *CAService
	keyPairRepo *repositories.KeyPairRepository
}

// SubmitCSRRequest is the input for submitting a new CSR.
type SubmitCSRRequest struct {
	CommonName   string   `json:"common_name"`
	DNSNames     []string `json:"dns_names"`
	IPAddresses  []string `json:"ip_addresses"`
	KeyAlgorithm string   `json:"key_algorithm"`
	KeyPairID    uint     `json:"key_pair_id"`
}

// NewCSRService constructs a CSRService.
func NewCSRService(
	repo *repositories.CSRRepository,
	certRepo *repositories.CertificateRepository,
	caSvc *CAService,
	keyPairRepo *repositories.KeyPairRepository,
) *CSRService {
	return &CSRService{
		repo:       repo,
		certRepo:   certRepo,
		caSvc:      caSvc,
		keyPairRepo: keyPairRepo,
	}
}

// SubmitCSR creates a CSR using the customer's stored key pair.
// It parses the private key from the DB, signs the CSR, and saves it as pending.
func (s *CSRService) SubmitCSR(req *SubmitCSRRequest, requesterID uint) (*models.CSR, error) {
	// 1. Validate
	if strings.TrimSpace(req.CommonName) == "" {
		return nil, fmt.Errorf("common_name is required")
	}
	if req.KeyPairID == 0 {
		return nil, fmt.Errorf("key_pair_id is required — select a key pair first")
	}

	// 2. Load the key pair and verify ownership
	kp, err := s.keyPairRepo.FindByID(req.KeyPairID)
	if err != nil {
		return nil, fmt.Errorf("key pair not found")
	}
	if kp.OwnerID != requesterID {
		return nil, fmt.Errorf("access denied: key pair belongs to another user")
	}

	// 3. Parse the private key from stored PEM
	privKey, err := ParsePrivateKeyPEM(kp.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	// 4. Parse IP addresses
	var ipAddrs []net.IP
	for _, ipStr := range req.IPAddresses {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %q", ipStr)
		}
		ipAddrs = append(ipAddrs, ip)
	}

	// 5. Build the CSR template
	var sigAlgo x509.SignatureAlgorithm
	switch kp.Algorithm {
	case "RSA":
		sigAlgo = x509.SHA256WithRSA
	case "ECDSA":
		sigAlgo = x509.ECDSAWithSHA256
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", kp.Algorithm)
	}

	sigAlgoStr := sigAlgo.String()

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: req.CommonName,
		},
		DNSNames:           req.DNSNames,
		IPAddresses:        ipAddrs,
		SignatureAlgorithm: sigAlgo,
	}

	// 6. Sign CSR with the customer's private key
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	// 7. Encode to PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	// 8. Save CSR record
	record := &models.CSR{
		Subject:            req.CommonName,
		Pem:                string(csrPEM),
		KeyAlgorithm:       kp.Algorithm,
		SignatureAlgorithm:  sigAlgoStr,
		DNSNames:           req.DNSNames,
		IPAddresses:        formatIPAddrs(ipAddrs),
		Status:             models.CSRStatusPending,
		RequesterID:        requesterID,
		KeyPairID:          &kp.ID,
		CreatedAt:          nowFunc(),
	}

	saved, err := s.repo.Create(record)
	if err != nil {
		return nil, fmt.Errorf("persist CSR: %w", err)
	}
	return saved, nil
}

// ApproveCSR ký CSR bằng Root CA → tạo Certificate thực sự → lưu DB.
//
// Luồng:
//  1. Load CA bundle (cert + private key) từ DB qua CAService
//  2. Tìm CSR theo id, kiểm tra status = pending
//  3. Parse CSR PEM → *x509.CertificateRequest
//  4. Xây dựng x509.Certificate template từ thông tin CSR
//  5. CA ký → certDER → certPEM
//  6. Lưu Certificate vào bảng certificates
//  7. Cập nhật CSR status → approved
func (s *CSRService) ApproveCSR(id uint, approverID uint) (*models.CSR, error) {
	// 1. Load CA bundle từ DB
	ca, err := s.caSvc.LoadCA()
	if err != nil {
		return nil, fmt.Errorf("approve: %w", err)
	}

	// 2. Lấy CSR từ DB
	csrRecord, err := s.repo.FindByID(id)
	if err != nil {
		return nil, fmt.Errorf("approve: CSR %d not found: %w", id, err)
	}
	if csrRecord.Status != models.CSRStatusPending {
		return nil, fmt.Errorf("approve: CSR %d is not pending (status=%s)", id, csrRecord.Status)
	}

	// 3. Parse CSR PEM → *x509.CertificateRequest
	block, _ := pem.Decode([]byte(csrRecord.Pem))
	if block == nil {
		return nil, fmt.Errorf("approve: invalid CSR PEM for id=%d", id)
	}
	parsedCSR, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("approve: parse CSR: %w", err)
	}
	//hàm này sẽ tóm lấy thành phần số (3)
	//  - Chữ ký số, và dùng chính thành phần số (2)
	// - Public Key có sẵn trong CSR để tiến hành xác minh lại (verify) chữ ký đó.
	if err := parsedCSR.CheckSignature(); err != nil {
		return nil, fmt.Errorf("approve: CSR signature invalid: %w", err)
	}

	// 4. Xây dựng certificate template
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("approve: generate serial: %w", err)
	}

	now := nowFunc()
	certTemplate := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               parsedCSR.Subject,
		DNSNames:              parsedCSR.DNSNames,
		IPAddresses:           parsedCSR.IPAddresses,
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour), // 1 năm
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// 5. CA ký certificate
	// - template: thông tin cert mới
	// - parent:   CA cert (ca.Cert)
	// - pub:      public key của user (lấy từ CSR)
	// - priv:     private key của CA (ca.PrivateKey)
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, ca.Cert, parsedCSR.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("approve: sign certificate: %w", err)
	}

	// 6. Encode → PEM và tính fingerprint SHA-256
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	fp := sha256.Sum256(certDER)
	fingerprint := hex.EncodeToString(fp[:])

	// 7. Lưu Certificate vào DB
	certRecord := &models.Certificate{
		Subject:      parsedCSR.Subject.CommonName,
		Issuer:       ca.Cert.Subject.CommonName,
		Serial:       serial.String(),
		Fingerprint:   fingerprint,
		NotBefore:    now,
		NotAfter:    now.Add(365 * 24 * time.Hour),
		KeyUsage:    []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsage: []string{"serverAuth", "clientAuth"},
		DNSNames:     csrRecord.DNSNames,
		IPAddresses: csrRecord.IPAddresses,
		IsCA:         false,
		CertPEM:      string(certPEM),
		KeyAlgorithm:  csrRecord.KeyAlgorithm, // RSA | ECDSA — propagated from CSR
		Profile:      "tls-server",
		Status:       models.CertStatusActive,
		CreatedAt:    now,
		ParentID:    &ca.RecordID,    // link to Root CA record
		RequesterID: &csrRecord.RequesterID,
	}
	if _, err := s.certRepo.Create(certRecord); err != nil {
		return nil, fmt.Errorf("approve: save certificate: %w", err)
	}

	// 8. Cập nhật CSR status → approved
	approvedAt := now
	csrRecord.Status = models.CSRStatusApproved
	csrRecord.ApprovedAt = &approvedAt
	csrRecord.ApproverID = &approverID

	updated, err := s.repo.Update(csrRecord)
	if err != nil {
		return nil, fmt.Errorf("approve: update CSR status: %w", err)
	}
	return updated, nil
}

// RejectCSR transitions a CSR from pending to rejected.
func (s *CSRService) RejectCSR(id uint, notes string) (*models.CSR, error) {
	csrRecord, err := s.repo.FindByID(id)
	if err != nil {
		return nil, fmt.Errorf("reject: CSR %d not found: %w", id, err)
	}
	if csrRecord.Status != models.CSRStatusPending {
		return nil, fmt.Errorf("reject: CSR %d is not pending", id)
	}

	now := nowFunc()
	csrRecord.Status = models.CSRStatusRejected
	csrRecord.RejectedAt = &now
	csrRecord.Notes = notes

	updated, err := s.repo.Update(csrRecord)
	if err != nil {
		return nil, fmt.Errorf("reject: update CSR: %w", err)
	}
	return updated, nil
}

// GetCSRByID retrieves a single CSR by ID.
func (s *CSRService) GetCSRByID(id uint) (*models.CSR, error) {
	return s.repo.FindByID(id)
}

// ListByRequesterID returns all CSRs belonging to a specific customer.
func (s *CSRService) ListByRequesterID(requesterID uint) ([]*models.CSR, error) {
	return s.repo.FindByRequesterID(requesterID)
}

// ListPendingCSRs returns all CSRs awaiting approval.
func (s *CSRService) ListPendingCSRs() ([]*models.CSR, error) {
	return s.repo.FindPending()
}

// ListAllCSRs returns all CSRs.
func (s *CSRService) ListAllCSRs() ([]*models.CSR, error) {
	return s.repo.FindAll()
}

// nowFunc is injectable for testability.
var nowFunc = func() time.Time { return time.Now() }

func formatIPAddrs(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}
