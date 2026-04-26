package services

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/your-org/x509-mvc/models"
	"github.com/your-org/x509-mvc/repositories"
)

// CertificateService handles certificate business logic
type CertificateService struct {
	repo  *repositories.CertificateRepository
	dbRepo *repositories.DBRepository
	converter *Converter
	audit *AuditLogService
}

// NewCertificateService constructs a CertificateService
func NewCertificateService(
	repo *repositories.CertificateRepository,
	dbRepo *repositories.DBRepository,
	converter *Converter,
	auditService *AuditLogService,
) *CertificateService {
	return &CertificateService{
		repo: repo,
		dbRepo: dbRepo,
		converter: converter,
		audit: auditService,
	}
}

// CertificateResponse is the API-facing shape for a certificate.
type CertificateResponse struct {
	ID            uint      `json:"id"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	Serial        string    `json:"serial"`
	Fingerprint   string    `json:"fingerprint"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DNSNames      []string  `json:"dns_names"`
	IPAddresses   []string  `json:"ip_addresses"`
	IsCA          bool      `json:"is_ca"`
	IsRevoked     bool      `json:"is_revoked"`
	RevokedAt     *time.Time  `json:"revoked_at,omitempty"`
	CertPEM       string    `json:"cert_pem,omitempty"`
	RequesterID   *uint     `json:"requester_id,omitempty"`
	ParentID      *uint     `json:"parent_id,omitempty"`
	KeyAlgorithm  string    `json:"key_algorithm,omitempty"`
	Profile       string    `json:"profile"`
	Status        models.CertStatus `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
}

// toCertificateResponse maps a domain model to the API response.
func toCertificateResponse(c *models.Certificate) *CertificateResponse {
	return &CertificateResponse{
		ID:           c.ID,
		Subject:      c.Subject,
		Issuer:       c.Issuer,
		Serial:       c.Serial,
		Fingerprint:  c.Fingerprint,
		NotBefore:    c.NotBefore,
		NotAfter:     c.NotAfter,
		DNSNames:     c.DNSNames,
		IPAddresses:  c.IPAddresses,
		IsCA:         c.IsCA,
		IsRevoked:    c.IsRevoked,
		RevokedAt:    c.RevokedAt,
		CertPEM:      c.CertPEM,
		RequesterID:   c.RequesterID,
		ParentID:     c.ParentID,
		KeyAlgorithm: c.KeyAlgorithm,
		Profile:      c.Profile,
		Status:       c.Status,
		CreatedAt:    c.CreatedAt,
	}
}

// deriveKeyAlgorithm parses the private key PEM block header to determine the algorithm.
// Falls back to "" if the PEM cannot be decoded or is not a recognised key type.
func deriveKeyAlgorithm(keyPEM string) string {
	if keyPEM == "" {
		return ""
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return ""
	}
	switch block.Type {
	case "RSA PRIVATE KEY", "RSA PRIVATE KEY (2.5.8.1.1":
		return "RSA"
	case "EC PRIVATE KEY", "EC PRIVATE KEY (1.2.840.10045.2.1":
		return "ECDSA"
	case "PRIVATE KEY":
		// Try to parse the PKCS8 wrapper to detect algorithm
		return deriveAlgorithmFromPKCS8(block.Bytes)
	default:
		return ""
	}
}

// deriveAlgorithmFromPKCS8 peeks at the algorithm OID inside a PKCS#8 private key.
func deriveAlgorithmFromPKCS8(der []byte) string {
	// PKCS#8 AlgorithmIdentifier: SEQUENCE { OID, anything }
	if len(der) < 2 {
		return ""
	}
	// Simple peek: look for RSA or EC OID bytes in the first ~30 bytes
	rsaOID := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01} // rsaEncryption 1.2.840.113549.1.1.1
	ecOID := []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01} // id-ecPublicKey 1.2.840.10045.2.1
	for i := 0; i < len(der)-len(rsaOID); i++ {
		if string(der[i:i+len(rsaOID)]) == string(rsaOID) {
			return "RSA"
		}
		if i < len(der)-len(ecOID) && string(der[i:i+len(ecOID)]) == string(ecOID) {
			return "ECDSA"
		}
	}
	return ""
}

func (s *CertificateService) GetCertificate(id uint) (*CertificateResponse, error) {
	cert, err := s.repo.FindByID(id)
	if err != nil {
		return nil, err
	}
	return toCertificateResponse(cert), nil
}

func (s *CertificateService) ListCertificates() ([]*CertificateResponse, error) {
	certs, err := s.repo.FindAll()
	if err != nil {
		return nil, err
	}
	out := make([]*CertificateResponse, len(certs))
	for i, c := range certs {
		out[i] = toCertificateResponse(c)
	}
	return out, nil
}

// ListByRequesterID returns only certificates issued to a specific customer.
func (s *CertificateService) ListByRequesterID(requesterID uint) ([]*CertificateResponse, error) {
	certs, err := s.repo.FindByRequesterID(requesterID)
	if err != nil {
		return nil, err
	}
	out := make([]*CertificateResponse, len(certs))
	for i, c := range certs {
		out[i] = toCertificateResponse(c)
	}
	return out, nil
}

func (s *CertificateService) SearchCertificates(query string) ([]*CertificateResponse, error) {
	certs, err := s.repo.FindBySubject(query)
	if err != nil {
		return nil, err
	}
	out := make([]*CertificateResponse, len(certs))
	for i, c := range certs {
		out[i] = toCertificateResponse(c)
	}
	return out, nil
}

func (s *CertificateService) GetExpiringCertificates(withinDays int) ([]*CertificateResponse, error) {
	certs, err := s.repo.FindExpiring(withinDays)
	if err != nil {
		return nil, err
	}
	out := make([]*CertificateResponse, len(certs))
	for i, c := range certs {
		out[i] = toCertificateResponse(c)
	}
	return out, nil
}

func (s *CertificateService) ImportCertificate(pemStr string, keyPEM string) (*CertificateResponse, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("import: invalid PEM content")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("import: parse x509 cert: %w", err)
	}

	fp := sha256.Sum256(cert.Raw)
	fingerprint := hex.EncodeToString(fp[:])

	// Extract SANs from the parsed certificate
	var dnsNames, ipAddresses []string
	for _, dns := range cert.DNSNames {
		dnsNames = append(dnsNames, dns)
	}
	for _, ip := range cert.IPAddresses {
		ipAddresses = append(ipAddresses, ip.String())
	}

	model := &models.Certificate{
		Subject:     cert.Subject.CommonName,
		Issuer:      cert.Issuer.CommonName,
		Serial:      cert.SerialNumber.String(),
		Fingerprint: fingerprint,
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
		IsCA:        cert.IsCA,
		CertPEM:     pemStr,
		KeyPEM:      keyPEM,
		Profile:     "imported",
		Status:      models.CertStatusActive,
		CreatedAt:   time.Now(),
	}

	if cert.NotAfter.Before(time.Now()) {
		model.Status = models.CertStatusExpired
	}

	created, err := s.repo.Create(model)
	if err != nil {
		return nil, err
	}
	return toCertificateResponse(created), nil
}

func (s *CertificateService) RevokeCertificate(id uint, reason string) (*CertificateResponse, error) {
	cert, err := s.repo.FindByID(id)
	if err != nil {
		return nil, fmt.Errorf("revoke: cert not found: %w", err)
	}

	if cert.Status == models.CertStatusRevoked {
		return nil, errors.New("revoke: cert is already revoked")
	}

	cert.Status = models.CertStatusRevoked
	cert.IsRevoked = true
	now := time.Now()
	cert.RevokedAt = &now

	updated, err := s.repo.Update(cert)
	if err != nil {
		return nil, err
	}
	return toCertificateResponse(updated), nil
}

func (s *CertificateService) RenewCertificate(id uint, newCSR *models.CSR) (*CertificateResponse, error) {
	return nil, errors.New("renew flow must go through CA approve route. Submit new CSR and Approve it")
}

func (s *CertificateService) DeleteCertificate(id uint, adminID uint) error {
	cert, err := s.repo.FindByID(id)
	if err != nil {
		return err
	}
	err = s.repo.Delete(id)
	if err == nil {
		description := fmt.Sprintf("Deleted certificate | Domain: %s", cert.Subject)
		s.audit.Record(&LogRequest{
			UserID:      IntPtr(adminID),
			Action:      "delete",
			EntityType:  strPtr("certificate"),
			EntityID:    IntPtr(id),
			Description: description,
		})
	}
	return err
}

// ValidatePEM parses a PEM-encoded certificate and returns whether it is valid.
func (s *CertificateService) ValidatePEM(pemStr string, adminID uint) (bool, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return false, errors.New("invalid PEM content")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse error: %w", err)
	}
	
	// Determine if certificate is valid
	isValid := cert.NotBefore.Before(time.Now()) && cert.NotAfter.After(time.Now())
	validStr := "NO"
	if isValid {
		validStr = "YES"
	}
	
	// Format expiry date as YYYY-MM-DD
	expiryStr := cert.NotAfter.Format("2006-01-02")
	
	// Log certificate validation
	description := fmt.Sprintf("Validated certificate PEM | Domain: %s | Valid: %s | Expires: %s", cert.Subject, validStr, expiryStr)
	s.audit.Record(&LogRequest{
		UserID:      IntPtr(adminID),
		Action:      "validate",
		EntityType:  strPtr("certificate"),
		Description: description,
	})
	return isValid, nil
}

// LogCertificateDownload logs when a certificate is downloaded
func (s *CertificateService) LogCertificateDownload(userID uint, domain string) {
	description := fmt.Sprintf("Downloaded certificate | Domain: %s | Format: PEM", domain)
	s.audit.Record(&LogRequest{
		UserID:      IntPtr(userID),
		Action:      "download",
		EntityType:  strPtr("certificate"),
		Description: description,
	})
}
