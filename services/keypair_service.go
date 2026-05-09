package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/your-org/x509-mvc/models"
	"github.com/your-org/x509-mvc/repositories"
)

// KeyPairService handles cryptographic key pair generation and storage.
type KeyPairService struct {
	repo  *repositories.KeyPairRepository
	audit *AuditLogService
}

// NewKeyPairService constructs a KeyPairService.
func NewKeyPairService(repo *repositories.KeyPairRepository, auditService *AuditLogService) *KeyPairService {
	return &KeyPairService{repo: repo, audit: auditService}
}

// GenerateRequest is the input for generating a key pair.
type GenerateRequest struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"` // RSA or ECDSA
	KeySize   int    `json:"key_size"`  // 2048, 4096 for RSA; 256, 384 for ECDSA
}

// GenerateResponse is the output after generating a key pair.
type GenerateResponse struct {
	ID            uint      `json:"id"`
	Name          string    `json:"name"`
	Algorithm     string    `json:"algorithm"`
	KeySize       int       `json:"key_size"`
	Fingerprint   string    `json:"fingerprint"`
	OwnerID      uint      `json:"owner_id"`
	CreatedAt    time.Time `json:"created_at"`
	PrivateKeyPEM string   `json:"private_key_pem"` // returned only on generation
}

// ListByOwner returns all key pairs for an owner (private key NOT included).
func (s *KeyPairService) ListByOwner(ownerID uint) ([]*models.KeyPair, error) {
	return s.repo.FindByOwnerID(ownerID)
}

// GetByID returns a key pair by ID.
func (s *KeyPairService) GetByID(id uint) (*models.KeyPair, error) {
	return s.repo.FindByID(id)
}

// Delete soft-deletes a key pair.
func (s *KeyPairService) Delete(id uint, userID uint) error {
	// Fetch keypair details before deletion for audit log
	kp, err := s.repo.FindByID(id)
	if err != nil {
		return err
	}
	
	err = s.repo.Delete(id)
	if err == nil {
		description := fmt.Sprintf("Deleted key pair | Algorithm: %s | Key Size: %d bits", kp.Algorithm, kp.KeySize)
		s.audit.Record(&LogRequest{
			UserID:      IntPtr(userID),
			Action:      "delete",
			EntityType:  strPtr("key_pair"),
			EntityID:    IntPtr(id),
			Description: description,
		})
	}
	return err
}

// Generate creates a new key pair and stores it.
func (s *KeyPairService) Generate(req *GenerateRequest, ownerID uint) (*GenerateResponse, error) {
	if req.Name == "" {
		return nil, errors.New("name is required")
	}
	if req.Algorithm != "RSA" && req.Algorithm != "ECDSA" {
		return nil, errors.New("algorithm must be RSA or ECDSA")
	}

	var (
		pubPEM, privPEM string
		fingerprint     string
	)

	switch req.Algorithm {
	case "RSA":
		switch req.KeySize {
		case 2048, 4096:
			// OK
		default:
			return nil, errors.New("RSA key size must be 2048 or 4096")
		}
		pubPEM, privPEM, fingerprint = generateRSAKeyPair(req.KeySize)

	case "ECDSA":
		switch req.KeySize {
		case 256, 384:
			// OK
		default:
			return nil, errors.New("ECDSA key size must be 256 or 384")
		}
		pubPEM, privPEM, fingerprint = generateECDSAKeyPair(req.KeySize)
	}

	kp := &models.KeyPair{
		Name:          req.Name,
		Algorithm:     req.Algorithm,
		KeySize:       req.KeySize,
		PublicKeyPEM:  pubPEM,
		PrivateKeyPEM: privPEM,
		Fingerprint:   fingerprint,
		OwnerID:      ownerID,
		CreatedAt:    time.Now(),
	}

	saved, err := s.repo.Create(kp)
	if err != nil {
		return nil, fmt.Errorf("keypair: save: %w", err)
	}

	// Log the key pair generation
	description := fmt.Sprintf("Created key pair | Algorithm: %s | Key Size: %d bits", req.Algorithm, req.KeySize)
	s.audit.Record(&LogRequest{
		UserID:      IntPtr(ownerID),
		Action:      "create",
		EntityType:  strPtr("key_pair"),
		EntityID:    IntPtr(saved.ID),
		Description: description,
	})

	return &GenerateResponse{
		ID:             saved.ID,
		Name:           saved.Name,
		Algorithm:      saved.Algorithm,
		KeySize:        saved.KeySize,
		Fingerprint:    saved.Fingerprint,
		OwnerID:       saved.OwnerID,
		CreatedAt:      saved.CreatedAt,
		PrivateKeyPEM:  saved.PrivateKeyPEM, // returned on generation so customer can download it
	}, nil
}

// ─── Internal helpers ───────────────────────────────────────────────────────────

func generateRSAKeyPair(bits int) (pubPEM, privPEM, fingerprint string) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic("generate RSA key: " + err.Error())
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic("marshal RSA public key: " + err.Error())
	}

	pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	// Encode private key as PKCS#8
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic("marshal PKCS8: " + err.Error())
	}
	privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}))

	fingerprint = sha256Hex(pubDER)
	return
}

func generateECDSAKeyPair(bits int) (pubPEM, privPEM, fingerprint string) {
	var curve elliptic.Curve
	switch bits {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	default:
		panic("unsupported ECDSA key size: " + fmt.Sprint(bits))
	}

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic("generate ECDSA key: " + err.Error())
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic("marshal ECDSA public key: " + err.Error())
	}

	pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic("marshal PKCS8: " + err.Error())
	}
	privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}))

	fingerprint = sha256Hex(pubDER)
	return
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

// BuildCSR generates a CSR PEM using the stored private key.
func (s *KeyPairService) BuildCSR(kp *models.KeyPair, commonName string, dnsNames []string) (string, error) {
	privKey, err := ParsePrivateKeyPEM(kp.PrivateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}

	var pubKey any
	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		pubKey = &key.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &key.PublicKey
	default:
		return "", errors.New("unsupported key type")
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
		DNSNames: dnsNames,
	}

	// Sign CSR with the private key
	var algo x509.SignatureAlgorithm
	switch kp.Algorithm {
	case "RSA":
		algo = x509.SHA256WithRSA
	case "ECDSA":
		algo = x509.ECDSAWithSHA256
	default:
		return "", errors.New("unsupported algorithm")
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		return "", fmt.Errorf("create CSR: %w", err)
	}
	_ = algo

	_ = algo
	_ = pubKey

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return string(csrPEM), nil
}

// LogKeyPairDownload logs when a private key is downloaded
func (s *KeyPairService) LogKeyPairDownload(userID uint, keyName string, algorithm string, keySize int) {
	description := fmt.Sprintf("Downloaded private key | Key Pair: %s | Algorithm: %s | Key Size: %d bits", keyName, algorithm, keySize)
	s.audit.Record(&LogRequest{
		UserID:      IntPtr(userID),
		Action:      "download_key",
		EntityType:  strPtr("key_pair"),
		Description: description,
	})
}
