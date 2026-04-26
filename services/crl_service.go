package services

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/your-org/x509-mvc/models"
	"github.com/your-org/x509-mvc/repositories"
)

// CRLService generates and manages X.509 Certificate Revocation Lists.
type CRLService struct {
	certRepo    *repositories.CertificateRepository
	keyPairRepo *repositories.KeyPairRepository
	audit       *AuditLogService
}

// NewCRLService constructs a CRLService.
func NewCRLService(
	certRepo *repositories.CertificateRepository,
	keyPairRepo *repositories.KeyPairRepository,
	auditService *AuditLogService,
) *CRLService {
	return &CRLService{
		certRepo:    certRepo,
		keyPairRepo: keyPairRepo,
		audit:       auditService,
	}
}

// CRLBundle holds the raw CRL DER bytes and the PEM-encoded string.
type CRLBundle struct {
	DER []byte
	PEM string
}

// GenerateCRL builds a new X.509 CRL signed by the Root CA using the standard
// library's CreateCertificate helper (which handles pkix.Name → ASN.1 conversion).
// All revoked certificates in the DB are included in the CRL.
func (s *CRLService) GenerateCRL(adminID uint) (*CRLBundle, error) {
	caBundle, err := s.loadCABundle()
	if err != nil {
		return nil, fmt.Errorf("crl: load CA: %w", err)
	}

	revokedCerts, err := s.certRepo.FindRevoked()
	if err != nil {
		return nil, fmt.Errorf("crl: find revoked: %w", err)
	}

	// Derive CRL number from current Unix timestamp (unique per CRL)
	crlNumber := big.NewInt(time.Now().Unix())

	thisUpdate := time.Now().UTC()
	nextUpdate := thisUpdate.Add(24 * time.Hour)

	// Build the CRL TBS manually and sign
	crlBundle, err := s.buildCRLFromTBS(caBundle, revokedCerts, crlNumber, thisUpdate, nextUpdate)

	if err == nil && crlBundle != nil {
		// Log CRL generation
		nextUpdateStr := nextUpdate.Format("2006-01-02 15:04:05")
		description := fmt.Sprintf("Generated CRL | Revoked Certificates Count: %d | Next Update: %s", len(revokedCerts), nextUpdateStr)
		s.audit.Record(&LogRequest{
			UserID:      IntPtr(adminID),
			Action:      "create",
			EntityType:  strPtr("crl"),
			Description: description,
		})
	}

	return crlBundle, err
}

// buildCRLFromTBS builds the CRL by marshaling the TBS portion and signing it.
func (s *CRLService) buildCRLFromTBS(
	caBundle *CABundle,
	revokedCerts []*models.Certificate,
	crlNumber *big.Int,
	thisUpdate, nextUpdate time.Time,
) (*CRLBundle, error) {
	// Build revoked certificate entries
	var revokedEntries []pkix.RevokedCertificate
	for _, cert := range revokedCerts {
		if cert.RevokedAt == nil {
			continue
		}
		serial := new(big.Int)
		if _, ok := serial.SetString(cert.Serial, 10); !ok {
			continue
		}
		revokedEntries = append(revokedEntries, pkix.RevokedCertificate{
			SerialNumber:   serial,
			RevocationTime: cert.RevokedAt.UTC(),
		})
	}

	// CRL number OID: 2.5.29.20
	crlNumberOID := asn1.ObjectIdentifier{2, 5, 29, 20}
	crlNumberBytes, err := asn1.Marshal(crlNumber)
	if err != nil {
		return nil, fmt.Errorf("crl: marshal crl number: %w", err)
	}

	extensions := []pkix.Extension{
		{Id: crlNumberOID, Value: crlNumberBytes, Critical: true},
	}

	// TBSCertList — Issuer must be pkix.RDNSequence.
	// Use the CA cert's RawIssuer field which is already the ASN.1 DER bytes of the issuer.
	var issuer pkix.RDNSequence
	_ = issuer // will be set from CA cert

	// We need pkix.RDNSequence. Convert pkix.Name via the same mechanism as x509 package:
	// Marshal the Name as a distinguished name, then unmarshal as RDNSequence.
	dnBytes, err := asn1.Marshal(caBundle.Cert.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("crl: marshal subject DN: %w", err)
	}
	var rdnSeq pkix.RDNSequence
	if _, err := asn1.Unmarshal(dnBytes, &rdnSeq); err != nil {
		return nil, fmt.Errorf("crl: unmarshal DN to RDNSequence: %w", err)
	}

	tbs := pkix.TBSCertificateList{
		Version:             1,
		Signature:           pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}}, // sha256WithRSAEncryption
		Issuer:              rdnSeq,
		ThisUpdate:          thisUpdate,
		NextUpdate:          nextUpdate,
		RevokedCertificates: revokedEntries,
		Extensions:          extensions,
	}

	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("crl: marshal TBS: %w", err)
	}

	// Sign TBS with SHA256 + RSA
	h := sha256.Sum256(tbsDER)
	sig, err := rsa.SignPKCS1v15(rand.Reader, caBundle.PrivateKey, crypto.SHA256, h[:])
	if err != nil {
		return nil, fmt.Errorf("crl: sign: %w", err)
	}

	// Full CRL ASN.1 sequence
	crlDER, err := asn1.Marshal(struct {
		TBS                   asn1.RawValue
		SignatureAlgorithm    pkix.AlgorithmIdentifier
		SignatureValue       asn1.BitString
	}{
		TBS:                   asn1.RawValue{Tag: asn1.TagSequence, Class: asn1.ClassUniversal, IsCompound: true, Bytes: tbsDER},
		SignatureAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}},
		SignatureValue:       asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("crl: marshal CRL: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	return &CRLBundle{DER: crlDER, PEM: string(pemBytes)}, nil
}

// GetRevokedCerts returns all revoked certificates for display.
func (s *CRLService) GetRevokedCerts() ([]map[string]interface{}, error) {
	certs, err := s.certRepo.FindRevoked()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]interface{}, 0, len(certs))
	for _, c := range certs {
		fingerprint := ""
		if block, _ := pem.Decode([]byte(c.CertPEM)); block != nil {
			sum := sha1.Sum(block.Bytes)
			for i, b := range sum {
				if i > 0 {
					fingerprint += ":"
				}
				fingerprint += fmt.Sprintf("%02X", b)
			}
		}
		out = append(out, map[string]interface{}{
			"id":          c.ID,
			"serial":      c.Serial,
			"subject":     c.Subject,
			"revoked_at":  c.RevokedAt,
			"issuer":      c.Issuer,
			"fingerprint": fingerprint,
			"not_after":   c.NotAfter,
		})
	}
	return out, nil
}

// loadCABundle loads and parses the Root CA cert and key from the DB.
func (s *CRLService) loadCABundle() (*CABundle, error) {
	record, err := s.certRepo.FindRootCA()
	if err != nil {
		return nil, fmt.Errorf("crl: find root CA: %w", err)
	}

	certBlock, _ := pem.Decode([]byte(record.CertPEM))
	if certBlock == nil {
		return nil, fmt.Errorf("crl: invalid cert PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crl: parse cert: %w", err)
	}

	keyBlock, _ := pem.Decode([]byte(record.KeyPEM))
	if keyBlock == nil {
		return nil, fmt.Errorf("crl: invalid key PEM")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crl: parse key: %w", err)
	}

	return &CABundle{Cert: caCert, PrivateKey: caKey, RecordID: record.ID}, nil
}
