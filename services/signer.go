package services

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

// Signer handles x509 certificate and CSR signing operations.
type Signer struct{}

// NewSigner creates a new Signer instance.
func NewSigner() *Signer {
	// TODO: implement
	panic("TODO: implement")
}

// SignCertificate signs a CSR using the given CA certificate and private key,
// producing a signed leaf certificate valid for the requested duration.
func (s *Signer) SignCertificate(
	csr *x509.CertificateRequest,
	caCert *x509.Certificate,
	caKey crypto.PrivateKey,
	template *x509.Certificate,
) ([]byte, error) {
	// TODO: implement
	panic("TODO: implement")
}

// GenerateSelfSignedCA generates a self-signed CA certificate and private key.
func (s *Signer) GenerateSelfSignedCA(
	subject pkix.Name,
	notBefore, notAfter time.Time,
	keyBits int,
) ([]byte, crypto.PrivateKey, error) {
	// TODO: implement
	panic("TODO: implement")
}

// EncodePrivateKey encodes a private key to PEM string.
func (s *Signer) EncodePrivateKey(key crypto.PrivateKey) (string, error) {
	// TODO: implement
	panic("TODO: implement")
}

// EncodeCertificate encodes a certificate to PEM string.
func (s *Signer) EncodeCertificate(cert *x509.Certificate) (string, error) {
	// TODO: implement
	panic("TODO: implement")
}
