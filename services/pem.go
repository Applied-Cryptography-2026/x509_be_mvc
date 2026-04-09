package services

import (
	"crypto/x509"
)

// DecodePEMBlock extracts the first matching PEM block and returns its DER bytes.
func DecodePEMBlock(pemStr string, blockType string) ([]byte, error) {
	// TODO: implement
	panic("TODO: implement")
}

// EncodeToPEM DER-encodes a value and wraps it in a PEM block.
func EncodeToPEM(der []byte, blockType string) string {
	// TODO: implement
	panic("TODO: implement")
}

// ParseCertificatePEM parses a PEM-encoded certificate.
func ParseCertificatePEM(pemStr string) (*x509.Certificate, error) {
	// TODO: implement
	panic("TODO: implement")
}

// ParsePrivateKeyPEM parses a PEM-encoded private key (supports RSA, ECDSA, Ed25519).
func ParsePrivateKeyPEM(pemStr string) (any, error) {
	// TODO: implement
	panic("TODO: implement")
}

func parsePrivateKey(der []byte) (any, error) {
	// TODO: implement
	panic("TODO: implement")
}

// ParseCSRPEM parses a PEM-encoded CSR.
func ParseCSRPEM(pemStr string) (*x509.CertificateRequest, error) {
	// TODO: implement
	panic("TODO: implement")
}
