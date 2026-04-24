package services

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"
)

// SHA256Fingerprint returns the colon-separated SHA-256 fingerprint of a certificate.
func SHA256Fingerprint(cert *x509.Certificate) string {
	// TODO: implement
	fp := sha256.Sum256(cert.Raw)
	return formatFingerprint(fp[:])

}

// formatFingerprint converts raw bytes to a colon-separated uppercase hex string.
func formatFingerprint(data []byte) string {
	// TODO: implement
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
