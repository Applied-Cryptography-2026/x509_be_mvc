package services

import (
	"crypto/x509"
)

// SHA256Fingerprint returns the colon-separated SHA-256 fingerprint of a certificate.
func SHA256Fingerprint(cert *x509.Certificate) string {
	// TODO: implement
	panic("TODO: implement")
}

// SHA1Fingerprint returns the colon-separated SHA-1 fingerprint.
func SHA1Fingerprint(cert *x509.Certificate) string {
	// TODO: implement
	panic("TODO: implement")
}

// MD5Fingerprint returns the colon-separated MD5 fingerprint.
func MD5Fingerprint(cert *x509.Certificate) string {
	// TODO: implement
	panic("TODO: implement")
}

// formatFingerprint converts raw bytes to a colon-separated uppercase hex string.
func formatFingerprint(data []byte) string {
	// TODO: implement
	panic("TODO: implement")
}
