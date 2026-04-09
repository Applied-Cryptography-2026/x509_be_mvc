package services

import (
	"crypto/x509"
	"net"

	"github.com/your-org/x509-mvc/models"
)

// Converter converts between x509.Certificate and domain model.
type Converter struct{}

// NewConverter creates a new Converter.
func NewConverter() *Converter {
	return &Converter{}
}

// ToModel converts an x509.Certificate to the models.Certificate.
func (c *Converter) ToModel(cert *x509.Certificate, pemStr, keyPEM string) *models.Certificate {
	// TODO: implement
	panic("TODO: implement")
}

// ToX509 converts a models.Certificate PEM string back to an x509.Certificate.
func (c *Converter) ToX509(cert *models.Certificate) (*x509.Certificate, error) {
	// TODO: implement
	panic("TODO: implement")
}

// ---------------------------------------------------------------------------

func keyUsageStrings(ku x509.KeyUsage) []string {
	// TODO: implement
	panic("TODO: implement")
}

func extKeyUsageStrings(eku []x509.ExtKeyUsage) []string {
	// TODO: implement
	panic("TODO: implement")
}

func ipStrings(ips []net.IP) []string {
	// TODO: implement
	panic("TODO: implement")
}
