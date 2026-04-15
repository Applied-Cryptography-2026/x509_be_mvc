package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/your-org/x509-mvc/services"
)

// CLI provides a command-line interface for x509 operations.
type CLI struct {
	in  io.Reader
	out io.Writer
	err io.Writer
}

// NewCLI creates a CLI instance with the given input/output writers.
func NewCLI(in io.Reader, out, err io.Writer) *CLI {
	return &CLI{in: in, out: out, err: err}
}

func main() {
	cli := NewCLI(os.Stdin, os.Stdout, os.Stderr)
	cli.Run(os.Args[1:])
}

func (c *CLI) Run(args []string) {
	fs := flag.NewFlagSet("x509-cli", flag.ContinueOnError)
	fs.SetOutput(c.err)

	var (
		cmd        = fs.String("cmd", "info", "Command: info|validate|sign|fingerprint")
		certFile   = fs.String("cert", "", "Path to certificate PEM file")
		csrFile    = fs.String("csr", "", "Path to CSR PEM file (for sign)")
		caCertFile = fs.String("ca-cert", "", "Path to CA certificate (for sign)")
		caKeyFile  = fs.String("ca-key", "", "Path to CA private key (for sign)")
		days       = fs.Int("days", 365, "Validity period in days (for sign)")
	)

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			c.usage()
			return
		}
		c.error("failed to parse flags: %v", err)
		return
	}

	switch *cmd {
	case "info":
		c.infoCmd(*certFile)
	case "validate":
		c.validateCmd(*certFile)
	case "fingerprint":
		c.fingerprintCmd(*certFile)
	case "sign":
		c.signCmd(*csrFile, *caCertFile, *caKeyFile, *days)
	default:
		c.error("unknown command: %s", *cmd)
		c.usage()
	}
}

func (c *CLI) infoCmd(certFile string) {
	if certFile == "" {
		c.error("info: -cert flag is required")
		return
	}

	data, err := os.ReadFile(certFile)
	if err != nil {
		c.error("info: failed to read cert file: %v", err)
		return
	}

	cert, err := services.ParseCertificatePEM(string(data))
	if err != nil {
		c.error("info: failed to parse certificate: %v", err)
		return
	}

	fmt.Fprintf(c.out, "Subject:     %s\n", cert.Subject.String())
	fmt.Fprintf(c.out, "Issuer:      %s\n", cert.Issuer.String())
	fmt.Fprintf(c.out, "Serial:      %s\n", cert.SerialNumber.Text(16))
	fmt.Fprintf(c.out, "Not Before:  %s\n", cert.NotBefore)
	fmt.Fprintf(c.out, "Not After:   %s\n", cert.NotAfter)
	fmt.Fprintf(c.out, "Is CA:       %t\n", cert.IsCA)
	fmt.Fprintf(c.out, "DNS Names:   %v\n", cert.DNSNames)
	fmt.Fprintf(c.out, "IP Addresses: %v\n", cert.IPAddresses)
}

func (c *CLI) validateCmd(certFile string) {
	if certFile == "" {
		c.error("validate: -cert flag is required")
		return
	}

	data, err := os.ReadFile(certFile)
	if err != nil {
		c.error("validate: failed to read cert file: %v", err)
		return
	}

	cert, err := services.ParseCertificatePEM(string(data))
	if err != nil {
		c.error("validate: failed to parse certificate: %v", err)
		return
	}
	_ = cert

	// Use the existing ValidatePEM helper directly
	valid, verr := services.ValidatePEMString(string(data))
	if !valid {
		fmt.Fprintf(c.out, "VALID: false\nERROR: %v\n", verr)
	} else {
		fmt.Fprintf(c.out, "VALID: true\n")
	}
}

func (c *CLI) fingerprintCmd(certFile string) {
	if certFile == "" {
		c.error("fingerprint: -cert flag is required")
		return
	}

	data, err := os.ReadFile(certFile)
	if err != nil {
		c.error("fingerprint: failed to read cert file: %v", err)
		return
	}

	cert, err := services.ParseCertificatePEM(string(data))
	if err != nil {
		c.error("fingerprint: failed to parse certificate: %v", err)
		return
	}

	fmt.Fprintf(c.out, "SHA-256: %s\n", services.SHA256Fingerprint(cert))
}

func (c *CLI) signCmd(csrFile, caCertFile, caKeyFile string, days int) {
	if csrFile == "" || caCertFile == "" || caKeyFile == "" {
		c.error("sign: -csr, -ca-cert, and -ca-key flags are required")
		return
	}

	// TODO: wire full signing logic here using services/signer.go
	fmt.Fprintf(c.out, "sign command not yet wired — use services/signer directly\n")
	_ = csrFile
	_ = caCertFile
	_ = caKeyFile
	_ = days
}

func (c *CLI) usage() {
	fmt.Fprintf(c.out, `x509-cli - x509 certificate management CLI

Usage:
  x509-cli -cmd <command> [flags]

Commands:
  info         Print certificate information
  validate     Validate certificate structure
  fingerprint  Print certificate SHA-256 fingerprint
  sign         Sign a CSR with a CA (not yet implemented)

Flags:
  -cert string    Path to certificate PEM file
  -csr string     Path to CSR PEM file
  -ca-cert string Path to CA certificate PEM file
  -ca-key string  Path to CA private key PEM file
  -days int       Validity period in days (default 365)
`)
}

func (c *CLI) error(format string, args ...any) {
	fmt.Fprintf(c.err, format+"\n", args...)
}
