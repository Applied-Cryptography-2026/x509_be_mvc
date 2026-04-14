package services

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// DecodePEMBlock extracts the first matching PEM block and returns its DER bytes.
func DecodePEMBlock(pemStr string, blockType string) ([]byte, error) {
	data := []byte(pemStr)
	for{
		block, rest := pem.Decode(data)
		if block == nil{
			return nil, fmt.Errorf("PEM block type %s not found", blockType)
		}
		if block.Type == blockType{
			return block.Bytes, nil
		}
		// If no match, continue searching in the remaining data
		data = rest 
		// If no more data to parse
		if len(data) == 0{
			break
		}
	}
	return nil, fmt.Errorf("PEM block type %s not found", blockType)
}

// EncodeToPEM DER-encodes a value and wraps it in a PEM block.
func EncodeToPEM(der []byte, blockType string) string {
	pemEncode := new(bytes.Buffer)
	err := pem.Encode(pemEncode, &pem.Block{
		Type: blockType,
		Bytes: der,
	})

	if err != nil{
		return ""
	}

	return pemEncode.String()
}

// ParseCertificatePEM parses a PEM-encoded certificate.
func ParseCertificatePEM(pemStr string) (*x509.Certificate, error) {
	derBytes, err := DecodePEMBlock(pemStr, "CERTIFICATE")
	if err != nil{
		return nil, fmt.Errorf("Cannot decode PEM: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil{
		return nil, fmt.Errorf("Cannot parse x509 certificate: %v", err)
	}

	return cert, nil
}

// ParsePrivateKeyPEM parses a PEM-encoded private key (supports RSA, ECDSA, Ed25519).
func ParsePrivateKeyPEM(pemStr string) (any, error) {
	// Bước 1: Decode PEM để lấy dữ liệu DER
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("Cannot decode block PEM, invalid format!")
	}

	// Bước 2: Thử parse theo chuẩn PKCS#8 (chuẩn hiện đại, hỗ trợ đa thuật toán)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	// Bước 3: Nếu PKCS#8 lỗi, có thể đó là chuẩn cũ PKCS#1 (thường dành riêng cho RSA)
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	return nil, fmt.Errorf("unsupported key type: %s or format mismatch", block.Type)
}

func parsePrivateKey(der []byte) (any, error) {
	// Đã có sẵn der, chỉ cần parse để có priv key, pub key
	// 1. Thử chuẩn PKCS#8 (Hiện đại, đa năng: RSA, ECDSA, Ed25519)
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}

	// 2. Thử chuẩn PKCS#1 (Dành riêng cho RSA cũ)
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unable to identify private key format (supports PKCS#8, PKCS#1, SEC1)")
}

// ParseCSRPEM parses a PEM-encoded CSR.
func ParseCSRPEM(pemStr string) (*x509.CertificateRequest, error) {
	// decode để lấy der
	derBytes, err := DecodePEMBlock(pemStr, "CERTIFICATE REQUEST")
	if err != nil {
		return nil, fmt.Errorf("failed to decode PEM for CSR: %v", err)
	}

	// parse der 
	csr, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %v", err)
	}

	// kiểm tra tính hợp lệ của signature
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid signature in CSR: %v", err)
	}

	return csr, nil
}
