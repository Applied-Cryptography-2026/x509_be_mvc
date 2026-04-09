package models

import "errors"

// ─── Auth errors ─────────────────────────────────────────────────────────────

var (
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrUserNotFound           = errors.New("user not found")
	ErrUserAlreadyExists      = errors.New("user already exists")
	ErrTokenExpired           = errors.New("token has expired")
	ErrTokenInvalid           = errors.New("token is invalid")
	ErrTokenMissing           = errors.New("token is missing")
	ErrRefreshTokenExpired    = errors.New("refresh token has expired")
	ErrRefreshTokenRevoked    = errors.New("refresh token has been revoked")
	ErrRefreshTokenReused     = errors.New("refresh token has been reused")
	ErrRefreshTokenInvalid    = errors.New("refresh token is invalid")
	ErrPasswordWeak           = errors.New("password must be at least 8 characters")
	ErrPasswordIncorrect      = errors.New("current password is incorrect")
	ErrInsufficientPermission = errors.New("insufficient permissions")
)

// ─── Admin errors ────────────────────────────────────────────────────────────

var (
	ErrAdminNotFound      = errors.New("admin account not found")
	ErrAdminAlreadyExists = errors.New("admin account already exists")
)

// ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
// ─── Certificate errors ───────────────────────────────────────────────────────

var (
	ErrCertNotFound        = errors.New("certificate not found")
	ErrCertAlreadyExists   = errors.New("certificate already exists")
	ErrCertExpired         = errors.New("certificate has expired")
	ErrCertNotYetValid     = errors.New("certificate is not yet valid")
	ErrCertRevoked         = errors.New("certificate has been revoked")
	ErrCertInvalid         = errors.New("certificate is invalid")
	ErrCertKeyMismatch     = errors.New("certificate does not match its private key")
	ErrCertChainBroken     = errors.New("certificate chain is broken")
	ErrCertParseFailed     = errors.New("failed to parse certificate")
	ErrCertUnsupportedAlgo = errors.New("unsupported signature algorithm")
)

// ─── CSR errors ───────────────────────────────────────────────────────────────

var (
	ErrCSRNotFound      = errors.New("CSR not found")
	ErrCSRAlreadyExists = errors.New("CSR already exists")
	ErrCSRInvalid       = errors.New("CSR is invalid")
	ErrCSRRejected      = errors.New("CSR was rejected")
	ErrCSRNotApproved   = errors.New("CSR is not approved")
)

// ─── CA errors ───────────────────────────────────────────────────────────────

var (
	ErrCANotFound      = errors.New("CA certificate not found")
	ErrCANotCA         = errors.New("certificate is not a CA")
	ErrCANotSelfSigned = errors.New("CA certificate must be self-signed or signed by a parent CA")
)

// ─── Key errors ──────────────────────────────────────────────────────────────

var (
	ErrKeyNotFound      = errors.New("private key not found")
	ErrKeyDecryptFailed = errors.New("failed to decrypt private key")
	ErrKeyAlgorithm     = errors.New("incompatible key algorithm")
)
