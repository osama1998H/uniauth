package domain

import "errors"

// Sentinel errors used across the service layer.
var (
	ErrNotFound          = errors.New("not found")
	ErrAlreadyExists     = errors.New("already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnauthorized      = errors.New("unauthorized")
	ErrForbidden         = errors.New("forbidden")
	ErrTokenExpired      = errors.New("token expired")
	ErrTokenInvalid      = errors.New("token invalid")
	ErrUserInactive      = errors.New("user account is inactive")
	ErrOrgInactive       = errors.New("organization is inactive")
	ErrAPIKeyRevoked     = errors.New("api key has been revoked")
	ErrAPIKeyExpired     = errors.New("api key has expired")
	ErrWeakPassword      = errors.New("password does not meet requirements")
	ErrInvalidInput      = errors.New("invalid input")
)
