// Package ca provides certificate authority functionality for MITM proxying.
// This is a stub for Phase 1; implementation comes in Phase 2.
package ca

// CA holds the root certificate and key used to sign per-host certificates.
type CA struct{}

// New creates a new CA. Currently a placeholder.
func New() (*CA, error) {
	return &CA{}, nil
}
