package signer

import (
	"crypto"
	"io"
)

// Signer is an interface for cryptographic signing operations and certificate retrieval.
type Signer interface {

	// SignBytes signs a message byte slice and returns the signature or an error.
	SignBytes(message []byte) ([]byte, error)

	// SignString signs a message string and returns the signature or an error.
	SignString(message string) ([]byte, error)

	// GetCerts retrieves the certificate chain as a slice of byte slices or an error.
	GetCerts() ([][]byte, error)

	// Public crypto.Signer interface compatible function, returns the public key associated with the signer for verification purposes.
	Public() crypto.PublicKey

	// Sign crypto.Signer interface compatible function, applies a cryptographic signature to the provided digest using the given random source and signing options.
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)

	// Close cleans up resources associated with the signer and returns an error if any.
	Close() error
}
