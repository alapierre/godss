package keystore

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/alapierre/godss/signer"
	"github.com/youmark/pkcs8"
)

type X509KeyStoreSigner struct {
	backend     crypto.Signer
	certificate *x509.Certificate
}

type X509KeyStoreOption func(*x509KeyStoreOptions)

type x509KeyStoreOptions struct {
	privateKeyPassword []byte
}

func WithPrivateKeyPassword(password string) X509KeyStoreOption {
	return func(o *x509KeyStoreOptions) {
		o.privateKeyPassword = []byte(password)
	}
}

func NewX509KeyStoreSigner(privateKeyPath string, certificatePath string, opts ...X509KeyStoreOption) (signer.Signer, error) {

	if _, err := os.Stat(privateKeyPath); err != nil {
		return nil, fmt.Errorf("private key file %q not available: %w", privateKeyPath, err)
	}
	if _, err := os.Stat(certificatePath); err != nil {
		return nil, fmt.Errorf("certificate file %q not available: %w", certificatePath, err)
	}

	cfg := x509KeyStoreOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	privateKey, err := loadPrivateKey(privateKeyPath, cfg.privateKeyPassword)
	if err != nil {
		return nil, err
	}

	certificate, err := loadCertificate(certificatePath)
	if err != nil {
		return nil, err
	}

	return &X509KeyStoreSigner{backend: privateKey, certificate: certificate}, nil
}

func (x *X509KeyStoreSigner) SignBytes(message []byte) ([]byte, error) {
	h := crypto.SHA256.New()
	_, _ = h.Write(message)
	digest := h.Sum(nil)

	return x.Sign(rand.Reader, digest, crypto.SHA256)
}

func (x *X509KeyStoreSigner) SignString(message string) ([]byte, error) {
	return x.SignBytes([]byte(message))
}

func (x *X509KeyStoreSigner) GetCerts() ([][]byte, error) {
	return [][]byte{x.certificate.Raw}, nil
}

func (x *X509KeyStoreSigner) Public() crypto.PublicKey {
	return x.backend.Public()
}

func (x *X509KeyStoreSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := x.backend.Sign(r, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("signing error: %w", err)
	}
	return sig, nil
}

func (x *X509KeyStoreSigner) Close() error {
	return nil
}

func loadPrivateKey(path string, password []byte) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("nieprawidłowy format klucza prywatnego (brak bloku PEM)")
	}

	var keyAny any

	switch block.Type {
	case "ENCRYPTED PRIVATE KEY":
		if len(password) == 0 {
			return nil, fmt.Errorf("klucz jest zaszyfrowany (ENCRYPTED PRIVATE KEY), ale nie podano hasła")
		}
		keyAny, err = pkcs8.ParsePKCS8PrivateKey(block.Bytes, password)

	case "PRIVATE KEY":
		// PKCS#8 niezaszyfrowany
		keyAny, err = x509.ParsePKCS8PrivateKey(block.Bytes)

	case "EC PRIVATE KEY":
		// SEC1 EC private key
		keyAny, err = x509.ParseECPrivateKey(block.Bytes)

	default:
		return nil, fmt.Errorf("nieobsługiwany typ PEM: %q", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("błąd parsowania/odszyfrowania klucza prywatnego: %w", err)
	}

	sig, ok := keyAny.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("wczytany klucz nie implementuje crypto.Signer (jest: %T)", keyAny)
	}
	return sig, nil
}

// Wczytuje certyfikat z pliku PEM
func loadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("nieprawidłowy format certyfikatu")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("błąd parsowania certyfikatu: %w", err)
	}

	return cert, nil
}
