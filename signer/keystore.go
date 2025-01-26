package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

type X509KeyStoreSigner struct {
	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
}

func NewX509KeyStoreSigner(privateKeyPath string, certificatePath string) (Signer, error) {
	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		return nil, err
	}

	certificate, err := loadCertificate(certificatePath)
	if err != nil {
		return nil, err
	}

	return &X509KeyStoreSigner{privateKey, certificate}, nil
}

func (x *X509KeyStoreSigner) SignBytes(message []byte) ([]byte, error) {

	hash := crypto.SHA256.New()
	hash.Write(message)
	hashedData := hash.Sum(nil)

	// Podpisz dane za pomocą klucza prywatnego
	signature, err := rsa.SignPKCS1v15(rand.Reader, x.privateKey, crypto.SHA256, hashedData)
	if err != nil {
		return nil, fmt.Errorf("Signing error: %v\n", err)

	}

	return signature, nil
}

func (x *X509KeyStoreSigner) SignString(message string) ([]byte, error) {
	return x.SignBytes([]byte(message))
}

func (x *X509KeyStoreSigner) GetCerts() ([][]byte, error) {
	return [][]byte{x.certificate.Raw}, nil
}

func (x *X509KeyStoreSigner) Public() crypto.PublicKey {
	return x.privateKey.Public()
}

func (x *X509KeyStoreSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {

	signature, err := rsa.SignPKCS1v15(rand, x.privateKey, opts.HashFunc(), digest)
	if err != nil {
		return nil, fmt.Errorf("Signing error: %v\n", err)
	}

	return signature, nil
}

func (x *X509KeyStoreSigner) Close() error {
	return nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("nieprawidłowy format klucza prywatnego")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("błąd parsowania klucza prywatnego: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("klucz prywatny nie jest typu RSA")
	}
	return rsaKey, nil
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
