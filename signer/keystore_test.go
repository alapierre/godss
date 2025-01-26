package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestX509KeyStoreSigner(t *testing.T) {

	signer, err := NewX509KeyStoreSigner("../test_data/private_key.pem", "../test_data/certificate.pem")

	if err != nil {
		t.Error(err)
	}

	originalText := "Hello World!"
	signed, err := signer.SignString(originalText)

	if err != nil {
		t.Error(err)
	}

	t.Logf("Signed: %s", base64.StdEncoding.EncodeToString(signed))

	publicKey, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Errorf("Klucz publiczny nie jest typu RSA")
	}

	hashed := sha256.Sum256([]byte(originalText))

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signed)
	if err != nil {
		t.Errorf("Podpis nie jest prawidłowy: %v\n", err)
	} else {
		fmt.Println("Podpis jest prawidłowy")
	}
}

func TestX509SignerInterface(t *testing.T) {

	signer, err := NewX509KeyStoreSigner("../test_data/private_key.pem", "../test_data/certificate.pem")

	if err != nil {
		t.Error(err)
	}

	originalText := "Hello World!"
	hashed := sha256.Sum256([]byte(originalText))

	signed, err := signer.Sign(rand.Reader, hashed[:], crypto.SHA256)

	if err != nil {
		t.Error(err)
	}

	t.Logf("Signed: %s", base64.StdEncoding.EncodeToString(signed))

	publicKey, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Errorf("Klucz publiczny nie jest typu RSA")
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signed)
	if err != nil {
		t.Errorf("Podpis nie jest prawidłowy: %v\n", err)
	} else {
		fmt.Println("Podpis jest prawidłowy")
	}
}
