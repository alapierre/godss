package signer

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
)

func TestSign(t *testing.T) {

	pin := os.Getenv("PIN")
	if pin == "" {
		t.Skip("Pomijanie testu: brak PIN do karty inteligentnej (zmienna środowiskowa PIN nie jest ustawiona)")
	}

	mod := "/opt/proCertumSmartSign/libcryptoCertum3PKCS.so"

	sig, err := NewPkcs11Signer(Pkcs11Config{
		Pkcs11ModulePath: mod,
		Pin:              pin,
		SlotNumber:       0,
	})

	defer sig.Close()

	if err != nil {
		t.Error(err)
	}

	originalText := "Hello World!"
	signed, err := sig.SignString(originalText)

	if err != nil {
		t.Error(err)
	}

	t.Logf("Signed: %s", base64.StdEncoding.EncodeToString(signed))

	b, _ := sig.GetCerts()
	cert, err := x509.ParseCertificate(b[0])
	if err != nil {
		t.Errorf("Błąd parsowania certyfikatu: %v\n", err)
	}

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
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
