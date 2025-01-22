package signer

import (
	"encoding/base64"
	"os"
	"testing"
)

func TestSign(t *testing.T) {

	mod := "/opt/proCertumSmartSign/libcryptoCertum3PKCS.so"
	pin := os.Getenv("PIN")
	if pin == "" {
		t.Errorf("PIN envirnoment variable is not set")
	}

	sig, err := NewPkcs11Signer(Pkcs11Config{
		Pkcs11ModulePath: mod,
		Pin:              pin,
		SlotNumber:       0,
	})

	defer sig.Close()

	if err != nil {
		t.Error(err)
	}

	signed, err := sig.SignString("Hello World!")

	if err != nil {
		t.Error(err)
	}

	t.Logf("Signed: %s", base64.StdEncoding.EncodeToString(signed))

}
