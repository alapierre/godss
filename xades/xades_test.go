package xades

import (
	"crypto"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alapierre/godss/card"
	"github.com/alapierre/godss/keystore"
	"github.com/beevik/etree"
)

func TestKeyStoreSign(t *testing.T) {

	signer, err := keystore.NewX509KeyStoreSigner("../test_data/private_key.pem", "../test_data/certificate.pem")

	if err != nil {
		t.Error(err)
	}

	if err != nil {
		t.Error(err)
	}

	x := New(Config{
		Canonicalizer: MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
		IsEnveloped:   true,
		Hash:          crypto.SHA256,
		ReferenceURI:  "",
		SigningTime:   time.Time{},
	}, signer)

	var sampleXml = `<invoice><Number>12345</Number></invoice>`

	doc := etree.NewDocument()
	err = doc.ReadFromString(strings.ReplaceAll(sampleXml, "\n", ""))
	if err != nil {
		t.Error(err)
	}

	root := removeComments(doc.Root())
	c, _ := canonicalSerialize(root)
	fmt.Printf("source: %s\n", c)

	signature, err := x.SignDocument(root)
	if err != nil {
		t.Error(err)
	}

	str, err := signature.WriteToString()
	fmt.Println(str)
}

func TestSign(t *testing.T) {

	pin := os.Getenv("SIG_PIN")
	if pin == "" {
		t.Skip("Pomijanie testu: brak PIN do karty inteligentnej (zmienna środowiskowa PIN nie jest ustawiona)")
	}

	sig, err := card.NewPkcs11Signer(card.Pkcs11Config{
		Pkcs11ModulePath: "/opt/proCertumSmartSign/libcryptoCertum3PKCS.so",
		Pin:              pin,
		SlotNumber:       0,
	})

	if err != nil {
		t.Error(err)
	}

	defer sig.Close()

	x := New(Config{
		Canonicalizer: MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
		IsEnveloped:   true,
		Hash:          crypto.SHA256,
		ReferenceURI:  "",
		SigningTime:   time.Time{},
	}, sig)

	var sampleXml = `<invoice><Number>12345</Number></invoice>`

	doc := etree.NewDocument()
	err = doc.ReadFromString(strings.ReplaceAll(sampleXml, "\n", ""))
	if err != nil {
		t.Error(err)
	}

	root := removeComments(doc.Root())
	c, _ := canonicalSerialize(root)
	fmt.Printf("source: %s\n", c)

	signature, err := x.SignDocument(root)
	if err != nil {
		t.Error(err)
	}

	str, err := signature.WriteToString()
	fmt.Println(str)
}

func removeComments(elem *etree.Element) *etree.Element {
	copy := elem.Copy()
	for _, token := range copy.Child {
		_, ok := token.(*etree.Comment)
		if ok {
			copy.RemoveChild(token)
		}
	}
	for i, child := range elem.ChildElements() {
		copy.ChildElements()[i] = removeComments(child)
	}
	return copy
}
