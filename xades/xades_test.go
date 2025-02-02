package xades

import (
	"crypto"
	"fmt"
	"github.com/alapierre/godss/signer"
	"github.com/beevik/etree"
	"os"
	"strings"
	"testing"
	"time"
)

func TestKeyStoreSign(t *testing.T) {

	signer, err := signer.NewX509KeyStoreSigner("../test_data/private_key.pem", "../test_data/certificate.pem")

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

	signature, err := x.CreateSignature(root)
	if err != nil {
		t.Error(err)
	}

	b, err := canonicalSerialize(signature)
	if err != nil {
		fmt.Printf("%v\n", err.Error())
	}
	fmt.Println(string(b))
}

func TestSign(t *testing.T) {

	pin := os.Getenv("PIN")
	if pin == "" {
		t.Skip("Pomijanie testu: brak PIN do karty inteligentnej (zmienna środowiskowa PIN nie jest ustawiona)")
	}

	sig, err := signer.NewPkcs11Signer(signer.Pkcs11Config{
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

	signature, err := x.CreateSignature(root)
	if err != nil {
		t.Error(err)
	}

	//ret := doc.Root().Copy()
	//ret.Child = append(ret.Child, signedXML)
	//
	//signedDoc := etree.NewDocument()
	//signedDoc.SetRoot(ret)

	//res, err := signedDoc.WriteToString()
	//if err != nil {
	//	fmt.Printf("failed to serialize signed XML: %v", err)
	//	t.Error(err)
	//}

	//signedDoc := etree.NewDocument()
	//signedDoc.SetRoot(signedXML)
	//
	//res, err := signedDoc.WriteToString()
	//if err != nil {
	//	fmt.Printf("failed to serialize signed XML: %v", err)
	//	os.Exit(1)
	//}
	//
	//fmt.Printf("Signed XML: %s\n", res)

	b, err := canonicalSerialize(signature)
	if err != nil {
		fmt.Printf("%v\n", err.Error())
	}
	fmt.Println(string(b))

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
