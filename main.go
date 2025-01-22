package main

import (
	"fmt"
	"github.com/alapierre/godss/signer"
	"github.com/alapierre/godss/xades"
	"github.com/beevik/etree"
	"os"
	"strings"
)

// Example usage
func main() {

	pin := os.Getenv("PIN")
	if pin == "" {
		panic("PIN envirnoment variable is not set")
	}

	sig, err := signer.NewPkcs11Signer(signer.Pkcs11Config{
		Pkcs11ModulePath: "/opt/proCertumSmartSign/libcryptoCertum3PKCS.so",
		Pin:              pin,
		SlotNumber:       0,
	})

	if err != nil {
		panic(err)
	}

	defer sig.Close()

	x := xades.NewDefault(sig)
	var sampleXml = `<invoice><Number>12345</Number></invoice>`

	doc := etree.NewDocument()
	err = doc.ReadFromString(strings.ReplaceAll(sampleXml, "\n", ""))
	if err != nil {
		panic(err)
	}

	signature, err := x.CreateSignature(doc.Root())
	if err != nil {
		panic(err)
	}

	signedDoc := etree.NewDocument()
	signedDoc.SetRoot(signature)
	signedXML, err := signedDoc.WriteToString()

	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", signedXML)

}
