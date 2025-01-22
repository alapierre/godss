# godss
First comprehensive solution in Go for creating XAdES-compliant XML signatures using PKCS#11 tokens or keystores. This library enables seamless signing of XML documents, supporting cryptographic devices for secure digital signatures.

[![GoDoc](https://godoc.org/github.com/alapierre/godss?status.svg)](https://godoc.org/github.com/alapierre/godss)

# Usage

````go
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
````

## Acknowledgments

This project was inspired by and partially based on [[goxades](https://github.com/artemkunich/goxades/)], which is licensed under the Apache License, Version 2.0.
Some constants and types are copied from [[goxmldsig](https://github.com/russellhaering/goxmldsig)], which is also licensed under the Apache License, Version 2.0.

Significant portions of codebase have been modified or rewritten to better fit the needs of this project.
