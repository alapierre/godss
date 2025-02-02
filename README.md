# godss
First comprehensive solution in Go for creating XAdES-compliant XML signatures using PKCS#11 tokens or keystores. This library enables seamless signing of XML documents, supporting cryptographic devices for secure digital signatures.

[![GoDoc](https://godoc.org/github.com/alapierre/godss?status.svg)](https://godoc.org/github.com/alapierre/godss)
[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=alapierre_godss&metric=alert_status)](https://sonarcloud.io/dashboard?id=alapierre_godss)
[![Build Status](https://github.com/alapierre/godss/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/alapierre/godss/actions/workflows/go.yml)

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

## Generating test sign certyficate

````shell
openssl req -x509 -newkey rsa:4096 -keyout private_key.pem -out certificate.pem -days 365 -nodes
````

or:

````shell
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:3072
openssl req -new -key private_key.pem -out cert_request.csr
openssl x509 -req -in cert_request.csr -signkey private_key.pem -out certificate.pem -days 365
````

optionally you can pack it in .p12 file:

````shell
openssl pkcs12 -export -inkey private_key.pem -in certificate.pem -out certificate.p12 -name "My Certificate"
````

## Acknowledgments

This project was inspired by and partially based on [[goxades](https://github.com/artemkunich/goxades/)], which is licensed under the Apache License, Version 2.0.
Some constants and types are copied from [[goxmldsig](https://github.com/russellhaering/goxmldsig)], which is also licensed under the Apache License, Version 2.0.

Significant portions of codebase have been modified or rewritten to better fit the needs of this project.

## Other implementations

- https://github.com/digitalautonomy/goxades_sri/