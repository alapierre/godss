# godss
First comprehensive solution in Go for creating XAdES-compliant XML signatures using PKCS#11 tokens or keystores. This library enables seamless signing of XML documents, supporting cryptographic devices for secure digital signatures.

[![GoDoc](https://godoc.org/github.com/alapierre/godss?status.svg)](https://godoc.org/github.com/alapierre/godss)
[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=alapierre_godss&metric=alert_status)](https://sonarcloud.io/dashboard?id=alapierre_godss)
[![Build Status](https://github.com/alapierre/godss/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/alapierre/godss/actions/workflows/go.yml)

## Usage

````go
package main

import (
	"fmt"
	"os"

	"github.com/alapierre/godss/keystore"
	"github.com/alapierre/godss/xades"
)

func main() {
	privateKeyPath := "test_data/private_key.pem"
	certPath := "test_data/certificate.pem"
	xml := []byte(`<invoice><Number>12345</Number></invoice>`)

	sig, err := keystore.NewX509KeyStoreSigner(privateKeyPath, certPath)

	if err != nil {
		panic(err)
	}

	defer sig.Close()

	x := xades.NewDefault(sig)

	signedXML, err := x.SignBytes(xml)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(signedXML))
}
````

Check `cmd/godss/main.go` for an example

## CLI

```shell
SIG_PIN='.....' ./godss keystore -k ../../test_data/auth-cert.key -c ../../test_data/auth-cert.crt ../../test_data/authv2_20260216072211.xml
```

```shell
./godss card -d /opt/proCertumSmartSign/libcryptoCertum3PKCS.so -s 0 ../../test_data/authv2_20260216072211.xml
```

Will ask for PIN, but you can also use `SIG_PIN` env variable.

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

## Tools    

- https://tools.chilkat.io/