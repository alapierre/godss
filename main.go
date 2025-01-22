package main

import (
	"fmt"
	"github.com/alapierre/godss/goxades"
	"github.com/beevik/etree"
	"os"
)

// Example usage
func main() {
	config := goxades.Config{
		PKCS11ModulePath: "/opt/proCertumSmartSign/libcryptoCertum3PKCS.so",
		Pin:              os.Getenv("PIN"),
		SlotNumber:       0,
		XMLToSign:        `<YourXMLDocument id="signedData"></YourXMLDocument>`,
	}

	if config.Pin == "" {
		panic("PIN environment variable is not set")
	}

	signer, err := goxades.NewSigner(config)
	if err != nil {
		fmt.Printf("Error creating signer: %v\n", err)
		os.Exit(1)
	}
	defer signer.Close()

	signedXML, err := signer.SignXML()
	if err != nil {
		fmt.Printf("Error signing XML: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Signed XML: %s\n", signedXML)

	signedDoc := etree.NewDocument()
	signedDoc.SetRoot(signedXML)

	res, err := signedDoc.WriteToString()
	if err != nil {
		fmt.Printf("failed to serialize signed XML: %v", err)
		os.Exit(1)
	}

	fmt.Printf("Signed XML: %s\n", res)

}
