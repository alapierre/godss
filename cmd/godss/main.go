package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/akamensky/argparse"
	"github.com/alapierre/godss/card"
	"github.com/alapierre/godss/keystore"
	"github.com/alapierre/godss/signer"
	"github.com/alapierre/godss/version"
	"github.com/alapierre/godss/xades"
	"github.com/beevik/etree"
	"golang.org/x/term"
)

func main() {

	parser := argparse.NewParser("godss", "XAdES signature CLI "+version.Version)
	in := parser.FilePositional(0, 0, &argparse.Options{Required: true, Help: "File to sign"})

	store := parser.NewCommand("keystore", "Sign XML document with key and certificate from pem files (RSA or EC)")
	cert := store.String("c", "cert", &argparse.Options{Required: true, Help: "Cert / public key file"})
	key := store.String("k", "key", &argparse.Options{Required: true, Help: "Key file in pem format, could be encrypted (provide pass as SIG_PIN env variable)"})

	cardCmd := parser.NewCommand("card", "Sign XML document with PKCS#11 token")
	slot := cardCmd.Int("s", "slot", &argparse.Options{Required: true, Help: "PKCS#11 slot number", Default: 0})
	driver := cardCmd.String("d", "driver", &argparse.Options{Required: true, Help: "PKCS#11 module path"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

	pass := os.Getenv("SIG_PIN")
	if pass == "" {
		fmt.Println("PIN environment variable is not set")
	}

	var signedDoc *etree.Document

	if store.Happened() {
		signedDoc, err = signWithKeystore(*key, *cert, pass, in)
		if err != nil {
			fmt.Printf("Cannot sign: %v", err)
			os.Exit(1)
		}
	} else if cardCmd.Happened() {

		if pass == "" {
			pass, err = promptPIN("Provide PIN: ")
			if err != nil {
				fmt.Printf("Cannot read PIN: %v", err)
				os.Exit(1)
			}
		}

		signedDoc, err = singWithSmartCard(pass, *driver, uint(*slot), in)
		if err != nil {
			fmt.Printf("Cannot sign: %v", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("No signing method specified")
		os.Exit(1)
	}

	err = signedDoc.WriteToFile(prepareOutPath(in))
	if err != nil {
		panic(err)
	}
}

func signWithKeystore(key, cert, pass string, in io.Reader) (*etree.Document, error) {

	var sig signer.Signer
	var err error

	if pass != "" {
		sig, err = keystore.NewX509KeyStoreSigner(key, cert, keystore.WithPrivateKeyPassword(pass))
		if err != nil {
			return nil, fmt.Errorf("cannot initialize keystore signer: %w", err)
		}
	} else {
		sig, err = keystore.NewX509KeyStoreSigner(key, cert)
		if err != nil {
			return nil, fmt.Errorf("cannot initialize keystore signer: %w", err)
		}
	}

	defer sig.Close()

	x := xades.NewDefault(sig)
	doc := etree.NewDocument()
	_, err = doc.ReadFrom(in)

	if err != nil {
		return nil, err
	}

	signedDoc, err := x.SignDocument(doc.Root())
	if err != nil {
		return nil, err
	}

	return signedDoc, nil
}

func singWithSmartCard(pin, driver string, slot uint, in io.Reader) (*etree.Document, error) {

	sig, err := card.NewPkcs11Signer(card.Pkcs11Config{
		Pkcs11ModulePath: driver,
		Pin:              pin,
		SlotNumber:       slot,
	})

	if err != nil {
		return nil, err
	}

	defer sig.Close()

	x := xades.NewDefault(sig)

	doc := etree.NewDocument()
	_, err = doc.ReadFrom(in)
	if err != nil {
		return nil, err
	}

	signedDoc, err := x.SignDocument(doc.Root())
	if err != nil {
		return nil, err
	}

	return signedDoc, nil
}

func prepareOutPath(inFile *os.File) string {

	inPath := inFile.Name()
	dir := filepath.Dir(inPath)
	base := filepath.Base(inPath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)

	outName := stem + ".signed" + ext
	return filepath.Join(dir, outName)
}

func promptPIN(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("stdin nie jest terminalem (nie da się bezpiecznie zapytać o PIN); ustaw SIG_PIN")
	}

	_, _ = fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}

	pin := strings.TrimSpace(string(b))
	if pin == "" {
		return "", fmt.Errorf("PIN nie może być pusty")
	}
	return pin, nil
}
