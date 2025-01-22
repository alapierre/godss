package signer

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/miekg/pkcs11"
	"io"
	"math/big"
	"os"
)

type Pkcs11Config struct {
	Pkcs11ModulePath string
	Pin              string
	SlotNumber       uint
}

type pkcs11signer struct {
	config     Pkcs11Config
	pkcs       *pkcs11.Ctx
	hash       crypto.Hash
	session    *pkcs11.SessionHandle
	publicKey  crypto.PublicKey
	privateKey *pkcs11.ObjectHandle
	certChain  [][]byte
}

func NewPkcs11Signer(config Pkcs11Config) (Signer, error) {
	ctx := pkcs11.New(config.Pkcs11ModulePath)
	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize pkcs11: %v", err)
	}

	sig := &pkcs11signer{
		config: config,
		pkcs:   ctx,
		hash:   crypto.SHA256,
	}

	if err := sig.cardInit(); err != nil {
		return nil, err
	}

	if err := sig.findSigningKeys(); err != nil {
		return nil, fmt.Errorf("failed to find signing keys: %v", err)
	}

	return sig, nil
}

// SignBytes signs the given message using the private key and returns the signature or an error if signing fails.
func (s *pkcs11signer) SignBytes(message []byte) ([]byte, error) {
	return s.sign(message)
}

// SignString converts the input string to bytes and signs it using SignBytes, returning the signature or an error.
func (s *pkcs11signer) SignString(message string) ([]byte, error) {
	return s.SignBytes([]byte(message))
}

func (s *pkcs11signer) GetCerts() ([][]byte, error) {
	return s.certChain, nil
}

// sign signs the given message using the PKCS#11 private key and returns the resulting signature or an error.
func (s *pkcs11signer) sign(message []byte) ([]byte, error) {

	err := s.pkcs.SignInit(*s.session, []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil),
	}, *s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize signing: %v", err)
	}

	signature, err := s.pkcs.Sign(*s.session, message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %v", err)
	}
	return signature, nil
}

func (s *pkcs11signer) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *pkcs11signer) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) (signature []byte, err error) {
	return s.SignBytes(digest)
}

func (s *pkcs11signer) Close() error {

	var errs []error

	if s.pkcs != nil {
		if err := s.pkcs.CloseSession(*s.session); err != nil {
			errs = append(errs, err)
		}

		if err := s.pkcs.Finalize(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *pkcs11signer) cardInit() error {

	slots, err := s.pkcs.GetSlotList(true)
	if err != nil {
		return fmt.Errorf("failed to get slot list: %v", err)
	}
	if len(slots) <= int(s.config.SlotNumber) {
		return fmt.Errorf("invalid slot number")
	}

	session, err := s.pkcs.OpenSession(slots[s.config.SlotNumber], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("failed to open session: %v", err)
	}

	s.session = &session

	if err := s.pkcs.Login(*s.session, pkcs11.CKU_USER, s.config.Pin); err != nil {
		return fmt.Errorf("failed to login: %v", err)
	}
	return nil
}

func (s *pkcs11signer) findSigningKeys() error {

	session := *s.session

	if err := s.pkcs.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}); err != nil {
		return fmt.Errorf("failed to initialize object search: %v", err)
	}

	objects, _, err := s.pkcs.FindObjects(session, 1)
	if err != nil {
		return fmt.Errorf("failed to find objects: %v", err)
	}

	if err := s.pkcs.FindObjectsFinal(session); err != nil {
		return err
	}

	if len(objects) == 0 {
		return fmt.Errorf("no signing key found")
	}
	s.privateKey = &objects[0]

	// Znajdź odpowiadający klucz publiczny
	err = s.pkcs.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	})
	if err != nil {
		return fmt.Errorf("failed to initialize object search: %v", err)
	}
	publicKeys, _, err := s.pkcs.FindObjects(session, 1)
	if err != nil {
		return fmt.Errorf("failed to find public key: %v", err)
	}
	if err := s.pkcs.FindObjectsFinal(session); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "warning: FindObjectsFinal operation failed: %v\n", err)
	}
	if len(publicKeys) == 0 {
		return fmt.Errorf("no public key found")
	}
	publicKey := publicKeys[0]

	// Pobierz atrybuty klucza publicznego
	pubKeyAttrs, err := s.pkcs.GetAttributeValue(session, publicKey, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		return fmt.Errorf("failed to get public key attributes: %v", err)
	}

	// Utwórz klucz publiczny RSA
	modulus := new(big.Int).SetBytes(pubKeyAttrs[0].Value)
	exponent := new(big.Int).SetBytes(pubKeyAttrs[1].Value)
	s.publicKey = &rsa.PublicKey{
		N: modulus,
		E: int(exponent.Int64()),
	}

	// Pobierz certyfikat
	err = s.pkcs.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	})
	if err != nil {
		return fmt.Errorf("failed to initialize object search: %v", err)
	}
	certs, _, err := s.pkcs.FindObjects(session, 1)
	if err != nil {
		return fmt.Errorf("failed to find certificate: %v", err)
	}

	if err := s.pkcs.FindObjectsFinal(session); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "warning: FindObjectsFinal operation failed: %v\n", err)
	}

	if len(certs) == 0 {
		return fmt.Errorf("no certificate found")
	}
	cert := certs[0]

	// Pobierz atrybuty certyfikatu
	certAttrs, err := s.pkcs.GetAttributeValue(session, cert, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return fmt.Errorf("failed to get certificate attributes: %v", err)
	}

	// Parsuj certyfikat
	parsedCert, err := x509.ParseCertificate(certAttrs[0].Value)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	s.certChain = [][]byte{parsedCert.Raw}

	return nil
}
