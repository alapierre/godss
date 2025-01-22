package goxades

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/beevik/etree"
	"github.com/miekg/pkcs11"
	goxmldsig "github.com/russellhaering/goxmldsig"
	"io"
	"math/big"
)

// Config holds the configuration for XAdES signing.
type Config struct {
	PKCS11ModulePath string
	Pin              string
	SlotNumber       uint
	XMLToSign        string
}

// SampleSigner is responsible for signing XML documents using XAdES.
type SampleSigner struct {
	config Config
	ctx    *pkcs11.Ctx
}

// NewSigner creates a new SampleSigner instance.
func NewSigner(config Config) (*SampleSigner, error) {
	ctx := pkcs11.New(config.PKCS11ModulePath)
	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize pkcs11: %v", err)
	}
	return &SampleSigner{
		config: config,
		ctx:    ctx,
	}, nil
}

// Close releases resources held by the signer.
func (s *SampleSigner) Close() {
	if s.ctx != nil {
		s.ctx.Finalize()
	}
}

// SignXML signs the provided XML and returns the signed document.
func (s *SampleSigner) SignXML() (*etree.Element, error) {
	// Open session
	slots, err := s.ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %v", err)
	}
	if len(slots) <= int(s.config.SlotNumber) {
		return nil, fmt.Errorf("invalid slot number")
	}

	session, err := s.ctx.OpenSession(slots[s.config.SlotNumber], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %v", err)
	}
	defer s.ctx.CloseSession(session)

	// Login
	if err := s.ctx.Login(session, pkcs11.CKU_USER, s.config.Pin); err != nil {
		return nil, fmt.Errorf("failed to login: %v", err)
	}
	defer s.ctx.Logout(session)

	// Find signing key
	if err := s.ctx.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize object search: %v", err)
	}
	objects, _, err := s.ctx.FindObjects(session, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to find objects: %v", err)
	}
	s.ctx.FindObjectsFinal(session)
	if len(objects) == 0 {
		return nil, fmt.Errorf("no signing key found")
	}

	// Parse the XML to sign
	doc := etree.NewDocument()
	if err := doc.ReadFromString(s.config.XMLToSign); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %v", err)
	}

	// Znajdź odpowiadający klucz publiczny
	err = s.ctx.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize object search: %v", err)
	}
	publicKeys, _, err := s.ctx.FindObjects(session, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to find public key: %v", err)
	}
	s.ctx.FindObjectsFinal(session)
	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("no public key found")
	}
	publicKey := publicKeys[0]

	// Pobierz atrybuty klucza publicznego
	pubKeyAttrs, err := s.ctx.GetAttributeValue(session, publicKey, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key attributes: %v", err)
	}

	// Utwórz klucz publiczny RSA
	modulus := new(big.Int).SetBytes(pubKeyAttrs[0].Value)
	exponent := new(big.Int).SetBytes(pubKeyAttrs[1].Value)
	pubKey := &rsa.PublicKey{
		N: modulus,
		E: int(exponent.Int64()),
	}

	// Pobierz certyfikat
	err = s.ctx.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize object search: %v", err)
	}
	certs, _, err := s.ctx.FindObjects(session, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to find certificate: %v", err)
	}
	s.ctx.FindObjectsFinal(session)
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate found")
	}
	cert := certs[0]

	// Pobierz atrybuty certyfikatu
	certAttrs, err := s.ctx.GetAttributeValue(session, cert, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate attributes: %v", err)
	}

	// Parsuj certyfikat
	parsedCert, err := x509.ParseCertificate(certAttrs[0].Value)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Prepare XML signer
	signer := &PKCS11Signer{
		ctx:        s.ctx,
		session:    session,
		privateKey: objects[0],
		publicKey:  pubKey,
	}

	certChain := [][]byte{parsedCert.Raw}

	signatureContext, err := goxmldsig.NewSigningContext(signer, certChain)
	signatureContext.IdAttribute = "id"
	signatureContext.GetSignatureMethodIdentifier()

	signedXML, err := signatureContext.SignEnveloped(doc.Root())
	if err != nil {
		return nil, fmt.Errorf("failed to sign XML: %v", err)
	}
	return signedXML, nil
}

type PKCS11Signer struct {
	ctx        *pkcs11.Ctx
	session    pkcs11.SessionHandle
	privateKey pkcs11.ObjectHandle
	publicKey  crypto.PublicKey
}

func (s *PKCS11Signer) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *PKCS11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	err := s.ctx.SignInit(s.session, []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil),
	}, s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize signing: %v", err)
	}

	signature, err := s.ctx.Sign(s.session, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %v", err)
	}
	return signature, nil
}

func CreateSignatureSample(doc *etree.Element, signer crypto.Signer, cert *x509.Certificate) (*etree.Element, error) {
	// Create <SignedInfo>
	signedInfo := etree.NewElement("SignedInfo")
	signedInfo.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")

	// Add canonicalization method
	canonicalizationMethod := etree.NewElement("CanonicalizationMethod")
	canonicalizationMethod.CreateAttr("Algorithm", "http://www.w3.org/2006/12/xml-c14n11")
	signedInfo.AddChild(canonicalizationMethod)

	// Add signature method
	signatureMethod := etree.NewElement("SignatureMethod")
	signatureMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	signedInfo.AddChild(signatureMethod)

	// Add <Reference> with digest
	reference := etree.NewElement("Reference")
	reference.CreateAttr("URI", "")
	transforms := etree.NewElement("Transforms")
	transform := etree.NewElement("Transform")
	transform.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
	transforms.AddChild(transform)
	reference.AddChild(transforms)

	// Calculate digest of the document

	signedDoc := etree.NewDocument()
	signedDoc.SetRoot(doc)
	docBytes, err := signedDoc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize document for digest calculation: %v", err)
	}
	hash := sha256.Sum256(docBytes)
	digestMethod := etree.NewElement("DigestMethod")
	digestMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	reference.AddChild(digestMethod)
	digestValue := etree.NewElement("DigestValue")
	digestValue.SetText(base64.StdEncoding.EncodeToString(hash[:]))
	reference.AddChild(digestValue)
	signedInfo.AddChild(reference)

	// SignBytes the <SignedInfo> element
	infoDoc := etree.NewDocument()
	infoDoc.SetRoot(signedInfo)
	signedInfoBytes, err := infoDoc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize SignedInfo: %v", err)
	}

	digest := sha256.Sum256(signedInfoBytes)                     // Wynik: [32]byte
	signature, err := signer.Sign(nil, digest[:], crypto.SHA256) // Użycie `digest[:]` konwertuje na []byte
	if err != nil {
		return nil, fmt.Errorf("failed to sign SignedInfo: %v", err)
	}

	// Create <SignatureValue>
	signatureValue := etree.NewElement("SignatureValue")
	signatureValue.SetText(base64.StdEncoding.EncodeToString(signature))

	// Create <KeyInfo> with the certificate
	keyInfo := etree.NewElement("KeyInfo")
	x509Data := etree.NewElement("X509Data")
	x509Certificate := etree.NewElement("X509Certificate")
	x509Certificate.SetText(base64.StdEncoding.EncodeToString(cert.Raw))
	x509Data.AddChild(x509Certificate)
	keyInfo.AddChild(x509Data)

	// Combine into <Signature>
	signatureEl := etree.NewElement("Signature")
	signatureEl.CreateAttr("Id", "Signature-1")
	signatureEl.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
	signatureEl.AddChild(signedInfo)
	signatureEl.AddChild(signatureValue)
	signatureEl.AddChild(keyInfo)

	return signatureEl, nil
}
