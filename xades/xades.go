package xades

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/alapierre/godss/signer"
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

type Config struct {
	Canonicalizer Canonicalizer
	IsEnveloped   bool
	Hash          crypto.Hash
	ReferenceURI  string
	SigningTime   time.Time
}

type Xades struct {
	config Config
	signer signer.Signer
}

func NewDefault(s signer.Signer) *Xades {
	return &Xades{
		config: Config{
			Canonicalizer: MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
			IsEnveloped:   true,
			Hash:          crypto.SHA256,
			ReferenceURI:  "",
			SigningTime:   time.Time{},
		},
		signer: s,
	}
}

func New(config Config, s signer.Signer) *Xades {
	return &Xades{
		config: config,
		signer: s,
	}
}

// SignDocument creates an XML signature for the provided toSign and returns the signed document or an error.
func (x *Xades) SignDocument(toSign *etree.Element) (*etree.Document, error) {
	sigID, refID, xadesID, sigValueID := makeIDs()

	// 1) DigestValue of toSign (root element without signature yet)
	digestData, err := DigestValue(toSign, &x.config.Canonicalizer, x.config.Hash)
	if err != nil {
		return nil, err
	}

	// signing time
	signTime := x.config.SigningTime
	if signTime.IsZero() {
		signTime = time.Now()
	}

	// 2) SignedProperties (needs refID + xadesID)
	signedProperties, err := x.createSignedProperties(signTime, xadesID, refID)
	if err != nil {
		return nil, err
	}

	// Digest of SignedProperties
	qualifiedSignedProperties := qualifySignedPropertiesForDigest(signedProperties)
	digestProperties, err := DigestValue(qualifiedSignedProperties, &x.config.Canonicalizer, x.config.Hash)
	if err != nil {
		return nil, err
	}

	// 3) SignedInfo
	signedInfo, err := x.createSignedInfo(digestData, digestProperties, refID, xadesID)
	if err != nil {
		return nil, err
	}

	qualifiedSignedInfo := qualifySignedInfoForSignature(signedInfo)

	// 4) SignatureValue
	signatureValueText, err := x.signatureValue(qualifiedSignedInfo, &x.config.Canonicalizer)
	if err != nil {
		return nil, err
	}
	signatureValue := createSignatureValue(signatureValueText, sigValueID)

	// 5) KeyInfo
	certs, err := x.signer.GetCerts()
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate chain: %w", err)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	keyInfo := createKeyInfo(base64.StdEncoding.EncodeToString(certs[0]))

	// 6) Object (XAdES QualifyingProperties)
	object := createObject(signedProperties, sigID)

	// 7) Signature element
	signature := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.SignatureTag,
		Attr: []etree.Attr{
			{Space: "xmlns", Key: xmldsigPrefix, Value: dsig.Namespace},
			{Key: "Id", Value: sigID},
		},
		Child: []etree.Token{signedInfo, signatureValue, keyInfo, object},
	}

	// append signature to a copy of the request
	res := toSign.Copy()
	res.AddChild(signature.Copy())

	signedDoc := etree.NewDocument()
	signedDoc.SetRoot(res)

	return signedDoc, nil
}

// SignBytes signs the given XML byte slice, returning the signed XML or an error if signing fails.
func (x *Xades) SignBytes(xml []byte) ([]byte, error) {

	if len(xml) == 0 {
		return nil, fmt.Errorf("xml input is empty")
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xml); err != nil {
		return nil, fmt.Errorf("failed to parse xml: %w", err)
	}

	if doc.Root() == nil {
		return nil, fmt.Errorf("xml has no root element")
	}

	signedDoc, err := x.SignDocument(doc.Root())
	if err != nil {
		return nil, err
	}

	out, err := signedDoc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize signed xml: %w", err)
	}

	return out, nil
}

// signatureValue calculates signature over canonicalized SignedInfo
func (x *Xades) signatureValue(element *etree.Element, canonicalizer *Canonicalizer) (string, error) {
	canonical, err := (*canonicalizer).Canonicalize(element)
	if err != nil {
		return "", err
	}

	derOrRaw, err := x.signer.SignBytes(canonical)
	if err != nil {
		return "", err
	}

	certs, _ := x.signer.GetCerts()
	if len(certs) == 0 {
		return "", fmt.Errorf("certificate chain is empty")
	}
	cert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	// ECDSA: XMLDSIG wants raw r||s, not DER.
	if _, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		raw, err := ecdsaDERToXMLDSIGRaw(derOrRaw, cert)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(raw), nil
	}

	// RSA: keep as is
	return base64.StdEncoding.EncodeToString(derOrRaw), nil
}

// DigestValue calculates digest over canonicalized element
func DigestValue(element *etree.Element, canonicalizer *Canonicalizer, hash crypto.Hash) (string, error) {
	canonical, err := (*canonicalizer).Canonicalize(element)
	if err != nil {
		return "", err
	}

	h := hash.New()
	if _, err := h.Write(canonical); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

func createSignatureValue(base64Signature, sigValueID string) *etree.Element {
	e := etree.Element{
		Space: xmldsigPrefix,
		Tag:   SignatureValueTag,
		Attr: []etree.Attr{
			{Key: "Id", Value: sigValueID},
		},
	}
	e.SetText(base64Signature)
	return &e
}

func createObject(signedProperties *etree.Element, signatureID string) *etree.Element {
	qualifyingProperties := etree.Element{
		Space: Prefix, // "xades"
		Tag:   QualifyingPropertiesTag,
		Attr: []etree.Attr{
			{Space: "xmlns", Key: Prefix, Value: xadesNamespace},
			{Key: targetAttr, Value: "#" + signatureID},
		},
		Child: []etree.Token{signedProperties},
	}

	object := etree.Element{
		Space: xmldsigPrefix,
		Tag:   "Object",
		Child: []etree.Token{&qualifyingProperties},
	}
	return &object
}

func createKeyInfo(base64Certificate string) *etree.Element {
	x509Certificate := etree.Element{
		Space: xmldsigPrefix,
		Tag:   X509CertificateTag,
	}
	x509Certificate.SetText(base64Certificate)

	x509Data := etree.Element{
		Space: xmldsigPrefix,
		Tag:   X509DataTag,
		Child: []etree.Token{&x509Certificate},
	}

	keyInfo := etree.Element{
		Space: xmldsigPrefix,
		Tag:   KeyInfoTag,
		Child: []etree.Token{&x509Data},
	}
	return &keyInfo
}

func (x *Xades) createSignedProperties(signTime time.Time, xadesID string, dataRefID string) (*etree.Element, error) {
	certs, _ := x.signer.GetCerts()
	if len(certs) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}

	parsedCert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// xades:SigningTime
	signingTime := etree.Element{Space: Prefix, Tag: SigningTimeTag}
	signingTime.SetText(signTime.UTC().Format("2006-01-02T15:04:05Z"))

	// xades:SigningCertificate/xades:Cert/xades:CertDigest (ds:DigestMethod + ds:DigestValue)
	digestMethod := etree.Element{
		Space: xmldsigPrefix,
		Tag:   DigestMethodTag,
		Attr:  []etree.Attr{{Key: AlgorithmAttr, Value: digestAlgorithmIdentifiers[crypto.SHA256]}},
	}
	digestValue := etree.Element{
		Space: xmldsigPrefix,
		Tag:   DigestValueTag,
	}
	sum := sha256.Sum256(certs[0])
	digestValue.SetText(base64.StdEncoding.EncodeToString(sum[:]))

	certDigest := etree.Element{
		Space: Prefix,
		Tag:   CertDigestTag,
		Child: []etree.Token{&digestMethod, &digestValue},
	}

	// xades:IssuerSerial (ds:X509IssuerName + ds:X509SerialNumber)
	issuerName := etree.Element{Space: xmldsigPrefix, Tag: "X509IssuerName"}
	issuerName.SetText(parsedCert.Issuer.String())

	serialNumber := etree.Element{Space: xmldsigPrefix, Tag: "X509SerialNumber"}
	serialNumber.SetText(parsedCert.SerialNumber.String())

	issuerSerial := etree.Element{
		Space: Prefix,
		Tag:   IssuerSerialTag,
		Child: []etree.Token{&issuerName, &serialNumber},
	}

	cert := etree.Element{
		Space: Prefix,
		Tag:   CertTag,
		Child: []etree.Token{
			&certDigest,
			&issuerSerial,
		},
	}

	signingCertificate := etree.Element{
		Space: Prefix,
		Tag:   SigningCertificateTag,
		Child: []etree.Token{&cert},
	}

	signedSignatureProperties := etree.Element{
		Space: Prefix,
		Tag:   SignedSignaturePropertiesTag,
		Child: []etree.Token{
			&signingTime,
			&signingCertificate,
		},
	}

	// xades:SignedDataObjectProperties/xades:DataObjectFormat[@ObjectReference="#refId"]/xades:MimeType
	dataObjectFormat := etree.Element{
		Space: Prefix,
		Tag:   "DataObjectFormat",
		Attr: []etree.Attr{
			{Key: "ObjectReference", Value: "#" + dataRefID},
		},
	}
	mimeType := etree.Element{Space: Prefix, Tag: "MimeType"}
	mimeType.SetText(mimeTypeTextXML)
	dataObjectFormat.AddChild(&mimeType)

	signedDataObjectProperties := etree.Element{
		Space: Prefix,
		Tag:   "SignedDataObjectProperties",
		Child: []etree.Token{&dataObjectFormat},
	}

	// xades:SignedProperties
	signedProperties := etree.Element{
		Space: Prefix,
		Tag:   SignedPropertiesTag,
		Attr:  []etree.Attr{{Key: "Id", Value: xadesID}},
		Child: []etree.Token{
			&signedSignatureProperties,
			&signedDataObjectProperties,
		},
	}

	return &signedProperties, nil
}

func (x *Xades) createSignedInfo(digestValueDataText string, digestValuePropertiesText string, dataRefID, xadesID string) (*etree.Element, error) {
	// CanonicalizationMethod
	canonicalizationMethod := etree.Element{
		Space: xmldsigPrefix,
		Tag:   CanonicalizationMethodTag,
		Attr: []etree.Attr{
			{Key: AlgorithmAttr, Value: x.config.Canonicalizer.Algorithm().String()},
		},
	}

	// SignatureMethod (based on public key type)
	certs, _ := x.signer.GetCerts()
	if len(certs) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	parsedCert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	alg, err := signatureMethodURI(parsedCert, x.config.Hash)
	if err != nil {
		return nil, err
	}

	signatureMethod := etree.Element{
		Space: xmldsigPrefix,
		Tag:   SignatureMethodTag,
		Attr:  []etree.Attr{{Key: AlgorithmAttr, Value: alg}},
	}

	// Reference #1: whole document (URI="") with filter2 subtract ds:Signature + c14n
	transformsData := etree.Element{Space: xmldsigPrefix, Tag: TransformsTag}
	if x.config.IsEnveloped {
		transformsData.AddChild(makeFilter2Transform())
	}
	transformData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   TransformTag,
		Attr:  []etree.Attr{{Key: AlgorithmAttr, Value: x.config.Canonicalizer.Algorithm().String()}},
	}
	transformsData.AddChild(&transformData)

	digestMethodData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   DigestMethodTag,
		Attr:  []etree.Attr{{Key: AlgorithmAttr, Value: digestAlgorithmIdentifiers[x.config.Hash]}},
	}
	digestValueData := etree.Element{Space: xmldsigPrefix, Tag: DigestValueTag}
	digestValueData.SetText(digestValueDataText)

	referenceData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   ReferenceTag,
		Attr: []etree.Attr{
			{Key: "Id", Value: dataRefID},
			{Key: URIAttr, Value: x.config.ReferenceURI},
		},
		Child: []etree.Token{&transformsData, &digestMethodData, &digestValueData},
	}

	// Reference #2: SignedProperties
	transformsProperties := etree.Element{Space: xmldsigPrefix, Tag: TransformsTag}
	transformProps := etree.Element{
		Space: xmldsigPrefix,
		Tag:   TransformTag,
		Attr:  []etree.Attr{{Key: AlgorithmAttr, Value: x.config.Canonicalizer.Algorithm().String()}},
	}
	transformsProperties.AddChild(&transformProps)

	digestMethodProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   DigestMethodTag,
		Attr:  []etree.Attr{{Key: AlgorithmAttr, Value: digestAlgorithmIdentifiers[x.config.Hash]}},
	}
	digestValueProperties := etree.Element{Space: xmldsigPrefix, Tag: DigestValueTag}
	digestValueProperties.SetText(digestValuePropertiesText)

	referenceProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   ReferenceTag,
		Attr: []etree.Attr{
			{Key: URIAttr, Value: "#" + xadesID},
			{Key: "Type", Value: signedPropertiesType},
		},
		Child: []etree.Token{&transformsProperties, &digestMethodProperties, &digestValueProperties},
	}

	signedInfo := etree.Element{
		Space: xmldsigPrefix,
		Tag:   SignedInfoTag,
		Child: []etree.Token{
			&canonicalizationMethod,
			&signatureMethod,
			&referenceData,
			&referenceProperties,
		},
	}
	return &signedInfo, nil
}

// qualifySignedInfoForSignature adds xmlns:ds to SignedInfo so c14n has the ds prefix mapping
func qualifySignedInfoForSignature(signedInfo *etree.Element) *etree.Element {
	q := signedInfo.Copy()
	q.Attr = append(q.Attr, etree.Attr{Space: "xmlns", Key: xmldsigPrefix, Value: dsNamespace})
	return q
}

// qualifySignedPropertiesForDigest adds xmlns:ds and xmlns:xades to SignedProperties for digest calculation
func qualifySignedPropertiesForDigest(signedProperties *etree.Element) *etree.Element {
	q := signedProperties.Copy()
	q.Attr = append(q.Attr,
		etree.Attr{Space: "xmlns", Key: xmldsigPrefix, Value: dsNamespace},
		etree.Attr{Space: "xmlns", Key: Prefix, Value: xadesNamespace},
	)
	return q
}

func makeFilter2Transform() *etree.Element {
	xpath := etree.Element{
		Space: "dsig-filter2",
		Tag:   "XPath",
		Attr: []etree.Attr{
			{Key: "Filter", Value: "subtract"},
			{Space: "xmlns", Key: "dsig-filter2", Value: xmldsigFilter2NS},
		},
	}
	xpath.SetText(xpathSubtractSignature)

	t := etree.Element{
		Space: xmldsigPrefix,
		Tag:   TransformTag,
		Attr: []etree.Attr{
			{Key: AlgorithmAttr, Value: xmldsigFilter2Algo},
		},
		Child: []etree.Token{&xpath},
	}
	return &t
}

func signatureMethodURI(cert *x509.Certificate, h crypto.Hash) (string, error) {
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if h == crypto.SHA256 {
			return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", nil
		}
		return "", fmt.Errorf("unsupported hash for ECDSA: %v", h)

	case *rsa.PublicKey:
		if h == crypto.SHA256 {
			return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", nil
		}
		return "", fmt.Errorf("unsupported hash for RSA: %v", h)

	default:
		return "", fmt.Errorf("unsupported public key type: %T", cert.PublicKey)
	}
}

func makeIDs() (sigID, refID, xadesID, sigValueID string) {
	nonce := fmt.Sprintf("%d", time.Now().UnixNano())
	sigID = "id-" + nonce
	refID = "r-id-" + nonce + "-1"
	xadesID = "xades-id-" + nonce
	sigValueID = "value-id-" + nonce
	return
}
