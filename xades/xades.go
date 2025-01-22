package xades

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/alapierre/godss/signer"
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"time"
)

type Config struct {
	Canonicalizer Canonicalizer
	IsEnveloped   bool
	Hash          crypto.Hash
	ReferenceURI  string
	SigningTime   time.Time
}

type Xades interface {
	CreateSignature(signedData *etree.Element) (*etree.Element, error)
}

type xades struct {
	config Config
	signer signer.Signer
}

func New(config Config, signer signer.Signer) Xades {
	return &xades{
		config: config,
		signer: signer,
	}
}

func printXml(el *etree.Element) {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())

	//doc.WriteSettings = etree.WriteSettings{
	//	CanonicalAttrVal: true,
	//	CanonicalEndTags: false,
	//	CanonicalText:    true,
	//}

	s, err := doc.WriteToString()
	if err != nil {
		fmt.Printf("failed to serialize XML: %v", err)
	}

	fmt.Printf("`%s`\n", s)
}

// CreateSignature create filled signature element
func (x *xades) CreateSignature(signedData *etree.Element) (*etree.Element, error) {

	//DigestValue of signedData
	digestData, err := DigestValue(signedData, &x.config.Canonicalizer, x.config.Hash)
	if err != nil {
		return nil, err
	}

	printXml(signedData)
	fmt.Printf("DigestData: %s\n", digestData)

	if x.config.SigningTime.IsZero() {
		x.config.SigningTime = time.Now()
	}
	//DigestValue of signedProperties
	signedProperties, err := x.createSignedProperties(x.config.SigningTime)
	if err != nil {
		return nil, err
	}

	qualifiedSignedProperties := createQualifiedSignedProperties(signedProperties)

	digestProperties, err := DigestValue(qualifiedSignedProperties, &x.config.Canonicalizer, x.config.Hash)
	if err != nil {
		return nil, err
	}

	//SignatureValue
	signedInfo := x.createSignedInfo(digestData, digestProperties)
	qualifiedSignedInfo := createQualifiedSignedInfo(signedInfo)

	signatureValueText, err := x.SignatureValue(qualifiedSignedInfo, &x.config.Canonicalizer)
	if err != nil {
		return nil, err
	}

	signatureValue := createSignatureValue(signatureValueText)
	certs, _ := x.signer.GetCerts()
	keyInfo := createKeyInfo(base64.StdEncoding.EncodeToString(certs[0]))
	object := createObject(signedProperties)

	signature := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.SignatureTag,
		Attr: []etree.Attr{
			{Key: "Id", Value: "Signature"},
			{Key: "xmlns", Value: dsig.Namespace},
			//{Space: "xmlns", Key: "ds", Value: "http://www.w3.org/2000/09/xmldsig#"},
		},
		Child: []etree.Token{signedInfo, signatureValue, keyInfo, object},
	}
	return &signature, nil
}

// DigestValue calculate hash for digest
func DigestValue(element *etree.Element, canonicalizer *Canonicalizer, hash crypto.Hash) (base64encoded string, err error) {

	canonical, err := (*canonicalizer).Canonicalize(element)
	if err != nil {
		return
	}

	fmt.Printf("Canonical: %s\n", canonical)

	_hash := hash.New()
	_, err = _hash.Write(canonical)
	if err != nil {
		return "", err
	}

	base64encoded = base64.StdEncoding.EncodeToString(_hash.Sum(nil))
	return
}

// SignatureValue calculate signature
func (x *xades) SignatureValue(element *etree.Element, canonicalizer *Canonicalizer) (base64encoded string, err error) {

	canonical, err := (*canonicalizer).Canonicalize(element)

	fmt.Printf("Canonical SignedInfo: %s\n", canonical)

	if err != nil {
		return
	}

	buffer, err := x.signer.SignBytes(canonical)
	if err != nil {
		return
	}
	base64encoded = base64.StdEncoding.EncodeToString(buffer)
	return
}

func createSignatureValue(base64Signature string) *etree.Element {
	signatureValue := etree.Element{
		Space: xmldsigPrefix,
		Tag:   SignatureValueTag,
	}
	signatureValue.SetText(base64Signature)
	return &signatureValue
}

func createObject(signedProperties *etree.Element) *etree.Element {

	qualifyingProperties := etree.Element{
		Space: Prefix,
		Tag:   QualifyingPropertiesTag,
		Attr: []etree.Attr{
			{Space: "xmlns", Key: Prefix, Value: Namespace},
			{Key: targetAttr, Value: "#Signature"},
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

	x509Cerificate := etree.Element{
		Space: xmldsigPrefix,
		Tag:   X509CertificateTag,
	}
	x509Cerificate.SetText(base64Certificate)

	x509Data := etree.Element{
		Space: xmldsigPrefix,
		Tag:   X509DataTag,
		Child: []etree.Token{&x509Cerificate},
	}
	keyInfo := etree.Element{
		Space: xmldsigPrefix,
		Tag:   KeyInfoTag,
		Child: []etree.Token{&x509Data},
	}
	return &keyInfo
}

func (x *xades) createSignedProperties(signTime time.Time) (*etree.Element, error) {

	digestMethod := etree.Element{
		Space: xmldsigPrefix,
		Tag:   DigestMethodTag,
		Attr: []etree.Attr{
			{Key: AlgorithmAttr, Value: digestAlgorithmIdentifiers[crypto.SHA1]},
		},
	}

	digestValue := etree.Element{
		Space: xmldsigPrefix,
		Tag:   DigestValueTag,
	}

	certs, _ := x.signer.GetCerts()
	if len(certs) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	hash := sha1.Sum(certs[0])
	digestValue.SetText(base64.StdEncoding.EncodeToString(hash[0:]))

	certDigest := etree.Element{
		Space: Prefix,
		Tag:   CertDigestTag,
		Child: []etree.Token{&digestMethod, &digestValue},
	}

	x509IssuerName := etree.Element{
		Space: xmldsigPrefix,
		Tag:   "X509IssuerName",
	}

	// Parsuj pierwszy certyfikat w łańcuchu
	parsedCert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	x509IssuerName.SetText(parsedCert.Issuer.String())
	x509SerialNumber := etree.Element{
		Space: xmldsigPrefix,
		Tag:   "X509SerialNumber",
	}
	x509SerialNumber.SetText(parsedCert.SerialNumber.String())

	issuerSerial := etree.Element{
		Space: Prefix,
		Tag:   IssuerSerialTag,
		Child: []etree.Token{&x509IssuerName, &x509SerialNumber},
	}

	cert := etree.Element{
		Space: Prefix,
		Tag:   CertTag,
		Child: []etree.Token{&certDigest, &issuerSerial},
	}

	signingCertificate := etree.Element{
		Space: Prefix,
		Tag:   SigningCertificateTag,
		Child: []etree.Token{&cert},
	}

	signingTime := etree.Element{
		Space: Prefix,
		Tag:   SigningTimeTag,
	}
	signingTime.SetText(signTime.Format("2006-01-02T15:04:05Z"))

	signedSignatureProperties := etree.Element{
		Space: Prefix,
		Tag:   SignedSignaturePropertiesTag,
		Child: []etree.Token{&signingTime, &signingCertificate},
	}

	signedProperties := etree.Element{
		Space: Prefix,
		Tag:   SignedPropertiesTag,
		Attr: []etree.Attr{
			{Key: "Id", Value: "SignedProperties"},
		},
		Child: []etree.Token{&signedSignatureProperties},
	}

	return &signedProperties, nil
}

func createQualifiedSignedProperties(signedProperties *etree.Element) *etree.Element {

	qualifiedSignedProperties := signedProperties.Copy()
	qualifiedSignedProperties.Attr = append(
		signedProperties.Attr,
		etree.Attr{Space: "xmlns", Key: xmldsigPrefix, Value: "http://www.w3.org/2000/09/xmldsig#"},
		etree.Attr{Space: "xmlns", Key: Prefix, Value: Namespace},
	)

	return qualifiedSignedProperties
}

func (x *xades) createSignedInfo(digestValueDataText string, digestValuePropertiesText string) *etree.Element {

	var transformEnvSign etree.Element

	if x.config.IsEnveloped {
		transformEnvSign = etree.Element{
			Space: xmldsigPrefix,
			Tag:   TransformTag,
			Attr: []etree.Attr{
				{Key: AlgorithmAttr, Value: EnvelopedSignatureAlgorithmId.String()},
			},
		}
	}

	transformData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   TransformTag,
		Attr: []etree.Attr{
			{Key: AlgorithmAttr, Value: x.config.Canonicalizer.Algorithm().String()},
		},
	}

	transformProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   TransformTag,
		Attr: []etree.Attr{
			{Key: AlgorithmAttr, Value: x.config.Canonicalizer.Algorithm().String()},
		},
	}

	transformsData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   TransformsTag,
	}
	if x.config.IsEnveloped {
		transformsData.AddChild(&transformEnvSign)
	}
	transformsData.AddChild(&transformData)

	digestMethodData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   DigestMethodTag,
		Attr: []etree.Attr{
			{Key: AlgorithmAttr, Value: digestAlgorithmIdentifiers[x.config.Hash]},
		},
	}

	digestMethodProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   DigestMethodTag,
		Attr: []etree.Attr{
			{Key: AlgorithmAttr, Value: digestAlgorithmIdentifiers[x.config.Hash]},
		},
	}

	digestValueData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   DigestValueTag,
	}
	digestValueData.SetText(digestValueDataText)

	transformsProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   TransformsTag,
		Child: []etree.Token{&transformProperties},
	}

	digestValueProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   DigestValueTag,
	}
	digestValueProperties.SetText(digestValuePropertiesText)

	canonicalizationMethod := etree.Element{
		Space: xmldsigPrefix,
		Tag:   CanonicalizationMethodTag,
		Attr: []etree.Attr{
			{Key: AlgorithmAttr, Value: x.config.Canonicalizer.Algorithm().String()},
		},
	}

	signatureMethod := etree.Element{
		Space: xmldsigPrefix,
		Tag:   SignatureMethodTag,
		Attr: []etree.Attr{
			{Key: AlgorithmAttr, Value: signatureMethodIdentifiers[x.config.Hash]},
		},
	}

	referenceData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   ReferenceTag,
		Attr: []etree.Attr{
			{Key: URIAttr, Value: x.config.ReferenceURI},
		},
		Child: []etree.Token{&transformsData, &digestMethodData, &digestValueData},
	}

	referenceProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   ReferenceTag,
		Attr: []etree.Attr{
			{Key: URIAttr, Value: "#SignedProperties"},
			{Key: "Type", Value: "http://uri.etsi.org/01903#SignedProperties"},
		},
		Child: []etree.Token{&transformsProperties, &digestMethodProperties, &digestValueProperties},
	}

	signedInfo := etree.Element{
		Space: xmldsigPrefix,
		Tag:   SignedInfoTag,
		Child: []etree.Token{&canonicalizationMethod, &signatureMethod, &referenceData, &referenceProperties},
	}

	return &signedInfo
}

func createQualifiedSignedInfo(signedInfo *etree.Element) *etree.Element {
	qualifiedSignedInfo := signedInfo.Copy()
	qualifiedSignedInfo.Attr = append(qualifiedSignedInfo.Attr, etree.Attr{Space: "xmlns", Key: xmldsigPrefix, Value: "http://www.w3.org/2000/09/xmldsig#"})
	return qualifiedSignedInfo
}
