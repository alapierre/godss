package xades

import "crypto"

const (
	xmldsigPrefix string = ""
	Prefix        string = "xades"
	Namespace     string = "http://uri.etsi.org/01903/v1.3.2#"
)

const (
	SignedPropertiesTag          string = "SignedProperties"
	SignedSignaturePropertiesTag string = "SignedSignatureProperties"
	SigningTimeTag               string = "SigningTime"
	SigningCertificateTag        string = "SigningCertificate"
	CertTag                      string = "Cert"
	IssuerSerialTag              string = "IssuerSerial"
	CertDigestTag                string = "CertDigest"
	QualifyingPropertiesTag      string = "QualifyingProperties"
)

const (
	signedPropertiesAttr string = "SignedProperties"
	targetAttr           string = "Target"
)

var digestAlgorithmIdentifiers = map[crypto.Hash]string{
	crypto.SHA1:   "http://www.w3.org/2000/09/xmldsig#sha1",
	crypto.SHA256: "http://www.w3.org/2001/04/xmlenc#sha256",
	crypto.SHA512: "http://www.w3.org/2001/04/xmlenc#sha512",
}

var signatureMethodIdentifiers = map[crypto.Hash]string{
	crypto.SHA1:   "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
	crypto.SHA256: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	crypto.SHA512: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
}

// Tags
const (
	SignatureTag              = "Signature"
	SignedInfoTag             = "SignedInfo"
	CanonicalizationMethodTag = "CanonicalizationMethod"
	SignatureMethodTag        = "SignatureMethod"
	ReferenceTag              = "Reference"
	TransformsTag             = "Transforms"
	TransformTag              = "Transform"
	DigestMethodTag           = "DigestMethod"
	DigestValueTag            = "DigestValue"
	SignatureValueTag         = "SignatureValue"
	KeyInfoTag                = "KeyInfo"
	X509DataTag               = "X509Data"
	X509CertificateTag        = "X509Certificate"
	InclusiveNamespacesTag    = "InclusiveNamespaces"
)

const (
	AlgorithmAttr  = "Algorithm"
	URIAttr        = "URI"
	DefaultIdAttr  = "ID"
	PrefixListAttr = "PrefixList"
)

// Supported canonicalization algorithms
const (
	EnvelopedSignatureAlgorithmId                  AlgorithmID = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	CanonicalXML10ExclusiveWithCommentsAlgorithmId AlgorithmID = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
	CanonicalXML10ExclusiveAlgorithmId             AlgorithmID = "http://www.w3.org/2001/10/xml-exc-c14n#"
)
