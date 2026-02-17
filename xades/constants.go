package xades

import "crypto"

const (
	SignedPropertiesTag                            string      = "SignedProperties"
	SignedSignaturePropertiesTag                   string      = "SignedSignatureProperties"
	SigningTimeTag                                 string      = "SigningTime"
	SigningCertificateTag                          string      = "SigningCertificate"
	CertTag                                        string      = "Cert"
	IssuerSerialTag                                string      = "IssuerSerial"
	CertDigestTag                                  string      = "CertDigest"
	QualifyingPropertiesTag                        string      = "QualifyingProperties"
	dsNamespace                                                = "http://www.w3.org/2000/09/xmldsig#"
	xadesNamespace                                             = "http://uri.etsi.org/01903/v1.3.2#"
	xmldsigFilter2Algo                                         = "http://www.w3.org/2002/06/xmldsig-filter2"
	xmldsigFilter2NS                                           = "http://www.w3.org/2002/06/xmldsig-filter2"
	signedPropertiesType                                       = "http://uri.etsi.org/01903#SignedProperties"
	mimeTypeTextXML                                            = "text/xml"
	xpathSubtractSignature                                     = "/descendant::ds:Signature"
	xmldsigPrefix                                  string      = "ds"
	Prefix                                         string      = "xades"
	targetAttr                                     string      = "Target"
	SignedInfoTag                                              = "SignedInfo"
	CanonicalizationMethodTag                                  = "CanonicalizationMethod"
	SignatureMethodTag                                         = "SignatureMethod"
	ReferenceTag                                               = "Reference"
	TransformsTag                                              = "Transforms"
	TransformTag                                               = "Transform"
	DigestMethodTag                                            = "DigestMethod"
	DigestValueTag                                             = "DigestValue"
	SignatureValueTag                                          = "SignatureValue"
	KeyInfoTag                                                 = "KeyInfo"
	X509DataTag                                                = "X509Data"
	X509CertificateTag                                         = "X509Certificate"
	AlgorithmAttr                                              = "Algorithm"
	URIAttr                                                    = "URI"
	CanonicalXML10ExclusiveWithCommentsAlgorithmId AlgorithmID = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
	CanonicalXML10ExclusiveAlgorithmId             AlgorithmID = "http://www.w3.org/2001/10/xml-exc-c14n#"
)

var digestAlgorithmIdentifiers = map[crypto.Hash]string{
	crypto.SHA1:   "http://www.w3.org/2000/09/xmldsig#sha1",
	crypto.SHA256: "http://www.w3.org/2001/04/xmlenc#sha256",
	crypto.SHA512: "http://www.w3.org/2001/04/xmlenc#sha512",
}
