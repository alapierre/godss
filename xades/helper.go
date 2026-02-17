package xades

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

type ecdsaDER struct {
	R, S *big.Int
}

func ecdsaDERToXMLDSIGRaw(der []byte, cert *x509.Certificate) ([]byte, error) {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate is not ECDSA")
	}

	var sig ecdsaDER
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("ecdsa signature is not ASN.1 DER: %w", err)
	}
	if sig.R == nil || sig.S == nil {
		return nil, fmt.Errorf("ecdsa signature missing R/S")
	}

	size := (pub.Curve.Params().BitSize + 7) / 8 // P-256 -> 32
	rb := make([]byte, size)
	sb := make([]byte, size)

	sig.R.FillBytes(rb)
	sig.S.FillBytes(sb)

	return append(rb, sb...), nil
}
