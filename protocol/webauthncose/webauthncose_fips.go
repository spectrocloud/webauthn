//go:build boringcrypto
// +build boringcrypto

package webauthncose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

// Verify Octet Key Pair (OKP) Public Key Signature.
func (k *OKPPublicKeyData) Verify(data []byte, sig []byte) (bool, error) {
	return false, fmt.Errorf("Octet Key Pair not supported for FIPS")
}

func DisplayPublicKey(cpk []byte) string {
	parsedKey, err := ParsePublicKey(cpk)
	if err != nil {
		return keyCannotDisplay
	}

	switch k := parsedKey.(type) {
	case RSAPublicKeyData:
		rKey := &rsa.PublicKey{
			N: big.NewInt(0).SetBytes(k.Modulus),
			E: int(uint(k.Exponent[2]) | uint(k.Exponent[1])<<8 | uint(k.Exponent[0])<<16),
		}

		data, err := x509.MarshalPKIXPublicKey(rKey)
		if err != nil {
			return keyCannotDisplay
		}

		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: data,
		})

		return string(pemBytes)
	case EC2PublicKeyData:
		var curve elliptic.Curve

		switch COSEAlgorithmIdentifier(k.Algorithm) {
		case AlgES256:
			curve = elliptic.P256()
		case AlgES384:
			curve = elliptic.P384()
		case AlgES512:
			curve = elliptic.P521()
		default:
			return keyCannotDisplay
		}

		eKey := &ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(k.XCoord),
			Y:     big.NewInt(0).SetBytes(k.YCoord),
		}

		data, err := x509.MarshalPKIXPublicKey(eKey)
		if err != nil {
			return keyCannotDisplay
		}

		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: data,
		})

		return string(pemBytes)
	default:
		return "Cannot display key of this type"
	}
}
