//go:build go1.13 && !boringcrypto
// +build go1.13,!boringcrypto

package webauthncose

import (
	"crypto/ed25519"
	"crypto/x509"
)

func marshalEd25519PublicKey(pub ed25519.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}
