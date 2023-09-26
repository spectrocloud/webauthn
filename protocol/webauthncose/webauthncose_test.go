package webauthncose

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestP256SignatureVerification(t *testing.T) {
	// Private/public key pair was generated with the following:
	//
	// $ openssl ecparam -genkey -name secp256r1 -noout -out private_key.pem
	// $ openssl ec -in private_key.pem -noout -text
	// Private-Key: (256 bit)
	// priv:
	// 	48:7f:36:1d:df:d7:34:40:e7:07:f4:da:a6:77:5b:
	// 	37:68:59:e8:a3:c9:f2:9b:3b:b6:94:a1:29:27:c0:
	// 	21:3c
	// pub:
	// 	04:f7:39:f8:c7:7b:32:f4:d5:f1:32:65:86:1f:eb:
	// 	d7:6e:7a:9c:61:a1:14:0d:29:6b:8c:16:30:25:08:
	// 	87:03:16:c2:49:70:ad:78:11:cc:d9:da:7f:1b:88:
	// 	f2:02:be:ba:c7:70:66:3e:f5:8b:a6:83:46:18:6d:
	// 	d7:78:20:0d:d4
	// ASN1 OID: prime256v1
	// NIST CURVE: P-256
	// ----.
	pubX, err := hex.DecodeString("f739f8c77b32f4d5f13265861febd76e7a9c61a1140d296b8c16302508870316")
	assert.Nil(t, err)
	pubY, err := hex.DecodeString("c24970ad7811ccd9da7f1b88f202bebac770663ef58ba68346186dd778200dd4")
	assert.Nil(t, err)

	key := EC2PublicKeyData{
		// These constants are from https://datatracker.ietf.org/doc/rfc9053/
		// (see "ECDSA" and "Elliptic Curve Keys").
		PublicKeyData: PublicKeyData{
			KeyType:   2,  // EC.
			Algorithm: -7, // "ES256".
		},
		Curve:  1, // P-256.
		XCoord: pubX,
		YCoord: pubY,
	}

	data := []byte("webauthnFTW")

	// Valid signature obtained with:
	// $ echo -n 'webauthnFTW' | openssl dgst -sha256 -sign private_key.pem | xxd -ps | tr -d '\n'.
	validSig, err := hex.DecodeString("3045022053584980793ee4ec01d583f303604c4f85a7e87df3fe9551962c5ab69a5ce27b022100c801fd6186ca4681e87fbbb97c5cb659f039473995a75a9a9dffea2708d6f8fb")
	assert.Nil(t, err)

	// Happy path, verification should succeed.
	ok, err := VerifySignature(key, data, validSig)
	assert.True(t, ok, "invalid EC signature")
	assert.Nil(t, err, "error verifying EC signature")

	// Verification against BAD data should fail.
	ok, err = VerifySignature(key, []byte("webauthnFTL"), validSig)
	assert.Nil(t, err, "error verifying EC signature")
	assert.False(t, ok, "verification against bad data is successful!")
}
