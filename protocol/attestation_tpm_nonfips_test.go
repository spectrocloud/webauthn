//go:build !boringcrypto
// +build !boringcrypto

package protocol

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/assert"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

func getTPMAttestionKeys() ([]byte, []byte, []byte, rsa.PrivateKey, ecdsa.PrivateKey, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, rsa.PrivateKey{}, ecdsa.PrivateKey{}, err
	}

	r := webauthncose.RSAPublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.RSAKey),
			Algorithm: int64(webauthncose.AlgRS256),
		},
		Modulus:  rsaKey.N.Bytes(),
		Exponent: uint32ToBytes(uint32(rsaKey.E)),
	}

	eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, rsa.PrivateKey{}, ecdsa.PrivateKey{}, err
	}

	c := CredentialPublicKey{
		KeyType:   int64(webauthncose.EllipticKey),
		Algorithm: int64(webauthncose.AlgES256),
		Curve:     int64(webauthncose.P256),
		XCoord:    eccKey.X.Bytes(),
		YCoord:    eccKey.Y.Bytes(),
	}

	e := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   c.KeyType,
			Algorithm: c.Algorithm,
		},
		Curve:  c.Curve,
		XCoord: c.XCoord,
		YCoord: c.YCoord,
	}

	okpKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, rsa.PrivateKey{}, ecdsa.PrivateKey{}, err
	}

	o := webauthncose.OKPPublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.OctetKey),
			Algorithm: int64(webauthncose.AlgEdDSA),
		},
		Curve:  int64(webauthncose.Ed25519),
		XCoord: okpKey,
	}

	epk, err := webauthncbor.Marshal(e)
	if err != nil {
		return nil, nil, nil, rsa.PrivateKey{}, ecdsa.PrivateKey{}, err
	}

	rpk, err := webauthncbor.Marshal(r)
	if err != nil {
		return nil, nil, nil, rsa.PrivateKey{}, ecdsa.PrivateKey{}, err
	}

	opk, err := webauthncbor.Marshal(o)

	return epk, rpk, opk, *rsaKey, *eccKey, err
}

func TestTPMAttestationVerificationFailPubArea(t *testing.T) {
	epk, rpk, opk, rsaKey, eccKey, err := getTPMAttestionKeys()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		keyType   webauthncose.COSEKeyType
		rsaParams tpm2.RSAParams
		eccParams tpm2.ECCParams
		cpk       []byte
		wantErr   string
	}{
		{
			"TPM Negative Test pubArea curve mismatch",
			webauthncose.EllipticKey,
			tpm2.RSAParams{},
			tpm2.ECCParams{CurveID: tpm2.CurveNISTP224, Point: tpm2.ECPoint{XRaw: eccKey.X.Bytes(), YRaw: eccKey.Y.Bytes()}},
			epk,
			"Mismatch between ECCParameters in pubArea and credentialPublicKey",
		},
		{
			"TPM Negative Test pubArea X mismatch",
			webauthncose.EllipticKey,
			tpm2.RSAParams{},
			tpm2.ECCParams{CurveID: tpm2.CurveNISTP256, Point: tpm2.ECPoint{XRaw: corruptBytes(eccKey.X.Bytes()), YRaw: eccKey.Y.Bytes()}},
			epk,
			"Mismatch between ECCParameters in pubArea and credentialPublicKey",
		},
		{
			"TPM Negative Test pubArea Y mismatch",
			webauthncose.EllipticKey,
			tpm2.RSAParams{},
			tpm2.ECCParams{CurveID: tpm2.CurveNISTP256, Point: tpm2.ECPoint{XRaw: eccKey.X.Bytes(), YRaw: corruptBytes(eccKey.Y.Bytes())}},
			epk,
			"Mismatch between ECCParameters in pubArea and credentialPublicKey",
		},
		{
			"TPM Negative Test pubArea N mismatch",
			webauthncose.RSAKey,
			tpm2.RSAParams{ModulusRaw: corruptBytes(rsaKey.N.Bytes()), ExponentRaw: uint32(rsaKey.E)},
			tpm2.ECCParams{},
			rpk,
			"Mismatch between RSAParameters in pubArea and credentialPublicKey",
		},
		{
			"TPM Negative Test pubArea E mismatch",
			webauthncose.RSAKey,
			tpm2.RSAParams{ModulusRaw: rsaKey.N.Bytes(), ExponentRaw: uint32(rsaKey.E + 1)},
			tpm2.ECCParams{},
			rpk,
			"Mismatch between RSAParameters in pubArea and credentialPublicKey",
		},
		{
			"TPM Negative Test pubArea unsupported key type",
			webauthncose.OctetKey,
			tpm2.RSAParams{},
			tpm2.ECCParams{},
			opk,
			"Unsupported Public Key Type",
		},
	}
	for _, tt := range tests {
		attStmt := make(map[string]interface{}, len(defaultAttStatement))
		for id, v := range defaultAttStatement {
			attStmt[id] = v
		}

		public := tpm2.Public{}

		switch tt.keyType {
		case webauthncose.EllipticKey:
			public = defaultECCPublic
			public.ECCParameters.CurveID = tt.eccParams.CurveID
			public.ECCParameters.Point.XRaw = tt.eccParams.Point.XRaw
			public.ECCParameters.Point.YRaw = tt.eccParams.Point.YRaw
		case webauthncose.RSAKey:
			public = defaultRSAPublic
			public.RSAParameters.ExponentRaw = tt.rsaParams.ExponentRaw
			public.RSAParameters.ModulusRaw = tt.rsaParams.ModulusRaw
		case webauthncose.OctetKey:
			public = defaultECCPublic
		}

		attStmt["pubArea"], _ = public.Encode()
		att := AttestationObject{
			AttStatement: attStmt,
			AuthData: AuthenticatorData{
				AttData: AttestedCredentialData{
					CredentialPublicKey: tt.cpk,
				},
			},
		}

		attestationType, _, err := verifyTPMFormat(att, nil)
		if tt.wantErr != "" {
			assert.Contains(t, err.Error(), tt.wantErr)
		} else {
			assert.Equal(t, "attca", attestationType)
		}
	}
}
