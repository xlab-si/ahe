package signatures

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSig(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	skBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	skString := base64.StdEncoding.EncodeToString(skBytes)

	ciphers := []string{"bla,bla2", "bla3,bla4"}

	signedCts, errCode := SignCiphers(skString, "", ciphers, nil)
	assert.Equal(t, 0, errCode)

	verify, errCode := VerifyCiphers(signedCts, "", "")
	assert.Equal(t, 0, errCode)
	assert.True(t, verify)
}
