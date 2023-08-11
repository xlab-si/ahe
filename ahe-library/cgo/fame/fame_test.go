package fame_test

import (
	"github.com/fentec-project/gofe/abe"
	"github.com/stretchr/testify/assert"
	fame2 "github.com/xlab-si/ahe/ahe-library/cgo/fame"
	"math/rand"
	"strconv"
	"testing"
)

func TestFameSerialize(t *testing.T) {
	// abe -> string -> abe
	fame := abe.NewFAME()
	fameRaw := fame2.FameToRaw(fame)
	fameNew, err := fame2.FameFromRaw(fameRaw)
	if err != nil {
		t.Fatalf("Failed to deserialize fame %s: %v\n", fameRaw, err)
	}
	assert.Equal(t, fame.P.String(), fameNew.P.String())

	// string -> abe -> string
	maabeNewRaw := fame2.FameToRaw(fameNew)
	assert.Equal(t, fameRaw, maabeNewRaw)
}

func TestFameSecPubKeySerialize(t *testing.T) {
	fame := abe.NewFAME()

	pubKey, secKey, err := fame.GenerateMasterKeys()
	if err != nil {
		t.Fatalf("Failed generation private and public keys: %v\n", err)
	}
	secRaw, err := fame2.FameSecToRaw(secKey)
	if err != nil {
		t.Fatalf("Failed marshall private keys: %v\n", err)
	}
	secKey2, err := fame2.FameSecFromRaw(secRaw)
	assert.Equal(t, secKey, secKey2)

	pubRaw, err := fame2.FamePubToRaw(pubKey)
	if err != nil {
		t.Fatalf("Failed marshall private keys: %v\n", err)
	}
	pubKey2, err := fame2.FamePubFromRaw(pubRaw)
	assert.Equal(t, pubKey, pubKey2)
}

func TestFameCipherSerialize(t *testing.T) {
	// abe -> string -> abe
	maabe := abe.NewFAME()
	pk, _, err := maabe.GenerateMasterKeys()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v\n", err)
	}

	n := rand.Intn(1000000000)
	msg := "Attack at dawn!" + strconv.Itoa(n)
	msp, _ := abe.BooleanToMSP("at1 AND at2", false)

	ct, err := maabe.Encrypt(msg, msp, pk)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v\n", err)
	}
	ctRaw, err := fame2.FameCipherToRaw(ct)
	if err != nil {
		t.Fatalf("Failed to marshall: %v\n", err)
	}
	ctNew, err := fame2.FameCipherFromRaw(ctRaw)
	if err != nil {
		t.Fatalf("Failed to deserialize ct %s: %v\n", ctRaw, err)
	}

	assert.Equal(t, ct, ctNew)
}

func TestFameKeysSerialize(t *testing.T) {
	// abe -> string -> abe
	maabe := abe.NewFAME()
	_, sk, err := maabe.GenerateMasterKeys()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v\n", err)
	}
	attribs := []string{"at1", "at2", "at3"}
	attribKey, err := maabe.GenerateAttribKeys(attribs, sk)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v\n", err)
	}

	keyRaw, err := fame2.FameKeysToRaw(attribKey)
	if err != nil {
		t.Fatalf("Failed to marshall: %v\n", err)
	}
	attribKeyNew, err := fame2.FameKeysFromRaw(keyRaw)
	if err != nil {
		t.Fatalf("Failed to deserialize %s: %v\n", keyRaw, err)
	}

	assert.Equal(t, attribKey, attribKeyNew)
}

func TestFameGoC(t *testing.T) {
	fame := fame2.Go_Ahe_fame_NewFAME()
	pk, sk, status := fame2.Go_Ahe_fame_GenerateMasterKeys(fame)
	if status != 0 {
		t.Fatalf("Error generating keys")
	}

	bf := "(at1 AND at2) OR at3"
	n := rand.Intn(1000000000)
	msg := "Attack at dawn!" + strconv.Itoa(n)
	ct, status := fame2.Go_Ahe_fame_Encrypt(fame, msg, bf, pk)
	if status != 0 {
		t.Fatalf("Error encrypting msg %d", status)
	}

	attribs1 := []string{"at1", "at2"}
	keys1, status := fame2.Go_Ahe_fame_GenerateAttribKeys(fame, attribs1, sk)
	if status != 0 {
		t.Fatalf("Failed to generate attribute keys")
	}

	attribs2 := []string{"at1"}
	keys2, status := fame2.Go_Ahe_fame_GenerateAttribKeys(fame, attribs2, sk)
	if status != 0 {
		t.Fatalf("Failed to generate attribute keys")
	}

	pt1, status := fame2.Go_Ahe_fame_Decrypt(fame, ct, keys1, pk)
	assert.Equal(t, status, 0)
	assert.Equal(t, msg, pt1)

	pt2, status := fame2.Go_Ahe_fame_Decrypt(fame, ct, keys2, pk)
	assert.Equal(t, -5, status)
	assert.Equal(t, "", pt2)
}
