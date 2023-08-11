package maabe_test

import (
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
	maabe2 "github.com/xlab-si/ahe/ahe-library/cgo/maabe"
	"github.com/xlab-si/ahe/ahe-library/cgo/utils"
	"math/rand"
	"reflect"
	"strconv"
	"testing"
)

func TestMaabeSerialize(t *testing.T) {
	// abe -> string -> abe
	maabe := abe.NewMAABE()
	maabeRaw := maabe2.MaabeToRaw(maabe)
	maabeNew, err := maabe2.MaabeFromRaw(maabeRaw)
	if err != nil {
		t.Fatalf("Failed to deserialize maabe %s: %v\n", maabeRaw, err)
	}
	assert.Equal(t, maabe.G1.String(), maabeNew.G1.String())
	assert.Equal(t, maabe.G2.String(), maabeNew.G2.String())
	assert.Equal(t, maabe.Gt.String(), maabeNew.Gt.String())
	assert.Equal(t, maabe.P.String(), maabeNew.P.String())

	// string -> abe -> string
	maabeNewRaw := maabe2.MaabeToRaw(maabeNew)
	assert.ElementsMatch(t, maabeRaw, maabeNewRaw)
}

func TestMaabePubSerialize(t *testing.T) {
	// abe -> string -> abe
	maabe := abe.NewMAABE()
	attribs := []string{"auth:at1", "auth:at2"}
	auth, err := maabe.NewMAABEAuth("auth", attribs)
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth", err)
	}
	pk := auth.Pk
	pkRaw := maabe2.MaabePubToRaw(pk)
	pkNew, err := maabe2.MaabePubFromRaw(pkRaw)
	if err != nil {
		t.Fatalf("Failed to deserialize pk: %v\n", err)
	}
	assert.ElementsMatch(t, pk.Attribs, pkNew.Attribs)
	for _, at := range pk.Attribs {
		assert.Equal(t, pk.EggToAlpha[at].String(), pkNew.EggToAlpha[at].String())
		assert.Equal(t, pk.GToY[at].String(), pkNew.GToY[at].String())
	}
	// string -> abe -> string
	pkNewRaw := maabe2.MaabePubToRaw(pkNew)
	assert.ElementsMatch(t, pkRaw, pkNewRaw)
}

func TestMaabeAuthSerialize(t *testing.T) {
	// abe -> string -> abe
	maabe := abe.NewMAABE()
	attribs := []string{"auth:at1", "auth:at2"}
	auth, err := maabe.NewMAABEAuth("auth", attribs)
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth", err)
	}
	authRaw := maabe2.MaabeAuthToRaw(auth)
	authNew, err := maabe2.MaabeAuthFromRaw(authRaw)
	if err != nil {
		t.Fatalf("Failed to deserialize auth %s: %v\n", authRaw, err)
	}
	assert.Equal(t, auth.ID, authNew.ID)
	assert.Equal(t, auth.Maabe.P.String(), authNew.Maabe.P.String())
	assert.Equal(t, auth.Maabe.G1.String(), authNew.Maabe.G1.String())
	assert.Equal(t, auth.Maabe.G2.String(), authNew.Maabe.G2.String())
	assert.Equal(t, auth.Maabe.Gt.String(), authNew.Maabe.Gt.String())
	assert.ElementsMatch(t, auth.Pk.Attribs, authNew.Pk.Attribs)
	assert.ElementsMatch(t, auth.Sk.Attribs, authNew.Sk.Attribs)
	eq := reflect.DeepEqual(auth.Pk.EggToAlpha, authNew.Pk.EggToAlpha)
	if !eq {
		t.Errorf("Authority pubkeys not equal")
	}
	eq = reflect.DeepEqual(auth.Pk.GToY, authNew.Pk.GToY)
	if !eq {
		t.Errorf("Authority pubkeys not equal")
	}
	eq = reflect.DeepEqual(auth.Sk.Alpha, authNew.Sk.Alpha)
	if !eq {
		t.Errorf("Authority pubkeys not equal")
	}
	eq = reflect.DeepEqual(auth.Sk.Y, authNew.Sk.Y)
	if !eq {
		t.Errorf("Authority pubkeys not equal")
	}

	// string -> abe -> string
	authNewRaw := maabe2.MaabeAuthToRaw(authNew)
	assert.ElementsMatch(t, authRaw, authNewRaw)
}

func TestMatrixSerialize(t *testing.T) {
	// matrix -> string -> matrix
	p := bn256.Order
	n := rand.Intn(100) + 1
	sampler := sample.NewUniform(p)
	m, _ := data.NewRandomMatrix(n, n, sampler)
	mRaw := utils.MatrixToString(m)
	mNew := utils.MatrixFromString(mRaw)
	assert.Equal(t, m.Rows(), mNew.Rows())
	assert.Equal(t, m.Cols(), mNew.Cols())
	for i := 0; i < m.Rows(); i++ {
		for j := 0; j < m.Cols(); j++ {
			assert.Equal(t, m[i][j].String(), mNew[i][j].String())
		}
	}

	// string -> matrix -> string
	mNewRaw := utils.MatrixToString(mNew)
	assert.Equal(t, mRaw, mNewRaw)
}

func TestMaabeCipherSerialize(t *testing.T) {
	// abe -> string -> abe
	maabe := abe.NewMAABE()
	attribs1 := []string{"auth1:at1", "auth1:at2"}
	attribs2 := []string{"auth2:at1", "auth2:at2"}
	attribs3 := []string{"auth3:at1", "auth3:at2"}
	auth1, _ := maabe.NewMAABEAuth("auth1", attribs1)
	auth2, _ := maabe.NewMAABEAuth("auth2", attribs2)
	auth3, _ := maabe.NewMAABEAuth("auth3", attribs3)
	msp, _ := abe.BooleanToMSP("((auth1:at1 AND auth2:at1) OR (auth1:at2 AND auth2:at2)) OR (auth3:at1 AND auth3:at2)", false)
	pks := []*abe.MAABEPubKey{auth1.PubKeys(), auth2.PubKeys(), auth3.PubKeys()}

	n := rand.Intn(1000000000)
	msg := "Attack at dawn!" + strconv.Itoa(n)

	ct, err := maabe.Encrypt(msg, msp, pks)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v\n", err)
	}
	ctRaw := maabe2.MaabeCipherToRaw(ct)
	ctNew, err := maabe2.MaabeCipherFromRaw(ctRaw)
	if err != nil {
		t.Fatalf("Failed to deserialize ct %s: %v\n", ctRaw, err)
	}
	gid := "gid1"
	keys1, _ := auth1.GenerateAttribKeys(gid, attribs1)
	key11, key12 := keys1[0], keys1[1]
	keys2, _ := auth2.GenerateAttribKeys(gid, attribs2)
	key21, key22 := keys2[0], keys2[1]
	keys3, _ := auth3.GenerateAttribKeys(gid, attribs3)
	key31, key32 := keys3[0], keys3[1]
	ks1 := []*abe.MAABEKey{key11, key21, key31} // ok
	ks2 := []*abe.MAABEKey{key12, key22, key32} // ok

	msgNew1, err := maabe.Decrypt(ct, ks1)
	if err != nil {
		t.Fatalf("Error decryptiong keyset1: %v\n", err)
	}
	msgNew2, err := maabe.Decrypt(ct, ks2)
	if err != nil {
		t.Fatalf("Error decryptiong keyset2: %v\n", err)
	}
	assert.Equal(t, msg, msgNew1)
	assert.Equal(t, msg, msgNew2)

	// string -> abe -> string
	ctNewRaw := maabe2.MaabeCipherToRaw(ctNew)
	assert.ElementsMatch(t, ctRaw, ctNewRaw)
}

func TestMaabeKeySerialize(t *testing.T) {
	// abe -> string -> abe
	maabe := abe.NewMAABE()
	attribs := []string{"auth:at1", "auth:at2"}
	auth, _ := maabe.NewMAABEAuth("auth", attribs)
	gid := "user"
	keys, err := auth.GenerateAttribKeys(gid, attribs)
	if err != nil {
		t.Fatalf("Error generating keys %v", err)
	}
	keysRaw := maabe2.MaabeKeysToRaw(keys)
	keysNew, err := maabe2.MaabeKeysFromRaw(keysRaw)
	if err != nil {
		t.Fatalf("Error generating Maabe %v", err)
	}
	assert.Equal(t, len(keys), len(keysNew))

	// string -> abe -> string
	keysNewRaw := maabe2.MaabeKeysToRaw(keysNew)
	assert.ElementsMatch(t, keysRaw, keysNewRaw)
}

func TestMaabeGoC(t *testing.T) {
	maabe := maabe2.Go_Ahe_maabe_NewMAABE()
	attribs1 := []string{"auth1:at1", "auth1:at2"}
	attribs2 := []string{"auth2:at1", "auth2:at2"}
	attribs3 := []string{"auth3:at1", "auth3:at2"}
	auth1, status := maabe2.Go_Ahe_maabe_NewMAABEAuth(maabe, "auth1", attribs1)
	if status != 0 {
		t.Fatalf("Failed generation authority %s\n", "auth1")
	}
	auth2, status := maabe2.Go_Ahe_maabe_NewMAABEAuth(maabe, "auth2", attribs2)
	if status != 0 {
		t.Fatalf("Failed generation authority %s\n", "auth2")
	}
	auth3, status := maabe2.Go_Ahe_maabe_NewMAABEAuth(maabe, "auth3", attribs3)
	if status != 0 {
		t.Fatalf("Failed generation authority %s\n", "auth3")
	}
	bf := "((auth1:at1 AND auth2:at1) OR (auth1:at2 AND auth2:at2)) OR (auth3:at1 AND auth3:at2)"
	pks1, status := maabe2.Go_Ahe_maabe_MaabeAuthPubKeys(auth1)
	if status != 0 {
		t.Fatalf("Failed extracting pubkeys")
	}
	pks2, status := maabe2.Go_Ahe_maabe_MaabeAuthPubKeys(auth2)
	if status != 0 {
		t.Fatalf("Failed extracting pubkeys")
	}
	pks3, status := maabe2.Go_Ahe_maabe_MaabeAuthPubKeys(auth3)
	if status != 0 {
		t.Fatalf("Failed extracting pubkeys")
	}
	pks := append(pks1, pks2...)
	pks = append(pks, pks3...)
	n := rand.Intn(1000000000)
	msg := "Attack at dawn!" + strconv.Itoa(n)
	ct, status := maabe2.Go_Ahe_maabe_Encrypt(maabe, msg, bf, pks)
	if status != 0 {
		t.Fatalf("Error encrypting msg")
	}
	gid := "gid1"
	keys1, status := maabe2.Go_Ahe_maabe_GenerateAttribKeys(auth1, gid, attribs1)
	if status != 0 {
		t.Fatalf("Failed to generate attribute keys")
	}
	keys2, status := maabe2.Go_Ahe_maabe_GenerateAttribKeys(auth2, gid, attribs2)
	if status != 0 {
		t.Fatalf("Failed to generate attribute keys")
	}
	keys3, status := maabe2.Go_Ahe_maabe_GenerateAttribKeys(auth3, gid, attribs3)
	if status != 0 {
		t.Fatalf("Failed to generate attribute keys")
	}
	ks1 := append(keys1[0:3:3], keys2[0:3:3]...)
	ks1 = append(ks1, keys3[0:3:3]...)
	ks2 := append(keys1[3:6:6], keys2[3:6:6]...)
	ks2 = append(ks2, keys3[3:6:6]...)
	ks3 := append(keys1[0:3:3], keys2[3:6:6]...)
	ks4 := append(keys1[3:6:6], keys2[0:3:3]...)
	ks5 := append(keys3[0:3:3], keys3[3:6:6]...)
	pt1, status := maabe2.Go_Ahe_maabe_Decrypt(maabe, ct, ks1)
	assert.Equal(t, status, 0)
	assert.Equal(t, msg, pt1)
	pt2, status := maabe2.Go_Ahe_maabe_Decrypt(maabe, ct, ks2)
	assert.Equal(t, status, 0)
	assert.Equal(t, msg, pt2)
	_, status = maabe2.Go_Ahe_maabe_Decrypt(maabe, ct, ks3)
	assert.Equal(t, status, -1)
	_, status = maabe2.Go_Ahe_maabe_Decrypt(maabe, ct, ks4)
	assert.Equal(t, status, -1)
	pt5, status := maabe2.Go_Ahe_maabe_Decrypt(maabe, ct, ks5)
	assert.Equal(t, status, 0)
	assert.Equal(t, msg, pt5)
}
