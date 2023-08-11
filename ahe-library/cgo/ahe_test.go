package main_test

import (
	maabe2 "github.com/xlab-si/ahe/ahe-library/cgo/maabe"
	"github.com/xlab-si/ahe/ahe-library/cgo/utils"

	// "math/big"
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fentec-project/gofe/abe"
	"github.com/stretchr/testify/assert"
)

var (
	MaxAttribs int    = 100
	AttribStep int    = 10
	PtLen      int    = 100
	Msg        string = RandStringOfLen(PtLen)
)

func FuzzGoSliceCArray(f *testing.F) {
	f.Add("abcd", "1234", "lol:::")
	f.Add("", "", "")
	f.Add("", "dagl.fdsaf", "?????!!!##$")
	f.Add("\x00", "", "")
	f.Fuzz(func(t *testing.T, arg1, arg2, arg3 string) {
		goSlice := []string{arg1, arg2, arg3}
		cArray, l := main.GoSliceToCStringArray(goSlice)
		assert.Equal(t, l, len(goSlice))
		goSliceNew := main.CStringArrayToGoSlice(cArray, l)
		assert.Equal(t, len(goSlice), len(goSliceNew))
		assert.ElementsMatch(t, main.CleanStringSlice(goSlice), main.CleanStringSlice(goSliceNew))
	})
}

func FuzzMaabeFromRaw(f *testing.F) {
	f.Add("abcd", "1234", "lol:::", "      ")
	f.Add("", "", "", "lol ")
	f.Add("", "dagl.fdsaf", "?????!!!##$", "     ")
	f.Add("\x00", "", "", " ")
	f.Add("a\na", "b\rb", "c\tc", "d\bd")
	f.Fuzz(func(t *testing.T, arg1, arg2, arg3, arg4 string) {
		mSlice := []string{arg1, arg2, arg3, arg4}
		m, _ := maabe2.MaabeFromRaw(mSlice)
		if m != nil {
			t.Errorf("maabe should statistically be nil, instead: %v\n", m)
		}
	})
}

func FuzzMaabeAuthFromRaw(f *testing.F) {
	f.Add("abcd", "1234", "lol:::", "      ", "ldhalf", "\x00", "ok", "ei1213ie3oi", "cn,nvx  fj dfjads", "a,djnf\x00fk,dn")
	f.Add("", "", "", "lol ", "", "", "", "", "", "")
	f.Add("", "dagl.fdsaf", "?????!!!##$", "     ", "", "fndkfndsf", "1232145", "danfĆ;", "nafcv", "df")
	f.Add("a\na", "b\rb", "c\tc", "d\bd", "e\x00e", "f\"f", "", "asdf", "1234", "*?#$%!/&:_")
	f.Fuzz(func(t *testing.T, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10 string) {
		aSlice := []string{arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10}
		a, _ := maabe2.MaabeAuthFromRaw(aSlice)
		if a != nil {
			t.Errorf("maabe auth should statistically be nil, instead: %v\n", a)
		}
	})
}

func FuzzMaabePubFromRaw(f *testing.F) {
	f.Add("abcd", "1234", "lol:::")
	f.Add("", "", "")
	f.Add("", "?????!!!##$", "     ")
	f.Add("\x00", "\n", " ")
	f.Add("b\rb", "c\tc", "d\bd")
	f.Fuzz(func(t *testing.T, arg1, arg2, arg3 string) {
		pSlice := []string{arg1, arg2, arg3}
		p, _ := maabe2.MaabePubFromRaw(pSlice)
		if p != nil {
			t.Errorf("maabe should statistically be nil, instead: %v\n", p)
		}
	})
}

func RandStringOfLen(n int) string {
	// read seed from env if possible
	var seed int64
	var err error
	s := os.Getenv("SEED")
	if s == "" {
		seed = time.Now().UnixNano()
	} else {
		seed, err = strconv.ParseInt(s, 10, 64)
		if err != nil {
			seed = 0
		}
	}
	buff := make([]byte, n)
	rand.Seed(seed)
	rand.Read(buff)
	str := base64.StdEncoding.EncodeToString(buff)
	// Base 64 can be longer than len
	return str[:n]
}

func TestArraySlice(t *testing.T) {
	// string -> **char -> string
	l := rand.Intn(50) + 1
	goSlice := make([]string, l)
	for i := 0; i < l; i++ {
		n := rand.Intn(1000000000)
		goSlice[i] = "Attack at dawn!" + strconv.Itoa(n)
	}
	cArray, l := main.GoSliceToCStringArray(goSlice)
	goSliceNew := main.CStringArrayToGoSlice(cArray, l)
	assert.ElementsMatch(t, goSlice, goSliceNew)

	// string -> **char -> string -> **char -> string
	cArrayNew, ll := main.GoSliceToCStringArray(goSliceNew)
	assert.Equal(t, l, ll)
	goSliceNewNew := main.CStringArrayToGoSlice(cArrayNew, ll)
	assert.ElementsMatch(t, goSlice, goSliceNewNew)
}

// NewMaabe and NewMaabeAuth benchmarks are not really relevant

// func BenchmarkGoNewMAABE(b *testing.B) {
// for i := 0; i < b.N; i++ {
// abe.NewMAABE()
// }
// }

// func BenchmarkCNewMAABE(b *testing.B) {
// for i := 0; i < b.N; i++ {
// cgo.Ahe_maabe_NewMAABE()
// }
// }

// func BenchmarkGoNewMAABEAuth(b *testing.B) {
// maabe := abe.NewMAABE()
// for i := AttribStep; i <= MaxAttribs; i = i + AttribStep {
// attribs := make([]string, i)
// for j := 0; j < i; j++ {
// attribs[j] = "auth:at" + strconv.Itoa(j+1)
// }
// b.ResetTimer()
// b.Run(fmt.Sprintf("input_size_%d", i), func(b *testing.B) {
// for k := 0; k < b.N; k++ {
// maabe.NewMAABEAuth("auth", attribs)
// }
// })
// }
// }

// func BenchmarkCNewMAABEAuth(b *testing.B) {
// maabeC := cgo.Ahe_maabe_NewMAABE()
// idC := cgo.GoStringToCString("auth")
// for i := AttribStep; i <= MaxAttribs; i = i + AttribStep {
// attribs := make([]string, i)
// for j := 0; j < i; j++ {
// attribs[j] = "auth:at" + strconv.Itoa(j+1)
// }
// attribsC, _ := cgo.GoSliceToCStringArray(attribs)
// atCLen := cgo.GoIntToCInt(i)
// b.ResetTimer()
// b.Run(fmt.Sprintf("input_size_%d", i), func(b *testing.B) {
// for k := 0; k < b.N; k++ {
// cgo.Ahe_maabe_NewMAABEAuth(maabeC, idC, attribsC, atCLen)
// }
// })
// }
// }

func BenchmarkGoEncrypt(b *testing.B) {
	maabe := abe.NewMAABE()
	msg := Msg
	for i := AttribStep; i <= MaxAttribs; i = i + AttribStep {
		attribs := make([]string, i)
		for j := 0; j < i; j++ {
			attribs[j] = "auth:at" + strconv.Itoa(j+1)
		}
		auth, _ := maabe.NewMAABEAuth("auth", attribs)
		pks := []*abe.MAABEPubKey{auth.PubKeys()}
		bf := "(auth:at1 AND auth:at2)"
		for j := 3; j <= i; j = j + 2 {
			if j < i {
				bf += " OR (auth:at" + strconv.Itoa(j) + " AND auth:at" + strconv.Itoa(j+1) + ")"
			} else {
				bf += " OR auth:at" + strconv.Itoa(j)
			}
		}
		if i == 1 {
			bf = "auth:at1"
		}
		msp, _ := abe.BooleanToMSP(bf, false)
		b.ResetTimer()
		b.Run(fmt.Sprintf("msg_%s_input_size_%d", msg, i), func(b *testing.B) {
			for k := 0; k < b.N; k++ {
				maabe.Encrypt(msg, msp, pks)
			}
		})
	}
}

func BenchmarkCEncrypt(b *testing.B) {
	maabeC := main.Ahe_maabe_NewMAABE()
	idC := main.GoStringToCString("auth")
	msg := Msg
	msgC := main.GoStringToCString(msg)
	for i := AttribStep; i <= MaxAttribs; i = i + AttribStep {
		attribs := make([]string, i)
		for j := 0; j < i; j++ {
			attribs[j] = "auth:at" + strconv.Itoa(j+1)
		}
		attribsC, _ := main.GoSliceToCStringArray(attribs)
		atCLen := main.GoIntToCInt(i)
		auth, authLen := main.Ahe_maabe_NewMAABEAuth(maabeC, idC, attribsC, atCLen)
		pks, pksLen := main.Ahe_maabe_MaabeAuthPubKeys(auth, authLen)
		bf := "(auth:at1 AND auth:at2)"
		for j := 3; j <= i; j = j + 2 {
			if j < i {
				bf += " OR (auth:at" + strconv.Itoa(j) + " AND auth:at" + strconv.Itoa(j+1) + ")"
			} else {
				bf += " OR auth:at" + strconv.Itoa(j)
			}
		}
		if i == 1 {
			bf = "auth:at1"
		}
		bfC := main.GoStringToCString(bf)
		b.ResetTimer()
		b.Run(fmt.Sprintf("msg_%s_input_size_%d", msg, i), func(b *testing.B) {
			for k := 0; k < b.N; k++ {
				main.Ahe_maabe_Encrypt(maabeC, msgC, bfC, pks, pksLen)
			}
		})
	}
}

func BenchmarkGoDecrypt(b *testing.B) {
	maabe := abe.NewMAABE()
	msg := Msg
	gid := "gid"
	for i := AttribStep; i <= MaxAttribs; i = i + AttribStep {
		attribs := make([]string, i)
		for j := 0; j < i; j++ {
			attribs[j] = "auth:at" + strconv.Itoa(j+1)
		}
		auth, _ := maabe.NewMAABEAuth("auth", attribs)
		pks := []*abe.MAABEPubKey{auth.PubKeys()}
		bf := "(auth:at1 AND auth:at2)"
		for j := 3; j <= i; j = j + 2 {
			if j < i {
				bf += " OR (auth:at" + strconv.Itoa(j) + " AND auth:at" + strconv.Itoa(j+1) + ")"
			} else {
				bf += " OR auth:at" + strconv.Itoa(j)
			}
		}
		if i == 1 {
			bf = "auth:at1"
		}
		msp, _ := abe.BooleanToMSP(bf, false)
		ct, _ := maabe.Encrypt(msg, msp, pks)
		ks, _ := auth.GenerateAttribKeys(gid, attribs)
		b.ResetTimer()
		b.Run(fmt.Sprintf("msg_%s_input_size_%d", msg, i), func(b *testing.B) {
			for k := 0; k < b.N; k++ {
				maabe.Decrypt(ct, ks)
			}
		})
	}
}

func BenchmarkCDecrypt(b *testing.B) {
	maabeC := main.Ahe_maabe_NewMAABE()
	idC := main.GoStringToCString("auth")
	msg := Msg
	msgC := main.GoStringToCString(msg)
	gidC := main.GoStringToCString("gid")
	for i := AttribStep; i <= MaxAttribs; i = i + AttribStep {
		attribs := make([]string, i)
		for j := 0; j < i; j++ {
			attribs[j] = "auth:at" + strconv.Itoa(j+1)
		}
		attribsC, _ := main.GoSliceToCStringArray(attribs)
		atCLen := main.GoIntToCInt(i)
		auth, authLen := main.Ahe_maabe_NewMAABEAuth(maabeC, idC, attribsC, atCLen)
		pks, pksLen := main.Ahe_maabe_MaabeAuthPubKeys(auth, authLen)
		bf := "(auth:at1 AND auth:at2)"
		for j := 3; j <= i; j = j + 2 {
			if j < i {
				bf += " OR (auth:at" + strconv.Itoa(j) + " AND auth:at" + strconv.Itoa(j+1) + ")"
			} else {
				bf += " OR auth:at" + strconv.Itoa(j)
			}
		}
		if i == 1 {
			bf = "auth:at1"
		}
		bfC := main.GoStringToCString(bf)
		ctC, ctCLen := main.Ahe_maabe_Encrypt(maabeC, msgC, bfC, pks, pksLen)
		ks, ksLen := main.Ahe_maabe_GenerateAttribKeys(auth, authLen, gidC, attribsC, atCLen)
		b.ResetTimer()
		b.Run(fmt.Sprintf("msg_%s_input_size_%d", msg, i), func(b *testing.B) {
			for k := 0; k < b.N; k++ {
				main.Ahe_maabe_Decrypt(maabeC, ctC, ctCLen, ks, ksLen)
			}
		})
	}
}

func TestMaabeC(t *testing.T) {
	maabeC := main.Ahe_maabe_NewMAABE()
	assert.NotNil(t, maabeC)
	attribs1 := []string{"auth1:at1", "auth1:at2"}
	attribs1C, _ := main.GoSliceToCStringArray(attribs1)
	attribs2 := []string{"auth2:at1", "auth2:at2"}
	attribs2C, _ := main.GoSliceToCStringArray(attribs2)
	attribs3 := []string{"auth3:at1", "auth3:at2"}
	attribs3C, _ := main.GoSliceToCStringArray(attribs3)
	auth1, auth1Len := main.Ahe_maabe_NewMAABEAuth(maabeC, main.GoStringToCString("auth1"), attribs1C, main.GoIntToCInt(2))
	auth2, auth2Len := main.Ahe_maabe_NewMAABEAuth(maabeC, main.GoStringToCString("auth2"), attribs2C, main.GoIntToCInt(2))
	auth3, auth3Len := main.Ahe_maabe_NewMAABEAuth(maabeC, main.GoStringToCString("auth3"), attribs3C, main.GoIntToCInt(2))
	assert.NotNil(t, auth1)
	assert.NotNil(t, auth2)
	assert.NotNil(t, auth3)
	bf := main.GoStringToCString("((auth1:at1 AND auth2:at1) OR (auth1:at2 AND auth2:at2)) OR (auth3:at1 AND auth3:at2)")
	pks1, pks1Len := main.Ahe_maabe_MaabeAuthPubKeys(auth1, auth1Len)
	pks2, pks2Len := main.Ahe_maabe_MaabeAuthPubKeys(auth2, auth2Len)
	pks3, pks3Len := main.Ahe_maabe_MaabeAuthPubKeys(auth3, auth3Len)
	assert.NotNil(t, pks1)
	assert.NotNil(t, pks2)
	assert.NotNil(t, pks3)
	pks1Slice := main.CStringArrayToGoSlice(pks1, int(pks1Len))
	pks2Slice := main.CStringArrayToGoSlice(pks2, int(pks2Len))
	pks3Slice := main.CStringArrayToGoSlice(pks3, int(pks3Len))
	pksSlice := append(pks1Slice, pks2Slice...)
	pksSlice = append(pksSlice, pks3Slice...)
	pks, pksLen := main.GoSliceToCStringArray(pksSlice)
	n := rand.Intn(1000000000)
	msgC := main.GoStringToCString("Attack at dawn!" + strconv.Itoa(n))
	ctC, ctCLen := main.Ahe_maabe_Encrypt(maabeC, msgC, bf, pks, main.GoIntToCInt(pksLen))
	assert.NotNil(t, ctC)
	gid := main.GoStringToCString("gid1")
	keys1, keys1Len := main.Ahe_maabe_GenerateAttribKeys(auth1, auth1Len, gid, attribs1C, main.GoIntToCInt(2))
	keys2, keys2Len := main.Ahe_maabe_GenerateAttribKeys(auth2, auth1Len, gid, attribs2C, main.GoIntToCInt(2))
	keys3, keys3Len := main.Ahe_maabe_GenerateAttribKeys(auth3, auth1Len, gid, attribs3C, main.GoIntToCInt(2))
	assert.NotNil(t, keys1)
	assert.NotNil(t, keys2)
	assert.NotNil(t, keys3)
	keys1Slice := main.CStringArrayToGoSlice(keys1, int(keys1Len))
	keys2Slice := main.CStringArrayToGoSlice(keys2, int(keys2Len))
	keys3Slice := main.CStringArrayToGoSlice(keys3, int(keys3Len))
	ks1Slice := append(keys1Slice[0:3:3], keys2Slice[0:3:3]...)
	ks1Slice = append(ks1Slice, keys3Slice[0:3:3]...)
	ks2Slice := append(keys1Slice[3:6:6], keys2Slice[3:6:6]...)
	ks2Slice = append(ks2Slice, keys3Slice[3:6:6]...)
	ks3Slice := append(keys1Slice[0:3:3], keys2Slice[3:6:6]...)
	ks4Slice := append(keys1Slice[3:6:6], keys2Slice[0:3:3]...)
	ks5Slice := append(keys3Slice[0:3:3], keys3Slice[3:6:6]...)
	ks1, ks1Len := main.GoSliceToCStringArray(ks1Slice)
	ks2, ks2Len := main.GoSliceToCStringArray(ks2Slice)
	ks3, ks3Len := main.GoSliceToCStringArray(ks3Slice)
	ks4, ks4Len := main.GoSliceToCStringArray(ks4Slice)
	ks5, ks5Len := main.GoSliceToCStringArray(ks5Slice)
	pt1 := main.Ahe_maabe_Decrypt(maabeC, ctC, ctCLen, ks1, main.GoIntToCInt(ks1Len))
	assert.NotNil(t, pt1)
	assert.Equal(t, main.CStringToGoString(msgC), main.CStringToGoString(pt1))
	pt2 := main.Ahe_maabe_Decrypt(maabeC, ctC, ctCLen, ks2, main.GoIntToCInt(ks2Len))
	assert.NotNil(t, pt2)
	assert.Equal(t, main.CStringToGoString(msgC), main.CStringToGoString(pt2))
	pt3 := main.Ahe_maabe_Decrypt(maabeC, ctC, ctCLen, ks3, main.GoIntToCInt(ks3Len))
	assert.Nil(t, pt3)
	pt4 := main.Ahe_maabe_Decrypt(maabeC, ctC, ctCLen, ks4, main.GoIntToCInt(ks4Len))
	assert.Nil(t, pt4)
	pt5 := main.Ahe_maabe_Decrypt(maabeC, ctC, ctCLen, ks5, main.GoIntToCInt(ks5Len))
	assert.NotNil(t, pt5)
	assert.Equal(t, main.CStringToGoString(msgC), main.CStringToGoString(pt5))
}

func TestMarshalPubKey(t *testing.T) {
	// abe -> string -> abe
	maabe := abe.NewMAABE()
	attribs := []string{"auth:at1", "auth:at2"}
	auth, err := maabe.NewMAABEAuth("auth", attribs)
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth", err)
	}
	pk := auth.Pk
	mpk, err := maabe2.MarshalPubKey(pk)
	if err != nil {
		t.Fatalf("Error: %v\n", err)
	}
	pkNew, err := maabe2.UnmarshalPubKey(mpk)
	if err != nil {
		t.Fatalf("Error: %v\n", err)
	}
	assert.ElementsMatch(t, pk.Attribs, pkNew.Attribs)
	for _, at := range pk.Attribs {
		assert.Equal(t, pk.EggToAlpha[at].String(), pkNew.EggToAlpha[at].String())
		assert.Equal(t, pk.GToY[at].String(), pkNew.GToY[at].String())
	}
	// string -> abe -> string
	mpkNew, err := maabe2.MarshalPubKey(pkNew)
	if err != nil {
		t.Fatalf("Error: %v\n", err)
	}
	assert.ElementsMatch(t, mpk.Attribs, mpkNew.Attribs)
	for _, at := range mpk.Attribs {
		assert.Equal(t, mpk.EggToAlpha[at], mpkNew.EggToAlpha[at])
		assert.Equal(t, mpk.GToY[at], mpkNew.GToY[at])
	}
}

func TestMarshalAttribKey(t *testing.T) {
	// abe -> string -> abe
	maabe := abe.NewMAABE()
	attribs := []string{"auth:at1", "auth:at2"}
	auth, err := maabe.NewMAABEAuth("auth", attribs)
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth", err)
	}
	ks, err := auth.GenerateAttribKeys("user", attribs)
	if err != nil {
		t.Fatalf("Failed generating keys: %v\n", err)
	}
	mks, err := maabe2.MarshalKeys(ks)
	if err != nil {
		t.Fatalf("Error: %v\n", err)
	}
	ksNew, err := maabe2.UnmarshalKeys(mks)
	if err != nil {
		t.Fatalf("Error: %v\n", err)
	}
	for i, k := range ks {
		assert.Equal(t, k.Gid, ksNew[i].Gid)
		assert.Equal(t, k.Attrib, ksNew[i].Attrib)
		assert.Equal(t, k.Key.String(), ksNew[i].Key.String())
	}
	// string -> abe -> string
	mksNew, err := maabe2.MarshalKeys(ksNew)
	if err != nil {
		t.Fatalf("Error: %v\n", err)
	}
	for i, k := range mks {
		assert.Equal(t, k.Gid, mksNew[i].Gid)
		assert.Equal(t, k.Attrib, mksNew[i].Attrib)
		assert.Equal(t, k.Key, mksNew[i].Key)
	}
}

func TestMarshalCipher(t *testing.T) {
	// abe -> string -> abe
	maabe := abe.NewMAABE()
	attribs := []string{"auth:at1", "auth:at2"}
	auth, err := maabe.NewMAABEAuth("auth", attribs)
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v", "auth", err)
	}
	msg := "Attack at dawn!"
	bf := "(auth:at1 AND auth:at2)"
	msp, err := abe.BooleanToMSP(bf, false)
	if err != nil {
		t.Fatalf("Failed generation of msp: %v", err)
	}
	ct, err := maabe.Encrypt(msg, msp, []*abe.MAABEPubKey{auth.Pk})
	if err != nil {
		t.Fatalf("Failed encryption: %v", err)
	}
	mct, err := maabe2.MarshalCipher(ct)
	if err != nil {
		t.Fatalf("Failed to marshal cipher: %v", err)
	}
	ctNew, err := maabe2.UnmarshalCipher(mct)
	if err != nil {
		t.Fatalf("Failed to unmarshal cipher: %v", err)
	}
	assert.Equal(t, ct.SymEnc, ctNew.SymEnc)
	assert.Equal(t, ct.Iv, ctNew.Iv)
	assert.Equal(t, utils.MatrixToString(ct.Msp.Mat), utils.MatrixToString(ctNew.Msp.Mat))
	assert.Equal(t, strings.Join(ct.Msp.RowToAttrib, " "), strings.Join(ctNew.Msp.RowToAttrib, " "))
	assert.Equal(t, ct.C0.String(), ctNew.C0.String())
	for at, c1 := range ct.C1x {
		assert.Equal(t, c1.String(), ctNew.C1x[at].String())
		assert.Equal(t, ct.C2x[at].String(), ctNew.C2x[at].String())
		assert.Equal(t, ct.C3x[at].String(), ctNew.C3x[at].String())
	}
	mctNew, err := maabe2.MarshalCipher(ctNew)
	if err != nil {
		t.Fatalf("Failed to marshal cipher: %v", err)
	}
	assert.Equal(t, mct.SymEnc, mctNew.SymEnc)
	assert.Equal(t, mct.Iv, mctNew.Iv)
	assert.Equal(t, mct.MSPP, mctNew.MSPP)
	assert.Equal(t, mct.MSPMat, mctNew.MSPMat)
	assert.Equal(t, mct.MSPRowToAttrib, mctNew.MSPRowToAttrib)
	assert.Equal(t, mct.C0, mctNew.C0)
	for at, c1 := range mct.C1 {
		assert.Equal(t, c1, mctNew.C1[at])
		assert.Equal(t, mct.C2[at], mctNew.C2[at])
		assert.Equal(t, mct.C3[at], mctNew.C3[at])
	}
}

func TestJSONPubKey(t *testing.T) {
	// abe -> json -> abe
	maabe := abe.NewMAABE()
	attribs := []string{"auth:at1", "auth:at2"}
	auth, err := maabe.NewMAABEAuth("auth", attribs)
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth", err)
	}
	pk := auth.Pk
	pkJSON, err := maabe2.PublicKeyToJSON(pk)
	if err != nil {
		t.Fatalf("Failed to marshal pk: %v\n", err)
	}
	pkNew, err := maabe2.JSONToPublicKey(pkJSON)
	if err != nil {
		t.Fatalf("Failed to unmarshal pk: %v\n", err)
	}
	assert.ElementsMatch(t, maabe2.MaabePubToRaw(pk), maabe2.MaabePubToRaw(pkNew))
	// json -> abe -> json
	pkNewJSON, err := maabe2.PublicKeyToJSON(pkNew)
	if err != nil {
		t.Fatalf("Failed to marshal pkNew: %v\n", err)
	}
	assert.Equal(t, pkJSON, pkNewJSON)
}

func TestJSONAttribKey(t *testing.T) {
	// abe -> json -> abe
	maabe := abe.NewMAABE()
	attribs := []string{"auth:at1", "auth:at2"}
	auth, err := maabe.NewMAABEAuth("auth", attribs)
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth", err)
	}
	ks, err := auth.GenerateAttribKeys("user", attribs)
	if err != nil {
		t.Fatalf("Failed generation ks: %v\n", err)
	}
	ksJSON, err := maabe2.AttribKeysToJSON(ks)
	if err != nil {
		t.Fatalf("Failed to marshal ks: %v\n", err)
	}
	ksNew, err := maabe2.JSONToAttribKeys(ksJSON)
	if err != nil {
		t.Fatalf("Failed to unmarshal ks: %v\n", err)
	}
	assert.ElementsMatch(t, maabe2.MaabeKeysToRaw(ks), maabe2.MaabeKeysToRaw(ksNew))
	// json -> abe -> json
	ksNewJSON, err := maabe2.AttribKeysToJSON(ksNew)
	if err != nil {
		t.Fatalf("Failed to marshal ksNew: %v\n", err)
	}
	assert.Equal(t, ksJSON, ksNewJSON)
}

func TestJSONCipherKey(t *testing.T) {
	// abe -> json -> abe
	maabe := abe.NewMAABE()
	attribs := []string{"auth:at1", "auth:at2"}
	auth, err := maabe.NewMAABEAuth("auth", attribs)
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth", err)
	}
	msg := "Attack at dawn!"
	bf := "(auth:at1 AND auth:at2)"
	msp, err := abe.BooleanToMSP(bf, false)
	if err != nil {
		t.Fatalf("Failed generation of msp: %v\n", err)
	}
	ct, err := maabe.Encrypt(msg, msp, []*abe.MAABEPubKey{auth.Pk})
	if err != nil {
		t.Fatalf("Failed encryption: %v\n", err)
	}
	ctJSON, err := maabe2.CipherToJSON(ct)
	if err != nil {
		t.Fatalf("Failed to marshal ct: %v\n", err)
	}
	ctNew, err := maabe2.JSONToCipher(ctJSON)
	if err != nil {
		t.Fatalf("Failed to unmarshal ct: %v\n", err)
	}
	assert.ElementsMatch(t, maabe2.MaabeCipherToRaw(ct), maabe2.MaabeCipherToRaw(ctNew))
	// json -> abe -> json
	ctNewJSON, err := maabe2.CipherToJSON(ctNew)
	if err != nil {
		t.Fatalf("Failed to marshal ctNew: %v\n", err)
	}
	assert.Equal(t, ctJSON, ctNewJSON)
}

func TestJSONC(t *testing.T) {
	maabeC := main.Ahe_maabe_NewMAABE()
	assert.NotNil(t, maabeC)
	attribs := []string{"auth:at1", "auth:at2"}
	attribsC, _ := main.GoSliceToCStringArray(attribs)
	auth, authLen := main.Ahe_maabe_NewMAABEAuth(maabeC, main.GoStringToCString("auth"), attribsC, main.GoIntToCInt(2))
	assert.NotNil(t, auth)
	bf := main.GoStringToCString("(auth:at1 AND auth:at2)")
	pks, pksLen := main.Ahe_maabe_MaabeAuthPubKeys(auth, authLen)
	assert.NotNil(t, pks)
	n := rand.Intn(1000000000)
	msgC := main.GoStringToCString("Attack at dawn!" + strconv.Itoa(n))
	ctC, ctCLen := main.Ahe_maabe_Encrypt(maabeC, msgC, bf, pks, pksLen)
	assert.NotNil(t, ctC)
	gid := main.GoStringToCString("gid")
	ks, ksLen := main.Ahe_maabe_GenerateAttribKeys(auth, authLen, gid, attribsC, main.GoIntToCInt(2))

	// abe -> json -> abe
	pksJSON := main.Ahe_maabe_PubKeyToJSON(pks, pksLen)
	pksNew, pksNewLen := main.Ahe_maabe_PubKeyFromJSON(pksJSON)
	if main.CIntToGoInt(pksNewLen) == 0 {
		t.Errorf("pkNew has len 0")
	}
	assert.ElementsMatch(t, main.CStringArrayToGoSlice(pks, main.CIntToGoInt(pksLen)), main.CStringArrayToGoSlice(pksNew, main.CIntToGoInt(pksNewLen)))
	// json -> abe -> json
	pksNewJSON := main.Ahe_maabe_PubKeyToJSON(pksNew, pksNewLen)
	assert.Equal(t, main.CStringToGoString(pksJSON), main.CStringToGoString(pksNewJSON))

	// abe -> json -> abe
	ctJSON := main.Ahe_maabe_CipherToJSON(ctC, ctCLen)
	ctNew, ctNewLen := main.Ahe_maabe_CipherFromJSON(ctJSON)
	if main.CIntToGoInt(ctNewLen) == 0 {
		t.Errorf("ctNew has len 0")
	}
	assert.ElementsMatch(t, main.CStringArrayToGoSlice(ctC, main.CIntToGoInt(ctCLen)), main.CStringArrayToGoSlice(ctNew, main.CIntToGoInt(ctNewLen)))
	// json -> abe -> json
	ctNewJSON := main.Ahe_maabe_CipherToJSON(ctNew, ctNewLen)
	assert.Equal(t, main.CStringToGoString(ctJSON), main.CStringToGoString(ctNewJSON))

	// abe -> json -> abe
	ksJSON := main.Ahe_maabe_AttribKeysToJSON(ks, ksLen)
	ksNew, ksNewLen := main.Ahe_maabe_AttribKeysFromJSON(ksJSON)
	if main.CIntToGoInt(ksNewLen) == 0 {
		t.Errorf("ksNew has len 0")
	}
	assert.ElementsMatch(t, main.CStringArrayToGoSlice(ks, main.CIntToGoInt(ksLen)), main.CStringArrayToGoSlice(ksNew, main.CIntToGoInt(ksNewLen)))
	// json -> abe -> json
	ksNewJSON := main.Ahe_maabe_AttribKeysToJSON(ksNew, ksNewLen)
	assert.Equal(t, main.CStringToGoString(ksJSON), main.CStringToGoString(ksNewJSON))
}

func TestFameC(t *testing.T) {
	fameC := main.Ahe_fame_NewFAME()
	assert.NotNil(t, fameC)

	pkC, skC := main.Ahe_fame_GenerateMasterKeys(fameC)

	bf := main.GoStringToCString("(at1 AND at2) OR at3")

	n := rand.Intn(1000000000)
	msgC := main.GoStringToCString("Attack at dawn!" + strconv.Itoa(n))
	ctC, ctCLen := main.Ahe_fame_Encrypt(fameC, msgC, bf, pkC)
	assert.NotNil(t, ctC)

	attribs1 := []string{"at1", "at2"}
	attribs1C, attribs1CLen := main.GoSliceToCStringArray(attribs1)
	keys1C, keys1Len := main.Ahe_fame_GenerateAttribKeys(fameC, attribs1C, main.GoIntToCInt(attribs1CLen), skC)
	assert.NotNil(t, keys1C)

	attribs2 := []string{"at2"}
	attribs2C, attribs2CLen := main.GoSliceToCStringArray(attribs2)
	keys2C, keys2Len := main.Ahe_fame_GenerateAttribKeys(fameC, attribs2C, main.GoIntToCInt(attribs2CLen), skC)
	assert.NotNil(t, keys2C)

	pt1 := main.Ahe_fame_Decrypt(fameC, ctC, ctCLen, keys1C, keys1Len, pkC)
	assert.NotNil(t, pt1)
	assert.Equal(t, main.CStringToGoString(msgC), main.CStringToGoString(pt1))

	pt2 := main.Ahe_fame_Decrypt(fameC, ctC, ctCLen, keys2C, keys2Len, pkC)
	assert.Nil(t, pt2)
	//assert.Equal(t, cgo.CStringToGoString(msgC), cgo.CStringToGoString(pt1))

	//	gid := cgo.GoStringToCString("gid1")
	//	keys1, keys1Len := cgo.Ahe_maabe_GenerateAttribKeys(auth1, auth1Len, gid, attribs1C, cgo.GoIntToCInt(2))
	//	keys2, keys2Len := cgo.Ahe_maabe_GenerateAttribKeys(auth2, auth1Len, gid, attribs2C, cgo.GoIntToCInt(2))
	//	keys3, keys3Len := cgo.Ahe_maabe_GenerateAttribKeys(auth3, auth1Len, gid, attribs3C, cgo.GoIntToCInt(2))
	//	assert.NotNil(t, keys1)
	//	assert.NotNil(t, keys2)
	//	assert.NotNil(t, keys3)
	//	keys1Slice := cgo.CStringArrayToGoSlice(keys1, int(keys1Len))
	//	keys2Slice := cgo.CStringArrayToGoSlice(keys2, int(keys2Len))
	//	keys3Slice := cgo.CStringArrayToGoSlice(keys3, int(keys3Len))
	//	ks1Slice := append(keys1Slice[0:3:3], keys2Slice[0:3:3]...)
	//	ks1Slice = append(ks1Slice, keys3Slice[0:3:3]...)
	//	ks2Slice := append(keys1Slice[3:6:6], keys2Slice[3:6:6]...)
	//	ks2Slice = append(ks2Slice, keys3Slice[3:6:6]...)
	//	ks3Slice := append(keys1Slice[0:3:3], keys2Slice[3:6:6]...)
	//	ks4Slice := append(keys1Slice[3:6:6], keys2Slice[0:3:3]...)
	//	ks5Slice := append(keys3Slice[0:3:3], keys3Slice[3:6:6]...)
	//	ks1, ks1Len := cgo.GoSliceToCStringArray(ks1Slice)
	//	ks2, ks2Len := cgo.GoSliceToCStringArray(ks2Slice)
	//	ks3, ks3Len := cgo.GoSliceToCStringArray(ks3Slice)
	//	ks4, ks4Len := cgo.GoSliceToCStringArray(ks4Slice)
	//	ks5, ks5Len := cgo.GoSliceToCStringArray(ks5Slice)
	//	pt1 := cgo.Ahe_maabe_Decrypt(fameC, ctC, ctCLen, ks1, cgo.GoIntToCInt(ks1Len))
	//	assert.NotNil(t, pt1)
	//	assert.Equal(t, cgo.CStringToGoString(msgC), cgo.CStringToGoString(pt1))
	//	pt2 := cgo.Ahe_maabe_Decrypt(fameC, ctC, ctCLen, ks2, cgo.GoIntToCInt(ks2Len))
	//	assert.NotNil(t, pt2)
	//	assert.Equal(t, cgo.CStringToGoString(msgC), cgo.CStringToGoString(pt2))
	//	pt3 := cgo.Ahe_maabe_Decrypt(fameC, ctC, ctCLen, ks3, cgo.GoIntToCInt(ks3Len))
	//	assert.Nil(t, pt3)
	//	pt4 := cgo.Ahe_maabe_Decrypt(fameC, ctC, ctCLen, ks4, cgo.GoIntToCInt(ks4Len))
	//	assert.Nil(t, pt4)
	//	pt5 := cgo.Ahe_maabe_Decrypt(fameC, ctC, ctCLen, ks5, cgo.GoIntToCInt(ks5Len))
	//	assert.NotNil(t, pt5)
	//	assert.Equal(t, cgo.CStringToGoString(msgC), cgo.CStringToGoString(pt5))
}
