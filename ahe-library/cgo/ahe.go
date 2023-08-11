package main

//#include <stdlib.h>
import "C"

import (
	"github.com/fentec-project/gofe/abe"
	fame2 "github.com/xlab-si/ahe/ahe-library/cgo/fame"
	"github.com/xlab-si/ahe/ahe-library/cgo/fame/decentralized"
	maabe2 "github.com/xlab-si/ahe/ahe-library/cgo/maabe"
	"github.com/xlab-si/ahe/ahe-library/cgo/signatures"
	"unsafe"
)

// C strings to slices and back

func CleanStringSlice(ents []string) []string {
	// the main issue are the zero bytes which terminate C strings
	// since 0x00 is the ONLY UTF-8 character with a zero byte anywhere in its
	// representation (as per the UTF-8 spec), we can safely remove them
	for i, ent := range ents {
		entBytes := []byte(ent)
		entBytesNew := make([]byte, 0)
		for _, b := range entBytes {
			if b != 0 {
				entBytesNew = append(entBytesNew, b)
			}
		}
		ents[i] = string(entBytesNew)
	}
	return ents
}

func GoSliceToCStringArray(ents []string) (**C.char, int) {
	if len(ents) == 0 {
		return nil, 0
	}
	ents = CleanStringSlice(ents)
	cArray := C.malloc(C.size_t(len(ents)) * C.size_t(unsafe.Sizeof(uintptr(0))))
	goArray := (*[1<<16 - 1]*C.char)(cArray)
	for i, ent := range ents {
		goArray[i] = C.CString(ent)
	}
	cData := (**C.char)(cArray)
	return cData, len(ents)
}

func CStringArrayToGoSlice(cdata **C.char, l int) []string {
	if cdata == nil {
		return []string{}
	}
	cdataPointer := unsafe.Pointer(cdata)
	goSliceOfChar := unsafe.Slice((**C.char)(cdataPointer), l)
	goSlice := make([]string, l)
	for i := 0; i < l; i++ {
		goSlice[i] = C.GoString(goSliceOfChar[i])
	}
	// for _, ent := range goSliceOfChar {
	// C.free(unsafe.Pointer(ent))
	// }
	// C.free(unsafe.Pointer(cdata))
	return CleanStringSlice(goSlice)
}

// exported functions - C types

func CIntToGoInt(i C.int) int {
	return int(i)
}

func GoIntToCInt(i int) C.int {
	return C.int(i)
}

func CStringToGoString(s *C.char) string {
	return C.GoString(s)
}

func GoStringToCString(s string) *C.char {
	return C.CString(s)
}

//export Ahe_maabe_NewMAABE
func Ahe_maabe_NewMAABE() **C.char {
	maabe := abe.NewMAABE()
	maabeRaw := maabe2.MaabeToRaw(maabe)
	maabeRawC, l := GoSliceToCStringArray(maabeRaw)
	// l should always be 4
	if l != 4 {
		return nil
	}
	return maabeRawC
}

//export Ahe_maabe_NewMAABEAuth
func Ahe_maabe_NewMAABEAuth(maabeRawC **C.char, id *C.char, attribs **C.char, attribsLen C.int) (**C.char, C.int) {
	maabeRaw := CStringArrayToGoSlice(maabeRawC, 4)
	idString := C.GoString(id)
	attribsList := CStringArrayToGoSlice(attribs, int(attribsLen))
	auth, status := maabe2.Go_Ahe_maabe_NewMAABEAuth(maabeRaw, idString, attribsList)
	if status != 0 {
		return nil, C.int(0)
	}
	authC, l := GoSliceToCStringArray(auth)
	return authC, C.int(l)
}

//export Ahe_maabe_MaabeAuthPubKeys
func Ahe_maabe_MaabeAuthPubKeys(authC **C.char, authCLen C.int) (**C.char, C.int) {
	authRaw := CStringArrayToGoSlice(authC, int(authCLen))
	pubkeys, status := maabe2.Go_Ahe_maabe_MaabeAuthPubKeys(authRaw)
	if status != 0 {
		return nil, C.int(0)
	}
	pubkeysC, l := GoSliceToCStringArray(pubkeys)
	return pubkeysC, C.int(l)
}

//export Ahe_maabe_AddAttribute
func Ahe_maabe_AddAttribute(authC **C.char, authCLen C.int, attrib *C.char) (**C.char, C.int) {
	authRaw := CStringArrayToGoSlice(authC, int(authCLen))
	attribString := C.GoString(attrib)
	authNew, status := maabe2.Go_Ahe_maabe_AddAttribute(authRaw, attribString)
	if status != 0 {
		return nil, C.int(0)
	}
	authNewC, l := GoSliceToCStringArray(authNew)
	return authNewC, C.int(l)
}

//export Ahe_maabe_Encrypt
func Ahe_maabe_Encrypt(maabeRawC **C.char, msg *C.char, booleanFormula *C.char, pubkeys **C.char, pubkeysLen C.int) (**C.char, C.int) {
	maabeRaw := CStringArrayToGoSlice(maabeRawC, 4)
	msgString := C.GoString(msg)
	booleanFormulaString := C.GoString(booleanFormula)
	pubkeysString := CStringArrayToGoSlice(pubkeys, int(pubkeysLen))
	enc, status := maabe2.Go_Ahe_maabe_Encrypt(maabeRaw, msgString, booleanFormulaString, pubkeysString)
	if status != 0 {
		return nil, C.int(0)
	}
	encC, l := GoSliceToCStringArray(enc)
	return encC, C.int(l)
}

//export Ahe_maabe_GenerateAttribKeys
func Ahe_maabe_GenerateAttribKeys(authC **C.char, authCLen C.int, gid *C.char, attribs **C.char, attribsLen C.int) (**C.char, C.int) {
	authRaw := CStringArrayToGoSlice(authC, int(authCLen))
	gidString := C.GoString(gid)
	attribsString := CStringArrayToGoSlice(attribs, int(attribsLen))
	keys, status := maabe2.Go_Ahe_maabe_GenerateAttribKeys(authRaw, gidString, attribsString)
	if status != 0 {
		return nil, C.int(0)
	}
	keysC, l := GoSliceToCStringArray(keys)
	return keysC, C.int(l)
}

//export Ahe_maabe_Decrypt
func Ahe_maabe_Decrypt(maabeRawC **C.char, ctRawC **C.char, ctRawCLen C.int, ksRawC **C.char, ksRawCLen C.int) *C.char {
	maabeRaw := CStringArrayToGoSlice(maabeRawC, 4)
	ksRaw := CStringArrayToGoSlice(ksRawC, int(ksRawCLen))
	ctRaw := CStringArrayToGoSlice(ctRawC, int(ctRawCLen))
	dec, status := maabe2.Go_Ahe_maabe_Decrypt(maabeRaw, ctRaw, ksRaw)
	if status != 0 {
		return nil
	}
	decC := C.CString(dec)
	return decC
}

//export Ahe_maabe_PubKeyToJSON
func Ahe_maabe_PubKeyToJSON(pkC **C.char, pkCLen C.int) *C.char {
	pkStr := CStringArrayToGoSlice(pkC, int(pkCLen))
	pkJSON, status := maabe2.Go_Ahe_maabe_PubKeyToJSON(pkStr)
	if status != 0 {
		return nil
	}
	return C.CString(string(pkJSON[:]))
}

//export Ahe_maabe_PubKeyFromJSON
func Ahe_maabe_PubKeyFromJSON(data *C.char) (**C.char, C.int) {
	jsonStr := C.GoString(data)
	jsonBytes := []byte(jsonStr)
	pkStr, status := maabe2.Go_Ahe_maabe_PubKeyFromJSON(jsonBytes)
	if status != 0 {
		return nil, C.int(0)
	}
	pkC, pkCLen := GoSliceToCStringArray(pkStr)
	return pkC, C.int(pkCLen)
}

//export Ahe_maabe_AttribKeysToJSON
func Ahe_maabe_AttribKeysToJSON(ks **C.char, ksLen C.int) *C.char {
	ksStr := CStringArrayToGoSlice(ks, int(ksLen))
	ksJSON, status := maabe2.Go_Ahe_maabe_AttribKeysToJSON(ksStr)
	if status != 0 {
		return nil
	}
	return C.CString(string(ksJSON[:]))
}

//export Ahe_maabe_AttribKeysFromJSON
func Ahe_maabe_AttribKeysFromJSON(data *C.char) (**C.char, C.int) {
	jsonStr := C.GoString(data)
	jsonBytes := []byte(jsonStr)
	ksStr, status := maabe2.Go_Ahe_maabe_AttribKeysFromJSON(jsonBytes)
	if status != 0 {
		return nil, C.int(0)
	}
	ksC, ksCLen := GoSliceToCStringArray(ksStr)
	return ksC, C.int(ksCLen)
}

//export Ahe_maabe_CipherToJSON
func Ahe_maabe_CipherToJSON(ct **C.char, ctLen C.int) *C.char {
	ctStr := CStringArrayToGoSlice(ct, int(ctLen))
	ctJSON, status := maabe2.Go_Ahe_maabe_CipherToJSON(ctStr)
	if status != 0 {
		return nil
	}
	return C.CString(string(ctJSON[:]))
}

//export Ahe_maabe_CipherFromJSON
func Ahe_maabe_CipherFromJSON(data *C.char) (**C.char, C.int) {
	jsonStr := C.GoString(data)
	jsonBytes := []byte(jsonStr)
	ctStr, status := maabe2.Go_Ahe_maabe_CipherFromJSON(jsonBytes)
	if status != 0 {
		return nil, C.int(0)
	}
	ctC, ctCLen := GoSliceToCStringArray(ctStr)
	return ctC, C.int(ctCLen)
}

//export Ahe_fame_NewFAME
func Ahe_fame_NewFAME() *C.char {
	fame := abe.NewFAME()
	fameRaw := fame2.FameToRaw(fame)
	fameRawC := GoStringToCString(fameRaw)

	return fameRawC
}

//export Ahe_fame_GenerateMasterKeys
func Ahe_fame_GenerateMasterKeys(fameRawC *C.char) (*C.char, *C.char) {
	maabeRaw := CStringToGoString(fameRawC)
	pk, sk, status := fame2.Go_Ahe_fame_GenerateMasterKeys(maabeRaw)
	if status != 0 {
		return nil, nil
	}
	pkC := GoStringToCString(pk)
	skC := GoStringToCString(sk)

	return pkC, skC
}

//export Ahe_fame_Encrypt
func Ahe_fame_Encrypt(fameRawC *C.char, msg *C.char, booleanFormula *C.char, pubkey *C.char) (**C.char, C.int) {
	maabeRaw := CStringToGoString(fameRawC)
	msgString := C.GoString(msg)
	booleanFormulaString := C.GoString(booleanFormula)
	pubkeysString := CStringToGoString(pubkey)
	enc, status := fame2.Go_Ahe_fame_Encrypt(maabeRaw, msgString, booleanFormulaString, pubkeysString)
	if status != 0 {
		return nil, C.int(0)
	}
	encC, l := GoSliceToCStringArray(enc)
	return encC, C.int(l)
}

//export Ahe_fame_GenerateAttribKeys
func Ahe_fame_GenerateAttribKeys(fameRawC *C.char, attribs **C.char, attribsLen C.int, skRawC *C.char) (**C.char, C.int) {
	maabeRaw := CStringToGoString(fameRawC)
	attribsString := CStringArrayToGoSlice(attribs, int(attribsLen))
	skRaw := CStringToGoString(skRawC)
	keys, status := fame2.Go_Ahe_fame_GenerateAttribKeys(maabeRaw, attribsString, skRaw)
	if status != 0 {
		return nil, C.int(0)
	}
	keysC, l := GoSliceToCStringArray(keys)
	return keysC, C.int(l)
}

//export Ahe_fame_Decrypt
func Ahe_fame_Decrypt(fameRawC *C.char, ctRawC **C.char, ctRawCLen C.int, ksRawC **C.char, ksRawCLen C.int, pkRawC *C.char) *C.char {
	maabeRaw := CStringToGoString(fameRawC)
	ksRaw := CStringArrayToGoSlice(ksRawC, int(ksRawCLen))
	ctRaw := CStringArrayToGoSlice(ctRawC, int(ctRawCLen))
	pkRaw := CStringToGoString(pkRawC)
	dec, status := fame2.Go_Ahe_fame_Decrypt(maabeRaw, ctRaw, ksRaw, pkRaw)
	if status != 0 {
		return nil
	}
	decC := C.CString(dec)
	return decC
}

//export Ahe_fame_decrytAttribKeys
func Ahe_fame_decrytAttribKeys(attribKeys *C.char, randKeys **C.char, randKeysLen C.int) (**C.char, C.int) {
	decKeysRaw := CStringArrayToGoSlice(randKeys, int(randKeysLen))
	attribKeysString := CStringToGoString(attribKeys)

	key, err := decentralized.Go_Ahe_fame_DecryptAttribKeys(attribKeysString, decKeysRaw)
	if err != 0 {
		return nil, 0
	}
	keyC, l := GoSliceToCStringArray(key)

	return keyC, C.int(l)
}

//export Ahe_fame_joinDecAttribKeys
func Ahe_fame_joinDecAttribKeys(decKeys **C.char, decKeysLen C.int) (**C.char, C.int) {
	decKeysRaw := CStringArrayToGoSlice(decKeys, int(decKeysLen))
	key, err := decentralized.Go_Ahe_fame_JoinDecAttribKeys(decKeysRaw)
	if err != 0 {
		return nil, 0
	}
	keyC, l := GoSliceToCStringArray(key)

	return keyC, C.int(l)
}

//export Ahe_GenerateSigKeys
func Ahe_GenerateSigKeys() (*C.char, *C.char) {
	pk, sk, err := signatures.GenerateSignKeys()
	if err != 0 {
		return nil, nil
	}
	skRaw := GoStringToCString(sk)
	pkRaw := GoStringToCString(pk)

	return pkRaw, skRaw
}

//export Ahe_SignCiphers
func Ahe_SignCiphers(skRaw *C.char, ctsRaw **C.char, ctsRawCLen C.int, proofRaw *C.char) *C.char {
	sk := CStringToGoString(skRaw)
	proof := CStringToGoString(proofRaw)
	cts := CStringArrayToGoSlice(ctsRaw, int(ctsRawCLen))

	ctSigned, err := signatures.SignCiphers(sk, proof, cts, nil)
	if err != 0 {
		return nil
	}

	ctSignedRaw := GoStringToCString(ctSigned)

	return ctSignedRaw
}

//export Ahe_VerifySig
func Ahe_VerifySig(ctsSignedRaw *C.char, uuidRaw *C.char, caRaw *C.char) C.int {
	ctsSigned := CStringToGoString(ctsSignedRaw)
	uuid := CStringToGoString(uuidRaw)
	ca := CStringToGoString(caRaw)
	check, status := signatures.VerifyCiphers(ctsSigned, uuid, ca)
	if status != 0 || check == false {
		return 0
	} else {
		return 1
	}
}

func main() {}
