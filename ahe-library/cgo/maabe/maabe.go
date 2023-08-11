package maabe

//#include <stdlib.h>
import "C"

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/xlab-si/ahe/ahe-library/cgo/utils"
	"math/big"
	"strings"
)

// serialization functions

func MaabeFromRaw(maabeRaw []string) (*abe.MAABE, error) {
	if len(maabeRaw) != 4 {
		return nil, fmt.Errorf("maabe not appropriate length")
	}
	for _, ent := range maabeRaw {
		if ent == "" {
			return nil, fmt.Errorf("list can not contain empty elements")
		}
	}
	p := new(big.Int)
	g1 := new(bn256.G1)
	g2 := new(bn256.G2)
	gt := new(bn256.GT)
	p, ok := p.SetString(maabeRaw[0], 10)
	if !ok {
		return nil, fmt.Errorf("could not set p")
	}
	g1Raw, err := base64.StdEncoding.DecodeString(maabeRaw[1])
	if err != nil {
		return nil, fmt.Errorf("decoding error")
	}
	g2Raw, err := base64.StdEncoding.DecodeString(maabeRaw[2])
	if err != nil {
		return nil, fmt.Errorf("decoding error")
	}
	gtRaw, err := base64.StdEncoding.DecodeString(maabeRaw[3])
	if err != nil {
		return nil, fmt.Errorf("decoding error")
	}
	_, err = g1.Unmarshal(g1Raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal error: %v", err)
	}
	_, err = g2.Unmarshal(g2Raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal error: %v", err)
	}
	_, err = gt.Unmarshal(gtRaw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal error: %v", err)
	}
	return &abe.MAABE{
		P:  p,
		G1: g1,
		G2: g2,
		Gt: gt,
	}, nil
}

func MaabeToRaw(maabe *abe.MAABE) []string {
	s := make([]string, 4)
	s[0] = maabe.P.String()
	s[1] = base64.StdEncoding.EncodeToString(maabe.G1.Marshal())
	s[2] = base64.StdEncoding.EncodeToString(maabe.G2.Marshal())
	s[3] = base64.StdEncoding.EncodeToString(maabe.Gt.Marshal())
	return s
}

func MaabeAuthFromRaw(maabeAuthRaw []string) (*abe.MAABEAuth, error) {
	if len(maabeAuthRaw) <= 5 {
		return nil, fmt.Errorf("maabe auth not appropriate length")
	}
	if len(maabeAuthRaw)%5 != 0 {
		return nil, fmt.Errorf("maabe auth not appropriate length")
	}
	attribs := make([]string, (len(maabeAuthRaw)-5)/5)
	eggToAlpha := make(map[string]*bn256.GT)
	gToY := make(map[string]*bn256.G2)
	alpha := make(map[string]*big.Int)
	y := make(map[string]*big.Int)
	var tmpAt string
	for i, item := range maabeAuthRaw {
		if i < 5 {
			continue
		}
		switch i % 5 {
		case 0:
			tmpAt = item
			attribs[(i-5)/5] = item
		case 1:
			tmpRaw, err := base64.StdEncoding.DecodeString(item)
			if err != nil {
				return nil, fmt.Errorf("error decoding: %v", err)
			}
			tmp := new(bn256.GT)
			_, err = tmp.Unmarshal(tmpRaw)
			if err != nil {
				return nil, fmt.Errorf("error unmarshaling: %v", err)
			}
			eggToAlpha[tmpAt] = tmp
		case 2:
			tmpRaw, err := base64.StdEncoding.DecodeString(item)
			if err != nil {
				return nil, fmt.Errorf("error decoding: %v", err)
			}
			tmp := new(bn256.G2)
			_, err = tmp.Unmarshal(tmpRaw)
			if err != nil {
				return nil, fmt.Errorf("error unmarshaling: %v", err)
			}
			gToY[tmpAt] = tmp
		case 3:
			tmp := new(big.Int)
			tmp, ok := tmp.SetString(item, 10)
			if !ok {
				return nil, fmt.Errorf("error assigning bigint from string")
			}
			alpha[tmpAt] = tmp
		case 4:
			tmp := new(big.Int)
			tmp, ok := tmp.SetString(item, 10)
			if !ok {
				return nil, fmt.Errorf("error assigning bigint from string")
			}
			y[tmpAt] = tmp
		}
	}
	maabe, err := MaabeFromRaw(maabeAuthRaw[1:5:5])
	if err != nil {
		return nil, fmt.Errorf("could not create maabe")
	}
	return &abe.MAABEAuth{
		ID:    maabeAuthRaw[0],
		Maabe: maabe,
		Pk: &abe.MAABEPubKey{
			Attribs:    attribs,
			EggToAlpha: eggToAlpha,
			GToY:       gToY,
		},
		Sk: &abe.MAABESecKey{
			Attribs: attribs,
			Alpha:   alpha,
			Y:       y,
		},
	}, nil
}

func MaabeAuthToRaw(maabeAuth *abe.MAABEAuth) []string {
	// the authority is represented by a list of strings in the following form
	// 0: ID
	// 1-4: MAABE
	// 5-tuples: (attribute, EggToAlpha, GToY, Alpha, Y)
	maabeAuthRaw := make([]string, 1+4+5*len(maabeAuth.Pk.Attribs))
	// ID
	maabeAuthRaw[0] = maabeAuth.ID
	// MAABE
	maabeRaw := MaabeToRaw(maabeAuth.Maabe)
	maabeAuthRaw[1] = maabeRaw[0]
	maabeAuthRaw[2] = maabeRaw[1]
	maabeAuthRaw[3] = maabeRaw[2]
	maabeAuthRaw[4] = maabeRaw[3]
	// KEYS
	for i, at := range maabeAuth.Pk.Attribs {
		maabeAuthRaw[5+5*i+0] = at
		maabeAuthRaw[5+5*i+1] = base64.StdEncoding.EncodeToString(maabeAuth.Pk.EggToAlpha[at].Marshal())
		maabeAuthRaw[5+5*i+2] = base64.StdEncoding.EncodeToString(maabeAuth.Pk.GToY[at].Marshal())
		maabeAuthRaw[5+5*i+3] = maabeAuth.Sk.Alpha[at].String()
		maabeAuthRaw[5+5*i+4] = maabeAuth.Sk.Y[at].String()
	}
	return maabeAuthRaw
}

func MaabePubFromRaw(maabePubRaw []string) (*abe.MAABEPubKey, error) {
	// pubkeys should be a list of string triplets (attrib, base64 eggToAlpha, base64 gToY)
	if len(maabePubRaw)%3 != 0 {
		return nil, fmt.Errorf("pubkeys not correct length")
	}
	attribs := make([]string, len(maabePubRaw)/3)
	eggToAlpha := make(map[string]*bn256.GT)
	gToY := make(map[string]*bn256.G2)
	var tmpAt string
	for i, item := range maabePubRaw {
		switch i % 3 {
		case 0:
			tmpAt = item
			attribs[i/3] = item
		case 1:
			gtRaw, err := base64.StdEncoding.DecodeString(item)
			if err != nil {
				return nil, fmt.Errorf("error decoding: %v", err)
			}
			gt := new(bn256.GT)
			_, err = gt.Unmarshal(gtRaw)
			if err != nil {
				return nil, fmt.Errorf("error unmarshaling: %v", err)
			}
			eggToAlpha[tmpAt] = gt
		case 2:
			g2Raw, err := base64.StdEncoding.DecodeString(item)
			if err != nil {
				return nil, fmt.Errorf("error decoding: %v", err)
			}
			g2 := new(bn256.G2)
			_, err = g2.Unmarshal(g2Raw)
			if err != nil {
				return nil, fmt.Errorf("error unmarshaling: %v", err)
			}
			gToY[tmpAt] = g2
		}
	}
	return &abe.MAABEPubKey{
		Attribs:    attribs,
		EggToAlpha: eggToAlpha,
		GToY:       gToY,
	}, nil
}

func MaabePubToRaw(pk *abe.MAABEPubKey) []string {
	pkStr := make([]string, 3*len(pk.Attribs))
	for i, at := range pk.Attribs {
		pkStr[3*i+0] = at
		pkStr[3*i+1] = base64.StdEncoding.EncodeToString(pk.EggToAlpha[at].Marshal())
		pkStr[3*i+2] = base64.StdEncoding.EncodeToString(pk.GToY[at].Marshal())
	}
	return pkStr
}

func MaabeCipherToRaw(ct *abe.MAABECipher) []string {
	// ciphertext should be a list of strings of the form
	// 0: base64 of SymEnc
	// 1: base64 of Iv
	// 2: MSP P as string - currently just the string "0", since P is not used anywhere
	// 3: MSP matrix serialized as above
	// 4: MSP RowToAttribute concatenated by spaces
	// 5: C0 marshalled and 64
	// 4-tuples: (attribute, C1, C2, C3)
	ctRaw := make([]string, 1+1+3+1+4*len(ct.C1x))
	ctRaw[0] = base64.StdEncoding.EncodeToString(ct.SymEnc)
	ctRaw[1] = base64.StdEncoding.EncodeToString(ct.Iv)
	// ctRaw[2] = ct.Msp.P.String()
	ctRaw[2] = "0"
	ctRaw[3] = utils.MatrixToString(ct.Msp.Mat)
	ctRaw[4] = strings.Join(ct.Msp.RowToAttrib, " ")
	ctRaw[5] = base64.StdEncoding.EncodeToString(ct.C0.Marshal())
	i := 6
	for at, c1 := range ct.C1x {
		c2 := ct.C2x[at]
		c3 := ct.C3x[at]
		ctRaw[i] = at
		ctRaw[i+1] = base64.StdEncoding.EncodeToString(c1.Marshal())
		ctRaw[i+2] = base64.StdEncoding.EncodeToString(c2.Marshal())
		ctRaw[i+3] = base64.StdEncoding.EncodeToString(c3.Marshal())
		i = i + 4
	}
	return ctRaw
}

func MaabeCipherFromRaw(ctRaw []string) (*abe.MAABECipher, error) {
	if len(ctRaw) <= 6 {
		return nil, fmt.Errorf("ciphertext not correct len")
	}
	if (len(ctRaw)-6)%4 != 0 {
		return nil, fmt.Errorf("ciphertext not correct len")
	}
	symEnc, err := base64.StdEncoding.DecodeString(ctRaw[0])
	if err != nil {
		return nil, fmt.Errorf("cipher from raw error - 0: %v", err)
	}
	iv, err := base64.StdEncoding.DecodeString(ctRaw[1])
	if err != nil {
		return nil, fmt.Errorf("cipher from raw error - 1: %v", err)
	}
	// p, ok := new(big.Int).SetString(ctRaw[2], 10)
	// if !ok {
	// return nil, fmt.Errorf("cipher from raw error - 2")
	// }
	m := utils.MatrixFromString(ctRaw[3])
	rowToAttrib := strings.Split(ctRaw[4], " ")
	c0Raw, err := base64.StdEncoding.DecodeString(ctRaw[5])
	if err != nil {
		return nil, fmt.Errorf("cipher from raw error - 5: %v", err)
	}
	c0 := new(bn256.GT)
	_, err = c0.Unmarshal(c0Raw)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling: %v", err)
	}
	c1x := make(map[string]*bn256.GT)
	c2x := make(map[string]*bn256.G2)
	c3x := make(map[string]*bn256.G2)
	var tmpAt string
	for i, item := range ctRaw {
		if i < 6 {
			continue
		}
		switch (i - 6) % 4 {
		case 0:
			tmpAt = item
		case 1:
			c1Raw, err := base64.StdEncoding.DecodeString(item)
			if err != nil {
				return nil, fmt.Errorf("cipher from raw error - c1: %v", err)
			}
			c1 := new(bn256.GT)
			_, err = c1.Unmarshal(c1Raw)
			if err != nil {
				return nil, fmt.Errorf("error unmarshaling: %v", err)
			}
			c1x[tmpAt] = c1
		case 2:
			c2Raw, err := base64.StdEncoding.DecodeString(item)
			if err != nil {
				return nil, fmt.Errorf("cipher from raw error - c2: %v", err)
			}
			c2 := new(bn256.G2)
			_, err = c2.Unmarshal(c2Raw)
			if err != nil {
				return nil, fmt.Errorf("error unmarshaling: %v", err)
			}
			c2x[tmpAt] = c2
		case 3:
			c3Raw, err := base64.StdEncoding.DecodeString(item)
			if err != nil {
				return nil, fmt.Errorf("cipher from raw error - c3: %v", err)
			}
			c3 := new(bn256.G2)
			_, err = c3.Unmarshal(c3Raw)
			if err != nil {
				return nil, fmt.Errorf("error unmarshaling: %v", err)
			}
			c3x[tmpAt] = c3
		}
	}
	return &abe.MAABECipher{
		C0:  c0,
		C1x: c1x,
		C2x: c2x,
		C3x: c3x,
		Msp: &abe.MSP{
			// P:           p,
			Mat:         m,
			RowToAttrib: rowToAttrib,
		},
		SymEnc: symEnc,
		Iv:     iv,
	}, nil
}

func MaabeKeysToRaw(keys []*abe.MAABEKey) []string {
	// a maabe attribute key collection consists of tuples (gid, attrib, b64 marshalled key) in a list of strings
	s := make([]string, 3*len(keys))
	for i, mk := range keys {
		s[3*i+0] = mk.Gid
		s[3*i+1] = mk.Attrib
		s[3*i+2] = base64.StdEncoding.EncodeToString(mk.Key.Marshal())
	}
	return s
}

func MaabeKeysFromRaw(keysRaw []string) ([]*abe.MAABEKey, error) {
	if len(keysRaw)%3 != 0 {
		return []*abe.MAABEKey{}, fmt.Errorf("wrong key len")
	}
	keys := make([]*abe.MAABEKey, len(keysRaw)/3)
	var (
		gid    string
		attrib string
		key    *bn256.G1
	)
	for i, item := range keysRaw {
		switch i % 3 {
		case 0:
			gid = item
		case 1:
			attrib = item
		case 2:
			k, err := base64.StdEncoding.DecodeString(item)
			if err != nil {
				return []*abe.MAABEKey{}, fmt.Errorf("error with attrib keys: %v", err)
			}
			key = new(bn256.G1)
			_, err = key.Unmarshal(k)
			if err != nil {
				return []*abe.MAABEKey{}, fmt.Errorf("error unmarshaling: %v", err)
			}
			keys[(i-2)/3] = &abe.MAABEKey{
				Gid:    gid,
				Attrib: attrib,
				Key:    key,
			}
		}
	}
	return keys, nil
}

// (exported) functions - Go types

func Go_Ahe_maabe_NewMAABE() []string {
	maabe := abe.NewMAABE()
	return MaabeToRaw(maabe)
}

func Go_Ahe_maabe_NewMAABEAuth(maabeRaw []string, id string, attribs []string) ([]string, int) {
	maabe, err := MaabeFromRaw(maabeRaw)
	if err != nil {
		return []string{}, -1
	}
	maabeAuth, err := maabe.NewMAABEAuth(id, attribs)
	if err != nil {
		return []string{}, -1
	}
	maabeAuthRaw := MaabeAuthToRaw(maabeAuth)
	return maabeAuthRaw, 0
}

func Go_Ahe_maabe_MaabeAuthPubKeys(authRaw []string) ([]string, int) {
	if len(authRaw)%5 != 0 {
		return []string{}, -1
	}
	s := make([]string, ((len(authRaw)-5)/5)*3)
	j := 0
	for i, item := range authRaw {
		if i < 5 {
			continue
		}
		switch (i - 5) % 5 {
		case 0:
			s[j] = item
			j++
		case 1:
			s[j] = item
			j++
		case 2:
			s[j] = item
			j++
		}
	}
	return s, 0
}

func Go_Ahe_maabe_AddAttribute(authorityRaw []string, attrib string) ([]string, int) {
	auth, err := MaabeAuthFromRaw(authorityRaw)
	if err != nil {
		return authorityRaw, -1
	}
	err = auth.AddAttribute(attrib)
	if err != nil {
		return authorityRaw, -1
	}
	return MaabeAuthToRaw(auth), 0
}

func Go_Ahe_maabe_Encrypt(maabeRaw []string, msg string, booleanFormula string, pubkeys []string) ([]string, int) {
	pks, err := MaabePubFromRaw(pubkeys)
	if err != nil {
		return []string{}, -1
	}
	pksList := []*abe.MAABEPubKey{pks}
	msp, err := abe.BooleanToMSP(booleanFormula, false)
	if err != nil {
		return []string{}, -1
	}
	maabe, err := MaabeFromRaw(maabeRaw)
	if err != nil {
		return []string{}, -1
	}
	ciphertext, err := maabe.Encrypt(msg, msp, pksList)
	if err != nil {
		return []string{}, -1
	}
	return MaabeCipherToRaw(ciphertext), 0
}

func Go_Ahe_maabe_GenerateAttribKeys(maabeAuthRaw []string, gid string, attribs []string) ([]string, int) {
	maabeAuth, err := MaabeAuthFromRaw(maabeAuthRaw)
	if err != nil {
		return []string{}, -1
	}
	keys, err := maabeAuth.GenerateAttribKeys(gid, attribs)
	if err != nil {
		return []string{}, -1
	}
	return MaabeKeysToRaw(keys), 0
}

func Go_Ahe_maabe_Decrypt(maabeRaw []string, ctRaw []string, ksRaw []string) (string, int) {
	maabe, err := MaabeFromRaw(maabeRaw)
	if err != nil {
		return "", -1
	}
	ct, err := MaabeCipherFromRaw(ctRaw)
	if err != nil {
		return "", -1
	}
	ks, err := MaabeKeysFromRaw(ksRaw)
	if err != nil {
		return "", -1
	}
	pt, err := maabe.Decrypt(ct, ks)
	if err != nil {
		return err.Error(), -1
	}
	return pt, 0
}

// JSON functions

type MarshaledPubKey struct {
	Attribs    []string          `json:"attributes"`
	EggToAlpha map[string]string `json:"eggToAlpha"`
	GToY       map[string]string `json:"gToY"`
}

type PubKeyJSONContainer struct {
	Pk *MarshaledPubKey `json:"pubkey"`
}

func MarshalPubKey(pk *abe.MAABEPubKey) (*MarshaledPubKey, error) {
	if pk == nil {
		return nil, fmt.Errorf("the public key can not be empty")
	}
	a := make([]string, len(pk.Attribs))
	egg := make(map[string]string)
	g := make(map[string]string)
	pkStr := MaabePubToRaw(pk)
	var tmpAt string = ""
	for i, item := range pkStr {
		switch i % 3 {
		case 0:
			a[i/3] = item
			tmpAt = item
		case 1:
			egg[tmpAt] = item
		case 2:
			g[tmpAt] = item
		}
	}
	return &MarshaledPubKey{
		Attribs:    a,
		EggToAlpha: egg,
		GToY:       g,
	}, nil
}

func UnmarshalPubKey(mpk *MarshaledPubKey) (*abe.MAABEPubKey, error) {
	if mpk == nil {
		return nil, fmt.Errorf("public key can not be empty")
	}
	pkStr := make([]string, 3*len(mpk.Attribs))
	for i, at := range mpk.Attribs {
		pkStr[3*i+0] = at
		pkStr[3*i+1] = mpk.EggToAlpha[at]
		pkStr[3*i+2] = mpk.GToY[at]
	}
	pubkey, err := MaabePubFromRaw(pkStr)
	if err != nil {
		return nil, err
	}
	return pubkey, nil
}

func PublicKeyToJSON(pk *abe.MAABEPubKey) ([]byte, error) {
	mpk, err := MarshalPubKey(pk)
	if err != nil {
		return []byte{}, err
	}
	jsonDict := map[string]*MarshaledPubKey{"pubkey": mpk}
	jsonBytes, err := json.Marshal(jsonDict)
	if err != nil {
		return []byte{}, err
	}
	return jsonBytes, nil
}

func JSONToPublicKey(data []byte) (*abe.MAABEPubKey, error) {
	var pk PubKeyJSONContainer
	err := json.Unmarshal(data, &pk)
	if err != nil {
		return nil, err
	}
	pubkey, err := UnmarshalPubKey(pk.Pk)
	if err != nil {
		return nil, err
	}
	return pubkey, nil
}

type MarshaledAttribKey struct {
	Gid    string `json:"gid"`
	Attrib string `json:"attribute"`
	Key    string `json:"key"`
}

type AttribKeysJSONContainer struct {
	Keys []*MarshaledAttribKey `json:"keys"`
}

func MarshalKeys(ks []*abe.MAABEKey) ([]*MarshaledAttribKey, error) {
	if len(ks) == 0 {
		return []*MarshaledAttribKey{}, fmt.Errorf("the list of keys can not be empty")
	}
	mks := make([]*MarshaledAttribKey, len(ks))
	ksStr := MaabeKeysToRaw(ks)
	for i := 0; i < len(ks); i++ {
		mks[i] = &MarshaledAttribKey{
			Gid:    ksStr[3*i+0],
			Attrib: ksStr[3*i+1],
			Key:    ksStr[3*i+2],
		}
	}
	return mks, nil
}

func UnmarshalKeys(mks []*MarshaledAttribKey) ([]*abe.MAABEKey, error) {
	if len(mks) == 0 {
		return []*abe.MAABEKey{}, fmt.Errorf("the list of marshaled keys can not be empty")
	}
	ksStr := make([]string, 3*len(mks))
	for i, mk := range mks {
		ksStr[3*i+0] = mk.Gid
		ksStr[3*i+1] = mk.Attrib
		ksStr[3*i+2] = mk.Key
	}
	ks, err := MaabeKeysFromRaw(ksStr)
	if err != nil {
		return []*abe.MAABEKey{}, err
	}
	return ks, nil
}

func AttribKeysToJSON(ks []*abe.MAABEKey) ([]byte, error) {
	mks, err := MarshalKeys(ks)
	if err != nil {
		return []byte{}, err
	}
	jsonDict := map[string][]*MarshaledAttribKey{"keys": mks}
	jsonBytes, err := json.Marshal(jsonDict)
	if err != nil {
		return []byte{}, err
	}
	return jsonBytes, nil
}

func JSONToAttribKeys(data []byte) ([]*abe.MAABEKey, error) {
	var ks AttribKeysJSONContainer
	err := json.Unmarshal(data, &ks)
	if err != nil {
		return []*abe.MAABEKey{}, err
	}
	attribKeys, err := UnmarshalKeys(ks.Keys)
	if err != nil {
		return []*abe.MAABEKey{}, err
	}
	return attribKeys, nil
}

type MarshaledCipher struct {
	SymEnc         string            `json:"symEnc"`
	Iv             string            `json:"iv"`
	MSPP           string            `json:"msp-p"`
	MSPMat         string            `json:"msp-mat"`
	MSPRowToAttrib string            `json:"msp-rta"`
	C0             string            `json:"c0"`
	C1             map[string]string `json:"c1"`
	C2             map[string]string `json:"c2"`
	C3             map[string]string `json:"c3"`
}

type CipherJSONContainer struct {
	Cipher *MarshaledCipher `json:"cipher"`
}

func MarshalCipher(ct *abe.MAABECipher) (*MarshaledCipher, error) {
	if ct == nil {
		return nil, fmt.Errorf("the cipher can not be empty")
	}
	c1 := make(map[string]string)
	c2 := make(map[string]string)
	c3 := make(map[string]string)
	ctStr := MaabeCipherToRaw(ct)
	var tmpAt string = ""
	for i, item := range ctStr {
		if i < 6 {
			continue
		}
		switch (i - 6) % 4 {
		case 0:
			tmpAt = item
		case 1:
			c1[tmpAt] = item
		case 2:
			c2[tmpAt] = item
		case 3:
			c3[tmpAt] = item
		}
	}
	return &MarshaledCipher{
		SymEnc:         ctStr[0],
		Iv:             ctStr[1],
		MSPP:           ctStr[2],
		MSPMat:         ctStr[3],
		MSPRowToAttrib: ctStr[4],
		C0:             ctStr[5],
		C1:             c1,
		C2:             c2,
		C3:             c3,
	}, nil
}

func UnmarshalCipher(mct *MarshaledCipher) (*abe.MAABECipher, error) {
	if mct == nil {
		return nil, fmt.Errorf("the marshaled cipher should not be empty")
	}
	ctStr := make([]string, 6+4*len(mct.C1))
	ctStr[0] = mct.SymEnc
	ctStr[1] = mct.Iv
	ctStr[2] = mct.MSPP
	ctStr[3] = mct.MSPMat
	ctStr[4] = mct.MSPRowToAttrib
	ctStr[5] = mct.C0
	i := 6
	for at, c1 := range mct.C1 {
		ctStr[i+0] = at
		ctStr[i+1] = c1
		ctStr[i+2] = mct.C2[at]
		ctStr[i+3] = mct.C3[at]
		i = i + 4
	}
	ct, err := MaabeCipherFromRaw(ctStr)
	if err != nil {
		return nil, err
	}
	return ct, nil
}

func CipherToJSON(ct *abe.MAABECipher) ([]byte, error) {
	mct, err := MarshalCipher(ct)
	if err != nil {
		return []byte{}, err
	}
	jsonDict := map[string]*MarshaledCipher{"cipher": mct}
	jsonBytes, err := json.Marshal(jsonDict)
	if err != nil {
		return []byte{}, err
	}
	return jsonBytes, nil
}

func JSONToCipher(data []byte) (*abe.MAABECipher, error) {
	var ct CipherJSONContainer
	err := json.Unmarshal(data, &ct)
	if err != nil {
		return nil, err
	}
	cipher, err := UnmarshalCipher(ct.Cipher)
	if err != nil {
		return nil, err
	}
	return cipher, nil
}

// exported JSON functions

func Go_Ahe_maabe_PubKeyToJSON(pkStr []string) ([]byte, int) {
	pk, err := MaabePubFromRaw(pkStr)
	if err != nil {
		return []byte{}, -1
	}
	pkJSON, err := PublicKeyToJSON(pk)
	if err != nil {
		return []byte{}, -1
	}
	return pkJSON, 0
}

func Go_Ahe_maabe_PubKeyFromJSON(data []byte) ([]string, int) {
	pk, err := JSONToPublicKey(data)
	if err != nil {
		return []string{}, -1
	}
	pkStr := MaabePubToRaw(pk)
	return pkStr, 0
}

func Go_Ahe_maabe_AttribKeysToJSON(ksStr []string) ([]byte, int) {
	ks, err := MaabeKeysFromRaw(ksStr)
	if err != nil {
		return []byte{}, -1
	}
	ksJSON, err := AttribKeysToJSON(ks)
	if err != nil {
		return []byte{}, -1
	}
	return ksJSON, 0
}

func Go_Ahe_maabe_AttribKeysFromJSON(data []byte) ([]string, int) {
	ks, err := JSONToAttribKeys(data)
	if err != nil {
		return []string{}, -1
	}
	ksStr := MaabeKeysToRaw(ks)
	return ksStr, 0
}

func Go_Ahe_maabe_CipherToJSON(ctStr []string) ([]byte, int) {
	ct, err := MaabeCipherFromRaw(ctStr)
	if err != nil {
		return []byte{}, -1
	}
	ctJSON, err := CipherToJSON(ct)
	if err != nil {
		return []byte{}, -1
	}
	return ctJSON, 0
}

func Go_Ahe_maabe_CipherFromJSON(data []byte) ([]string, int) {
	ct, err := JSONToCipher(data)
	if err != nil {
		return []string{}, -1
	}
	ctStr := MaabeCipherToRaw(ct)
	return ctStr, 0
}
