package fame

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

func FameFromRaw(maabeRaw string) (*abe.FAME, error) {
	p := new(big.Int)
	p, ok := p.SetString(maabeRaw, 10)
	if !ok {
		return nil, fmt.Errorf("could not set p")
	}
	return &abe.FAME{
		P: p,
	}, nil
}

func FameToRaw(maabe *abe.FAME) string {
	s := maabe.P.String()
	return s
}

func FameSecFromRaw(fameSecRaw string) (*abe.FAMESecKey, error) {
	var secKey abe.FAMESecKey
	byteSecKey, err := base64.StdEncoding.DecodeString(fameSecRaw)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(byteSecKey, &secKey)
	if err != nil {
		return nil, err
	}

	return &secKey, nil
}

func FameSecToRaw(fameSec *abe.FAMESecKey) (string, error) {
	bytes, err := json.Marshal(fameSec)
	str := base64.StdEncoding.EncodeToString(bytes)

	return str, err
}

func FamePubFromRaw(famePubRaw string) (*abe.FAMEPubKey, error) {
	var secKey abe.FAMEPubKey
	byteSecKey, err := base64.StdEncoding.DecodeString(famePubRaw)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(byteSecKey, &secKey)
	if err != nil {
		return nil, err
	}

	return &secKey, nil
}

func FamePubToRaw(famePub *abe.FAMEPubKey) (string, error) {
	bytes, err := json.Marshal(famePub)
	str := base64.StdEncoding.EncodeToString(bytes)

	return str, err
}

func FameCipherToRaw(ct *abe.FAMECipher) ([]string, error) {
	var err error
	ctRaw := make([]string, 7+len(ct.Ct))
	ctRaw[0] = base64.StdEncoding.EncodeToString(ct.SymEnc)
	ctRaw[1] = base64.StdEncoding.EncodeToString(ct.Iv)
	// ctRaw[2] = ct.Msp.P.String()
	ctRaw[2] = "0"
	ctRaw[3] = utils.MatrixToString(ct.Msp.Mat)
	ctRaw[4] = strings.Join(ct.Msp.RowToAttrib, " ")
	ct5Bytes, err := json.Marshal(ct.Ct0)
	if err != nil {
		return nil, err
	}
	ctRaw[5] = base64.StdEncoding.EncodeToString(ct5Bytes)
	ctRaw[6] = base64.StdEncoding.EncodeToString(ct.CtPrime.Marshal())
	index := 7
	var ciBytes []byte
	for i, ci := range ct.Ct {
		ciBytes, err = json.Marshal(ci)
		if err != nil {
			return nil, err
		}
		ctRaw[index+i] = base64.StdEncoding.EncodeToString(ciBytes)
	}
	return ctRaw, nil
}

func FameCipherFromRaw(ctRaw []string) (*abe.FAMECipher, error) {
	if len(ctRaw) <= 7 {
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
	var ct0 [3]*bn256.G2
	ctRaw5, err := base64.StdEncoding.DecodeString(ctRaw[5])
	if err != nil {
		return nil, fmt.Errorf("cipher from raw error - 2: %v", err)
	}
	err = json.Unmarshal(ctRaw5, &ct0)
	if err != nil {
		return nil, err
	}
	ctPrime := new(bn256.GT)
	ctPrimeBytes, err := base64.StdEncoding.DecodeString(ctRaw[6])
	if err != nil {
		return nil, err
	}
	_, err = ctPrime.Unmarshal(ctPrimeBytes)
	if err != nil {
		return nil, err
	}

	ct := make([][3]*bn256.G1, len(ctRaw)-7)
	for i := 7; i < len(ctRaw); i++ {
		var cti [3]*bn256.G1
		ctRawi, err := base64.StdEncoding.DecodeString(ctRaw[i])
		if err != nil {
			return nil, fmt.Errorf("cipher from raw error - 3: %v", err)
		}
		err = json.Unmarshal(ctRawi, &cti)
		if err != nil {
			return nil, err
		}

		ct[i-7] = cti
	}

	return &abe.FAMECipher{
		Ct0:     ct0,
		Ct:      ct,
		CtPrime: ctPrime,
		Msp: &abe.MSP{
			// P:           p,
			Mat:         m,
			RowToAttrib: rowToAttrib,
		},
		SymEnc: symEnc,
		Iv:     iv,
	}, nil
}

func FameKeysToRaw(keys *abe.FAMEAttribKeys) ([]string, error) {
	var err error
	keyRaw := make([]string, 3+len(keys.K))

	k0Bytes, err := json.Marshal(keys.K0)
	if err != nil {
		return nil, err
	}
	keyRaw[0] = base64.StdEncoding.EncodeToString(k0Bytes)

	kPrimeBytes, err := json.Marshal(keys.KPrime)
	if err != nil {
		return nil, err
	}
	keyRaw[1] = base64.StdEncoding.EncodeToString(kPrimeBytes)
	attribs := make([]string, len(keys.AttribToI))
	for e, i := range keys.AttribToI {
		attribs[i] = e
	}

	keyRaw[2] = strings.Join(attribs, " ")
	index := 3
	var kiBytes []byte
	for i, ki := range keys.K {
		kiBytes, err = json.Marshal(ki)
		if err != nil {
			return nil, err
		}
		keyRaw[index+i] = base64.StdEncoding.EncodeToString(kiBytes)
	}
	return keyRaw, nil
}

func FameKeysFromRaw(keysRaw []string) (*abe.FAMEAttribKeys, error) {
	if len(keysRaw) <= 3 {
		return nil, fmt.Errorf("keys not correct len")
	}

	var k0 [3]*bn256.G2
	kRaw0, err := base64.StdEncoding.DecodeString(keysRaw[0])
	if err != nil {
		return nil, fmt.Errorf("keys from raw error - 1: %v", err)
	}
	err = json.Unmarshal(kRaw0, &k0)
	if err != nil {
		return nil, err
	}

	var kPrime [3]*bn256.G1
	kRawPrime, err := base64.StdEncoding.DecodeString(keysRaw[1])
	if err != nil {
		return nil, fmt.Errorf("keys from raw error - 2: %v", err)
	}
	err = json.Unmarshal(kRawPrime, &kPrime)
	if err != nil {
		return nil, err
	}

	rowToAttrib := strings.Split(keysRaw[2], " ")
	attribToI := make(map[string]int)
	for i, e := range rowToAttrib {
		attribToI[e] = i
	}

	k := make([][3]*bn256.G1, len(keysRaw)-3)
	for i := 3; i < len(keysRaw); i++ {
		var ki [3]*bn256.G1
		kRawi, err := base64.StdEncoding.DecodeString(keysRaw[i])
		if err != nil {
			return nil, fmt.Errorf("keys from raw error - 3: %v", err)
		}
		err = json.Unmarshal(kRawi, &ki)
		if err != nil {
			return nil, err
		}

		k[i-3] = ki
	}

	return &abe.FAMEAttribKeys{
		K0:        k0,
		KPrime:    kPrime,
		K:         k,
		AttribToI: attribToI,
	}, nil
}

func Go_Ahe_fame_NewFAME() string {
	maabe := abe.NewFAME()
	return FameToRaw(maabe)
}

func Go_Ahe_fame_GenerateMasterKeys(fameRaw string) (string, string, int) {
	fame, err := FameFromRaw(fameRaw)
	if err != nil {
		return "", "", -1
	}
	pubKey, secKey, err := fame.GenerateMasterKeys()
	if err != nil {
		return "", "", -1
	}
	secRaw, err := FameSecToRaw(secKey)
	if err != nil {
		return "", "", -1
	}
	pubRaw, err := FamePubToRaw(pubKey)
	if err != nil {
		return "", "", -1
	}

	return pubRaw, secRaw, 0
}

func Go_Ahe_fame_Encrypt(fameRaw string, msg string, booleanFormula string, pubkey string) ([]string, int) {
	pks, err := FamePubFromRaw(pubkey)
	if err != nil {
		return []string{}, -1
	}
	msp, err := abe.BooleanToMSP(booleanFormula, false)
	if err != nil {
		return []string{}, -2
	}
	fame, err := FameFromRaw(fameRaw)
	if err != nil {
		return []string{}, -3
	}
	ciphertext, err := fame.Encrypt(msg, msp, pks)
	if err != nil {
		return []string{}, -4
	}
	ret, err := FameCipherToRaw(ciphertext)
	if err != nil {
		return []string{}, -5
	}

	return ret, 0
}

func Go_Ahe_fame_GenerateAttribKeys(fameRaw string, attribs []string, skRaw string) ([]string, int) {
	fame, err := FameFromRaw(fameRaw)
	if err != nil {
		return []string{}, -1
	}
	sk, err := FameSecFromRaw(skRaw)
	if err != nil {
		return []string{}, -2
	}

	keys, err := fame.GenerateAttribKeys(attribs, sk)
	if err != nil {
		return []string{}, -3
	}
	attribKey, err := FameKeysToRaw(keys)
	if err != nil {
		return []string{}, -4
	}

	return attribKey, 0
}

func Go_Ahe_fame_Decrypt(fameRaw string, ctRaw []string, ksRaw []string, pkRaw string) (string, int) {
	fame, err := FameFromRaw(fameRaw)
	if err != nil {
		return "", -1
	}
	ct, err := FameCipherFromRaw(ctRaw)
	if err != nil {
		return "", -2
	}
	ks, err := FameKeysFromRaw(ksRaw)
	if err != nil {
		fmt.Println(err)
		return "", -3
	}
	pk, err := FamePubFromRaw(pkRaw)
	if err != nil {
		return "", -4
	}

	pt, err := fame.Decrypt(ct, ks, pk)
	if err != nil {
		return "", -5
	}

	return pt, 0
}
