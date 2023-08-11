package fame

import (
	"ahe-key-server/fame_key_authority/decentralized/protocol"
	"cgo/fame"
	"cgo/fame/decentralized"
	"github.com/fentec-project/gofe/abe"
	"strings"
	"syscall/js"
)

func Go_Ahe_fame_GenerateMasterKeys(this js.Value, args []js.Value) interface{} {
	scheme := abe.NewFAME()
	pubKey, secKey, err := scheme.GenerateMasterKeys()
	if err != nil {
		return err.Error()
	}
	secRaw, err := fame.FameSecToRaw(secKey)
	if err != nil {
		return err.Error()
	}
	pubRaw, err := fame.FamePubToRaw(pubKey)
	if err != nil {
		return err.Error()
	}

	return []interface{}{pubRaw, secRaw}
}

func Go_Ahe_fame_Encrypt(this js.Value, args []js.Value) interface{} {
	scheme := abe.NewFAME()
	pks, err := fame.FamePubFromRaw(args[2].String())
	if err != nil {
		return err.Error()
	}
	msp, err := abe.BooleanToMSP(args[1].String(), false)
	if err != nil {
		return err.Error()
	}
	ciphertext, err := scheme.Encrypt(args[0].String(), msp, pks)
	if err != nil {
		return err.Error()
	}
	ret, err := fame.FameCipherToRaw(ciphertext)
	if err != nil {
		return err.Error()
	}

	retInterface := make([]interface{}, len(ret))
	for i, _ := range retInterface {
		retInterface[i] = interface{}(ret[i])
	}

	return retInterface
}

func Go_Ahe_fame_GenerateAttribKeys(this js.Value, args []js.Value) interface{} {
	scheme := abe.NewFAME()

	sk, err := fame.FameSecFromRaw(args[0].String())
	if err != nil {
		return err.Error()
	}

	attribs := make([]string, args[1].Length())
	for i, _ := range attribs {
		attribs[i] = args[1].Index(i).String()
	}

	keys, err := scheme.GenerateAttribKeys(attribs, sk)
	if err != nil {
		return err.Error()
	}
	ret, err := fame.FameKeysToRaw(keys)
	if err != nil {
		return err.Error()
	}

	retInterface := make([]interface{}, len(ret))
	for i, _ := range retInterface {
		retInterface[i] = interface{}(ret[i])
	}

	return retInterface
}

func Go_Ahe_fame_Decrypt(this js.Value, args []js.Value) interface{} {
	scheme := abe.NewFAME()
	ctRaw := make([]string, args[0].Length())
	for i, _ := range ctRaw {
		ctRaw[i] = args[0].Index(i).String()
	}
	ct, err := fame.FameCipherFromRaw(ctRaw)
	if err != nil {
		return err.Error()
	}

	ksRaw := make([]string, args[1].Length())
	for i, _ := range ksRaw {
		ksRaw[i] = args[1].Index(i).String()
	}
	ks, err := fame.FameKeysFromRaw(ksRaw)
	if err != nil {
		return err.Error()
	}

	pk, err := fame.FamePubFromRaw(args[2].String())
	if err != nil {
		return err.Error()
	}

	pt, err := scheme.Decrypt(ct, ks, pk)
	if err != nil {
		return err.Error()
	}

	return pt
}

func Go_Ahe_fame_DecrytAttribKeys(this js.Value, args []js.Value) interface{} {
	enc := args[0].String()

	keys := make([]string, args[1].Length())
	for i, _ := range keys {
		keys[i] = args[1].Index(i).String()
	}

	//fmt.Println(enc, keys)

	attribKeyString, err := decentralized.DecryptAttribKeys(enc, keys)
	//fmt.Println(attribKeyString, err)

	//attribKeyString, err := decentralized.Go_Ahe_fame_DecryptAttribKeys(enc, keys)

	if err != nil {
		return err.Error()
	}

	retInterface := make([]interface{}, len(attribKeyString))
	for i, _ := range retInterface {
		retInterface[i] = interface{}(attribKeyString[i])
	}

	return retInterface
}

func Go_Ahe_fame_JoinDecAttribKeys(this js.Value, args []js.Value) interface{} {
	keys := make([]string, args[0].Length())
	for i, _ := range keys {
		keys[i] = args[0].Index(i).String()
	}

	var err error
	decAttribKey := make([]*protocol.FAMEDecAttribKeys, len(keys))
	for i, e := range keys {
		attribKeySlice := strings.Split(e, "\n")
		decAttribKey[i], err = protocol.FameDecKeysFromRaw(attribKeySlice)
		if err != nil {
			return err.Error()
		}
	}

	key, err := protocol.JoinDecAttribKeys(decAttribKey)
	if err != nil {
		return err.Error()
	}
	attribKey, err := fame.FameKeysToRaw(key)
	if err != nil {
		return err.Error()
	}

	retInterface := make([]interface{}, len(attribKey))
	for i, _ := range retInterface {
		retInterface[i] = interface{}(attribKey[i])
	}

	return retInterface
}
