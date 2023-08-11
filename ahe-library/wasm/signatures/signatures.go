package signatures

import (
	"github.com/xlab-si/ahe/ahe-library/cgo/signatures"
	"syscall/js"
)

func Go_Ahe_GenerateSignKeys(this js.Value, args []js.Value) interface{} {
	pk, sk, err := signatures.GenerateSignKeys()
	if err != 0 {
		return nil
	}

	retInterface := make([]interface{}, 2)
	retInterface[0] = interface{}(pk)
	retInterface[1] = interface{}(sk)

	return retInterface
}

func Go_Ahe_SignCiphers(this js.Value, args []js.Value) interface{} {
	sk := args[0].String()
	ctsRaw := make([]string, args[1].Length())
	for i, _ := range ctsRaw {
		ctsRaw[i] = args[1].Index(i).String()
	}
	proof := args[2].String()

	ctsSigned, err := signatures.SignCiphers(sk, proof, ctsRaw, nil)
	if err != 0 {
		return nil
	}

	return ctsSigned
}

func Go_Ahe_VerifyCiphers(this js.Value, args []js.Value) interface{} {
	cts := args[0].String()
	uuid := args[1].String()
	ca := args[2].String()

	check, err := signatures.VerifyCiphers(cts, uuid, ca)
	if err != 0 {
		return false
	}

	return check
}
