//go:build js && wasm
// +build js,wasm

package main

import (
	"syscall/js"

	"he_wasm/fame"
	"he_wasm/signatures"
)

func registerCallback() {
	js.Global().Set("AheGenerateMasterKeys", js.FuncOf(fame.Go_Ahe_fame_GenerateMasterKeys))
	js.Global().Set("AheGenerateAttribKeys", js.FuncOf(fame.Go_Ahe_fame_GenerateAttribKeys))
	js.Global().Set("AheEncrypt", js.FuncOf(fame.Go_Ahe_fame_Encrypt))
	js.Global().Set("AheDecrypt", js.FuncOf(fame.Go_Ahe_fame_Decrypt))
	js.Global().Set("AheDecrytAttribKeys", js.FuncOf(fame.Go_Ahe_fame_DecrytAttribKeys))
	js.Global().Set("AheJoinDecAttribKeys", js.FuncOf(fame.Go_Ahe_fame_JoinDecAttribKeys))
	js.Global().Set("AheGenerateSignKeys", js.FuncOf(signatures.Go_Ahe_GenerateSignKeys))
	js.Global().Set("AheSignCiphers", js.FuncOf(signatures.Go_Ahe_SignCiphers))
	js.Global().Set("AheVerifyCiphers", js.FuncOf(signatures.Go_Ahe_VerifyCiphers))
}
func main() {
	c := make(chan struct{}, 0)
	// register functions
	registerCallback()
	println("WASM Go Initialized")
	<-c
}
