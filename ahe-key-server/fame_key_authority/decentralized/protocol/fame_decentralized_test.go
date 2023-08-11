package protocol

import (
	"fmt"
	"github.com/fentec-project/gofe/abe"
	"github.com/stretchr/testify/assert"
	"strconv"
	"testing"
	"time"
)

func TestFame(t *testing.T) {
	numAuth := 3
	InitProtocolValues(numAuth, 100)

	addresses := []string{}
	names := []string{}
	for i := 0; i < numAuth; i++ {
		addresses = append(addresses, "localhost:"+strconv.Itoa(6800+i))
		names = append(names, "node"+strconv.Itoa(i))
	}
	for i := numAuth - 1; i >= 0; i-- {
		myCrt, caPool := LoadCerts("../certs/node"+strconv.Itoa(i)+".crt", "../certs/node"+strconv.Itoa(i)+".key", "../certs/HEkeyCA.crt")
		go InitConnections(i, addresses, names, myCrt, caPool)
	}
	WaitConnections(Connections)
	WaitConnections(ConnectionsOffline)
	fmt.Println("connections created")

	for i := 0; i < numAuth; i++ {
		go Offline(t, i, numAuth)
	}
	time.Sleep(2 * time.Second)

	fmt.Println("offline phase finished")

	decPubKeyChan := make([]chan *FAMEDecPubKey, numAuth)
	decSecKeyChan := make([]chan *FAMEDecSecKey, numAuth)
	pubKeyChan := make([]chan *abe.FAMEPubKey, numAuth)
	for i := 0; i < numAuth; i++ {
		decPubKeyChan[i] = make(chan *FAMEDecPubKey, 1)
		decSecKeyChan[i] = make(chan *FAMEDecSecKey, 1)
		pubKeyChan[i] = make(chan *abe.FAMEPubKey, 1)

		go GenerateDecMasterKeys(i, decPubKeyChan[i], pubKeyChan[i], decSecKeyChan[i])
	}

	decPubKey := make([]*FAMEDecPubKey, numAuth)
	decSecKey := make([]*FAMEDecSecKey, numAuth)
	pubKeys := make([]*abe.FAMEPubKey, numAuth)
	for i := 0; i < numAuth; i++ {
		decPubKey[i] = <-decPubKeyChan[i]
		decSecKey[i] = <-decSecKeyChan[i]
		pubKeys[i] = <-pubKeyChan[i]
	}

	fmt.Println("public and private key generated")
	//fmt.Println(FameDecPubToRaw(decPubKey[0]))
	//fmt.Println(FameDecPubToRaw(decPubKey[1]))

	pubKey, err := JoinDecPubKeys(decPubKey)
	if err != nil {
		t.Fatalf("Failed join of public keys: %v", err)
	}
	//secKey := JoinDecSecKeys(decSecKey)
	//fmt.Println("public key", pubKey)
	//fmt.Println("sec key", secKey)

	attribs := []string{"at1", "at2", "at3", "at4", "at5"}
	decAttribKeyChan := make([]chan *FAMEDecAttribKeys, numAuth)
	for i := 0; i < numAuth; i++ {
		decAttribKeyChan[i] = make(chan *FAMEDecAttribKeys)
		go GenerateDecAttribKeys(attribs, DecSecKey[i], i, decAttribKeyChan[i])
	}

	decAttribKey := make([]*FAMEDecAttribKeys, numAuth)
	for i := 0; i < numAuth; i++ {
		decAttribKey[i] = <-decAttribKeyChan[i]
	}

	attribKey, err := JoinDecAttribKeys(decAttribKey)
	if err != nil {
		t.Fatalf("Failed to join attribue keys: %v", err)
	}
	fmt.Println("attribute key obtained")
	//fmt.Println("attribute key", attribKey)

	// now test if the obtained keys are working
	a := abe.NewFAME()
	msg := "Attack at dawn!"
	msp, err := abe.BooleanToMSP("(at5 AND at2) OR at6", false)
	//msp, err := abe.BooleanToMSP("(at1 AND at2) OR at4", false)
	if err != nil {
		t.Fatalf("Failed to generate the policy: %v", err)
	}

	cipher, err := a.Encrypt(msg, msp, pubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// decrypt the ciphertext with the keys of an entity
	// that has sufficient attributes
	msgCheck, err := a.Decrypt(cipher, attribKey, pubKey)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	assert.Equal(t, msg, msgCheck)

	// test to Raw
	pk0Raw, err := FameDecPubToRaw(decPubKey[0])
	if err != nil {
		t.Fatalf("Marshalling fail: %v", err)
	}
	pk0, err := FameDecPubFromRaw(pk0Raw)
	if err != nil {
		t.Fatalf("Marshalling fail: %v", err)
	}
	assert.Equal(t, pk0, decPubKey[0])

	key0Raw, err := FameDecKeysToRaw(decAttribKey[0])
	if err != nil {
		t.Fatalf("Marshalling fail: %v", err)
	}
	key0, err := FameDecKeysFromRaw(key0Raw)
	if err != nil {
		t.Fatalf("Marshalling fail: %v", err)
	}
	assert.Equal(t, decAttribKey[0], key0)
}

func Offline(t *testing.T, myI, n int) {
	err := GenLambda(myI, n, n/2, nil)
	if err != nil {
		t.Fatalf("Error generating lambda %d: %v", myI, err)
	}

	TriplesChan[myI] = make(chan *Triple, BackupNum)
	RandChan[myI] = make(chan *Share, BackupNum)
	for i := 0; i < BackupNum; i++ {
		triple, err := GenerateTriple(myI, n, n/2)
		if err != nil {
			t.Fatalf("Error generating triples %d: %v", myI, err)
		}
		TriplesChan[myI] <- triple

		r, err := GenerateRandShare(myI, n, n/2)
		if err != nil {
			t.Fatalf("Error generating shares %d: %v", myI, err)
		}
		RandChan[myI] <- r
	}
}
