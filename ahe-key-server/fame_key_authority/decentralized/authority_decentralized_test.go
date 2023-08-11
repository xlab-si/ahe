package decentralized

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/fentec-project/gofe/abe"
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/ahe/ahe-key-server/fame_key_authority/decentralized/protocol"
	fame2 "github.com/xlab-si/ahe/ahe-library/cgo/fame"
	"github.com/xlab-si/ahe/ahe-library/cgo/fame/decentralized"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRunFAMEDecAuthority(t *testing.T) {
	n := 3
	numRepeats := 20
	addressesInternal := make([]string, n)
	addressesExternal := make([]string, n)
	names := make([]string, n)
	portExternal := make([]int, n)
	for i := 0; i < n; i++ {
		addressesInternal[i] = "localhost:" + strconv.Itoa(6700+i)
		addressesExternal[i] = "localhost:" + strconv.Itoa(6600+i)
		names[i] = "node" + strconv.Itoa(i)
		portExternal[i] = 6600 + i
	}

	InitGlobalValues(n, 1000)
	for i := 0; i < n; i++ {
		go RunFAMEDecAuthority("load", i, n, addressesInternal, names, portExternal[i],
			"certs/node"+strconv.Itoa(i)+".crt", "certs/node"+strconv.Itoa(i)+".key",
			"certs/HEkeyCA.crt", "saved_data/test_node"+strconv.Itoa(i)+".txt")
	}
	time.Sleep(10 * time.Second)

	decPubKey := make([]*protocol.FAMEDecPubKey, n)
	pubKeys := make([]*abe.FAMEPubKey, n)
	for i := 0; i < n; i++ {
		decPubKey[i] = reqDecPubKey(t, addressesExternal[i])
	}
	pubKey, err := protocol.JoinDecPubKeys(decPubKey)
	if err != nil {
		t.Fatalf("Failed join of public keys: %v", err)
	}

	for i := 0; i < n; i++ {
		pubKeys[i] = reqPubKey(t, addressesExternal[i])
		assert.Equal(t, pubKey, pubKeys[i])
	}

	attrib := []string{"super_hero", "batman"}
	outChan := make([]chan bool, numRepeats)
	randKeys := make([]string, n)
	for i := n - 1; i >= 0; i-- {
		randBytes := make([]byte, 32)
		_, err = rand.Read(randBytes)
		if err != nil {
			t.Fatalf("Failed generating randomness: %v", err)
		}
		randKeys[i] = hex.EncodeToString(randBytes)

	}

	for repeat := 0; repeat < numRepeats; repeat++ {
		outChan[repeat] = make(chan bool)
		go goRoutineReqAttrib(t, addressesExternal, attrib, randKeys, "machine"+strconv.Itoa(repeat),
			n, pubKey, outChan[repeat])
		//time.Sleep(1000 * time.Millisecond)
	}

	for repeat := 0; repeat < numRepeats; repeat++ {
		ok := <-outChan[repeat]
		assert.Equal(t, true, ok)
	}

}

func goRoutineReqAttrib(t *testing.T, addressesExternal []string, attrib []string, randKeys []string, uuid string,
	n int, pubKey *abe.FAMEPubKey, ok chan bool) {
	var encKeys string

	for i := n - 1; i >= 0; i-- {
		resp := reqAttrib(t, addressesExternal[i], attrib, randKeys[i], uuid)
		if i == 0 {
			encKeys = resp
		} else {
			assert.Equal(t, "ok", resp)
		}
	}

	keysStings, err := decentralized.DecryptAttribKeys(encKeys, randKeys)
	if err != nil {
		t.Fatalf("Failed decrypting attribute keys: %v", err)
	}

	decAttribKey := make([]*protocol.FAMEDecAttribKeys, n)
	for i, e := range keysStings {
		decAttribKey[i], err = protocol.FameDecKeysFromRaw(strings.Split(e, "\n"))
		if err != nil {
			t.Fatalf("Failed unmarshalling attribute keys: %v", err)
		}
	}

	attribKey, err := protocol.JoinDecAttribKeys(decAttribKey)
	if err != nil {
		t.Fatalf("Failed to join attribue keys: %v", err)
	}
	fmt.Println("attribute key obtained for", uuid)

	a := abe.NewFAME()
	msg := "Attack at dawn!"
	msp, err := abe.BooleanToMSP("(super_hero AND batman) OR at6", false)
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
	ok <- true
}

func reqAttrib(t *testing.T, address string, attrib []string, randKey string, uuid string) string {
	caCert, err := ioutil.ReadFile("certs/HEkeyCA.crt")
	if err != nil {
		t.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	_ = caCertPool.AppendCertsFromPEM(caCert)
	trans := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}
	dialer := http.Client{Transport: trans, Timeout: 100 * time.Second}

	val := GetDecAttributeKeysForm{uuid, attrib, randKey}
	json_data, err := json.Marshal(val)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := dialer.Post("https://"+address+"/get-attribute-keys", "application/json", bytes.NewBuffer(json_data))
	if err != nil {
		t.Fatalf("Failed to get response: %s %v", uuid, err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	return string(body)
}

func reqDecPubKey(t *testing.T, address string) *protocol.FAMEDecPubKey {
	caCert, err := ioutil.ReadFile("certs/" + "/HEkeyCA.crt")
	if err != nil {
		t.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	_ = caCertPool.AppendCertsFromPEM(caCert)
	trans := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}
	dialer := http.Client{Transport: trans, Timeout: 15 * time.Second}

	resp, err := dialer.Get("https://" + address + "/decpubkey")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	pubKey, err := protocol.FameDecPubFromRaw(string(body))
	if err != nil {
		t.Fatal(err)
	}

	return pubKey
}

func reqPubKey(t *testing.T, address string) *abe.FAMEPubKey {
	caCert, err := ioutil.ReadFile("certs/" + "/HEkeyCA.crt")
	caCertPool := x509.NewCertPool()
	_ = caCertPool.AppendCertsFromPEM(caCert)
	trans := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}
	dialer := http.Client{Transport: trans, Timeout: 15 * time.Second}

	resp, err := dialer.Get("https://" + address + "/pubkeys")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	pubKey, err := fame2.FamePubFromRaw(string(body))
	if err != nil {
		t.Fatal(err)
	}

	return pubKey
}
