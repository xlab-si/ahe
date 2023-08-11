package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/fentec-project/gofe/abe"
	"github.com/xlab-si/ahe/ahe-key-server/fame_key_authority/decentralized/protocol"
	fame2 "github.com/xlab-si/ahe/ahe-library/cgo/fame"
	"github.com/xlab-si/ahe/ahe-library/cgo/fame/decentralized"
	"github.com/xlab-si/ahe/ahe-library/cgo/signatures"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var walletDir = "wallets/"
var certFile = "../cert/HEkeyCA.crt"

// variable for centralized setting
var keyManagementAddress = "https://localhost:6902"

// variable for decentralized setting
var keyManagementAddresses = []string{"https://localhost:6800", "https://localhost:6801", "https://localhost:6802"}

func main() {
	uuid := "GoMachine123"
	keyManagementSystem := os.Getenv("KEY_MANAGEMENT")
	// obtain the public key from the key management system
	var pk *abe.FAMEPubKey
	switch keyManagementSystem {
	case "centralized":
		err := savePubToWallet(keyManagementAddress, walletDir+"/wallet.pub")
		if err != nil {
			log.Fatal(err)
		}
		pk, err = readPubKey(walletDir + "/wallet.pub")
		if err != nil {
			log.Fatal(err)
		}
	case "decentralized":
		err := saveDecPubToWallet(keyManagementAddresses, walletDir+"/wallet.pub")
		if err != nil {
			log.Fatal(err)
		}
		pk, err = readPubKey(walletDir + "/wallet.pub")
		if err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Printf("Please specify SCHEME environment")
		return
	}
	fmt.Println("Public key obtained from a", keyManagementSystem, "key management system.")

	// get private keys from the key authorities
	attribs := []string{uuid, "super_admin"}
	var key *abe.FAMEAttribKeys
	switch keyManagementSystem {
	case "centralized":
		err := saveSecToWallet(keyManagementAddress, walletDir+"/wallet-"+uuid+".sec", uuid, attribs)
		if err != nil {
			log.Fatal(err)
		}
		key, err = readKey(walletDir + "/wallet-" + uuid + ".sec")
		if err != nil {
			log.Fatal(err)
		}
	case "decentralized":
		err := saveDecSecToWallet(keyManagementAddresses, walletDir+"/wallet-"+uuid+".sec", uuid, attribs)
		if err != nil {
			log.Fatal(err)
		}
		key, err = readKey(walletDir + "/wallet-" + uuid + ".sec")
		if err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Printf("Please specify SCHEME environment")
		return
	}

	fmt.Println("Private key obtained from a", keyManagementSystem,
		"key management system for attributes:", attribs)

	// initiate the encryption scheme and use it to encrypt data with a policy
	fame := abe.NewFAME()
	msg := "message1"
	policyString := "(doctor AND oncology) OR super_admin"
	policy, err := abe.BooleanToMSP(policyString, false)
	if err != nil {
		log.Fatal(err)
	}
	enc, err := fame.Encrypt(msg, policy, pk)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Message", msg, "encrypted with policy", policyString)

	// convert it to a string that can be sent or saved
	encStringSlice, err := fame2.FameCipherToRaw(enc)
	if err != nil {
		log.Fatal(err)
	}
	encString := strings.Join(encStringSlice, ",")

	// if you wish to sign the ciphertext, you can use the following functionality
	verKey, signKey, errCode := signatures.GenerateSignKeys()
	if errCode != 0 {
		log.Fatal(errCode)
	}

	// register the signature public key at the key management and get
	// a proof of it
	proof, err := sigToKeyManagement(keyManagementAddress, uuid, verKey)
	if err != nil {
		log.Fatal(err)
	}

	// note that you can sign multiple ciphertext at once
	// attaching the proof variable assures that the signature we provide
	// correspond to a public key that was verified by the key management
	encSigned, errCode := signatures.SignCiphers(signKey, proof, []string{encString}, []string{"cipher1"})
	if errCode != 0 {
		log.Fatal(errCode)
	}
	// encString and encSigned are both strings that can be sent or saved
	// in the case of the signed ciphertext

	// check the signatures and that the origin corresponds to uuid (whose public key was verified by CA)
	ca, err := ioutil.ReadFile(certFile)
	if err != nil {
		log.Fatal(err)
	}
	check, errCode := signatures.VerifyCiphers(encSigned, uuid, string(ca))
	if errCode != 0 {
		log.Fatal(errCode)
	}
	if check == false {
		log.Fatal(check)
	}
	ciphersMap := map[string]interface{}{}
	err = json.Unmarshal([]byte(encSigned), &ciphersMap)
	if err != nil {
		log.Fatal(err)
	}
	// make a ciphertext struct from string
	enc2, err := fame2.FameCipherFromRaw(strings.Split(ciphersMap["cipher1"].(string), ","))
	if err != nil {
		log.Fatal(err)
	}
	// the return of the above function should be the same as
	//enc2, err := fame2.FameCipherFromRaw(strings.Split(encString, ","))
	// which can be used if the ciphertext is not signed

	// having the proper attribute keys one can decrypt the message
	dec, err := fame.Decrypt(enc2, key, pk)
	if err != nil {
		log.Fatal(err)
	}

	// check of correctness
	if msg != dec {
		log.Fatal("Decryption does not equal message.")
	}

	fmt.Println("Message successfully decrypted.")
}

func savePubToWallet(keyManagementAddress string, wallet string) error {
	caCert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return err
	}

	caCertPool := x509.NewCertPool()
	_ = caCertPool.AppendCertsFromPEM(caCert)
	trans := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}
	dialer := http.Client{Transport: trans, Timeout: 15 * time.Second}
	resp, err := dialer.Get(keyManagementAddress + "/pubkeys")
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	err = os.WriteFile(wallet, body, 0644)
	if err != nil {
		return err
	}

	return nil
}

func saveDecPubToWallet(keyManagementAddresses []string, wallet string) error {
	var pubKeyBytes string
	caCert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return err
	}

	caCertPool := x509.NewCertPool()
	_ = caCertPool.AppendCertsFromPEM(caCert)
	trans := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}
	dialer := http.Client{Transport: trans, Timeout: 15 * time.Second}

	for i, address := range keyManagementAddresses {
		resp, err := dialer.Get(address + "/pubkeys")
		if err != nil {
			return err
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if i == 0 {
			err = os.WriteFile(wallet, body, 0644)
			if err != nil {
				return err
			}
			pubKeyBytes = string(body)
		} else {
			if string(body) != pubKeyBytes {
				if err != nil {
					log.Fatal("decentralized nodes returning different keys")
				}
			}
		}

	}

	return nil
}

func readPubKey(wallet string) (*abe.FAMEPubKey, error) {
	dat, err := os.ReadFile(wallet)
	if err != nil {
		return nil, err
	}
	pk, err := fame2.FamePubFromRaw(string(dat))

	return pk, err
}

type GetAttributeKeysForm struct {
	Uuid    string   `json:"uuid"`
	Attribs []string `json:"attributes"`
}

func saveSecToWallet(keyManagementAddress string, wallet string, uuid string, attribs []string) error {
	form := GetAttributeKeysForm{Uuid: uuid, Attribs: attribs}
	jsonForm, err := json.Marshal(form)
	if err != nil {
		return err
	}

	caCert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return err
	}

	caCertPool := x509.NewCertPool()
	_ = caCertPool.AppendCertsFromPEM(caCert)
	trans := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}
	dialer := http.Client{Transport: trans, Timeout: 15 * time.Second}
	resp, err := dialer.Post(keyManagementAddress+"/get-attribute-keys", "application/json",
		bytes.NewBuffer(jsonForm))
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	err = os.WriteFile(wallet, body, 0644)
	if err != nil {
		return err
	}

	return nil
}

type GetDecAttributeKeysForm struct {
	Uuid    string   `json:"uuid"`
	Attribs []string `json:"attributes"`
	SecKey  string   `json:"sec_key"`
}

func saveDecSecToWallet(keyManagementAddresses []string, wallet string, uuid string, attribs []string) error {
	randKeys := make([]string, len(keyManagementAddresses))
	caCert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return err
	}

	caCertPool := x509.NewCertPool()
	_ = caCertPool.AppendCertsFromPEM(caCert)
	trans := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}
	dialer := http.Client{Transport: trans, Timeout: 15 * time.Second}
	var encKeys string
	for i := len(keyManagementAddresses) - 1; i >= 0; i-- {
		randBytes := make([]byte, 32)
		_, err := rand.Read(randBytes)
		if err != nil {
			return err
		}
		randKeys[i] = hex.EncodeToString(randBytes)
	}

	for i := len(keyManagementAddresses) - 1; i >= 0; i-- {
		address := keyManagementAddresses[i]
		val := GetDecAttributeKeysForm{uuid, attribs, randKeys[i]}
		json_data, err := json.Marshal(val)
		if err != nil {
			return err
		}

		resp, err := dialer.Post(address+"/get-attribute-keys", "application/json", bytes.NewBuffer(json_data))
		if err != nil {
			return err
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if i == 0 {
			encKeys = string(body)
		} else {
			if string(body) != "ok" {
				return err
			}
		}
	}
	keysStings, err := decentralized.DecryptAttribKeys(encKeys, randKeys)
	if err != nil {
		return err
	}

	decAttribKey := make([]*protocol.FAMEDecAttribKeys, len(keyManagementAddresses))
	for i, e := range keysStings {
		decAttribKey[i], err = protocol.FameDecKeysFromRaw(strings.Split(e, "\n"))
		if err != nil {
			return err
		}
	}

	attribKey, err := protocol.JoinDecAttribKeys(decAttribKey)
	if err != nil {
		return err
	}

	attribKeyRaw, err := fame2.FameKeysToRaw(attribKey)
	if err != nil {
		return err
	}

	attribKeyString := strings.Join(attribKeyRaw, "\n")

	err = os.WriteFile(wallet, []byte(attribKeyString), 0644)
	if err != nil {
		return err
	}

	return nil
}

func readKey(wallet string) (*abe.FAMEAttribKeys, error) {
	dat, err := os.ReadFile(wallet)
	if err != nil {
		return nil, err
	}

	keyStrList := strings.Split(string(dat), "\n")
	key, err := fame2.FameKeysFromRaw(keyStrList)

	return key, err
}

type VerificationKey struct {
	Uuid   string `json:"uuid"`
	VerKey string `json:"verkey"`
}

func sigToKeyManagement(keyManagementAddress string, uuid string, sig string) (string, error) {
	form := VerificationKey{Uuid: uuid, VerKey: sig}
	jsonForm, err := json.Marshal(form)
	if err != nil {
		return "", err
	}

	caCert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return "", err
	}
	caCertPool := x509.NewCertPool()
	_ = caCertPool.AppendCertsFromPEM(caCert)
	trans := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}
	dialer := http.Client{Transport: trans, Timeout: 15 * time.Second}
	resp, err := dialer.Post(keyManagementAddress+"/pub-signature-keys", "application/json",
		bytes.NewBuffer(jsonForm))
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
