package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

type VerificationKey struct {
	Uuid   string `json:"uuid"`
	VerKey string `json:"verkey"`
}

type VerificationKeyProof struct {
	Uuid        string `json:"uuid"`
	VerKey      string `json:"verkey"`
	VerKeyProof string `json:"verkeyproof"`
}

func CheckRequest(header http.Header, w http.ResponseWriter) bool {
	// Content-Type: application/json
	if header["Content-Type"] == nil {
		http.Error(w, "No type header", http.StatusBadRequest)
		return false
	}
	// apparently headers have type []string
	if len(header["Content-Type"]) != 1 {
		http.Error(w, "Invalid type length", http.StatusBadRequest)
		return false
	}
	if header["Content-Type"][0] != "application/json" {
		http.Error(w, "Content type must be json", http.StatusBadRequest)
		return false
	}

	return true
}

func SignatureKeys(dataset map[string]string, caKeyFile string, w http.ResponseWriter, r *http.Request) {
	// INPUT: access token, name of device
	// OUTPUT: its public signature key
	switch r.Method {
	case "POST":
		fmt.Println("Received a request for signature public key")
		check := CheckRequest(r.Header, w)
		if check == false {
			return
		}
		// json unmarshal request
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		var form VerificationKey
		err = json.Unmarshal(body, &form)
		if err != nil {
			fmt.Printf("Error unmarshaling json: %v\n", err)
			http.Error(w, "Invalid json", http.StatusBadRequest)
			return
		}

		if form.VerKey == "" {
			fmt.Println("Saving public key")
			if key, ok := dataset[form.Uuid]; ok {
				ret := VerificationKey{Uuid: form.Uuid, VerKey: key}
				retJson, err := json.Marshal(ret)
				if err != nil {
					fmt.Printf("Error marshaling: %v\n", err)
					http.Error(w, "Failed marshalling json", http.StatusBadRequest)
					return
				}
				_, err = w.Write(retJson)
				if err != nil {
					fmt.Printf("Error returning verification key: %v\n", err)
					return
				}
				fmt.Println("Served a request for signature public key of " + form.Uuid + ".")
			} else {
				fmt.Println("Error finding uuid:")
				http.Error(w, "Error finding uuid", http.StatusBadRequest)
			}
		} else {
			// todo check if not already in
			dataset[form.Uuid] = form.VerKey
			fmt.Println("Saved the signature public key of " + form.Uuid + ".")
			caKey, err := ioutil.ReadFile("fame_key_authority/single/certs/HEkeyCA.key")
			if err != nil {
				log.Fatal(err)
			}
			block, _ := pem.Decode(caKey)
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)

			hash := sha256.New()
			toSign, err := json.Marshal(form)
			if err != nil {
				log.Fatal(err)
			}
			hash.Write(toSign)
			res := hash.Sum(nil)
			sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, res)

			proof := VerificationKeyProof{Uuid: form.Uuid, VerKey: form.VerKey, VerKeyProof: hex.EncodeToString(sig)}
			ret, err := json.Marshal(proof)
			if err != nil {
				log.Fatal(err)
			}
			_, err = w.Write(ret)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("Served a signature of the uuid and public key for " + form.Uuid + ".")
		}
	case "GET":
		fmt.Println("Received a request for all signature public key.")
		datasetBytes, _ := json.Marshal(dataset)
		w.Write(datasetBytes)
		fmt.Println("Served a request for all signature public key.")
	}
}
