package signatures

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"strconv"
)

func GenerateSignKeys() (string, string, int) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", 1
	}

	skBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", 2
	}
	skString := base64.StdEncoding.EncodeToString(skBytes)
	pk := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	pkString := hex.EncodeToString(pk)

	return pkString, skString, 0
}

type VerificationKey struct {
	Uuid   string `json:"uuid"`
	VerKey string `json:"verkey"`
}

type VerificationKeyProof struct {
	Uuid        string `json:"uuid"`
	VerKey      string `json:"verkey"`
	VerKeyProof string `json:"verkeyproof"`
}

func SignCiphers(skRaw string, proof string, cts []string, names []string) (string, int) {
	skRawBytes, err := base64.StdEncoding.DecodeString(skRaw)
	if err != nil {
		fmt.Println("failed decoding key")
		return "", 1
	}

	sk, err := x509.ParseECPrivateKey(skRawBytes)
	if err != nil {
		return "", 2
	}

	jsonMap := make(map[string]interface{})
	for i, ct := range cts {
		if names != nil {
			jsonMap[names[i]] = ct
		} else {
			jsonMap["cipher"+strconv.Itoa(i)] = ct
		}
	}

	jsonBytes, err := json.Marshal(jsonMap)
	hashSha := sha256.New()
	hashSha.Write(jsonBytes)
	hashed := hashSha.Sum(nil)

	sig, err := ecdsa.SignASN1(rand.Reader, sk, hashed)
	if err != nil {
		return "", 3
	}

	jsonMap["signature"] = hex.EncodeToString(sig)
	if proof != "" {
		var proofMap VerificationKeyProof
		err := json.Unmarshal([]byte(proof), &proofMap)
		if err != nil {
			return "", 6
		}
		jsonMap["proof"] = proofMap
	} else {
		sk, err := x509.ParseECPrivateKey(skRawBytes)
		if err != nil {
			return "", 5
		}
		pk := elliptic.Marshal(elliptic.P256(), sk.PublicKey.X, sk.PublicKey.Y)
		pkString := hex.EncodeToString(pk)
		vkProof := VerificationKeyProof{Uuid: "", VerKey: pkString, VerKeyProof: ""}
		jsonMap["proof"] = vkProof
	}

	jsonBytes, err = json.Marshal(jsonMap)
	if err != nil {
		return "", 4
	}

	return string(jsonBytes), 0
}

func VerifyCiphers(ctsSigned string, uuid string, ca string) (bool, int) {
	jsonMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(ctsSigned), &jsonMap)
	if err != nil {
		return false, 1
	}

	sig := jsonMap["signature"].(string)
	proofMap := jsonMap["proof"].(map[string]interface{})
	if uuid != "" {
		if proofMap["uuid"] != uuid {
			return false, 2
		}
	}
	if ca != "" {
		block, _ := pem.Decode([]byte(ca))
		cert, err := x509.ParseCertificate(block.Bytes)
		rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
		sigBytes, err := hex.DecodeString(proofMap["verkeyproof"].(string))
		if err != nil {
			return false, 3
		}
		verKey := VerificationKey{Uuid: proofMap["uuid"].(string), VerKey: proofMap["verkey"].(string)}
		hash := sha256.New()
		toSign, err := json.Marshal(verKey)
		if err != nil {
			log.Fatal(err)
		}
		hash.Write(toSign)
		res := hash.Sum(nil)
		check := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, res, sigBytes)
		if check != nil {
			return false, 4
		}
	}

	delete(jsonMap, "signature")
	delete(jsonMap, "proof")
	jsonBytes, err := json.Marshal(jsonMap)
	hashSha := sha256.New()
	hashSha.Write(jsonBytes)
	hashed := hashSha.Sum(nil)

	vk := proofMap["verkey"].(string)
	pk, err := hex.DecodeString(vk)
	if err != nil {
		return false, 5
	}
	var pkN ecdsa.PublicKey
	pkN.Curve = elliptic.P256()
	pkN.X, pkN.Y = elliptic.Unmarshal(elliptic.P256(), pk)

	sigBytes, err := hex.DecodeString(sig)
	valid := ecdsa.VerifyASN1(&pkN, hashed, sigBytes)

	return valid, 0
}
