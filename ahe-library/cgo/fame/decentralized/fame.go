package decentralized

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/xlab-si/ahe/ahe-key-server/fame_key_authority/decentralized/protocol"
	"github.com/xlab-si/ahe/ahe-library/cgo/fame"
	"strings"
)

func Go_Ahe_fame_JoinDecAttribKeys(decKeys []string) ([]string, int) {
	decAttribKey := make([]*protocol.FAMEDecAttribKeys, len(decKeys))
	var err error
	for i, e := range decKeys {
		attribKeySlice := strings.Split(e, "\n")
		decAttribKey[i], err = protocol.FameDecKeysFromRaw(attribKeySlice)
		if err != nil {
			return nil, 1
		}
	}

	key, err := protocol.JoinDecAttribKeys(decAttribKey)
	if err != nil {
		return nil, 2
	}
	attribKey, err := fame.FameKeysToRaw(key)

	return attribKey, 0
}

func Go_Ahe_fame_DecryptAttribKeys(enc string, keys []string) ([]string, int) {
	attribKeysStrings, err := DecryptAttribKeys(enc, keys)
	if err != nil {
		return nil, 1
	}

	return attribKeysStrings, 0
}

func DecryptAttribKeys(enc string, keys []string) ([]string, error) {
	encSlice := strings.Split(enc, ",")
	ret := make([]string, len(keys))
	for i, keyString := range keys {
		keyBytes, err := hex.DecodeString(keyString)
		if err != nil {
			fmt.Printf("Error decoding sec key: %v\n", err)
			return nil, err
		}

		c, err := aes.NewCipher(keyBytes)
		if err != nil {
			return nil, err
		}

		e, err := base64.StdEncoding.DecodeString(encSlice[i])
		if err != nil {
			return nil, err
		}

		msgPad := make([]byte, len(e))
		iv := make([]byte, c.BlockSize())
		decrypter := cipher.NewCBCDecrypter(c, iv)
		decrypter.CryptBlocks(msgPad, e)

		// unpad the message
		padLen := int(msgPad[len(msgPad)-1])
		if (len(msgPad) - padLen) < 0 {
			return nil, fmt.Errorf("failed to decrypt")
		}
		msgByte := msgPad[0:(len(msgPad) - padLen)]

		ret[i] = string(msgByte)
	}

	return ret, nil
}
