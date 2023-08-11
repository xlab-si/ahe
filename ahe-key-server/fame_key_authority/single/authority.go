package single

import (
	"ahe-key-server/signature"
	"encoding/json"
	"fmt"
	"github.com/fentec-project/gofe/abe"
	"github.com/gorilla/mux"
	"github.com/xlab-si/ahe/ahe-library/cgo/fame"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var secKey *abe.FAMESecKey
var pubKey *abe.FAMEPubKey

// var userRecord map[string]string = make(map[string]string)
// var userTokens map[string]*AuthToken = make(map[string]*AuthToken)

var VerificationKeysDataset = make(map[string]string)

func HomePage(w http.ResponseWriter, r *http.Request) {
	n, err := fmt.Fprintf(w, "Authority server running.")
	if err != nil || n == 0 {
		fmt.Printf("Failed to print status message: %v", err)
	}
	fmt.Println("Served a request for home page.")
}

func GetPubKeys(pk *abe.FAMEPubKey, w http.ResponseWriter, r *http.Request) {
	pkStr, err := fame.FamePubToRaw(pk)
	if err != nil {
		fmt.Printf("Error marshaling pk: %v\n", err)
	}
	n, err := fmt.Fprintf(w, "%s", pkStr)
	if err != nil || n == 0 {
		fmt.Printf("Failed to print public keys: %v", err)
	}
	fmt.Println("Served a request for ABE public keys.")
}

type GetAttributeKeysForm struct {
	Uuid    string   `json:"uuid"`
	Attribs []string `json:"attributes"`
}

func GetAttributeKeys(scheme *abe.FAME, sk *abe.FAMESecKey, w http.ResponseWriter, r *http.Request) {
	// the authenticated user requests attribute keys
	// INPUT: access token, gid, list of attributes
	// OUTPUT: list of attribute keys
	switch r.Method {
	case "POST":
		check := signature.CheckRequest(r.Header, w)
		if check == false {
			fmt.Println("Http request check fail.")
			return
		}
		// json unmarshal request
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		var form GetAttributeKeysForm
		err = json.Unmarshal(body, &form)
		if err != nil {
			fmt.Printf("Error unmarshaling json: %v\n", err)
			http.Error(w, "Invalid json", http.StatusBadRequest)
			return
		}
		// check if attribute can be delegated
		// todo

		// generate attribute keys
		attribKeys, err := scheme.GenerateAttribKeys(form.Attribs, sk)
		if err != nil {
			fmt.Printf("Error generating attribute keys: %v\n", err)
			return
		}
		keyStrings, err := fame.FameKeysToRaw(attribKeys)
		if err != nil {
			fmt.Printf("Error json-marshaling attribute keys: %v\n", err)
			return
		}
		keyString := strings.Join(keyStrings, "\n")

		n, err := fmt.Fprintf(w, "%s", keyString)
		if err != nil || n == 0 {
			fmt.Printf("Error printing status: %v", err)
		}
		fmt.Println("Served a request for private ABE keys to "+form.Uuid+
			" for attributes ", form.Attribs)
	default:
		n, err := fmt.Fprintf(w, "Request method %s is not supported", r.Method)
		if err != nil || n == 0 {
			fmt.Printf("Error printing status: %v", err)
		}
	}
}

func FameService() {
	var err error
	// get auth id from env
	mode := os.Getenv("MODE")
	scheme := abe.NewFAME()

	if mode == "default" || mode == "" {
		secKeyBytes, err := os.ReadFile("fame_key_authority/single/sec_key.txt")
		if err != nil {
			fmt.Printf("Error loading secret key: %v", err)
			os.Exit(1)
		}

		secKey, err = fame.FameSecFromRaw(string(secKeyBytes))

		pubKeyBytes, err := os.ReadFile("fame_key_authority/single/pub_key.txt")
		if err != nil {
			fmt.Printf("Error loading public key: %v", err)
			os.Exit(1)
		}

		pubKey, err = fame.FamePubFromRaw(string(pubKeyBytes))
		if err != nil {
			fmt.Printf("Error listening: %v", err)
			os.Exit(1)
		}

	} else if mode == "new" {
		fmt.Println("BEWARE: generating new master keys")
		pubKey, secKey, err = scheme.GenerateMasterKeys()
		if err != nil {
			fmt.Printf("Error initiating authority: %v", err)
			os.Exit(1)
		}
		//
		//secKeystring, err := fame.FameSecToRaw(secKey)
		//if err != nil {
		//	os.Exit(1)
		//}
		//pubKeystring, err := fame.FamePubToRaw(pubKey)
		//if err != nil {
		//	os.Exit(1)
		//}
		//err = os.WriteFile("fame_key_authority/sec_key.txt", []byte(secKeystring), 0644)
		//if err != nil {
		//	os.Exit(1)
		//}
		//
		//err = os.WriteFile("fame_key_authority/pub_key.txt", []byte(pubKeystring), 0644)
		//if err != nil {
		//	os.Exit(1)
		//}
	} else {
		fmt.Printf("Please specify a valid MODE environment")
		os.Exit(1)
	}

	r := mux.NewRouter()

	r.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		HomePage(writer, request)
	})
	r.HandleFunc("/pubkeys", func(writer http.ResponseWriter, request *http.Request) {
		GetPubKeys(pubKey, writer, request)
	})
	r.HandleFunc("/get-attribute-keys", func(writer http.ResponseWriter, request *http.Request) {
		GetAttributeKeys(scheme, secKey, writer, request)
	})
	r.HandleFunc("/pub-signature-keys", func(writer http.ResponseWriter, request *http.Request) {
		signature.SignatureKeys(VerificationKeysDataset, "fame_key_authority/single/certs/HEKeyManager.key", writer, request)
	})
	// determine port from env
	port := os.Getenv("AUTH_PORT")
	if port == "" {
		// default value
		port = "6900"
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		fmt.Printf("AUTH_PORT should be a number: %s\n", port)
		os.Exit(1)
	}
	fmt.Println("Auth http server running on with port ", port)
	server := &http.Server{
		Addr:         ":" + port,
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 10 * time.Second,
		Handler:      r,
	}

	go server.ListenAndServe()
	if err != nil {
		fmt.Printf("Error listening: %v", err)
		os.Exit(1)
	}
	fmt.Println("Auth https server running on port ", portInt-1)

	server2 := &http.Server{
		Addr:         ":" + strconv.Itoa(portInt-1),
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 10 * time.Second,
		Handler:      r,
	}

	err = server2.ListenAndServeTLS("fame_key_authority/single/certs/HEKeyManager.crt", "fame_key_authority/single/certs/HEKeyManager.key")
	if err != nil {
		fmt.Printf("Error listening: %v", err)
		os.Exit(1)
	}
}
