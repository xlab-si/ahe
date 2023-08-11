package decentralized

import (
	"ahe-key-server/fame_key_authority/decentralized/protocol"
	"ahe-key-server/fame_key_authority/single"
	"ahe-key-server/signature"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/fentec-project/gofe/abe"
	"github.com/gorilla/mux"
	"github.com/xlab-si/ahe/ahe-library/cgo/fame"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var VerificationKeysDataset = make(map[string]string)

type Queue struct {
	mu    sync.Mutex
	queue map[string]GetDecAttributeKeysForm
}

var QueueVar []Queue

var QueueOut []chan string
var TaskChan []chan GetDecAttributeKeysForm

// var userRecord map[string]string = make(map[string]string)
// var userTokens map[string]*AuthToken = make(map[string]*AuthToken)

func QueueAdd(myI int) {
	conn := protocol.ConnectionsQueue[myI][0]
	for {
		newTask := <-QueueOut[myI]
		if myI == 0 {
			Node0QueueVar.mu.Lock()
			if _, ok := Node0QueueVar.queue[newTask]; !ok {
				Node0QueueVar.queue[newTask] = make(map[int]chan string)
			}
			Node0QueueVar.queue[newTask][0] = make(chan string, 1)

			if len(Node0QueueVar.queue[newTask]) == len(protocol.Connections) {
				SendStartTask(newTask)
			}
			Node0QueueVar.mu.Unlock()

		} else {
			_, err := conn.Write([]byte(newTask + "\n"))
			if err != nil {
				fmt.Printf("Failed to send a new task to node 0: %v", err)
				continue
			}
		}
	}
}

func UpdateCurrent(myI int) {
	connReader := protocol.ConnectionsReadersQueue[myI][0]
	for {
		msg, err := connReader.ReadBytes('\n')
		if err != nil {
			fmt.Printf("Failed to read a new task from node 0: %v", err)
			continue
		}
		msgString := string(msg)[:len(string(msg))-1]
		//fmt.Println("i should start", msgString, myI)

		QueueVar[myI].mu.Lock()
		TaskChan[myI] <- QueueVar[myI].queue[msgString]
		QueueVar[myI].mu.Unlock()

	}
}

type Node0Queue struct {
	mu    sync.Mutex
	queue map[string]map[int]chan string
}

var Node0QueueVar Node0Queue

func Node0AddQueues(i int) {
	connReader := protocol.ConnectionsReadersQueue[0][i]
	for {
		msg, err := connReader.ReadBytes('\n')
		if err != nil {
			fmt.Printf("Failed to read a new task from node %d: %v", i, err)
			continue
		}
		Node0QueueVar.mu.Lock()

		msgStr := string(msg)[:len(string(msg))-1]
		if _, ok := Node0QueueVar.queue[msgStr]; !ok {
			Node0QueueVar.queue[msgStr] = make(map[int]chan string)
		}
		Node0QueueVar.queue[msgStr][i] = nil

		if len(Node0QueueVar.queue[msgStr]) == len(protocol.Connections) {
			SendStartTask(msgStr)
		}
		Node0QueueVar.mu.Unlock()
	}
}

func SendStartTask(msg string) {
	for i, conn := range protocol.ConnectionsQueue[0] {
		if i == 0 {
			QueueVar[0].mu.Lock()
			TaskChan[0] <- QueueVar[0].queue[msg]
			QueueVar[0].mu.Unlock()
			continue
		}
		_, err := conn.Write([]byte(msg + "\n"))
		if err != nil {
			fmt.Printf("Failed to send a start task to node %d: %v", i, err)
			return
		}
	}
}

func GetPubKeysDecentralized(pk *protocol.FAMEDecPubKey, w http.ResponseWriter, r *http.Request) {
	pkStr, err := protocol.FameDecPubToRaw(pk)
	//pkStr, err := json.Marshal(pk)
	if err != nil {
		fmt.Printf("Error marshaling json: %v\n", err)
	}
	n, err := fmt.Fprintf(w, "%s", pkStr)
	if err != nil || n == 0 {
		fmt.Printf("Failed to print public keys: %v", err)
	}
	fmt.Println("Served a request for a share of the ABE public key.")
}

func GetPubKey(pk *abe.FAMEPubKey, w http.ResponseWriter, r *http.Request) {
	pkStr, err := fame.FamePubToRaw(pk)
	if err != nil {
		fmt.Printf("Error marshaling pk: %v\n", err)
	}
	n, err := fmt.Fprintf(w, "%s", pkStr)
	if err != nil || n == 0 {
		fmt.Printf("Failed to print public keys: %v", err)
	}
	fmt.Println("Served a request for the ABE public key.")
}

type GetDecAttributeKeysForm struct {
	Uuid    string   `json:"uuid"`
	Attribs []string `json:"attributes"`
	SecKey  string   `json:"sec_key"`
}

func OutToNode0(out string, myI int) (string, error) {
	var err error
	if myI != 0 {
		_, err = protocol.Connections[myI][0].Write([]byte(out + "\n"))
		return "", err
	} else {
		retSlice := make([]string, len(protocol.Connections))
		retSlice[0] = out
		for i := 1; i < len(protocol.Connections); i++ {
			msg, err := protocol.ConnectionsReaders[myI][i].ReadSlice(byte('\n'))
			if err != nil {
				return "", err
			}
			retSlice[i] = string(msg[:len(msg)-1])
		}

		return strings.Join(retSlice, ","), err
	}
}

func AttribKeyProtocol(decSecKey *protocol.FAMEDecSecKey, myI int) {
	for {
		form := <-TaskChan[myI]
		attribKeys, err := protocol.GenerateDecAttribKeys(form.Attribs, decSecKey, myI, nil)
		if err != nil {
			continue
		}

		keyStrings, err := protocol.FameDecKeysToRaw(attribKeys)
		if err != nil {
			fmt.Printf("Error json-marshaling attribute keys: %v\n", err)
			continue

		}
		keyString := strings.Join(keyStrings, "\n")

		keyBytes, err := hex.DecodeString(form.SecKey)
		if err != nil {
			fmt.Printf("Error decoding sec key: %v\n", err)
			continue
		}

		c, err := aes.NewCipher(keyBytes)
		if err != nil {
			continue
		}

		// no need for iv since we have a different sec key every time
		iv := make([]byte, c.BlockSize())
		encrypterCBC := cipher.NewCBCEncrypter(c, iv)

		msgByte := []byte(keyString)

		// message is padded according to pkcs7 standard
		padLen := c.BlockSize() - (len(msgByte) % c.BlockSize())
		msgPad := make([]byte, len(msgByte)+padLen)
		copy(msgPad, msgByte)
		for i := len(msgByte); i < len(msgPad); i++ {
			msgPad[i] = byte(padLen)
		}

		symEnc := make([]byte, len(msgPad))
		encrypterCBC.CryptBlocks(symEnc, msgPad)

		msg, err := OutToNode0(base64.StdEncoding.EncodeToString(symEnc), myI)
		if err != nil {
			fmt.Printf("Error outsourcing attribute keys to node 0: %v\n", err)
			continue
		}

		QueueVar[myI].mu.Lock()
		delete(QueueVar[myI].queue, form.Uuid)
		QueueVar[myI].mu.Unlock()
		//fmt.Println(myI, msg)
		if myI == 0 {
			Node0QueueVar.mu.Lock()

			Node0QueueVar.queue[form.Uuid][0] <- msg
			Node0QueueVar.mu.Unlock()

		}
		fmt.Println("Finished attribute key protocol for", form.Uuid)
	}
}

func GetAttributeKeysDecentralized(myI int, decSecKey *protocol.FAMEDecSecKey, w http.ResponseWriter, r *http.Request) {
	// the authenticated user requests attribute keys
	// INPUT: access token, gid, list of attributes
	// OUTPUT: list of attribute keys
	switch r.Method {
	case "POST":
		fmt.Println("Received request for attribute keys.")
		check := signature.CheckRequest(r.Header, w)
		if check == false {
			fmt.Println("Check request fail")
			return
		}
		// json unmarshal request
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		var form GetDecAttributeKeysForm
		err = json.Unmarshal(body, &form)
		if err != nil {
			fmt.Printf("Error unmarshaling json: %v\n", err)
			http.Error(w, "Invalid json", http.StatusBadRequest)
			return
		}
		// check if attribute can be delegated
		// todo

		QueueVar[myI].mu.Lock()
		QueueVar[myI].queue[form.Uuid] = form
		QueueVar[myI].mu.Unlock()

		QueueOut[myI] <- form.Uuid

		if myI != 0 {
			n, err := w.Write([]byte("ok"))
			if err != nil || n == 0 {
				fmt.Printf("Error printing status: %v", err)
			}
		}

		if myI == 0 {
			for {
				Node0QueueVar.mu.Lock()

				if Node0QueueVar.queue[form.Uuid][0] != nil {
					Node0QueueVar.mu.Unlock()

					break
				}
				Node0QueueVar.mu.Unlock()

				time.Sleep(200 * time.Millisecond)
			}

			Node0QueueVar.mu.Lock()
			respChan := Node0QueueVar.queue[form.Uuid][0]
			Node0QueueVar.mu.Unlock()

			msg := <-respChan

			n, err := w.Write([]byte(msg))
			if err != nil || n == 0 {
				fmt.Printf("Error printing status: %v", err)
			}
			Node0QueueVar.mu.Lock()
			delete(Node0QueueVar.queue, form.Uuid)
			Node0QueueVar.mu.Unlock()
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

func InitGlobalValues(n, numBackup int) {
	protocol.InitProtocolValues(n, numBackup)
	Node0QueueVar.queue = make(map[string]map[int]chan string)
	QueueOut = make([]chan string, n)
	TaskChan = make([]chan GetDecAttributeKeysForm, n)
	QueueVar = make([]Queue, n)
}

type AuthData struct {
	Lambda           *big.Int
	LambdaMauerShare protocol.MauerShare
	DecSecKey        protocol.FAMEDecSecKey
	DecPubKey        protocol.FAMEDecPubKey
	PubKey           abe.FAMEPubKey
}

func SaveAuth(myI int, saveLoc string) error {
	a := AuthData{Lambda: protocol.Lambda[myI],
		LambdaMauerShare: *protocol.LambdaSumMauerShare[myI],
		DecSecKey:        *protocol.DecSecKey[myI],
		DecPubKey:        *protocol.DecPubKey[myI],
		PubKey:           *protocol.PubKey[myI],
	}

	aBytes, err := json.Marshal(a)
	if err != nil {
		return err
	}

	f, err := os.Create(saveLoc)
	if err != nil {
		return err
	}
	_, err = f.Write(aBytes)
	if err != nil {
		return err
	}

	err = f.Close()
	if err != nil {
		return err
	}

	return nil
}

func LoadAuth(myI int, saveLoc string) error {
	aBytes, err := os.ReadFile(saveLoc)
	if err != nil {
		return err
	}
	var a AuthData
	err = json.Unmarshal(aBytes, &a)
	if err != nil {
		return err
	}

	protocol.Lambda[myI] = a.Lambda
	protocol.LambdaSumMauerShare[myI] = &a.LambdaMauerShare
	protocol.DecSecKey[myI] = &a.DecSecKey
	protocol.DecPubKey[myI] = &a.DecPubKey
	protocol.PubKey[myI] = &a.PubKey

	return nil
}

func RunFAMEDecAuthority(mode string, myI int, n int, addresses, names []string, port int, myCrt, myKey,
	rootCACrt string, saveLoc string) {
	protocol.TriplesChan[myI] = make(chan *protocol.Triple, protocol.BackupNum)
	protocol.RandChan[myI] = make(chan *protocol.Share, protocol.BackupNum)
	QueueOut[myI] = make(chan string, 100)
	TaskChan[myI] = make(chan GetDecAttributeKeysForm, 100)
	QueueVar[myI].queue = make(map[string]GetDecAttributeKeysForm)

	var err error
	if mode == "load" {
		err = LoadAuth(myI, saveLoc)
		if err != nil {
			fmt.Printf("Error loading data %d: %v", myI, err)
			os.Exit(1)
		}
		fmt.Println("Master keys loaded from", saveLoc)
		myCrt, caPool := protocol.LoadCerts(myCrt, myKey, rootCACrt)
		err = protocol.InitConnections(myI, addresses, names, myCrt, caPool)
		if err != nil {
			fmt.Printf("Error initiating connections %d: %v", myI, err)
			os.Exit(1)
		}

		go protocol.ContinuousGen(myI, n, n/2, protocol.TriplesChan[myI], protocol.RandChan[myI])
	} else if mode == "new" {
		fmt.Println("BEWARE: generating new master keys")
		myCrt, caPool := protocol.LoadCerts(myCrt, myKey, rootCACrt)
		err = protocol.InitConnections(myI, addresses, names, myCrt, caPool)
		if err != nil {
			fmt.Printf("Error initiating connections %d: %v", myI, err)
			os.Exit(1)
		}

		err = protocol.GenLambda(myI, n, n/2, nil)
		if err != nil {
			fmt.Printf("Error generating lambda %d: %v", myI, err)
			os.Exit(1)
		}

		go protocol.ContinuousGen(myI, n, n/2, protocol.TriplesChan[myI], protocol.RandChan[myI])

		protocol.PubKey[myI], protocol.DecPubKey[myI], protocol.DecSecKey[myI], err = protocol.GenerateDecMasterKeys(myI, nil, nil, nil)
		if err != nil {
			fmt.Printf("Error generating master keys %d: %v", myI, err)
			os.Exit(1)
		}
		fmt.Println("New master keys generated.")
		err := SaveAuth(myI, saveLoc)
		if err != nil {
			fmt.Printf("Error saving keys %d: %v", myI, err)
			os.Exit(1)
		}
		//fmt.Println(FameDecPubToRaw(PubKeyDec[myI]))

	} else {
		fmt.Printf("Please specify a valid MODE environment")
		os.Exit(1)
	}

	if myI == 0 {
		for i := 1; i < len(protocol.Connections); i++ {
			go Node0AddQueues(i)
		}
	} else {
		go UpdateCurrent(myI)
	}

	go QueueAdd(myI)

	go AttribKeyProtocol(protocol.DecSecKey[myI], myI)

	r := mux.NewRouter()
	r.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		single.HomePage(writer, request)
	})
	r.HandleFunc("/decpubkey", func(writer http.ResponseWriter, request *http.Request) {
		GetPubKeysDecentralized(protocol.DecPubKey[myI], writer, request)
	})
	r.HandleFunc("/pubkeys", func(writer http.ResponseWriter, request *http.Request) {
		GetPubKey(protocol.PubKey[myI], writer, request)
	})
	r.HandleFunc("/get-attribute-keys", func(writer http.ResponseWriter, request *http.Request) {
		GetAttributeKeysDecentralized(myI, protocol.DecSecKey[myI], writer, request)
	})

	server := &http.Server{
		Addr:         ":" + strconv.Itoa(port),
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 10 * time.Second,
		Handler:      r,
	}

	fmt.Println("Auth running on port ", port)
	err = server.ListenAndServeTLS(myCrt, myKey)
	if err != nil {
		fmt.Printf("Error listening: %v", err)
		os.Exit(1)
	}
}
