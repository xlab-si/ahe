package protocol

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"strconv"
	"testing"
	"time"
)

func TestOffline(t *testing.T) {
	// set up parameters
	numAuth := 3
	threshold := 1
	InitProtocolValues(numAuth, 20)
	addresses := []string{}
	names := []string{}
	for i := 0; i < numAuth; i++ {
		TriplesChan[i] = make(chan *Triple, BackupNum)
		RandChan[i] = make(chan *Share, BackupNum)
		addresses = append(addresses, "localhost:"+strconv.Itoa(6800+i))
		names = append(names, "node"+strconv.Itoa(i))
	}

	// initialize connections
	for i := 0; i < numAuth; i++ {
		myCrt, caPool := LoadCerts("../certs/node"+strconv.Itoa(i)+".crt", "../certs/node"+strconv.Itoa(i)+".key", "../certs/HEkeyCA.crt")
		go InitConnections(i, addresses, names, myCrt, caPool)
	}
	WaitConnections(Connections)
	WaitConnections(ConnectionsOffline)
	for i := 0; i < numAuth; i++ {
		for j := i + 1; j < numAuth; j++ {
			CheckConnection(i, j, ConnectionsOffline, ConnectionsReadersOffline)
			CheckConnection(j, i, ConnectionsOffline, ConnectionsReadersOffline)
		}
	}
	fmt.Println("connections created")

	done := make([]chan bool, numAuth)
	for i := 0; i < numAuth; i++ {
		done[i] = make(chan bool, 1)
		go SingleAuthTest(t, i, numAuth, threshold, done[i])
	}
	for i := 0; i < numAuth; i++ {
		ok := <-done[i]
		if ok == false {
			t.Fatal("done fail")
		}
	}
}

func SingleAuthTest(t *testing.T, myI, numAuth, threshold int, doneChan chan bool) {
	var err error
	errsChan := make(chan error, 1)
	GenLambda(myI, numAuth, threshold, errsChan)

	err = <-errsChan
	if err != nil {
		t.Fatal(err)
	}

	lambdaSum, err := LambdaSumMauerShare[myI].Open(nil)
	if err != nil {
		t.Fatal(err)
	}

	lambdaTest := big.NewInt(0)
	for i := 0; i < numAuth; i++ {
		lambdaTest.Add(lambdaTest, Lambda[i])
		lambdaTest.Mod(lambdaTest, P)
	}

	assert.Equal(t, lambdaTest, lambdaSum)
	fmt.Println("Lambda created and tested")

	r, err := GenerateRandShare(myI, numAuth, threshold)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Open(r)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("random share created and tested")

	triple, err := GenerateTriple(myI, numAuth, threshold)
	if err != nil {
		t.Fatal(err)
	}

	tA, err := Open(triple.A)
	if err != nil {
		t.Fatal(err)
	}
	tB, err := Open(triple.B)
	if err != nil {
		t.Fatal(err)
	}
	tC, err := Open(triple.C)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 0, new(big.Int).Mod(new(big.Int).Mul(tA, tB), P).Cmp(tC))

	fmt.Println("random triples created and tested")

	go ContinuousGen(myI, numAuth, threshold, TriplesChan[myI], RandChan[myI])

	time.Sleep(time.Second)
	for i := 0; i < 100; i++ {
		r := <-RandChan[myI]
		_ = r
		t := <-TriplesChan[myI]
		_ = t
	}

	doneChan <- true
}
