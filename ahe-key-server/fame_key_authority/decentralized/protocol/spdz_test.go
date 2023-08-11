package protocol

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"strconv"
	"testing"
)

func TestSpdzOperations(t *testing.T) {
	numAuth := 5
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
		err := SetFakeLamda(i)
		if err != nil {
			t.Fatal(err)
		}
	}

	WaitConnections(Connections)
	WaitConnections(ConnectionsOffline)

	for i := 0; i < numAuth; i++ {
		TriplesChan[i] = make(chan *Triple, 2000)
		RandChan[i] = make(chan *Share, 2000)
		FakeTriplesGen(i, 2000)
	}

	done := make([]chan bool, numAuth)
	for i := 0; i < numAuth; i++ {
		done[i] = make(chan bool, 1)
		go testArithmetics(t, i, done[i])
	}
	for i := 0; i < numAuth; i++ {
		ok := <-done[i]
		if ok == false {
			t.Fatal("done fail")
		}
	}
	err := CloseConnections(Connections)
	if err != nil {
		t.Fatal(err)
	}
}

func testArithmetics(t *testing.T, myInt int, doneChan chan bool) {
	r1 := <-RandChan[myInt]
	r2 := <-RandChan[myInt]

	r3 := NewShare().Add(r1, r2)
	r3Check, err := Open(r3)
	if err != nil {
		t.Fatal(err)
	}

	r3.MulScalar(r3, big.NewInt(100))
	r3Check, err = Open(r3)

	_, err = r3.Mul(r3, r2)
	r3Check, err = Open(r3)

	r3InvertCheckCheck := new(big.Int).ModInverse(r3Check, P)
	r3Invert, err := NewShare().Invert(r3)
	r3InvertCheck, err := Open(r3Invert)
	assert.Equal(t, r3InvertCheckCheck, r3InvertCheck)

	//now := time.Now()
	//for j := 0; j < 1000; j++ {
	//	_, err = r3.Mul(r3, r3Invert)
	//}
	//fmt.Println("elapsed for 1000 multiplication and 10 auth", time.Since(now).Milliseconds())

	doneChan <- true
}
