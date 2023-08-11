package protocol

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"strconv"
	"testing"
)

func TestMauerShare(t *testing.T) {
	// set up parameters
	numAuth := 5
	threshold := 2

	InitProtocolValues(numAuth, 0)

	addresses := []string{}
	names := []string{}
	for i := 0; i < numAuth; i++ {
		addresses = append(addresses, "localhost:"+strconv.Itoa(6800+i))
		names = append(names, "node"+strconv.Itoa(i))
	}

	// initialize connections
	for i := 0; i < numAuth; i++ {
		myCrt, caPool := LoadCerts("../certs/node"+strconv.Itoa(i)+".crt", "../certs/node"+strconv.Itoa(i)+".key", "../certs/HEkeyCA.crt")
		go InitConnections(i, addresses, names, myCrt, caPool)
	}
	WaitConnections(ConnectionsOffline)
	for i := 0; i < numAuth; i++ {
		for j := i + 1; j < numAuth; j++ {
			CheckConnection(i, j, ConnectionsOffline, ConnectionsReadersOffline)
			CheckConnection(j, i, ConnectionsOffline, ConnectionsReadersOffline)
		}
	}
	fmt.Println("connections created")

	// initialize shares
	s1 := make([]*MauerShare, numAuth)
	s2 := make([]*MauerShare, numAuth)
	s3 := make([]*MauerShare, numAuth)
	for i := 0; i < numAuth; i++ {
		s1[i] = NewMauerShare(i, numAuth, threshold)
		s2[i] = NewMauerShare(i, numAuth, threshold)
		s3[i] = NewMauerShare(i, numAuth, threshold)
	}

	// share value
	var err error
	errsChan := make([]chan error, numAuth)
	s1Start := big.NewInt(1)
	s2Start := new(big.Int).Add(s1Start, s1Start)
	for i := 0; i < numAuth; i++ {
		errsChan[i] = make(chan error, 1)
		if i == 0 {
			go s1[i].ShareValue(s1Start, 0, i, errsChan[i])
		} else {
			go s1[i].ShareValue(nil, 0, i, errsChan[i])
		}
	}
	for i := 0; i < numAuth; i++ {
		err = <-errsChan[i]
		if err != nil {
			t.Fatal(err)
		}
	}
	fmt.Println("value shared")

	// test open value
	openChan := make([]chan *big.Int, numAuth)
	for i := 0; i < numAuth; i++ {
		//fmt.Println(s1[i])
		openChan[i] = make(chan *big.Int, 1)
		go s1[i].Open(openChan[i])
	}
	for i := 0; i < numAuth; i++ {
		s1Open := <-openChan[i]
		assert.Equal(t, 0, s1Open.Cmp(s1Start))
	}

	// test open value to one
	for i := 0; i < numAuth; i++ {
		openChan[i] = make(chan *big.Int, 1)
		go s1[i].OpenTo(1, openChan[i])
	}
	s1Open := <-openChan[1]
	assert.Equal(t, 0, s1Open.Cmp(s1Start))

	// test addition and check the result
	for i := 0; i < numAuth; i++ {
		go s2[i].Add(s1[i], s1[i], errsChan[i])
	}
	for i := 0; i < numAuth; i++ {
		err = <-errsChan[i]
	}
	for i := 0; i < numAuth; i++ {
		go s2[i].Open(openChan[i])
	}
	for i := 0; i < numAuth; i++ {
		s2Open := <-openChan[i]
		assert.Equal(t, 0, s2Open.Cmp(s2Start))
	}
	fmt.Println("addition working")

	// test multiplication and check the result
	for i := 0; i < numAuth; i++ {
		go s3[i].Mul(s2[i], s1[i], errsChan[i])
	}
	for i := 0; i < numAuth; i++ {
		err = <-errsChan[i]
	}
	for i := 0; i < numAuth; i++ {
		go s3[i].Open(openChan[i])
	}
	for i := 0; i < numAuth; i++ {
		s2Open := <-openChan[i]
		assert.Equal(t, 0, s2Open.Cmp(s2Start))
	}
	fmt.Println("multiplication working")

}
