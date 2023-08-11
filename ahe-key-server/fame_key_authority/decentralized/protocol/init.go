package protocol

import (
	"bufio"
	"crypto/tls"
	"github.com/fentec-project/gofe/abe"
	"math/big"
)

func InitProtocolValues(n, numBackup int) {
	TriplesChan = make([]chan *Triple, n)
	RandChan = make([]chan *Share, n)
	Connections = make([][]*tls.Conn, n)
	ConnectionsReaders = make([][]*bufio.Reader, n)
	ConnectionsOffline = make([][]*tls.Conn, n)
	ConnectionsReadersOffline = make([][]*bufio.Reader, n)
	ConnectionsQueue = make([][]*tls.Conn, n)
	ConnectionsReadersQueue = make([][]*bufio.Reader, n)
	DecPubKey = make([]*FAMEDecPubKey, n)
	PubKey = make([]*abe.FAMEPubKey, n)
	DecSecKey = make([]*FAMEDecSecKey, n)
	//SecKeyDec = make([]*FAMEDecSecKey, n)
	//PubKeyDec = make([]*FAMEDecPubKey, n)
	Lambda = make([]*big.Int, n)
	LambdaSumMauerShare = make([]*MauerShare, n)
	BackupNum = numBackup
}
