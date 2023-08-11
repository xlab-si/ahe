package protocol

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"time"
)

var TriplesChan []chan *Triple
var RandChan []chan *Share
var Connections [][]*tls.Conn
var ConnectionsReaders [][]*bufio.Reader
var ConnectionsOffline [][]*tls.Conn
var ConnectionsReadersOffline [][]*bufio.Reader
var ConnectionsQueue [][]*tls.Conn
var ConnectionsReadersQueue [][]*bufio.Reader

func LoadCerts(myCrt, myKey, rootCACrt string) (tls.Certificate, *x509.CertPool) {
	cert, err := tls.LoadX509KeyPair(myCrt, myKey)
	if err != nil {
		log.Fatal(err)
	}
	caCert, err := ioutil.ReadFile(rootCACrt)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	_ = caCertPool.AppendCertsFromPEM(caCert)

	return cert, caCertPool
}

func InitConnections(myI int, addresses, names []string, cert tls.Certificate, caCertPool *x509.CertPool) error {
	numAuth := len(addresses)
	Connections[myI] = make([]*tls.Conn, numAuth)
	ConnectionsReaders[myI] = make([]*bufio.Reader, numAuth)
	ConnectionsOffline[myI] = make([]*tls.Conn, numAuth)
	ConnectionsReadersOffline[myI] = make([]*bufio.Reader, numAuth)
	ConnectionsQueue[myI] = make([]*tls.Conn, numAuth)
	ConnectionsReadersQueue[myI] = make([]*bufio.Reader, numAuth)

	servConfig := &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: caCertPool}

	clientConfig := &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caCertPool}
	//log.Printf("listening on port %s\n", *port)
	listener, err := tls.Listen("tcp", addresses[myI], servConfig)
	if err != nil {
		log.Fatal("Error", err)
	}

	if err != nil {
		log.Println("Error", err)
		return err
	}

	for i := 0; i < numAuth; i++ {
		if i < myI {
			conn, err := listener.Accept()
			if err != nil {
				log.Println("Error", err)
				return err
			}
			Connections[myI][i] = conn.(*tls.Conn)
			ConnectionsReaders[myI][i] = bufio.NewReaderSize(conn, 100000)
			_, err = conn.Write([]byte("test" + strconv.Itoa(i) + " " + strconv.Itoa(myI) + "\n"))
			if err != nil {
				log.Fatal("Fail writing ")
			}
			peerCerts := Connections[myI][i].ConnectionState().PeerCertificates
			if peerCerts[0].Subject.CommonName != names[i] {
				log.Fatal("Fail common name ", peerCerts[0].Subject.CommonName, names[i])
			}

			conn, err = listener.Accept()
			if err != nil {
				log.Println("Error", err)
				return err
			}
			ConnectionsOffline[myI][i] = conn.(*tls.Conn)
			ConnectionsReadersOffline[myI][i] = bufio.NewReader(conn)
			_, err = conn.Write([]byte("test" + strconv.Itoa(i) + " " + strconv.Itoa(myI) + "\n"))
			if err != nil {
				log.Fatal("Fail writing ")
			}
			peerCerts = ConnectionsOffline[myI][i].ConnectionState().PeerCertificates
			if peerCerts[0].Subject.CommonName != names[i] {
				log.Fatal("Fail common name ", peerCerts[0].Subject.CommonName, names[i])
			}

			conn, err = listener.Accept()
			if err != nil {
				log.Println("Error", err)
				return err
			}
			ConnectionsQueue[myI][i] = conn.(*tls.Conn)
			ConnectionsReadersQueue[myI][i] = bufio.NewReader(conn)
			_, err = conn.Write([]byte("test" + strconv.Itoa(i) + " " + strconv.Itoa(myI) + "\n"))
			if err != nil {
				log.Fatal("Fail writing ")
			}
			peerCerts = ConnectionsQueue[myI][i].ConnectionState().PeerCertificates
			if peerCerts[0].Subject.CommonName != names[i] {
				log.Fatal("Fail common name ", peerCerts[0].Subject.CommonName, names[i])
			}
		}

		if i == myI && (myI != 0) {
			rr, _, err := ConnectionsReaders[myI][myI-1].ReadLine()
			if err != nil || string(rr) != "go" {
				log.Fatal("Fail receiving ")
			}
		}

		if i > myI {
			var conn *tls.Conn
			for {
				conn, err = tls.Dial("tcp", addresses[i], clientConfig)
				if err != nil {
					log.Println("Error", err)
					time.Sleep(time.Second)
				} else {
					break
				}
			}
			// sanity check
			Connections[myI][i] = conn
			ConnectionsReaders[myI][i] = bufio.NewReaderSize(conn, 100000)
			msg, err := ConnectionsReaders[myI][i].ReadSlice(byte('\n'))
			if err != nil || string(msg) == "test"+strconv.Itoa(i)+" "+strconv.Itoa(myI) {
				log.Fatal("Fail receiving ")
			}
			peerCerts := Connections[myI][i].ConnectionState().PeerCertificates
			if peerCerts[0].Subject.CommonName != names[i] {
				log.Fatal("Fail common name ", peerCerts[0].Subject.CommonName, names[i])
			}

			for {
				conn, err = tls.Dial("tcp", addresses[i], clientConfig)
				if err != nil {
					log.Println("Error", err)
					time.Sleep(time.Second)
				} else {
					break
				}
			}
			// sanity check
			ConnectionsOffline[myI][i] = conn
			ConnectionsReadersOffline[myI][i] = bufio.NewReader(conn)
			msg, err = ConnectionsReadersOffline[myI][i].ReadSlice(byte('\n'))
			if err != nil || string(msg) == "test"+strconv.Itoa(i)+" "+strconv.Itoa(myI) {
				log.Fatal("Fail receiving ")
			}
			peerCerts = ConnectionsOffline[myI][i].ConnectionState().PeerCertificates
			if peerCerts[0].Subject.CommonName != names[i] {
				log.Fatal("Fail common name ", peerCerts[0].Subject.CommonName, names[i])
			}

			for {
				conn, err = tls.Dial("tcp", addresses[i], clientConfig)
				if err != nil {
					log.Println("Error", err)
					time.Sleep(time.Second)
				} else {
					break
				}
			}
			// sanity check
			ConnectionsQueue[myI][i] = conn
			ConnectionsReadersQueue[myI][i] = bufio.NewReader(conn)
			msg, err = ConnectionsReadersQueue[myI][i].ReadSlice(byte('\n'))
			if err != nil || string(msg) == "test"+strconv.Itoa(i)+" "+strconv.Itoa(myI) {
				log.Fatal("Fail receiving ")
			}
			peerCerts = ConnectionsQueue[myI][i].ConnectionState().PeerCertificates
			if peerCerts[0].Subject.CommonName != names[i] {
				log.Fatal("Fail common name ", peerCerts[0].Subject.CommonName, names[i])
			}
		}
	}

	if myI != numAuth-1 {
		_, err = Connections[myI][myI+1].Write([]byte("go\n"))
		if err != nil {
			log.Fatal("Fail writing ")
		}
	}

	return nil
}

func CheckConnection(myI int, otherI int, connections [][]*tls.Conn, connectionsReaders [][]*bufio.Reader) {
	conn := connections[myI][otherI]
	connRead := connectionsReaders[myI][otherI]

	var err error
	if myI > otherI {
		msg, err := connRead.ReadSlice(byte('\n'))
		if err != nil || string(msg) == "test"+strconv.Itoa(otherI)+" "+strconv.Itoa(myI) {
			log.Fatal("Fail receiving ")
		}
	} else {
		_, err = conn.Write([]byte("test" + strconv.Itoa(otherI) + " " + strconv.Itoa(myI) + "\n"))
		if err != nil {
			log.Fatal("Fail writing ")
		}
	}
}

func WaitConnections(connections [][]*tls.Conn) {
	// check if all connections are done
	for {
		check := true
		for i := 0; i < len(connections); i++ {
			if connections[i] == nil {
				check = false
				break
			}
			for j := 0; j < len(connections); j++ {
				if i == j {
					continue
				}
				if connections[i][j] == nil {
					check = false
					break
				}
			}
		}
		if check {
			break
		}
		fmt.Println("waiting for all the connections to set up")
		time.Sleep(time.Second)
	}
}

func CloseConnections(connections [][]*tls.Conn) error {
	var err error
	for i := 0; i < len(Connections); i++ {
		for j := 0; j < len(Connections[i]); j++ {
			if i == j {
				continue
			}
			err = connections[i][j].Close()
			if err != nil {
				return err
			}
		}
	}

	return nil
}
