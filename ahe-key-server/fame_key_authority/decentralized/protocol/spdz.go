package protocol

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/fentec-project/bn256"
	"io"
	"math/big"
)

var Lambda []*big.Int
var BackupNum int

type Share struct {
	X *big.Int
	M *big.Int
	I int
}

type Triple struct {
	A *Share
	B *Share
	C *Share
}

type TransmittedShare struct {
	Share *big.Int
}

type OpenedCommit struct {
	Commit []byte
}

func NewShare() *Share {
	s := Share{}
	s.X = new(big.Int)
	s.M = new(big.Int)

	return &s
}

func JoinShares(shares []*Share) *big.Int {
	g := big.NewInt(0)
	for _, e := range shares {
		g.Add(g, e.X)
	}
	g.Mod(g, P)

	return g
}

func (s *Share) Set(s1 *Share) *Share {
	s.X.Set(s1.X)
	s.M.Set(s1.M)

	s.I = s1.I

	return s
}

func (s *Share) Add(s1 *Share, s2 *Share) *Share {
	s.X.Add(s1.X, s2.X)
	s.X.Mod(s.X, P)

	s.M.Add(s1.M, s2.M)
	s.M.Mod(s.M, P)

	s.I = s1.I

	return s
}

func (s *Share) Neg(s1 *Share) *Share {
	s.X.Neg(s1.X)
	s.X.Mod(s.X, P)

	s.M.Neg(s1.M)
	s.M.Mod(s.M, P)

	s.I = s1.I

	return s
}

func (s *Share) MulScalar(s1 *Share, s2 *big.Int) *Share {
	s.X.Mul(s1.X, s2)
	s.X.Mod(s.X, P)

	s.M.Mul(s1.M, s2)
	s.M.Mod(s.M, P)

	s.I = s1.I

	return s
}

func (s *Share) Mul(s1 *Share, s2 *Share) (*Share, error) {
	triple := <-TriplesChan[s1.I]
	epsilonShare := NewShare().Add(s1, NewShare().Neg(triple.A))
	epsilon, err := Open(epsilonShare)
	if err != nil {
		return nil, err
	}

	rhoShare := NewShare().Add(s2, NewShare().Neg(triple.B))
	rho, err := Open(rhoShare)
	if err != nil {
		return nil, err
	}

	epsB := NewShare().MulScalar(triple.B, epsilon)
	rhoA := NewShare().MulScalar(triple.A, rho)
	epsRho := NewShare().MulScalar(epsilonShare, rho)

	s.Set(triple.C)
	s.Add(s, epsB)
	s.Add(s, rhoA)
	s.Add(s, epsRho)

	s.I = s1.I

	return s, nil
}

func (s *Share) Invert(s1 *Share) (*Share, error) {
	r := <-RandChan[s1.I]

	s1MulRShare, err := NewShare().Mul(s1, r)
	if err != nil {
		return nil, err
	}
	s1MulR, err := Open(s1MulRShare)
	s1MulRInv := new(big.Int).ModInverse(s1MulR, P)

	s.MulScalar(r, s1MulRInv)

	return s, nil
}

func Open(s *Share) (*big.Int, error) {
	openShareBytes, err := json.Marshal(s.X)
	if err != nil {
		return nil, err
	}
	openShareBytes = append(openShareBytes, byte('\n'))

	x := new(big.Int).Set(s.X)
	var receivingShare big.Int
	//var err error
	for i := 0; i < s.I; i++ {
		conn := Connections[s.I][i]
		connReader := ConnectionsReaders[s.I][i]
		msg, err := connReader.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(msg, &receivingShare)
		if err != nil {
			return nil, err
		}
		//fmt.Println("recieved", receivingShare.Share, s.I)
		x.Add(x, &receivingShare)

		_, err = conn.Write(openShareBytes)
		if err != nil {
			return nil, err
		}
	}

	for i := s.I + 1; i < len(Connections); i++ {
		conn := Connections[s.I][i]
		_, err = conn.Write(openShareBytes)
		if err != nil {
			return nil, err
		}

		connReader := ConnectionsReaders[s.I][i]
		msg, err := connReader.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(msg, &receivingShare)
		if err != nil {
			return nil, err
		}
		x.Add(x, &receivingShare)
	}
	x.Mod(x, P)

	a := new(big.Int).Mul(x, Lambda[s.I])
	a.Mod(a, P)
	a.Neg(a)
	a.Add(a, s.M)
	a.Mod(a, P)

	// create and send commitments
	r, err := rand.Int(rand.Reader, P)
	if err != nil {
		return nil, err
	}
	shaHash := sha256.New()
	shaHash.Write(r.Bytes())
	shaHash.Write(a.Bytes())
	commitment := shaHash.Sum([]byte{})
	//commitment = append(commitment, byte('\n'))
	commitments := make([][]byte, len(Connections))
	for i := 0; i < s.I; i++ {
		hashMsg := make([]byte, 32)
		conn := Connections[s.I][i]
		connReader := ConnectionsReaders[s.I][i]
		n, err := io.ReadFull(connReader, hashMsg)

		//msg, err := connReader.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		if n != 32 {
			fmt.Println("hash len read fail", n)
			return nil, fmt.Errorf("hash len read fail")
		}
		commitments[i] = hashMsg
		//fmt.Println(msg, s.I, i)

		_, err = conn.Write(commitment)
		if err != nil {
			return nil, err
		}
	}

	for i := s.I + 1; i < len(Connections); i++ {
		hashMsg := make([]byte, 32)
		conn := Connections[s.I][i]

		_, err = conn.Write(commitment)
		if err != nil {
			return nil, err
		}

		connReader := ConnectionsReaders[s.I][i]
		n, err := io.ReadFull(connReader, hashMsg)
		//msg, err := connReader.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		if n != 32 {
			fmt.Println("hash len read fail", n)
			return nil, fmt.Errorf("hash len read fail")
		}

		commitments[i] = hashMsg
	}

	// send values
	allA := make([]*big.Int, len(Connections))
	aSum := new(big.Int).Set(a)
	openShareBytes, err = json.Marshal(a)
	openShareBytes = append(openShareBytes, '\n')
	if err != nil {
		return nil, err
	}
	for i := 0; i < s.I; i++ {
		conn := Connections[s.I][i]
		connReader := ConnectionsReaders[s.I][i]
		msg, err := connReader.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(msg, &receivingShare)
		if err != nil {
			return nil, err
		}
		//fmt.Println("recieved", receivingShare.Share, s.I)
		aSum.Add(aSum, &receivingShare)
		allA[i] = new(big.Int).Set(&receivingShare)

		_, err = conn.Write(openShareBytes)
		if err != nil {
			return nil, err
		}
	}

	for i := s.I + 1; i < len(Connections); i++ {
		conn := Connections[s.I][i]

		_, err = conn.Write(openShareBytes)
		if err != nil {
			return nil, err
		}

		connReader := ConnectionsReaders[s.I][i]
		msg, err := connReader.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(msg, &receivingShare)
		if err != nil {
			return nil, err
		}

		aSum.Add(aSum, &receivingShare)
		allA[i] = new(big.Int).Set(&receivingShare)
	}

	// reveal commitments
	randSend, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	randSend = append(randSend, byte('\n'))
	for i := 0; i < s.I; i++ {
		conn := Connections[s.I][i]
		connReader := ConnectionsReaders[s.I][i]
		msg, err := connReader.ReadBytes('\n')
		if err != nil {
			return nil, err
		}

		_, err = conn.Write(randSend)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(msg, &receivingShare)
		if err != nil {
			return nil, err
		}
		shaHash.Reset()
		shaHash.Write(receivingShare.Bytes())
		shaHash.Write(allA[i].Bytes())
		comm := shaHash.Sum([]byte{})
		if string(comm) != string(commitments[i]) {
			fmt.Println("commitment check fail", receivingShare.Bytes(), allA[i], i, comm)
			return nil, fmt.Errorf("commitment check fail")
		}
	}

	for i := s.I + 1; i < len(Connections); i++ {
		conn := Connections[s.I][i]

		_, err = conn.Write(randSend)
		if err != nil {
			return nil, err
		}

		connReader := ConnectionsReaders[s.I][i]
		msg, err := connReader.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(msg, &receivingShare)
		if err != nil {
			return nil, err
		}
		shaHash.Reset()
		shaHash.Write(receivingShare.Bytes())
		shaHash.Write(allA[i].Bytes())
		comm := shaHash.Sum([]byte{})
		if string(comm) != string(commitments[i]) {
			fmt.Println("commitment check fail", receivingShare.Bytes(), allA[i], i, comm)
			return nil, fmt.Errorf("commitment check fail")
		}
	}

	aSum.Mod(aSum, P)
	if aSum.Sign() != 0 {
		fmt.Println("mac check fail", aSum)
		return nil, fmt.Errorf("MAC check fail")
	}

	return x, nil
}

type G1Share struct {
	X *bn256.G1
	M *bn256.G1
	I int
}

type G2Share struct {
	X *bn256.G2
	M *bn256.G2
	I int
}

type GTShare struct {
	X *bn256.GT
	M *bn256.GT
	I int
}

func NewG1Share() *G1Share {
	s := G1Share{}
	s.X = new(bn256.G1)
	s.M = new(bn256.G1)

	return &s
}

func (g *G1Share) SetFromShare(s *Share) *G1Share {
	g.X = new(bn256.G1).ScalarBaseMult(s.X)
	g.M = new(bn256.G1).ScalarBaseMult(s.M)
	g.I = s.I

	return g
}

func (g *G1Share) SetFromShareWithBase(s *Share, b *bn256.G1) *G1Share {
	g.X = new(bn256.G1).ScalarMult(b, s.X)
	g.M = new(bn256.G1).ScalarMult(b, s.M)
	g.I = s.I

	return g
}

func (g *G1Share) Mul(s1 *G1Share, s2 *G1Share) *G1Share {
	g.X = new(bn256.G1).Add(s1.X, s2.X)
	g.M = new(bn256.G1).Add(s1.M, s2.M)
	g.I = s1.I

	return g
}

func NewG2Share() *G2Share {
	s := G2Share{}
	s.X = new(bn256.G2)
	s.M = new(bn256.G2)

	return &s
}

func (g *G2Share) SetFromShare(s *Share) *G2Share {
	g.X = new(bn256.G2).ScalarBaseMult(s.X)
	g.M = new(bn256.G2).ScalarBaseMult(s.M)
	g.I = s.I

	return g
}

func NewGTShare() *GTShare {
	s := GTShare{}
	s.X = new(bn256.GT)
	s.M = new(bn256.GT)

	return &s
}

func (g *GTShare) SetFromShare(s *Share) *GTShare {
	g.X = new(bn256.GT).ScalarBaseMult(s.X)
	g.M = new(bn256.GT).ScalarBaseMult(s.M)
	g.I = s.I

	return g
}

func JoinSharesG1(shares []*G1Share) *bn256.G1 {
	g := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for _, e := range shares {
		g.Add(g, e.X)
	}
	return g
}

func JoinSharesG2(shares []*G2Share) *bn256.G2 {
	g := new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	for _, e := range shares {
		g.Add(g, e.X)
	}

	return g
}

func JoinSharesGT(shares []*GTShare) *bn256.GT {
	g := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	for _, e := range shares {
		g.Add(g, e.X)
	}

	return g
}
