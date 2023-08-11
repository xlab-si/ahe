package protocol

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"strconv"
	"strings"
)

var P = bn256.Order

// FAMEDecSecKey represents a master secret key of a FAME scheme.
type FAMEDecSecKey struct {
	PartInt [7]*Share
	PartG1  [3]*G1Share
}

// FAMEDecPubKey represents a public key of a FAME scheme.
type FAMEDecPubKey struct {
	PartG2  [2]*G2Share
	PartGT  [2]*GTShare
	R       [4]*Share
	RPartG2 [2]*G2Share
	RPartGT [2]*GTShare
}

var DecPubKey []*FAMEDecPubKey
var DecSecKey []*FAMEDecSecKey
var PubKey []*abe.FAMEPubKey

// FAMEDecAttribKeys represents keys corresponding to attributes possessed by
// an entity and used for decrypting in a FAME scheme.
type FAMEDecAttribKeys struct {
	K0        [3]*G2Share
	K         [][3]*G1Share
	KPrime    [3]*G1Share
	R         [][3]*Share
	RK0       [3]*G2Share
	RK        [][3]*G1Share
	RKPrime   [3]*G1Share
	AttribToI map[string]int
}

// GenerateDecMasterKeys generates a new set of public keys, needed
// for encrypting data, and master secret keys needed for generating
// keys for decrypting.
func GenerateDecMasterKeys(myI int, decPubKeyChan chan *FAMEDecPubKey, pubKeyChan chan *abe.FAMEPubKey, secKeyChan chan *FAMEDecSecKey) (*abe.FAMEPubKey, *FAMEDecPubKey, *FAMEDecSecKey, error) {
	var partIntShare [7]*Share
	var partG1Share [3]*G1Share
	var partG2Share [2]*G2Share
	var partGTShare [2]*GTShare
	for i, _ := range partIntShare {
		r := <-RandChan[myI]
		partIntShare[i] = r
	}

	partG1Share[0] = NewG1Share().SetFromShare(partIntShare[4])
	partG1Share[1] = NewG1Share().SetFromShare(partIntShare[5])
	partG1Share[2] = NewG1Share().SetFromShare(partIntShare[6])

	partG2Share[0] = NewG2Share().SetFromShare(partIntShare[0])
	partG2Share[1] = NewG2Share().SetFromShare(partIntShare[1])

	dAPlusD := make([]*Share, 2)
	dA, err := NewShare().Mul(partIntShare[0], partIntShare[4])
	if err != nil {
		return nil, nil, nil, err
	}
	dAPlusD[0] = NewShare().Add(dA, partIntShare[6])
	partGTShare[0] = NewGTShare().SetFromShare(dAPlusD[0])

	dA2, err := NewShare().Mul(partIntShare[1], partIntShare[5])
	if err != nil {
		return nil, nil, nil, err
	}
	dAPlusD[1] = NewShare().Add(dA2, partIntShare[6])
	partGTShare[1] = NewGTShare().SetFromShare(dAPlusD[1])

	DecPubKey[myI] = &FAMEDecPubKey{PartG2: partG2Share, PartGT: partGTShare}
	DecSecKey[myI] = &FAMEDecSecKey{PartInt: partIntShare, PartG1: partG1Share}

	// make a kind of macs for pubkey to be able to check correctness when joining
	for i := 0; i < 4; i++ {
		DecPubKey[myI].R[i] = <-RandChan[myI]
	}
	for j := 0; j < 2; j++ {
		rPartG2, err := NewShare().Mul(partIntShare[j], DecPubKey[myI].R[j])
		if err != nil {
			return nil, nil, nil, err
		}
		DecPubKey[myI].RPartG2[j] = NewG2Share().SetFromShare(rPartG2)
	}
	for j := 0; j < 2; j++ {
		rPartGT, err := NewShare().Mul(dAPlusD[j], DecPubKey[myI].R[j+2])
		if err != nil {
			return nil, nil, nil, err
		}
		DecPubKey[myI].RPartGT[j] = NewGTShare().SetFromShare(rPartGT)
	}

	if decPubKeyChan != nil {
		decPubKeyChan <- DecPubKey[myI]
	}

	if secKeyChan != nil {
		secKeyChan <- DecSecKey[myI]
	}

	PubKey[myI], err = DecPubKey[myI].Open()
	if err != nil {
		return nil, nil, nil, err
	}

	if pubKeyChan != nil {
		pubKeyChan <- PubKey[myI]
	}

	return PubKey[myI], DecPubKey[myI], DecSecKey[myI], nil
}

func (s *FAMEDecPubKey) Open() (*abe.FAMEPubKey, error) {
	openShareString, err := FameDecPubToRaw(s)
	myI := s.PartG2[0].I

	//openShareBytes, err := json.Marshal(s.X)
	if err != nil {
		return nil, err
	}
	openShareBytes := append([]byte(openShareString), byte('\n'))
	decPubKey := make([]*FAMEDecPubKey, len(Connections))
	decPubKey[myI] = s
	for i := 0; i < myI; i++ {
		conn := Connections[myI][i]
		connReader := ConnectionsReaders[myI][i]
		msg, err := connReader.ReadBytes('\n')

		if err != nil {
			fmt.Println(err, myI)

			return nil, err
		}
		decPubKey[i], err = FameDecPubFromRaw(string(msg))
		if err != nil {
			fmt.Println(err, myI)

			return nil, err
		}

		_, err = conn.Write(openShareBytes)
		if err != nil {
			fmt.Println(err, myI)

			return nil, err
		}
	}

	for i := myI + 1; i < len(Connections); i++ {
		conn := Connections[myI][i]
		_, err = conn.Write(openShareBytes)
		if err != nil {
			fmt.Println(err, myI)

			return nil, err
		}

		connReader := ConnectionsReaders[myI][i]
		msg, err := connReader.ReadBytes('\n')
		if err != nil {
			fmt.Println(err, myI)

			return nil, err
		}

		decPubKey[i], err = FameDecPubFromRaw(string(msg))
		if err != nil {
			fmt.Println(err, myI)

			return nil, err
		}
	}

	pubKey, err := JoinDecPubKeys(decPubKey)

	return pubKey, err
}

func JoinDecPubKeys(shares []*FAMEDecPubKey) (*abe.FAMEPubKey, error) {
	var pubKey abe.FAMEPubKey
	for i := 0; i < 2; i++ {
		g2Shares := make([]*G2Share, len(shares))
		for j, e := range shares {
			g2Shares[j] = e.PartG2[i]
		}
		pubKey.PartG2[i] = JoinSharesG2(g2Shares)
	}

	for i := 0; i < 2; i++ {
		gTShares := make([]*GTShare, len(shares))
		for j, e := range shares {
			gTShares[j] = e.PartGT[i]
		}
		pubKey.PartGT[i] = JoinSharesGT(gTShares)
	}

	var pubKeyCheck abe.FAMEPubKey
	for i := 0; i < 2; i++ {
		g2Shares := make([]*G2Share, len(shares))
		rShares := make([]*Share, len(shares))
		for j, e := range shares {
			g2Shares[j] = e.RPartG2[i]
			rShares[j] = e.R[i]
		}
		pubKeyCheck.PartG2[i] = JoinSharesG2(g2Shares)
		r := JoinShares(rShares)
		check := new(bn256.G2).ScalarMult(pubKey.PartG2[i], r)
		if check.String() != pubKeyCheck.PartG2[i].String() {
			return nil, fmt.Errorf("mac check of the public key fail")
		}
	}

	for i := 0; i < 2; i++ {
		gTShares := make([]*GTShare, len(shares))
		rShares := make([]*Share, len(shares))
		for j, e := range shares {
			gTShares[j] = e.RPartGT[i]
			rShares[j] = e.R[i+2]
		}
		pubKeyCheck.PartGT[i] = JoinSharesGT(gTShares)
		r := JoinShares(rShares)
		check := new(bn256.GT).ScalarMult(pubKey.PartGT[i], r)
		if check.String() != pubKeyCheck.PartGT[i].String() {
			return nil, fmt.Errorf("mac check of the public key fail")
		}
	}

	return &pubKey, nil
}

func JoinDecSecKeys(shares []*FAMEDecSecKey) *abe.FAMESecKey {
	var secKey abe.FAMESecKey
	for i := 0; i < 4; i++ {
		iShares := make([]*Share, len(shares))
		for j, e := range shares {
			iShares[j] = e.PartInt[i]
		}
		secKey.PartInt[i] = JoinShares(iShares)
	}

	for i := 0; i < 3; i++ {
		g1Shares := make([]*G1Share, len(shares))
		for j, e := range shares {
			g1Shares[j] = e.PartG1[i]
		}
		secKey.PartG1[i] = JoinSharesG1(g1Shares)
	}

	return &secKey
}

func GenerateDecAttribKeys(gamma []string, sk *FAMEDecSecKey, myI int, outChan chan *FAMEDecAttribKeys) (*FAMEDecAttribKeys, error) {
	r1 := <-RandChan[myI]
	r2 := <-RandChan[myI]

	// make a kind of macs for pubkey to be able to check correctness when joining
	r := make([][3]*Share, len(gamma)+2)
	for i := 0; i < len(r); i++ {
		for j := 0; j < 3; j++ {
			r[i][j] = <-RandChan[myI]
		}
	}
	//for j := 0; j < 2; j++ {
	//	rPartG2, err := NewShare().Mul(partIntShare[j], DecPubKey[myI].R[j])
	//	if err != nil {
	//		return nil, nil, nil, err
	//	}
	//	DecPubKey[myI].RPartG2[j] = NewG2Share().SetFromShare(rPartG2)
	//}
	//for j := 0; j < 2; j++ {
	//	rPartGT, err := NewShare().Mul(dAPlusD[j], DecPubKey[myI].R[j+2])
	//	if err != nil {
	//		return nil, nil, nil, err
	//	}
	//	DecPubKey[myI].RPartGT[j] = NewGTShare().SetFromShare(rPartGT)
	//}

	var k0 [3]*G2Share
	var rK0 [3]*G2Share
	b1R1, err := NewShare().Mul(sk.PartInt[2], r1)
	if err != nil {
		return nil, err
	}
	k0[0] = NewG2Share().SetFromShare(b1R1)
	rk00, err := NewShare().Mul(r[0][0], b1R1)
	rK0[0] = NewG2Share().SetFromShare(rk00)

	b2R2, err := NewShare().Mul(sk.PartInt[3], r2)
	if err != nil {
		return nil, err
	}
	k0[1] = NewG2Share().SetFromShare(b2R2)
	rk01, err := NewShare().Mul(r[0][1], b2R2)
	if err != nil {
		return nil, err
	}
	rK0[1] = NewG2Share().SetFromShare(rk01)

	r1R2 := NewShare().Add(r1, r2)
	if err != nil {
		return nil, err
	}
	k0[2] = NewG2Share().SetFromShare(r1R2)
	rk02, err := NewShare().Mul(r[0][2], r1R2)
	if err != nil {
		return nil, err
	}
	rK0[2] = NewG2Share().SetFromShare(rk02)

	a1Inv, err := NewShare().Invert(sk.PartInt[0])
	if err != nil {
		return nil, err
	}
	a2Inv, err := NewShare().Invert(sk.PartInt[1])
	if err != nil {
		return nil, err
	}
	aInv := [2]*Share{a1Inv, a2Inv}

	var pow [2][3]*Share
	pow[0][0], err = NewShare().Mul(b1R1, a1Inv)
	if err != nil {
		return nil, err
	}
	pow[0][1], err = NewShare().Mul(b2R2, a1Inv)
	if err != nil {
		return nil, err
	}
	pow[0][2], err = NewShare().Mul(r1R2, a1Inv)
	if err != nil {
		return nil, err
	}
	pow[1][0], err = NewShare().Mul(b1R1, a2Inv)
	if err != nil {
		return nil, err
	}
	pow[1][1], err = NewShare().Mul(b2R2, a2Inv)
	if err != nil {
		return nil, err
	}
	pow[1][2], err = NewShare().Mul(r1R2, a2Inv)
	if err != nil {
		return nil, err
	}

	k := make([][3]*G1Share, len(gamma))
	rK := make([][3]*G1Share, len(gamma))
	attribToI := make(map[string]int)
	for i, y := range gamma {
		sigmaY := <-RandChan[myI]

		for t := 0; t < 2; t++ {
			hs0, err := bn256.HashG1(y + " 0 " + strconv.Itoa(t))
			if err != nil {
				return nil, err
			}

			h0 := NewG1Share().SetFromShareWithBase(pow[t][0], hs0)
			r0, err := NewShare().Mul(r[1+i][t], pow[t][0])
			if err != nil {
				return nil, err
			}
			rKh0 := NewG1Share().SetFromShareWithBase(r0, hs0)

			hs1, err := bn256.HashG1(y + " 1 " + strconv.Itoa(t))
			if err != nil {
				return nil, err
			}
			h1 := NewG1Share().SetFromShareWithBase(pow[t][1], hs1)
			r1, err := NewShare().Mul(r[1+i][t], pow[t][1])
			if err != nil {
				return nil, err
			}
			rKh1 := NewG1Share().SetFromShareWithBase(r1, hs1)

			hs2, err := bn256.HashG1(y + " 2 " + strconv.Itoa(t))
			if err != nil {
				return nil, err
			}
			h2 := NewG1Share().SetFromShareWithBase(pow[t][2], hs2)
			r2, err := NewShare().Mul(r[1+i][t], pow[t][2])
			if err != nil {
				return nil, err
			}
			rKh2 := NewG1Share().SetFromShareWithBase(r2, hs2)

			hs3, err := NewShare().Mul(sigmaY, aInv[t])
			if err != nil {
				return nil, err
			}
			h3 := NewG1Share().SetFromShare(hs3)
			r3, err := NewShare().Mul(r[1+i][t], hs3)
			if err != nil {
				return nil, err
			}
			rKh3 := NewG1Share().SetFromShare(r3)

			k[i][t] = NewG1Share().Mul(h0, h1)
			k[i][t] = k[i][t].Mul(k[i][t], h2)
			k[i][t] = k[i][t].Mul(k[i][t], h3)
			rK[i][t] = NewG1Share().Mul(rKh0, rKh1)
			rK[i][t] = rK[i][t].Mul(rK[i][t], rKh2)
			rK[i][t] = rK[i][t].Mul(rK[i][t], rKh3)
		}

		sigmaYNeg := NewShare().Neg(sigmaY)
		k[i][2] = NewG1Share().SetFromShare(sigmaYNeg)
		rKI, err := NewShare().Mul(r[1+i][2], sigmaYNeg)
		if err != nil {
			return nil, err
		}
		rK[i][2] = NewG1Share().SetFromShare(rKI)

		attribToI[y] = i
	}

	sigmaPrime := <-RandChan[myI]
	var k2 [3]*G1Share
	var rK2 [3]*G1Share
	for t := 0; t < 2; t++ {
		hs0, err := bn256.HashG1("0 0 0 " + strconv.Itoa(t))
		if err != nil {
			return nil, err
		}
		h0 := NewG1Share().SetFromShareWithBase(pow[t][0], hs0)
		r0, err := NewShare().Mul(r[1+len(k)][t], pow[t][0])
		if err != nil {
			return nil, err
		}
		rKh0 := NewG1Share().SetFromShareWithBase(r0, hs0)

		hs1, err := bn256.HashG1("0 0 1 " + strconv.Itoa(t))
		if err != nil {
			return nil, err
		}
		h1 := NewG1Share().SetFromShareWithBase(pow[t][1], hs1)
		r1, err := NewShare().Mul(r[1+len(k)][t], pow[t][1])
		if err != nil {
			return nil, err
		}
		rKh1 := NewG1Share().SetFromShareWithBase(r1, hs1)

		hs2, err := bn256.HashG1("0 0 2 " + strconv.Itoa(t))
		if err != nil {
			return nil, err
		}
		h2 := NewG1Share().SetFromShareWithBase(pow[t][2], hs2)
		r2, err := NewShare().Mul(r[1+len(k)][t], pow[t][2])
		if err != nil {
			return nil, err
		}
		rKh2 := NewG1Share().SetFromShareWithBase(r2, hs2)

		hs3, err := NewShare().Mul(sigmaPrime, aInv[t])
		if err != nil {
			return nil, err
		}
		h3 := NewG1Share().SetFromShare(hs3)
		r3, err := NewShare().Mul(r[1+len(k)][t], hs3)
		if err != nil {
			return nil, err
		}
		rKh3 := NewG1Share().SetFromShare(r3)

		k2[t] = NewG1Share().Mul(h0, h1)
		k2[t] = k2[t].Mul(k2[t], h2)
		k2[t] = k2[t].Mul(k2[t], h3)
		k2[t] = k2[t].Mul(k2[t], sk.PartG1[t])
		rK2[t] = NewG1Share().Mul(rKh0, rKh1)
		rK2[t] = rK2[t].Mul(rK2[t], rKh2)
		rK2[t] = rK2[t].Mul(rK2[t], rKh3)

		skR, err := NewShare().Mul(sk.PartInt[4+t], r[1+len(k)][t])
		if err != nil {
			return nil, err
		}
		gSkR := NewG1Share().SetFromShare(skR)
		rK2[t] = rK2[t].Mul(rK2[t], gSkR)
	}

	sigmaPrimeNeg := NewShare().Neg(sigmaPrime)
	k2[2] = NewG1Share().SetFromShare(sigmaPrimeNeg)
	k2[2] = k2[2].Mul(k2[2], sk.PartG1[2])
	rK22, err := NewShare().Mul(r[1+len(k)][2], sigmaPrimeNeg)
	if err != nil {
		return nil, err
	}
	rK2[2] = NewG1Share().SetFromShare(rK22)
	skR, err := NewShare().Mul(sk.PartInt[6], r[1+len(k)][2])
	if err != nil {
		return nil, err
	}
	gSkR := NewG1Share().SetFromShare(skR)
	rK2[2] = rK2[2].Mul(rK2[2], gSkR)

	res := &FAMEDecAttribKeys{K0: k0, K: k, KPrime: k2, AttribToI: attribToI, R: r, RK0: rK0, RK: rK, RKPrime: rK2}
	if outChan != nil {
		outChan <- res
	}

	return res, nil
}

func JoinDecAttribKeys(shares []*FAMEDecAttribKeys) (*abe.FAMEAttribKeys, error) {
	var attribKey abe.FAMEAttribKeys
	for i := 0; i < 3; i++ {
		g2Shares := make([]*G2Share, len(shares))
		for j, e := range shares {
			g2Shares[j] = e.K0[i]
		}
		attribKey.K0[i] = JoinSharesG2(g2Shares)
	}

	attribKey.K = make([][3]*bn256.G1, len(shares[0].K))
	for m, _ := range shares[0].K {
		for i := 0; i < 3; i++ {
			g1Shares := make([]*G1Share, len(shares))
			for j, e := range shares {
				g1Shares[j] = e.K[m][i]
			}
			attribKey.K[m][i] = JoinSharesG1(g1Shares)
		}
	}

	for i := 0; i < 3; i++ {
		g1Shares := make([]*G1Share, len(shares))
		for j, e := range shares {
			g1Shares[j] = e.KPrime[i]
			//fmt.Println(e.KPrime[i])
		}
		attribKey.KPrime[i] = JoinSharesG1(g1Shares)
	}

	attribKey.AttribToI = shares[0].AttribToI

	var attribKeyCheck abe.FAMEAttribKeys
	for i := 0; i < 3; i++ {
		g2Shares := make([]*G2Share, len(shares))
		rShares := make([]*Share, len(shares))
		for j, e := range shares {
			g2Shares[j] = e.RK0[i]
			rShares[j] = e.R[0][i]
		}
		attribKeyCheck.K0[i] = JoinSharesG2(g2Shares)
		r := JoinShares(rShares)
		check := new(bn256.G2).ScalarMult(attribKey.K0[i], r)
		if check.String() != attribKeyCheck.K0[i].String() {
			fmt.Println(check.String())
			fmt.Println(attribKeyCheck.K0[i].String())
			fmt.Println(i)
			return nil, fmt.Errorf("mac check of the attribute key fail")
		}
	}

	attribKeyCheck.K = make([][3]*bn256.G1, len(shares[0].K))
	for m, _ := range shares[0].RK {
		for i := 0; i < 3; i++ {
			g1Shares := make([]*G1Share, len(shares))
			rShares := make([]*Share, len(shares))
			for j, e := range shares {
				g1Shares[j] = e.RK[m][i]
				rShares[j] = e.R[m+1][i]
			}
			attribKeyCheck.K[m][i] = JoinSharesG1(g1Shares)
			r := JoinShares(rShares)
			check := new(bn256.G1).ScalarMult(attribKey.K[m][i], r)
			if check.String() != attribKeyCheck.K[m][i].String() {
				fmt.Println(check.String())
				fmt.Println(attribKeyCheck.K[m][i].String())
				fmt.Println(m, i)
				return nil, fmt.Errorf("mac check of the attribute key fail")
			}
		}
	}

	for i := 0; i < 3; i++ {
		g1Shares := make([]*G1Share, len(shares))
		rShares := make([]*Share, len(shares))
		for j, e := range shares {
			g1Shares[j] = e.RKPrime[i]
			rShares[j] = e.R[1+len(e.K)][i]
		}
		attribKeyCheck.KPrime[i] = JoinSharesG1(g1Shares)
		r := JoinShares(rShares)
		check := new(bn256.G1).ScalarMult(attribKey.KPrime[i], r)
		if check.String() != attribKeyCheck.KPrime[i].String() {
			fmt.Println(check.String())
			fmt.Println(attribKeyCheck.KPrime[i].String())
			fmt.Println(i)
			return nil, fmt.Errorf("mac check of the attribute key fail, kPrime")
		}
	}

	return &attribKey, nil
}

func FameDecPubToRaw(famePub *FAMEDecPubKey) (string, error) {
	bytes, err := json.Marshal(famePub)

	return string(bytes), err
}

func FameDecPubFromRaw(famePubRaw string) (*FAMEDecPubKey, error) {
	var secKey FAMEDecPubKey
	err := json.Unmarshal([]byte(famePubRaw), &secKey)
	if err != nil {
		return nil, err
	}

	return &secKey, nil
}

func FameDecKeysToRaw(keys *FAMEDecAttribKeys) ([]string, error) {
	var err error
	keyRaw := make([]string, 6+(2*len(keys.K)))

	k0Bytes, err := json.Marshal(keys.K0)
	if err != nil {
		return nil, err
	}
	keyRaw[0] = base64.StdEncoding.EncodeToString(k0Bytes)

	kPrimeBytes, err := json.Marshal(keys.KPrime)
	if err != nil {
		return nil, err
	}
	keyRaw[1] = base64.StdEncoding.EncodeToString(kPrimeBytes)
	attribs := make([]string, len(keys.AttribToI))
	for e, i := range keys.AttribToI {
		attribs[i] = e
	}

	keyRaw[2] = strings.Join(attribs, " ")
	index := 3
	var kiBytes []byte
	for i, ki := range keys.K {
		kiBytes, err = json.Marshal(ki)
		if err != nil {
			return nil, err
		}
		keyRaw[index+i] = base64.StdEncoding.EncodeToString(kiBytes)
	}

	rk0Bytes, err := json.Marshal(keys.RK0)
	if err != nil {
		return nil, err
	}
	keyRaw[len(keys.K)+3] = base64.StdEncoding.EncodeToString(rk0Bytes)

	rkPrimeBytes, err := json.Marshal(keys.RKPrime)
	if err != nil {
		return nil, err
	}
	keyRaw[len(keys.K)+4] = base64.StdEncoding.EncodeToString(rkPrimeBytes)

	rBytes, err := json.Marshal(keys.R)
	if err != nil {
		return nil, err
	}
	keyRaw[len(keys.K)+5] = base64.StdEncoding.EncodeToString(rBytes)
	index = len(keys.K) + 6
	var rkiBytes []byte
	for i, rki := range keys.RK {
		rkiBytes, err = json.Marshal(rki)
		if err != nil {
			return nil, err
		}
		keyRaw[index+i] = base64.StdEncoding.EncodeToString(rkiBytes)
	}

	return keyRaw, nil
}

func FameDecKeysFromRaw(keysRaw []string) (*FAMEDecAttribKeys, error) {
	if len(keysRaw) <= 3 {
		return nil, fmt.Errorf("keys not correct len")
	}

	var k0 [3]*G2Share
	kRaw0, err := base64.StdEncoding.DecodeString(keysRaw[0])
	if err != nil {
		return nil, fmt.Errorf("keys from raw error - 1: %v", err)
	}
	err = json.Unmarshal(kRaw0, &k0)
	if err != nil {
		return nil, err
	}

	var kPrime [3]*G1Share
	kRawPrime, err := base64.StdEncoding.DecodeString(keysRaw[1])
	if err != nil {
		return nil, fmt.Errorf("keys from raw error - 2: %v", err)
	}
	err = json.Unmarshal(kRawPrime, &kPrime)
	if err != nil {
		return nil, err
	}

	rowToAttrib := strings.Split(keysRaw[2], " ")
	attribToI := make(map[string]int)
	for i, e := range rowToAttrib {
		attribToI[e] = i
	}

	k := make([][3]*G1Share, (len(keysRaw)-6)/2)
	for i := 3; i < len(k)+3; i++ {
		var ki [3]*G1Share
		kRawi, err := base64.StdEncoding.DecodeString(keysRaw[i])
		if err != nil {
			return nil, fmt.Errorf("keys from raw error - 3: %v", err)
		}
		err = json.Unmarshal(kRawi, &ki)
		if err != nil {
			return nil, fmt.Errorf("keys from raw error - 3.5: %v", err)
		}

		k[i-3] = ki
	}

	var rk0 [3]*G2Share
	rkRaw0, err := base64.StdEncoding.DecodeString(keysRaw[len(k)+3])
	if err != nil {
		return nil, fmt.Errorf("keys from raw error - 4: %v", err)
	}
	err = json.Unmarshal(rkRaw0, &rk0)
	if err != nil {
		return nil, fmt.Errorf("keys from raw error - 4.5: %v", err)
	}

	var rkPrime [3]*G1Share
	rkRawPrime, err := base64.StdEncoding.DecodeString(keysRaw[len(k)+4])
	if err != nil {
		return nil, fmt.Errorf("keys from raw error - 5: %v", err)
	}
	err = json.Unmarshal(rkRawPrime, &rkPrime)
	if err != nil {
		return nil, fmt.Errorf("keys from raw error - 5.5: %v", err)
	}

	var r [][3]*Share
	rRaw, err := base64.StdEncoding.DecodeString(keysRaw[len(k)+5])
	if err != nil {
		return nil, fmt.Errorf("keys from raw error - 6: %v", err)
	}
	err = json.Unmarshal(rRaw, &r)
	if err != nil {
		return nil, fmt.Errorf("keys from raw error - 6.5: %v", err)
	}

	rk := make([][3]*G1Share, len(k))
	for i := len(k) + 6; i < len(keysRaw); i++ {
		var rki [3]*G1Share
		rkRawi, err := base64.StdEncoding.DecodeString(keysRaw[i])
		if err != nil {
			return nil, fmt.Errorf("keys from raw error - 7: %v", err)
		}
		err = json.Unmarshal(rkRawi, &rki)
		if err != nil {
			return nil, fmt.Errorf("keys from raw error - 7.5: %v", err)
		}

		rk[i-(len(k)+6)] = rki
	}

	return &FAMEDecAttribKeys{
		K0:        k0,
		KPrime:    kPrime,
		K:         k,
		AttribToI: attribToI,
		RK0:       rk0,
		RKPrime:   rkPrime,
		R:         r,
		RK:        rk,
	}, nil
}
