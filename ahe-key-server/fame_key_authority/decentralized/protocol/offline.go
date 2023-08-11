package protocol

import (
	"crypto/rand"
	"github.com/fentec-project/gofe/sample"
	"log"
	"math/big"
	"time"
)

var LambdaSumMauerShare []*MauerShare

func SetFakeLamda(myI int) error {
	var err error
	Lambda[myI], err = rand.Int(rand.Reader, P)
	if err != nil {
		return err
	}
	if myI == 0 {
		Lambda[myI] = big.NewInt(1)
	} else {
		Lambda[myI] = big.NewInt(0)
	}

	return nil
}

func FakeTriplesGen(myI, numTriples int) {
	for i := 0; i < numTriples; i++ {
		if myI == 0 {
			a := Share{X: big.NewInt(2), M: big.NewInt(2), I: myI}
			b := Share{X: big.NewInt(3), M: big.NewInt(3), I: myI}
			c := Share{X: big.NewInt(6), M: big.NewInt(6), I: myI}

			t := Triple{&a, &b, &c}

			TriplesChan[myI] <- &t
			sampler := sample.NewUniform(P)
			x, _ := sampler.Sample()
			r := Share{X: x, M: new(big.Int).Set(x), I: myI}
			RandChan[myI] <- &r
		} else {
			a := Share{X: big.NewInt(0), M: big.NewInt(0), I: myI}
			b := Share{X: big.NewInt(0), M: big.NewInt(0), I: myI}
			c := Share{X: big.NewInt(0), M: big.NewInt(0), I: myI}

			t := Triple{&a, &b, &c}

			TriplesChan[myI] <- &t

			r := Share{X: big.NewInt(0), M: big.NewInt(0), I: myI}
			RandChan[myI] <- &r
		}
	}
}

func GenLambda(myI, numAuth, threshold int, outChan chan error) error {
	var err error
	Lambda[myI], err = rand.Int(rand.Reader, P)
	if err != nil {
		return err
	}

	LambdaSumMauerShare[myI] = NewMauerShare(myI, numAuth, threshold)
	lambdaShare := NewMauerShare(myI, numAuth, threshold)
	for i := 0; i < numAuth; i++ {
		if i == myI {
			err = lambdaShare.ShareValue(Lambda[i], i, myI, nil)
			if err != nil {
				if outChan != nil {
					outChan <- err
				}
				return err
			}
		} else {
			err = lambdaShare.ShareValue(nil, i, myI, nil)
			if err != nil {
				if outChan != nil {
					outChan <- err
				}
				return err
			}
		}
		LambdaSumMauerShare[myI].Add(LambdaSumMauerShare[myI], lambdaShare, nil)
	}

	if outChan != nil {
		outChan <- nil
	}

	return nil
}

func MauerShareShareX(share *Share, numAuth, threshold int) (*MauerShare, error) {
	xShare := NewMauerShare(share.I, numAuth, threshold)
	xSumShare := NewMauerShare(share.I, numAuth, threshold)

	var err error
	for i := 0; i < numAuth; i++ {
		if i == share.I {
			err = xShare.ShareValue(share.X, i, share.I, nil)
			if err != nil {
				return nil, err
			}
		} else {
			err = xShare.ShareValue(nil, i, share.I, nil)
			if err != nil {
				return nil, err
			}
		}
		xSumShare.Add(xSumShare, xShare, nil)
	}

	return xSumShare, nil
}

func AuthShare(share *Share, numAuth, threshold int) (*Share, *MauerShare, error) {
	xSumShare, err := MauerShareShareX(share, numAuth, threshold)
	if err != nil {
		return nil, nil, err
	}
	m, err := rand.Int(rand.Reader, P)
	if err != nil {
		return nil, nil, err
	}
	share.M.Set(m)
	mFakeShare := &Share{X: m, M: nil, I: share.I}
	mSumShare, err := MauerShareShareX(mFakeShare, numAuth, threshold)

	lambdaX := NewMauerShare(share.I, numAuth, threshold)
	err = lambdaX.Mul(LambdaSumMauerShare[share.I], xSumShare, nil)
	if err != nil {
		return nil, nil, err
	}

	residual := NewMauerShare(share.I, numAuth, threshold)
	residual.Sub(mSumShare, lambdaX, nil)

	residualOpen, err := residual.OpenTo(0, nil)
	if err != nil {
		return nil, nil, err
	}

	if share.I == 0 {
		share.M.Sub(share.M, residualOpen)
		share.M.Mod(share.M, P)
	}

	return share, xSumShare, nil
}

func GenerateRandShare(myI, numAuth, threshold int) (*Share, error) {
	x, err := rand.Int(rand.Reader, P)
	if err != nil {
		return nil, err
	}

	r := &Share{X: x, M: new(big.Int), I: myI}

	_, _, err = AuthShare(r, numAuth, threshold)

	return r, err
}

func GenerateTriple(myI, numAuth, threshold int) (*Triple, error) {
	x, err := rand.Int(rand.Reader, P)
	if err != nil {
		return nil, err
	}
	a := &Share{X: x, M: new(big.Int), I: myI}
	_, aMauer, err := AuthShare(a, numAuth, threshold)
	if err != nil {
		return nil, err
	}

	y, err := rand.Int(rand.Reader, P)
	if err != nil {
		return nil, err
	}
	b := &Share{X: y, M: new(big.Int), I: myI}
	_, bMauer, err := AuthShare(b, numAuth, threshold)
	if err != nil {
		return nil, err
	}

	abMauer := NewMauerShare(myI, numAuth, threshold)
	err = abMauer.Mul(aMauer, bMauer, nil)
	if err != nil {
		return nil, err
	}

	z, err := rand.Int(rand.Reader, P)
	if err != nil {
		return nil, err
	}
	ab := &Share{X: z, M: new(big.Int), I: myI}
	if err != nil {
		return nil, err
	}
	abParialSumMauer, err := MauerShareShareX(ab, numAuth, threshold)
	if err != nil {
		return nil, err
	}
	residual := NewMauerShare(myI, numAuth, threshold)
	residual.Sub(abParialSumMauer, abMauer, nil)

	residualOpen, err := residual.OpenTo(0, nil)
	if err != nil {
		return nil, err
	}

	if myI == 0 {
		ab.X.Sub(ab.X, residualOpen)
		ab.X.Mod(ab.X, P)
	}

	_, _, err = AuthShare(ab, numAuth, threshold)

	return &Triple{A: a, B: b, C: ab}, err
}

func ContinuousGen(myI, numAuth, threshold int, triplesChan chan *Triple, randChan chan *Share) {
	command := ""
	for {
		if myI == 0 {
			command = ""
			if len(randChan) < BackupNum {
				command = "rand"
			} else if len(triplesChan) < BackupNum {
				command = "triple"
			}

			if command != "" {
				for i := 1; i < len(ConnectionsOffline); i++ {
					_, err := ConnectionsOffline[0][i].Write([]byte(command + "\n"))
					if err != nil {
						log.Fatal("Fail writing ")
					}
				}
			}
		} else {
			msg, err := ConnectionsReadersOffline[myI][0].ReadSlice(byte('\n'))
			if err != nil {
				log.Fatal("Fail reading")
			}
			command = string(msg)[:len(string(msg))-1]
		}

		if command == "rand" {
			r, err := GenerateRandShare(myI, numAuth, threshold)
			if err != nil {
				log.Fatal("fail generating rand shares", err)
			}
			randChan <- r
			continue
		}
		if command == "triple" {
			triple, err := GenerateTriple(myI, numAuth, threshold)
			if err != nil {
				log.Fatal("fail generating triples", err)
			}
			triplesChan <- triple
			continue
		}
		time.Sleep(time.Second)
	}
}
