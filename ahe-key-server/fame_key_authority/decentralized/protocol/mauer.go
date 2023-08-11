package protocol

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
)

type MauerShare struct {
	Shares     []*big.Int
	MyI        int
	NumParties int
	Threshold  int
}

func NewMauerShare(myI, numPartis, threshold int) *MauerShare {
	var share MauerShare
	share.Shares = make([]*big.Int, Choose(numPartis-1, numPartis-threshold-1))
	for i, _ := range share.Shares {
		share.Shares[i] = new(big.Int)
	}
	share.MyI = myI
	share.NumParties = numPartis
	share.Threshold = threshold

	return &share
}

func SplitVal(val *big.Int, n int) ([]*big.Int, error) {
	vec := make([]*big.Int, n)
	var err error
	sum := big.NewInt(0)
	for i := 0; i < n-1; i++ {
		vec[i], err = rand.Int(rand.Reader, P)
		if err != nil {
			return nil, err
		}
		sum.Add(sum, vec[i])
	}
	vec[n-1] = new(big.Int).Sub(val, sum)
	vec[n-1] = vec[n-1].Mod(vec[n-1], P)

	return vec, err
}

func (share *MauerShare) ShareValue(val *big.Int, senderI, myI int, outChan chan error) error {
	subsetsWithout := SubsetsWithout(share.NumParties, share.NumParties-share.Threshold-1, myI)
	transmittedShares := make([]*big.Int, len(subsetsWithout))
	subsets := Subsets(share.NumParties, share.NumParties-share.Threshold)
	if senderI != myI {
		msg, err := ConnectionsReadersOffline[myI][senderI].ReadBytes('\n')
		if err != nil {
			fmt.Println("Error receiving share", err)
			if outChan != nil {
				outChan <- err
			}
			return err
		}
		err = json.Unmarshal(msg, &transmittedShares)
		if err != nil {
			fmt.Println("Error unmarshalling", err, string(msg))
			if outChan != nil {
				outChan <- err
			}
			return err
		}

		share.Shares = transmittedShares

	} else {
		split, err := SplitVal(val, Choose(share.NumParties, share.NumParties-share.Threshold))
		if err != nil {
			return err
		}
		transmittedShares := make([][]*big.Int, share.NumParties)

		for i, e := range subsets {
			for _, j := range e {
				transmittedShares[j] = append(transmittedShares[j], split[i])
			}
		}

		for i := 0; i < share.NumParties; i++ {
			if i == myI {
				share.Shares = transmittedShares[i]
			} else {
				transmittedShareBytes, err := json.Marshal(transmittedShares[i])
				if err != nil {
					fmt.Println("Error marshalling", err)
					if outChan != nil {
						outChan <- err
					}
					return err
				}
				transmittedShareBytes = append(transmittedShareBytes, byte('\n'))

				_, err = ConnectionsOffline[myI][i].Write(transmittedShareBytes)
				if err != nil {
					fmt.Println("Error receiving", err)
					if outChan != nil {
						outChan <- err
					}
					return err
				}
			}

		}

	}
	if outChan != nil {
		outChan <- nil
	}
	return nil
}

func (share *MauerShare) Open(outChan chan *big.Int) (*big.Int, error) {
	allShares := make([][]*big.Int, share.NumParties)
	allShares[share.MyI] = share.Shares

	shareBytes, err := json.Marshal(share.Shares)
	if err != nil {
		fmt.Println("Error marshalling", err)
		if outChan != nil {
			outChan <- nil
		}
		return nil, err
	}
	shareBytes = append(shareBytes, '\n')

	for i := 0; i < share.MyI; i++ {
		msg, err := ConnectionsReadersOffline[share.MyI][i].ReadBytes('\n')
		if err != nil {
			fmt.Println("Error reading", err)
			if outChan != nil {
				outChan <- nil
			}
			return nil, err
		}
		err = json.Unmarshal(msg, &(allShares[i]))
		if err != nil {
			fmt.Println("Error unmarshalling", err)
			if outChan != nil {
				outChan <- nil
			}
			return nil, err
		}

		_, err = ConnectionsOffline[share.MyI][i].Write(shareBytes)
		if err != nil {
			fmt.Println("Error writing", err)

			if outChan != nil {
				outChan <- nil
			}
			return nil, err
		}
	}

	for i := share.MyI + 1; i < len(ConnectionsOffline); i++ {
		_, err = ConnectionsOffline[share.MyI][i].Write(shareBytes)
		if err != nil {
			fmt.Println("Error writing", err)

			if outChan != nil {
				outChan <- nil
			}
			return nil, err
		}

		msg, err := ConnectionsReadersOffline[share.MyI][i].ReadBytes('\n')
		if err != nil {
			fmt.Println("Error reading", err)
			if outChan != nil {
				outChan <- nil
			}
			return nil, err
		}
		err = json.Unmarshal(msg, &(allShares[i]))
		if err != nil {
			fmt.Println("Error unmarshalling", err)
			if outChan != nil {
				outChan <- nil
			}
			return nil, err
		}
	}

	sets := Subsets(share.NumParties, share.NumParties-share.Threshold)
	indexes := make([]int, share.NumParties)
	sum := big.NewInt(0)
	for _, subset := range sets {
		val := allShares[subset[0]][indexes[subset[0]]]
		for _, el := range subset {
			if val.Cmp(allShares[el][indexes[el]]) != 0 {
				fmt.Println("Error check", el, indexes[el], subset, val, allShares[el])
				if outChan != nil {
					outChan <- nil
				}
				return nil, fmt.Errorf("check fail")
			}
			indexes[el] += 1
		}
		sum.Add(sum, val)
	}
	sum.Mod(sum, P)

	if outChan != nil {
		outChan <- sum
	}

	return sum, nil
}

func (share *MauerShare) OpenTo(receivingI int, outChan chan *big.Int) (*big.Int, error) {
	if receivingI != share.MyI {
		shareBytes, err := json.Marshal(share.Shares)
		if err != nil {
			fmt.Println("Error marshalling", err)
			if outChan != nil {
				outChan <- nil
			}
			return nil, err
		}
		shareBytes = append(shareBytes, '\n')

		_, err = ConnectionsOffline[share.MyI][receivingI].Write(shareBytes)
		if err != nil {
			fmt.Println("Error writing", err)

			if outChan != nil {
				outChan <- nil
			}
			return nil, err
		}
		return nil, nil
	} else {
		allShares := make([][]*big.Int, share.NumParties)
		allShares[share.MyI] = share.Shares
		for i := 0; i < share.NumParties; i++ {
			if i == receivingI {
				continue
			}
			msg, err := ConnectionsReadersOffline[share.MyI][i].ReadBytes('\n')
			if err != nil {
				fmt.Println("Error reading", err)
				if outChan != nil {
					outChan <- nil
				}
				return nil, err
			}
			err = json.Unmarshal(msg, &(allShares[i]))
			if err != nil {
				fmt.Println("Error unmarshalling", err)
				if outChan != nil {
					outChan <- nil
				}
				return nil, err
			}
		}

		sets := Subsets(share.NumParties, share.NumParties-share.Threshold)
		indexes := make([]int, share.NumParties)
		sum := big.NewInt(0)
		for _, subset := range sets {
			val := allShares[subset[0]][indexes[subset[0]]]
			for _, el := range subset {
				if val.Cmp(allShares[el][indexes[el]]) != 0 {

					//fmt.Println("Error check", el, indexes[el], subset, val, allShares[el])
					if outChan != nil {
						outChan <- nil
					}
					return nil, fmt.Errorf("check fail")
				}
				indexes[el] += 1
			}
			sum.Add(sum, val)
		}
		sum.Mod(sum, P)

		if outChan != nil {
			outChan <- sum
		}

		return sum, nil
	}
}

func (share *MauerShare) Add(share1 *MauerShare, share2 *MauerShare, outChan chan error) {
	for i, e := range share.Shares {
		e.Add(share1.Shares[i], share2.Shares[i])
		e.Mod(e, P)
	}

	if outChan != nil {
		outChan <- nil
	}
}

func (share *MauerShare) Sub(share1 *MauerShare, share2 *MauerShare, outChan chan error) {
	for i, e := range share.Shares {
		e.Sub(share1.Shares[i], share2.Shares[i])
		e.Mod(e, P)
	}

	if outChan != nil {
		outChan <- nil
	}
}

func (share *MauerShare) Mul(share1 *MauerShare, share2 *MauerShare, outChan chan error) error {
	sharePairs := make([][]*big.Int, len(share1.Shares))
	for i, e := range share1.Shares {
		sharePairs[i] = make([]*big.Int, len(share2.Shares))
		for j, f := range share2.Shares {
			sharePairs[i][j] = new(big.Int).Mul(e, f)
			sharePairs[i][j].Mod(sharePairs[i][j], P)
		}
	}

	obtainedShares := make([][][]*MauerShare, share.NumParties)
	indicator := make([]int, share.NumParties)
	for auth := 0; auth < share.NumParties; auth++ {
		obtainedShares[auth] = make([][]*MauerShare, len(share1.Shares))
		indicator[auth] = 0
		for i := 0; i < len(share1.Shares); i++ {
			obtainedShares[auth][i] = make([]*MauerShare, len(share2.Shares))
			for j := 0; j < len(share2.Shares); j++ {
				obtainedShares[auth][i][j] = NewMauerShare(i, share.NumParties, share.Threshold)
				//fmt.Println(auth, i, j, sharePairs[i][j])
				if auth == share.MyI {
					obtainedShares[auth][i][j].ShareValue(sharePairs[i][j], auth, share.MyI, nil)
				} else {
					obtainedShares[auth][i][j].ShareValue(nil, auth, share.MyI, nil)
				}
			}
		}
	}

	subsets := Subsets(share.NumParties, share.NumParties-share.Threshold)
	checkedShares := make([][]*MauerShare, len(subsets))
	for i := 0; i < len(subsets); i++ {
		checkedShares[i] = make([]*MauerShare, len(subsets))
	}
	checkShare := NewMauerShare(share.MyI, share.NumParties, share.Threshold)
	for i, e := range subsets {
		for j, f := range subsets {
			intersection := Intrersect(e, f)
			checkedShares[i][j] = obtainedShares[intersection[0]][indicator[intersection[0]]/len(share1.Shares)][indicator[intersection[0]]%len(share2.Shares)]
			indicator[intersection[0]] = indicator[intersection[0]] + 1
			for _, auth := range intersection[1:] {
				checkShare.Sub(checkedShares[i][j], obtainedShares[auth][indicator[auth]/len(share1.Shares)][indicator[auth]%len(share2.Shares)], nil)
				//fmt.Println(checkShare)
				check, err := checkShare.Open(nil)
				if check.Cmp(big.NewInt(0)) != 0 || err != nil {
					outChan <- fmt.Errorf("check fail")
				}
				indicator[auth] = indicator[auth] + 1
			}
		}
	}

	for _, e := range share.Shares {
		e.SetInt64(0)
	}
	for i, _ := range subsets {
		for j, _ := range subsets {
			share.Add(share, checkedShares[i][j], nil)
		}
	}

	if outChan != nil {
		outChan <- nil
	}

	return nil

}

func Subsets(n, t int) [][]int {
	s := Set(n)

	return SubsetsRecursive(s, t)
}

func Set(n int) []int {
	s := make([]int, n)
	for i := 0; i < n; i++ {
		s[i] = i
	}
	return s
}

func SetWithout(n, without int) []int {
	s := make([]int, n-1)
	for i := 0; i < n; i++ {
		if i < without {
			s[i] = i
		}
		if i > without {
			s[i-1] = i
		}
	}
	return s
}

func SubsetsWithout(n, t, without int) [][]int {
	s := SetWithout(n, without)

	return SubsetsRecursive(s, t)
}

func SubsetsRecursive(s []int, t int) [][]int {
	if t == 0 {
		return [][]int{[]int{}}
	}
	if len(s) == t {
		return [][]int{s[:]}
	}

	smallerMinusOne := SubsetsRecursive(s[1:], t-1)
	smaller := SubsetsRecursive(s[1:], t)

	res := [][]int{}
	for _, set := range smallerMinusOne {
		newSet := append([]int{s[0]}, set...)
		res = append(res, newSet)
	}
	for _, set := range smaller {
		res = append(res, set)
	}

	return res
}

func Choose(n, k int) int {
	if n <= 1 || k == 0 || n == k {
		return 1
	}
	if newK := n - k; newK < k {
		k = newK
	}
	if k == 1 {
		return n
	}
	ret := n - k + 1
	for i, j := ret+1, 2; j <= k; i, j = i+1, j+1 {
		ret = ret * i / j
	}
	return ret
}

func Intrersect(s1, s2 []int) []int {
	s := make([]int, 0)
	i := 0
	s1Len := len(s1)
	for _, e := range s2 {
		for i < s1Len && s1[i] <= e {
			if s1[i] == e {
				s = append(s, e)
			}
			i++
		}
	}

	return s
}
