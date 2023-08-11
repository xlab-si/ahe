package utils

import (
	"github.com/fentec-project/gofe/data"
	"math/big"
	"strconv"
	"strings"
)

func MatrixToString(m data.Matrix) string {
	// returns rows, cols, data as a single space separated string
	r := m.Rows()
	c := m.Cols()
	s := strconv.Itoa(r) + " " + strconv.Itoa(c)
	for i, v := range m {
		ter := ""
		if i == r {
			ter = ""
		}
		s = s + v.String() + ter
	}
	return s
}

func MatrixFromString(s string) data.Matrix {
	d := strings.Split(s, " ")
	rows, _ := strconv.Atoi(d[0])
	cols, _ := strconv.Atoi(d[1])
	m := data.NewConstantMatrix(rows, cols, new(big.Int).SetInt64(0))
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			val, ok := new(big.Int).SetString(d[2+i*cols+j], 10)
			if !ok {
				return nil
			}
			m[i][j] = val
		}
	}
	return m
}