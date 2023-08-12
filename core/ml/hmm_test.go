package ml

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

/*
	type HiddenMarkovModel struct {
		Q []int       //状态集合
		I []int       //状态序列
		V []int       //观测集合
		O []int       //观测序列
		A [][]float64 //状态转换矩阵
		B [][]float64 //观测生成概率矩阵
		P []float64   //t时刻观测序列的生成概率
		T int         //t的轮数
	}
*/
func TestGenObserSeqByForward(t *testing.T) {
	hmm := HiddenMarkovModel{}
	hmm.Q = []int{1, 2, 3}
	hmm.V = []int{1, 2}    //1代表红，2代表白
	hmm.O = []int{0, 1, 0} //观测序列的值是观测值在V中的下标
	hmm.A = [][]float64{
		{0.5, 0.2, 0.3},
		{0.3, 0.5, 0.2},
		{0.2, 0.3, 0.5},
	}
	hmm.B = [][]float64{
		{0.5, 0.5},
		{0.4, 0.6},
		{0.7, 0.3},
	}
	hmm.P = make([]float64, len(hmm.Q))
	hmm.T = len(hmm.O)
	pi := []float64{0.2, 0.4, 0.4}
	hmm.GenObserSeqByForward(pi)

	sum1 := 0.0
	for i := 0; i < len(pi); i++ {
		sum1 += hmm.P[i]
	}
	fmt.Printf("sum1=%.5f\n", sum1)

	hmm.GenObserSeqByBackward(pi)
	sum2 := 0.0
	for i := 0; i < len(pi); i++ {
		sum2 += hmm.P[i]
	}
	fmt.Printf("sum2=%.5f\n", sum2)
	require.Equal(t, sum1, sum2)
}
