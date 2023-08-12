package ml

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

func (hmm *HiddenMarkovModel) GenObserSeqByForward(pi []float64) {
	size := len(pi)
	if size == 0 || size != len(hmm.Q) {
		return
	}
	if hmm.T != len(hmm.O) {
		return
	}

	//t=0，初始化前向概率
	for i := 0; i < len(hmm.Q); i++ {
		hmm.P[i] = pi[i] * hmm.B[i][hmm.O[0]]
	}

	for t := 1; t < hmm.T; t++ { //t时刻的观测值
		tmp := []float64{}
		for i := 0; i < len(hmm.Q); i++ { //t时刻的状态
			sum := 0.0
			for j := 0; j < len(hmm.Q); j++ { //t-1时刻的状态
				//t-1时刻前置状态*  t-1 -> t时刻的状态转换概率 * t时刻状态生成观测值概率
				sum += hmm.P[j] * hmm.A[j][i] * hmm.B[i][hmm.O[t]]
			}
			tmp = append(tmp, sum)
		}
		for i := 0; i < len(hmm.Q); i++ {
			hmm.P[i] = tmp[i]
		}
	}
}

func (hmm *HiddenMarkovModel) GenObserSeqByBackward(pi []float64) {
	size := len(pi)
	if size == 0 || size != len(hmm.Q) {
		return
	}
	if hmm.T != len(hmm.O) {
		return
	}

	//t=T，初始化最后一组状态的后向概率，默认均是1
	for i := 0; i < len(hmm.Q); i++ {
		hmm.P[i] = 1
	}

	for t := hmm.T - 2; t >= 0; t-- { //t时刻的观测值
		tmp := []float64{}
		for i := 0; i < len(hmm.Q); i++ { //t时刻的状态
			sum := 0.0
			for j := 0; j < len(hmm.Q); j++ { //t+1时刻的状态
				//t+1时刻的后置前置状态 *  t -> t+1时刻的状态转换概率 * t+1时刻状态生成观测值概率
				sum += hmm.P[j] * hmm.A[i][j] * hmm.B[j][hmm.O[t+1]]
			}
			tmp = append(tmp, sum)
		}
		for i := 0; i < len(hmm.Q); i++ {
			hmm.P[i] = tmp[i]
		}
	}
	//最后将第一个观测值纳入后向概率
	for i := 0; i < len(pi); i++ {
		hmm.P[i] = hmm.P[i] * pi[i] * hmm.B[i][hmm.O[0]]
	}
}
