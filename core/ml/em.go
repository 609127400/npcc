package ml

import "math"

// NormalDistri
type GaussianDistri struct {
	m float64 //mu
	s float64 //sigma
}

type GaussianMixtureModel struct {
	gds  []GaussianDistri
	as   []float64 //alpha
	size int
}

// 初始化为size个标准正态分布
func (gmm *GaussianMixtureModel) Init(size int) {
	gmm.size = size
	gmm.gds = make([]GaussianDistri, size)
	gmm.as = make([]float64, size)
	for i := 0; i < size; i++ {
		gmm.gds[i].m = float64(i)
		gmm.gds[i].s = 1
		gmm.as[i] = 1.00 / float64(size)
	}
}

// 计算某个分量的概率值
func (gmm *GaussianMixtureModel) P(index int, x float64) float64 {
	m := gmm.gds[index].m
	s := gmm.gds[index].s
	a := gmm.as[index]

	part1 := 1 / (math.Sqrt2 * math.SqrtPi * s)
	part2 := 0.0 - math.Pow(x-m, 2)/(2*math.Pow(m, 2))
	part3 := math.Pow(math.E, part2)

	return a * part1 * part3
}

type EM struct {
	model GaussianMixtureModel
	e     float64
	vaild bool
}

func (em *EM) ExpectMax(ss SampleSet) {
	//em.model.Init(2) //初始化模型
	//
	//m := 0
	//for 1 > em.e {
	//
	//	for j := 0; j < len(ss.data); j++ {
	//		g_jk := make([]float64, em.model.size)
	//		sum  := 0.0
	//		for k := 0; k < em.model.size; k++ {
	//			g_jk[k] = em.model.P(k, ss.data[j].x)
	//			sum += g_jk[k]
	//		}
	//		//写到这儿不清楚怎么写了
	//		for k := 0; k < em.model.size; k++ {
	//			g_head := g_jk[k] / sum
	//
	//			u_head :=
	//
	//		}
	//
	//	}
	//
	//	m++
	//}

}

func (em *EM) Class(x float64) {

}
