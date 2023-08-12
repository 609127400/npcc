package ml

import (
	"fmt"
	"math"
)

type AdaBoostingModel struct {
	a_m   []float64
	g_m   []int
	class []Type_Class
	m     int
}

type AdaBoosting struct {
	model AdaBoostingModel
	e     float64
	vaild bool
}

func (ab *AdaBoosting) Boosting(ss *SampleSet) error {
	size := len(ss.data)
	if size < 10 {
		return fmt.Errorf("ss is too short")
	}
	ab.e = 0.2
	ab.model.m = 0

	w_mi := make([]float64, size)
	w_mi[0] = 1.00 / float64(size)
	left_class := make([]int, size) //记录分割位置左侧的分类
	if ss.data[0].y == PN {
		left_class[0] = 1
	} else {
		left_class[0] = 0
	}

	var i, j int
	for i = 1; i < size; i++ {
		w_mi[i] = w_mi[i-1]
		//先记录分割位置左侧PN的个数
		if ss.data[i].y == PN {
			left_class[i] = left_class[i-1] + 1
		} else {
			left_class[i] = left_class[i-1]
		}
	}
	//确定分割位置左侧的类型
	for i = 0; i < size; i++ {
		if left_class[i] > i+1-left_class[i] {
			left_class[i] = int(PN)
		} else if left_class[i] < i+1-left_class[i] {
			left_class[i] = int(NN)
		} else {
			r_pn_count := left_class[size-1] - left_class[i] //右侧pn的个数
			if r_pn_count > size-1-i-r_pn_count {            //如果右侧pn个数多
				left_class[i] = int(NN) //则右侧是PN，相应的左侧就是NN
			} else {
				//如果左、右各自的PN、NN相等
				left_class[i] = int(PN)
			}
		}
	}

	var em float64
	var zm float64
	var em_min float64
	var am float64
	var sp int
	var t int

	for { //迭代
		em_min = 1000000
		//找到本轮em最小的分隔位置,从i与i+1处分割
		for i = 0; i < size-1; i++ {
			em = 0
			for j = 0; j < size; j++ {
				if j <= i && ss.data[j].y != Type_Class(left_class[i]) {
					em += w_mi[j]
				} else if j > i && ss.data[j].y != Type_Class(0-left_class[i]) {
					em += w_mi[j]
				}
			}

			if em < em_min {
				em_min = em
				sp = i
			}
		}
		am = 0.5 * math.Log((1-em_min)/em_min)
		//保存当次迭代的f(x)模型中的am和gm
		ab.model.a_m = append(ab.model.a_m, am)
		ab.model.g_m = append(ab.model.g_m, sp)
		ab.model.class = append(ab.model.class, Type_Class(left_class[sp]))
		ab.model.m++
		//打印当次迭代信息
		for i = 0; i < size; i++ {
			fmt.Printf("w_%d: %.5f ", i, w_mi[i])
		}
		fmt.Printf("\n")
		fmt.Printf("iteration: m: %d,  em: %.5f, a_m: %.5f, gm: %d\n", ab.model.m, em_min, am, sp)
		fmt.Println("-------------")
		//如果当次迭代的em已小于精度要求或超过10000次迭代，则退出迭代
		if em_min < ab.e || t > 10000 {
			break
		}

		//更新w_mi，先求zm，再更新w_mi，为下一次迭代做准备
		t++
		zm = 0.0
		for i = 0; i < size; i++ {
			if i <= sp {
				w_mi[i] = w_mi[i] * (math.Exp((0.0 - am) * float64(ss.data[i].y) * float64(left_class[sp])))
			} else {
				w_mi[i] = w_mi[i] * (math.Exp((0.0 - am) * float64(ss.data[i].y) * float64(0-left_class[sp])))
			}
			zm += w_mi[i]
		}
		for i = 0; i < size; i++ {
			w_mi[i] = w_mi[i] / zm
		}
	}

	ab.vaild = true
	return nil
}

func (ab *AdaBoosting) Class(x int) (Type_Class, error) {
	if !ab.vaild {
		return PN, fmt.Errorf("model is invalid")
	}

	res := 0.0
	for i := 0; i < ab.model.m; i++ {
		if x <= ab.model.g_m[i] {
			res += ab.model.a_m[i] * float64(ab.model.class[i])
		} else {
			res += ab.model.a_m[i] * float64(0-ab.model.class[i])
		}
	}

	if res > 0 {
		return PN, nil
	}
	return NN, nil
}
