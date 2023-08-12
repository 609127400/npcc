package ml

type Type_Class int

const (
	PN Type_Class = 1
	NN Type_Class = -1
)

type Sample struct {
	x float64
	y Type_Class
}

func (s *Sample) GetX() float64 {
	return s.x
}

func (s *Sample) GetY() Type_Class {
	return s.y
}

type SampleSet struct {
	data []Sample
}
