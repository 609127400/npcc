package ml

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBoosting(t *testing.T) {
	ss := &SampleSet{}
	ss.data = []Sample{{0, PN}, {1, PN}, {2, PN}, {3, NN}, {4, NN}, {5, NN},
		{6, PN}, {7, PN}, {8, PN}, {9, NN}}

	ab := &AdaBoosting{}
	ab.e = 0.01

	err := ab.Boosting(ss)
	assert.Equal(t, nil, err)

	c, err := ab.Class(0)
	assert.Equal(t, nil, err)
	assert.Equal(t, PN, c)

	c, err = ab.Class(1)
	assert.Equal(t, nil, err)
	assert.Equal(t, PN, c)

	c, err = ab.Class(2)
	assert.Equal(t, nil, err)
	assert.Equal(t, PN, c)

	c, err = ab.Class(3)
	assert.Equal(t, nil, err)
	assert.Equal(t, NN, c)

	c, err = ab.Class(4)
	assert.Equal(t, nil, err)
	assert.Equal(t, NN, c)

	c, err = ab.Class(5)
	assert.Equal(t, nil, err)
	assert.Equal(t, NN, c)

	c, err = ab.Class(6)
	assert.Equal(t, nil, err)
	assert.Equal(t, PN, c)

	c, err = ab.Class(7)
	assert.Equal(t, nil, err)
	assert.Equal(t, PN, c)

	c, err = ab.Class(8)
	assert.Equal(t, nil, err)
	assert.Equal(t, PN, c)

	c, err = ab.Class(9)
	assert.Equal(t, nil, err)
	assert.Equal(t, NN, c)
}
