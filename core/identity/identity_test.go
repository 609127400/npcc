package identity

import (
	"github.com/stretchr/testify/assert"
	"npcc/common/config"
	"testing"
)

var id *Identity

func TestIdentity_InitID(t *testing.T) {
	id = &Identity{}
	cf := &config.LocalConfig{}
	cf.Path = `D:\npcc\test\org1\members\id1`
	err := id.InitID(cf)
	assert.Equal(t, nil, err)
}

func TestIdentity_ECDSASignAndVerify(t *testing.T) {
	TestIdentity_InitID(t)

	msg := []byte("123")
	sig, err := id.Sign(msg, nil)
	assert.Equal(t, nil, err)
	ok, err := id.Verify(msg, sig, nil)
	assert.Equal(t, nil, err)
	assert.Equal(t, true, ok)
	fakemsg := []byte("124")
	ok, err = id.Verify(fakemsg, sig, nil)
	assert.Equal(t, nil, err)
	assert.Equal(t, false, ok)
}
