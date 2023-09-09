package main

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

func TestElectVoteCMD(t *testing.T) {
	start4NodesEnvironment(t)
	time.Sleep(3 * time.Second)

	//投node2三票
	os.Setenv("NPCC_CFG_PATH", `D:\npcc\test\org1\members\id1`)
	v := voteCMD()
	args := []string{"-r", "2", "--id", "QmWJ561CKzp3eZFq2Ni3sedtxf98ZnyjyzQWtWA1wTFF5P"}
	v.SetArgs(args)
	err := v.Execute()
	assert.Nil(t, err)

	err = v.Execute()
	assert.Nil(t, err)

	err = v.Execute()
	assert.Nil(t, err)

	time.Sleep(1000 * time.Second)
}

func TestElectListCMD(t *testing.T) {

	time.Sleep(1 * time.Second)

	os.Setenv("NPCC_CFG_PATH", `D:\npcc\test\org1\members\id2`)
	el := listCMD()
	err := el.Execute()
	if err != nil {
		fmt.Printf("elect list err: %s\n", err)
	}

	time.Sleep(1000 * time.Second)
}

func TestElectCheckCMD(t *testing.T) {
	start4NodesEnvironment(t)
	time.Sleep(3 * time.Second)

	vc := voteCMD()
	args := []string{"-r", "2", "--id", "QmWJ561CKzp3eZFq2Ni3sedtxf98ZnyjyzQWtWA1wTFF5P"}
	vc.SetArgs(args)

	os.Setenv("NPCC_CFG_PATH", `D:\npcc\test\org1\members\id1`)
	err := vc.Execute()
	assert.Nil(t, err)
	time.Sleep(1 * time.Second)

	os.Setenv("NPCC_CFG_PATH", `D:\npcc\test\org1\members\id2`)
	err = vc.Execute()
	assert.Nil(t, err)
	time.Sleep(1 * time.Second)

	os.Setenv("NPCC_CFG_PATH", `D:\npcc\test\org2\members\id3`)
	err = vc.Execute()
	assert.Nil(t, err)
	time.Sleep(1 * time.Second)

	cc := checkCMD()
	args = []string{"-r", "2"}
	cc.SetArgs(args)
	err = cc.Execute()
	assert.Nil(t, err)

	time.Sleep(100 * time.Second)
}
