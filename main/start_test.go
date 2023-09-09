package main

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

func startNode(t *testing.T, org, id int) {
	cfgValue := fmt.Sprintf(`D:\npcc\test\org%d\members\id%d`, org, id)
	os.Setenv("NPCC_CFG_PATH", cfgValue)
	cmd := startCMD()
	require.NoError(t, cmd.Execute(), fmt.Sprintf("start node[org:%d,id:%d] ok", org, id))
}

func start4NodesEnvironment(t *testing.T) {
	go func() {
		startNode(t, 1, 1)
	}()
	time.Sleep(1 * time.Second)
	go func() {
		startNode(t, 1, 2)
	}()
	time.Sleep(1 * time.Second)
	go func() {
		startNode(t, 2, 3)
	}()
	time.Sleep(1 * time.Second)
	go func() {
		startNode(t, 2, 4)
	}()
	time.Sleep(1 * time.Second)
}

func TestNodeStart(t *testing.T) {
	start4NodesEnvironment(t)
	time.Sleep(60 * time.Second)
}
