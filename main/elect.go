package main

import (
	"fmt"
	"npcc/node"
	"time"

	"github.com/spf13/cobra"
	"npcc/common/config"
)

func start(cmd *cobra.Command) error {
	lc := config.InitLocalConfig(cmd)

	fmt.Printf("start at %s\n", lc.Path)

	nodeInstance := node.NPCCNode{}
	nodeInstance.Init(lc)

	serve := make(chan error)
	go func() {
		var grpcErr error
		time.Sleep(600 * time.Second)
		serve <- grpcErr
	}()

	// Block until grpc server exits
	return <-serve
}

func startCMD() *cobra.Command {
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "start npcc",
		Long:  "start npcc blockchain peer",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return start(cmd)
		},
	}
	flagList := []string{
		"config",
	}
	attachFlags(startCmd, flagList)
	return startCmd
}
