package main

import (
	"log"
	"npcc/node"

	"github.com/spf13/cobra"
	"npcc/core/config"
)

func start(cmd *cobra.Command) error {
	lc := config.InitLocalConfig(cmd)

	log.Printf("%s start at %s", lc.ID.Name, lc.ID.Path)

	nodeInstance := node.NPCCNode{}
	err := nodeInstance.Init(lc)
	if err != nil {
		return err
	}

	return nodeInstance.Start()
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
	return startCmd
}
