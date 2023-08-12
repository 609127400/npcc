package main

import (
	"encoding/hex"
	"npcc/core/identity"
	"npcc/pbgo"

	"github.com/spf13/cobra"
	"npcc/core/config"
)

func elect(cmd *cobra.Command) error {
	lc := config.InitLocalConfig(cmd)
	if idFlag == "" && nodeFlag == "" {
		panic("must set flag n or id")
	}

	id := identity.Identity{}
	id.InitID(lc)

	v := pbgo.Vote{
		Node: nodeFlag,
		Id:   idFlag,
	}

	msg := []byte(v.Node + v.Id)
	sig, err := id.Sign(msg, nil)
	if err != nil {
		panic(err)
	}
	v.Signature = hex.EncodeToString(sig)

	//client := pbgo

	return nil
}

func electCMD() *cobra.Command {
	electCmd := &cobra.Command{
		Use:   "elect",
		Short: "npcc elect",
		Long:  "npcc elect congress people or member of committee",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return elect(cmd)
		},
	}
	flagList := []string{
		"role",
		"identity",
		"node",
	}
	attachFlags(electCmd, flagList)
	return electCmd
}
