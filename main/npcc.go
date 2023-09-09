package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var (
	cfgPathFlag string
)

var mainCmd = &cobra.Command{Use: "npcc"}

func main() {

	mainCmd.PersistentFlags().StringVarP(&cfgPathFlag, "config", "c", "",
		fmt.Sprintf("npcc node config path: %s", cfgPathFlag))

	mainCmd.AddCommand(startCMD())
	mainCmd.AddCommand(electCMD())

	if mainCmd.Execute() != nil {
		os.Exit(1)
	}
}
