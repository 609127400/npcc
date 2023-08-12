package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"os"
)

var flags *pflag.FlagSet

type LEADER_TYPE int

var (
	cfgPathFlag  string
	roleTypeFlag int32
	nodeFlag     string
	idFlag       string
)

func init() {
	resetFlags()
}

// Explicitly define a method to facilitate tests
func resetFlags() {
	flags = &pflag.FlagSet{}

	flags.StringVarP(&cfgPathFlag, "config", "c", "./npcc_config.yaml",
		fmt.Sprintf("npcc node config path: %s", cfgPathFlag))
	flags.Int32VarP(&roleTypeFlag, "role", "r", 0,
		fmt.Sprintf("npcc elect one role of congress: %d", roleTypeFlag))
	flags.StringVarP(&nodeFlag, "node", "n", "",
		fmt.Sprintf("npcc elect one node for congress: %s", nodeFlag))
	flags.StringVarP(&idFlag, "identity", "id", "",
		fmt.Sprintf("npcc elect one id for congress: %s", idFlag))

}

func attachFlags(cmd *cobra.Command, names []string) {
	cmdFlags := cmd.Flags()
	for _, name := range names {
		if flag := flags.Lookup(name); flag != nil {
			cmdFlags.AddFlag(flag)
		} else {
			panic(fmt.Errorf("Could not find flag '%s' to attach to command '%s'", name, cmd.Name()))
		}
	}
}

var mainCmd = &cobra.Command{Use: "npcc"}

func main() {

	mainCmd.AddCommand(startCMD())

	if mainCmd.Execute() != nil {
		os.Exit(1)
	}
}
