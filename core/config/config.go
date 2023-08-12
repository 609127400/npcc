package config

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"strings"
)

type LocalConfig struct {
	Path string
}

func InitLocalConfig(cmd *cobra.Command) *LocalConfig {
	viper.SetEnvPrefix("npcc")
	viper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

	//若命令行设置了配置文件，则直接使用
	//若未设置，则在NPCC_CFG_PATH下寻找npcc_config.yaml
	altPath := os.Getenv("NPCC_CFG_PATH")
	if altPath == "" {
		altPath = "."
	}
	flag := cmd.Flags().Lookup("config")
	if flag == nil {
		panic(fmt.Errorf("cmd no set config flag"))
	}
	cmdSetConfigFile := flag.Value.String()
	viper.AddConfigPath(altPath)
	viper.SetConfigName("npcc_config")
	if cmdSetConfigFile != "" {
		viper.SetConfigFile(cmdSetConfigFile)
	}
	err := viper.ReadInConfig()
	if err != nil {
		panic(err)
	}

	lc := &LocalConfig{}
	lc.Path = viper.GetString("identity.path")
	return lc
}
