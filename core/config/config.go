package config

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"npcc/common"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type BlockchainConfig struct {
	ChannelID string
}

type IdentityConfig struct {
	Name string
	Path string
}

type GRPCConfig struct {
	ListenAddr string
}

type P2PConfig struct {
	ListenAddr string
	ProtocolID string
	Bootstraps []string
}

type NetConfig struct {
	GRPC *GRPCConfig
	P2P  *P2PConfig
}

type TLSConfig struct {
	Enabled            bool
	ServerCert         string
	ServerKey          string
	ServerHostOverride string
	RootCert           string
	ClientAuthRequired bool
	ClientRootCAs      []string
	ClientKey          string
	ClientCert         string
}

type BriefLogConfig struct {
	Mode string
}

type VerboseLogConfig struct {
	Level          string
	ModuleLevel    map[string]string
	FilePath       string
	RotationMaxAge int
	RotationTime   int
	RotationSize   int
	LogInConsole   bool
	ShowLine       bool
}

type LogConfig struct {
	Brief   *BriefLogConfig
	Verbose *VerboseLogConfig
}

type LocalConfig struct {
	Blockchain *BlockchainConfig
	ID         *IdentityConfig
	Net        *NetConfig
	TLS        *TLSConfig
	Log        *LogConfig
}

var singletonLC *LocalConfig
var lock sync.Mutex

func InitLocalConfig(cmd *cobra.Command) *LocalConfig {
	v := viper.New()
	v.SetEnvPrefix("npcc")
	v.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	v.SetEnvKeyReplacer(replacer)

	//若命令行设置了配置文件，则直接使用
	//若未设置，则在NPCC_CFG_PATH下寻找npcc_config.yaml
	altPath := os.Getenv("NPCC_CFG_PATH")
	if altPath == "" {
		altPath = "."
	}
	cmdSetConfigFile := ""
	flag := cmd.Flags().Lookup("config")
	if flag != nil {
		cmdSetConfigFile = flag.Value.String()
	}
	v.AddConfigPath(altPath)
	v.SetConfigName("npcc_config")
	if cmdSetConfigFile != "" {
		v.SetConfigFile(cmdSetConfigFile)
	}
	err := v.ReadInConfig()
	if err != nil {
		panic(err)
	}

	lc := &LocalConfig{}

	bc := &BlockchainConfig{}
	bc.ChannelID = v.GetString("blockchain.channel")

	id := &IdentityConfig{}
	id.Path = v.GetString("identity.path")
	id.Name = v.GetString("identity.name")

	p2p := &P2PConfig{}
	grpc := &GRPCConfig{}
	p2p.ListenAddr = v.GetString("net.p2p.listenAddr")
	p2p.ProtocolID = v.GetString("net.p2p.protocolID")
	p2p.Bootstraps = v.GetStringSlice("net.p2p.bootstraps")
	grpc.ListenAddr = v.GetString("net.grpc.listenAddr")
	net := &NetConfig{}
	net.P2P = p2p
	net.GRPC = grpc

	tls := &TLSConfig{}
	tls.Enabled = v.GetBool("tls.enabled")
	tls.ClientAuthRequired = v.GetBool("tls.clientAuthRequired")
	tls.ServerCert = v.GetString("tls.cert")
	tls.ServerKey = v.GetString("tls.key")
	tls.RootCert = v.GetString("tls.rootCert")
	crcastr := v.GetString("tls.clientRootCAs")
	tls.ClientRootCAs = strings.Split(crcastr, ",")
	tls.ClientKey = v.GetString("tls.clientKey")
	tls.ClientCert = v.GetString("tls.clientCert")
	tls.ServerHostOverride = v.GetString("tls.serverHostOverride")

	blc := &BriefLogConfig{}
	blc.Mode = v.GetString("log.brief.mode")
	vlc := &VerboseLogConfig{}
	vlc.Level = v.GetString("log.verbose.level")
	vlc.ModuleLevel = v.GetStringMapString("log.verbose.moduleLevel")
	vlc.FilePath = v.GetString("log.verbose.filePath")
	vlc.RotationMaxAge = v.GetInt("log.verbose.rotationMaxAge")
	vlc.RotationTime = v.GetInt("log.verbose.rotationTime")
	vlc.RotationSize = v.GetInt("log.verbose.rotationSize")
	vlc.LogInConsole = v.GetBool("log.verbose.logInConsole")
	vlc.ShowLine = v.GetBool("log.verbose.showLine")
	logC := &LogConfig{}
	logC.Brief = blc
	logC.Verbose = vlc

	lc.Blockchain = bc
	lc.TLS = tls
	lc.ID = id
	lc.Net = net
	lc.Log = logC

	lock.Lock()
	singletonLC = lc
	lock.Unlock()

	return lc
}

func (lc *LocalConfig) ServerConfig() (*common.GRPCServerConfig, error) {
	serverConfig := &common.GRPCServerConfig{
		ConnectionTimeout: 5 * time.Second,
		SecOpts: common.SecureOptions{
			UseTLS: lc.TLS.Enabled,
		},
	}
	var path string
	if serverConfig.SecOpts.UseTLS {
		path = filepath.Join(lc.ID.Path, lc.TLS.ServerKey)
		serverKey, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("error loading TLS key (%s)", err)
		}
		path = filepath.Join(lc.ID.Path, lc.TLS.ServerCert)
		serverCert, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("error loading TLS certificate (%s)", err)
		}
		serverConfig.SecOpts.Certificate = serverCert
		serverConfig.SecOpts.Key = serverKey
		serverConfig.SecOpts.RequireClientCert = lc.TLS.ClientAuthRequired
		if serverConfig.SecOpts.RequireClientCert {
			var clientRoots [][]byte
			for _, file := range lc.TLS.ClientRootCAs {
				path = filepath.Join(lc.ID.Path, file)
				clientRoot, err := os.ReadFile(path)
				if err != nil {
					return nil, fmt.Errorf("error loading client root CAs (%s)", err)
				}
				clientRoots = append(clientRoots, clientRoot)
			}
			serverConfig.SecOpts.ClientRootCAs = clientRoots
		}
		// check for root cert
		if lc.TLS.RootCert != "" {
			path = filepath.Join(lc.ID.Path, lc.TLS.RootCert)
			rootCert, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("error loading TLS root certificate (%s)", err)
			}
			serverConfig.SecOpts.ServerRootCAs = [][]byte{rootCert}
		}
	}
	// get the default keepalive options
	serverConfig.KaOpts = common.DefaultKeepaliveOptions
	serverConfig.KaOpts.ServerInterval = common.DefaultGRPCKeepaliveInterval
	serverConfig.KaOpts.ServerTimeout = common.DefaultGRPCKeepaliveTimeout
	serverConfig.KaOpts.ServerMinInterval = common.DefaultGRPCKeepaliveMinInterval

	serverConfig.MaxRecvMsgSize = common.GRPCDefaultMaxRecvMsgSize
	serverConfig.MaxSendMsgSize = common.GRPCDefaultMaxSendMsgSize

	return serverConfig, nil
}

func (lc *LocalConfig) ClientConfig() (*common.GRPCClientConfig, error) {
	clientConfig := &common.GRPCClientConfig{}
	clientConfig.DialTimeout = common.DefaultConnectionTimeout

	secOpts := common.SecureOptions{
		UseTLS:             lc.TLS.Enabled,
		RequireClientCert:  lc.TLS.ClientAuthRequired,
		ServerNameOverride: lc.TLS.ServerHostOverride,
	}

	var path string
	var err error
	if secOpts.RequireClientCert {
		path = filepath.Join(lc.ID.Path, lc.TLS.ClientKey)
		secOpts.Key, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("unable to load %s.tls.clientKey.file", err)
		}
		path = filepath.Join(lc.ID.Path, lc.TLS.ClientCert)
		secOpts.Certificate, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("unable to load %s.tls.clientCert.file", err)
		}
	}
	clientConfig.SecOpts = secOpts

	if clientConfig.SecOpts.UseTLS {
		path = filepath.Join(lc.ID.Path, lc.TLS.RootCert)
		caPEM, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("unable to load TLS root cert file from %s", path)
		}
		clientConfig.SecOpts.ServerRootCAs = [][]byte{caPEM}
	}

	clientConfig.MaxRecvMsgSize = common.GRPCDefaultMaxRecvMsgSize
	clientConfig.MaxSendMsgSize = common.GRPCDefaultMaxSendMsgSize
	clientConfig.KaOpts = common.DefaultKeepaliveOptions

	return clientConfig, nil
}

func (lc *LocalConfig) P2PNodeConfig() (*common.P2PNodeConfig, error) {
	p2pNodeConfig := &common.P2PNodeConfig{}
	p2pNodeConfig.Name = lc.ID.Name
	p2pNodeConfig.Addr = lc.Net.P2P.ListenAddr
	p2pNodeConfig.Bootstraps = lc.Net.P2P.Bootstraps
	p2pNodeConfig.Topic = lc.Blockchain.ChannelID
	p2pNodeConfig.ProtocolID = lc.Net.P2P.ProtocolID

	path := filepath.Join(lc.ID.Path, lc.TLS.ServerKey)
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("err decode priv key pem")
	}

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		p2pNodeConfig.PrivKey = key
		return p2pNodeConfig, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		p2pNodeConfig.PrivKey = key
		return p2pNodeConfig, nil
	}

	return nil, fmt.Errorf("unsupport priv key and parse err")
}

func (lc *LocalConfig) LogConfig() (*common.LogConfig, error) {
	var ok bool
	logc := &common.LogConfig{}
	logc.BriefMode = lc.Log.Brief.Mode
	logc.LogLevel, ok = common.LOG_LEVEL_Value[lc.Log.Verbose.Level]
	if !ok {
		logc.LogLevel = common.LEVEL_INFO
	}
	logc.ModuleSpecialLevel = make(map[string]common.LOG_LEVEL)
	for k, v := range lc.Log.Verbose.ModuleLevel {
		if level, ok := common.LOG_LEVEL_Value[v]; ok {
			logc.ModuleSpecialLevel[k] = level
		}
	}
	logc.ChainID = lc.Blockchain.ChannelID
	logc.LogPath = lc.Log.Verbose.FilePath
	logc.RotationMaxAge = lc.Log.Verbose.RotationMaxAge
	logc.RotationTime = lc.Log.Verbose.RotationTime
	logc.RotationSize = lc.Log.Verbose.RotationSize
	logc.ShowLine = lc.Log.Verbose.ShowLine
	logc.LogInConsole = lc.Log.Verbose.LogInConsole

	return logc, nil
}
