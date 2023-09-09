package node

import (
	"fmt"
	"npcc/common"
	"npcc/core/config"
	"npcc/core/elect"
	"npcc/core/identity"
	"npcc/core/msgbus"
	"npcc/core/net"
	"npcc/pbgo"
)

type NPCCNode struct {
	id      *identity.Identity
	elector *elect.Elector
	p2pNode *net.P2PNode
	conf    *config.LocalConfig
	server  *common.GRPCServer
	msgBus  msgbus.MessageBus
}

func (n *NPCCNode) Init(c *config.LocalConfig) error {
	n.conf = c

	logConfig, err := c.LogConfig()
	if err != nil {
		return fmt.Errorf("get log config err: %s", err)
	}
	common.SetLogConfig(logConfig)

	p2pNodeConfig, err := c.P2PNodeConfig()
	if err != nil {
		return fmt.Errorf("get server config err: %s", err)
	}
	//在其它模块初始化之前，初始化messagebus
	n.msgBus = msgbus.InitMessageBus()

	n.id = &identity.Identity{}
	err = n.id.InitID(c)
	if err != nil {
		return fmt.Errorf("identity init err: %s", err)
	}

	n.p2pNode = net.NewLocalP2PNode(p2pNodeConfig)
	if n.p2pNode == nil {
		return fmt.Errorf("p2p net init err")
	}

	n.elector = elect.NewElector(n.id, n.p2pNode, c.Blockchain.ChannelID)

	serverConfig, err := c.ServerConfig()
	if err != nil {
		return fmt.Errorf("get server config err: %s", err)
	}
	fmt.Printf("node[%s] GRPC Server listen on %s\n", c.ID.Name, c.Net.GRPC.ListenAddr)
	n.server, err = common.NewGRPCServer(c.Net.GRPC.ListenAddr, serverConfig)
	if err != nil {
		return fmt.Errorf("get grpc server err: %s", err)
	}

	return nil
}

func (n *NPCCNode) Start() error {
	n.p2pNode.Start()
	n.elector.Start()
	pbgo.RegisterElectServer(n.server.Server(), n.elector)

	serve := make(chan error)
	go func() {
		var grpcErr error
		if grpcErr = n.server.Start(); grpcErr != nil {
			grpcErr = fmt.Errorf("grpc server exited with error: %s", grpcErr)
		}
		serve <- grpcErr
	}()

	return <-serve
}
