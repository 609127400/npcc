package node

import (
	"fmt"
	"npcc/core/config"
	"npcc/core/elect"
	"npcc/core/identity"
	"npcc/core/net"
	"time"
)

var channelID = "test111"

type NPCCNode struct {
	id      *identity.Identity
	elector *elect.Elector
	p2pNet  *net.Node
	conf    *config.LocalConfig
}

func (n *NPCCNode) Init(c *config.LocalConfig) error {
	n.conf = c
	n.p2pNet = net.InitLocalNodeWithTopic(channelID)
	if n.p2pNet == nil {
		return fmt.Errorf("p2p net init err")
	}
	n.id = &identity.Identity{}
	err := n.id.InitID(c)
	if err != nil {
		return fmt.Errorf("identity init err: %s", err)
	}
	n.elector = elect.NewElector(n.id, n.p2pNet)

	return nil
}

func (n *NPCCNode) Start() error {
	time.Sleep(5 * time.Second)
	n.elector.Vote()

	return nil
}
