package elect

import (
	"npcc/core/identity"
	"npcc/core/net"
)

type Elector struct {
	id       *identity.Identity
	localNet *net.Node
}

func NewElector(id *identity.Identity, p2pNet *net.Node) *Elector {
	return &Elector{id: id, localNet: p2pNet}
}

func (e *Elector) Vote() error {
	//对选票进行签名

	//发送选票
	return nil
}

func (e *Elector) CalloutVote() error {
	//验证选票合法性

	//记录选票

	return nil
}
