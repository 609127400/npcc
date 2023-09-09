package net

import "npcc/common"

type Message struct {
	Type  common.LocalMsgType //类型
	Topic string              //所属通道
	Data  []byte
}

type P2PMessageHandler interface {
	Handle(message Message) error
}
