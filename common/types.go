package common

type LocalMsgType uint32

func (lt *LocalMsgType) Type() LocalMsgType {
	return (*lt) & (0xff00)
}

func (lt *LocalMsgType) SubType() LocalMsgType {
	return (*lt) & (0x00ff)
}

// |--type--|-subtype-|
// 0000 0000 0000 0000
const (
	LocalNoUseType              LocalMsgType = 0
	LocalNetMsg                 LocalMsgType = 1 << 8
	LocalNetMsg_Discovery       LocalMsgType = LocalNetMsg | 1
	LocalElectMsg               LocalMsgType = 2 << 8
	LocalElectMsg_Vote          LocalMsgType = LocalElectMsg | 1
	LocalElectMsg_Check         LocalMsgType = LocalElectMsg | 2
	LocalElectMsg_CheckResponse LocalMsgType = LocalElectMsg | 3
)

type LocalMsg struct {
}
