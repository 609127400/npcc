package elect

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"npcc/common"
	"npcc/core/identity"
	"npcc/core/msgbus"
	"npcc/core/net"
	"npcc/pbgo"
	"strings"
	"sync"
	"time"
)

type Elector struct {
	pbgo.UnimplementedElectServer
	id        *identity.Identity
	p2pNode   *net.P2PNode
	votes     sync.Map
	channelID string

	electBoxManager *ElectBoxManager
	log             common.Logger
	started         bool

	_waitCheckReply chan *pbgo.CheckVoteBoxResponse
	_mutex          sync.Mutex
}

func NewElector(id *identity.Identity, n *net.P2PNode, channelID string) *Elector {
	e := &Elector{id: id, p2pNode: n}
	e.log = common.GetLogger(common.MODULE_ELECT)
	e.channelID = channelID
	e.electBoxManager = NewElectBoxManager(e.mockAddDataToBlockchain, e.log)
	e._waitCheckReply = make(chan *pbgo.CheckVoteBoxResponse, 1)

	return e
}

func (e *Elector) Start() error {
	msgbus.Register(common.LocalElectMsg, e)
	msgbus.Register(common.LocalNetMsg, e)
	return nil
}

func (e *Elector) Ballot(ctx context.Context, v *pbgo.Vote) (*pbgo.BallotResponse, error) {
	e.log.Infof("%s recv vote: %s, %s", e.p2pNode.Name(), v.Id, v.Role)
	role, ok := pbgo.Vote_Role_name[int32(v.Role)]
	if !ok {
		return nil, errors.Errorf("unvalid role[%d] of Vote", v.Role)
	}
	msg := []byte(v.Id + role)
	sig, err := hex.DecodeString(v.Signature)
	if err != nil {
		return nil, errors.Errorf("invalid sig: %s", err)
	}
	ok, err = e.id.Verify(msg, sig, nil)
	if err != nil {
		return nil, errors.Errorf("invalid sig: %s", err)
	}
	if !ok {
		return nil, errors.Errorf("invalid sig, verify err")
	}

	if v.Id == "" {
		v.Id = e.id.ID
	}
	//添加投票者信息
	v.Voter = e.id.Name
	if v.Pubkey, err = e.id.PublicKey().String(); err != nil {
		return nil, fmt.Errorf("get pubkey of identity err: %s", err)
	}

	br := &pbgo.BallotResponse{}
	//1.如果本节点就是leader，直接处理
	if e.p2pNode.IsLeader() {
		err = e.electBoxManager.Vote(v)
		if err != nil {
			br.Status = -1
		}
		return br, err
	}
	//2.否则，转发到leader
	if v.Role == pbgo.Vote_DEPUTY_TO_NPC {
		//人大代表在本地（局域网）中投，再上一级的投票在网络中投
		//获取当前能在局域网中获取的节点
		if !e.isNodeExist(v.Id) {
			br.Status = -1
			err = errors.Errorf("there is no peer with id[%s] in local net", v.Id)
			br.Msg = err.Error()
			return br, err
		}
		data, err := proto.Marshal(v)
		if err != nil {
			br.Status = -1
			br.Msg = err.Error()
			return br, err
		}
		netmsg := net.Message{
			Type:  common.LocalElectMsg_Vote,
			Topic: e.channelID,
			Data:  data,
		}
		if err := e.p2pNode.SendToNodes(nil, netmsg); err != nil {
			br.Status = -1
			br.Msg = fmt.Sprintf("send to nodes err: %s", err)
			return br, err
		}
		return br, nil
	} else {
		//TODO:处理其它类型的选举（跨本地网络）
	}

	//在节点中查看是否有对应的v.Id

	return br, nil
}
func (e *Elector) GetIdentity(ctx context.Context, id *pbgo.Identity) (*pbgo.ListResponse, error) {
	return nil, nil
}

func (e *Elector) List(ctx context.Context, empt *pbgo.Empt) (*pbgo.ListResponse, error) {
	ids := e.p2pNode.ListPeers()
	lr := &pbgo.ListResponse{Num: int32(len(ids))}
	for _, id := range ids {
		lr.Ids = append(lr.Ids, &pbgo.Identity{Id: id.String()})
	}
	return lr, nil
}

func (e *Elector) isNodeExist(id string) bool {
	ids := e.p2pNode.ListPeers()
	for _, n := range ids {
		if n.String() == id {
			return true
		}
	}
	return false
}

func (e *Elector) CalloutVote(ctx context.Context, v *pbgo.Vote) (*pbgo.CalloutVoteResponse, error) {
	if !e.p2pNode.IsLeader() {
		return nil, fmt.Errorf("not leader, no right to callout")
	}
	if !mockCheckIdentityToCalloutElect() {
		return nil, fmt.Errorf("no right to callout")
	}
	role, ok := pbgo.Vote_Role_name[int32(v.Role)]
	if !ok {
		return nil, fmt.Errorf("unknown role type[%d]", v.Role)
	}
	resp := &pbgo.CalloutVoteResponse{}
	report, err := e.electBoxManager.StopAndReport(role)
	if err != nil {
		e.log.Errorf("box stopAndReport err: %s", err)
	} else {
		resp.Form = report.DetailForm
	}
	//mock deal elect result
	err = e.mockAddDataToBlockchain(report.DetailForm)
	if err != nil {
		e.log.Errorf("add elect result to chain err: %s", err)
		//TODO:是否发起重试？
	}

	e.electBoxManager.Reset(role)

	return resp, err
}

func (e *Elector) CheckVoteBox(ctx context.Context, v *pbgo.Vote) (*pbgo.CheckVoteBoxResponse, error) {
	role, ok := pbgo.Vote_Role_name[int32(v.Role)]
	if !ok {
		return nil, fmt.Errorf("unknown role type[%d]", v.Role)
	}
	resp := &pbgo.CheckVoteBoxResponse{}
	if e.p2pNode.IsLeader() {
		report, err := e.electBoxManager.Check(role)
		if err != nil {
			e.log.Errorf("check elect info err: %s", err)
		} else {
			resp.Form = report.DetailForm
		}
		return resp, nil
	}

	//relay
	roleAndAddr := role + " " + e.p2pNode.PID()
	netmsg := net.Message{
		Type:  common.LocalElectMsg_Check,
		Topic: e.channelID,
		Data:  []byte(roleAndAddr),
	}

	e._mutex.Lock()
	defer e._mutex.Unlock()
	//预留一个空间，这样在下面的select等待与HandleMsgFromMsgBus中的case common.LocalElectMsg_CheckResponse并行
	//时，不会因超时出现阻塞
	close(e._waitCheckReply)
	e._waitCheckReply = make(chan *pbgo.CheckVoteBoxResponse, 1)

	if err := e.p2pNode.SendToNodes(nil, netmsg); err != nil {
		e.log.Errorf("relay check msg for elect info err: %s", err)
		return resp, err
	}

	select {
	case <-time.After(5 * time.Second):
		e.log.Errorf("wait elect check info from leader timeout")
		return resp, nil
	case resp = <-e._waitCheckReply:
		e.log.Infof("%s recv check msg response", e.p2pNode.Name())
		return resp, nil
	}
}

// 参照订阅的类型
func (e *Elector) HandleMsgFromMsgBus(busmsg *msgbus.BusMessage) error {
	switch busmsg.MsgType {
	case common.LocalElectMsg_Vote:
		e.log.Infof("%s recv elect vote relay msg from msgbus", e.p2pNode.Name())
		//TODO:通道检查
		data, ok := busmsg.Msg.([]byte)
		if !ok {
			e.log.Errorf("invaild elect msg data")
			return fmt.Errorf("invaild elect msg data")
		}
		v := &pbgo.Vote{}
		if err := proto.Unmarshal(data, v); err != nil {
			e.log.Errorf(err.Error())
			return err
		}
		_, ok = pbgo.Vote_Role_name[int32(v.Role)]
		if !ok {
			e.log.Errorf("unknown type of role[%d]", v.Role)
			return fmt.Errorf("unknown type of role[%d]", v.Role)
		}
		//TODO:vote签名检查
		e.handleElectVoteMsg(v)
	case common.LocalElectMsg_Check:
		roleAndAddr := strings.Split(string(busmsg.Msg.([]byte)), " ")
		if len(roleAndAddr) < 2 {
			err := fmt.Errorf("unvalid msg format for local elect msg check")
			e.log.Errorf(err.Error())
			return err
		}
		if err := e.handleElectCheckMsg(roleAndAddr[0], roleAndAddr[1]); err != nil {
			e.log.Error(err)
		}
	case common.LocalElectMsg_CheckResponse:
		resp := &pbgo.CheckVoteBoxResponse{}
		if err := proto.Unmarshal(busmsg.Msg.([]byte), resp); err != nil {
			e.log.Errorf("err unmarshal check info from leader: %s", err)
		}
		e._waitCheckReply <- resp
	case common.LocalNetMsg_Discovery:
		pid, ok := busmsg.Msg.(string)
		if !ok {
			e.log.Errorf("invaild discovery msg data")
			return fmt.Errorf("invaild discovery msg data")
		}
		e.handleDiscoveryMsg(pid)
	default:
		e.log.Errorf("unknown msg type from msgbus")
		return fmt.Errorf("unknown msg type from msgbus")
	}
	return nil
}

func (e *Elector) handleElectVoteMsg(vote *pbgo.Vote) error {
	e.log.Debugf("vote info: %v", vote)
	return e.electBoxManager.Vote(vote)
}

func (e *Elector) handleElectCheckMsg(role, addr string) error {
	e.log.Infof("check relay info: role:%s addr:%s", role, addr)
	resp := &pbgo.CheckVoteBoxResponse{}
	report, err := e.electBoxManager.Check(role)
	if err != nil {
		e.log.Errorf("check elect info err: %s", err)
	} else {
		resp.Form = report.DetailForm
	}
	data, err := proto.Marshal(resp)
	if err != nil {
		return err
	}
	msg := net.Message{
		Type:  common.LocalElectMsg_CheckResponse,
		Topic: e.channelID,
		Data:  data,
	}
	if err = e.p2pNode.SendToNodes([]string{addr}, msg); err != nil {
		return err
	}
	return nil
}

func (e *Elector) handleDiscoveryMsg(pid string) error {
	e.electBoxManager.AddIDToAllBox(pid)
	return nil
}

func (e *Elector) mockAddDataToBlockchain(data []byte) error {
	//把数据通过msgbus发送给上链模块
	e.log.Infof("put data to the chain[%s]", e.channelID)
	e.log.Infof("Doing....")
	e.log.Infof("OK, Done!")
	return nil
}

// TODO:检查是否是代表、leader、admin。只有这些人可以启动一个Box？
func mockCheckIdentityToStartElect() bool {
	return true
}

// 检查是否有权限callout
func mockCheckIdentityToCalloutElect() bool {
	return true
}
