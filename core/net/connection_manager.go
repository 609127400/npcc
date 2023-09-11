package net

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"math/rand"
	"npcc/common"
	"npcc/core/msgbus"
	"strings"
	"sync"
	"time"
)

// eliminationStrategy is strategy for eliminating connected peer
type eliminationStrategy int

const (
	// Random
	Random eliminationStrategy = iota + 1
	// FIFO FIRST_IN_FIRST_OUT
	FIFO
	// LIFO LAST_IN_FIRST_OUT
	LIFO
)

var eliminatedHighLevelConnBugError = errors.New("no high level connection will be eliminated bug. pls check why")

// DefaultMaxPeerCountAllow is the default max peer count allow.
const DefaultMaxPeerCountAllow = 100

// DefaultEliminationStrategy is the default strategy for elimination.
const DefaultEliminationStrategy = LIFO

// the interval of time allowed to connect，unit seconds
const allowedConnTimeIntervalLower = 3
const allowedConnTimeIntervalUpper = 10

// connRecorder is a connection recorder.
type peerConnections struct {
	pid  peer.ID
	conn map[network.Conn]struct{}
}

// PeerConnManager is a connection manager of peers.
type PeerConnManager struct {
	cmLock             sync.RWMutex
	maxSize            int
	strategy           eliminationStrategy
	highLevelPeersLock sync.RWMutex
	highLevelPeers     map[peer.ID]struct{}
	highLevelConn      []*peerConnections
	lowLevelConn       []*peerConnections
	connLatestTime     map[string]int64 // records the timestamp of the last connection of the peer
	//log                protocol.Logger
}

// SetStrategy set the elimination strategy. If not set, default is LIFO.
func (cm *PeerConnManager) SetStrategy(strategy int) {
	if strategy <= 0 {
		fmt.Printf("[PeerConnManager] wrong strategy set(strategy:%d). use default(default:%v)",
			strategy, DefaultEliminationStrategy)
		cm.strategy = DefaultEliminationStrategy
		return
	}
	cm.strategy = eliminationStrategy(strategy)
}

// SetMaxSize set max count of peers allowed. If not set, default is 20.
func (cm *PeerConnManager) SetMaxSize(maxSize int) {
	if maxSize < 1 {
		fmt.Printf("[PeerConnManager] wrong max size set(max size:%d). use default(default:%d)",
			maxSize, DefaultMaxPeerCountAllow)
		maxSize = DefaultMaxPeerCountAllow
	}
	cm.maxSize = maxSize
}

// NewPeerConnManager create a new PeerConnManager.
func NewPeerConnManager() *PeerConnManager {
	return &PeerConnManager{
		maxSize:        DefaultMaxPeerCountAllow,
		strategy:       DefaultEliminationStrategy,
		highLevelPeers: make(map[peer.ID]struct{}),
		highLevelConn:  make([]*peerConnections, 0),
		lowLevelConn:   make([]*peerConnections, 0),
		connLatestTime: make(map[string]int64),
	}
}

// IsHighLevel return true if the peer which is high-level (consensus & seeds) node. Otherwise, return false.
func (cm *PeerConnManager) IsHighLevel(peerId peer.ID) bool {
	cm.highLevelPeersLock.RLock()
	defer cm.highLevelPeersLock.RUnlock()
	_, ok := cm.highLevelPeers[peerId]
	return ok
}

// AddAsHighLevelPeer add a peer id as high level peer.
func (cm *PeerConnManager) AddAsHighLevelPeer(peerId peer.ID) {
	cm.highLevelPeersLock.Lock()
	defer cm.highLevelPeersLock.Unlock()
	cm.highLevelPeers[peerId] = struct{}{}
}

// RemoveHighLevelPeer remove a high level peer id.
func (cm *PeerConnManager) RemoveHighLevelPeer(peerId peer.ID) {
	cm.highLevelPeersLock.Lock()
	defer cm.highLevelPeersLock.Unlock()
	delete(cm.highLevelPeers, peerId)
}

// ClearHighLevelPeer clear all high level peer id records.
func (cm *PeerConnManager) ClearHighLevelPeer() {
	cm.highLevelPeersLock.Lock()
	defer cm.highLevelPeersLock.Unlock()
	cm.highLevelPeers = make(map[peer.ID]struct{})
}

func (cm *PeerConnManager) getHighLevelConnections(pid peer.ID) (map[network.Conn]struct{}, int) {
	for idx, connections := range cm.highLevelConn {
		if pid == connections.pid {
			return connections.conn, idx
		}
	}
	return nil, -1
}

func (cm *PeerConnManager) getLowLevelConnections(pid peer.ID) (map[network.Conn]struct{}, int) {
	for idx, connections := range cm.lowLevelConn {
		if pid == connections.pid {
			return connections.conn, idx
		}
	}
	return nil, -1
}

func (cm *PeerConnManager) eliminateConnections(isHighLevel bool) (peer.ID, error) {
	switch cm.strategy {
	case Random:
		return cm.eliminateConnectionsRandom(isHighLevel)
	case FIFO:
		return cm.eliminateConnectionsFIFO(isHighLevel)
	case LIFO:
		return cm.eliminateConnectionsLIFO(isHighLevel)
	default:
		fmt.Printf("[PeerConnManager] unknown elimination strategy[%v], use default[%v]",
			cm.strategy, DefaultEliminationStrategy)
		cm.strategy = DefaultEliminationStrategy
		return cm.eliminateConnections(isHighLevel)
	}
}

func (cm *PeerConnManager) closeLowLevelConnRandom(lowLevelConnCount int) (peer.ID, error) {
	rand.Seed(time.Now().UnixNano())
	random := rand.Intn(lowLevelConnCount)
	eliminatedPid := cm.lowLevelConn[random].pid
	for conn := range cm.lowLevelConn[random].conn {
		go func(connToClose network.Conn) {
			_ = connToClose.Close()
		}(conn)
	}
	if random == lowLevelConnCount-1 {
		cm.lowLevelConn = cm.lowLevelConn[:random]
	} else {
		cm.lowLevelConn = append(cm.lowLevelConn[:random], cm.lowLevelConn[random+1:]...)
	}
	return eliminatedPid, nil
}

func (cm *PeerConnManager) closeHighLevelConnRandom(highLevelConnCount int) (peer.ID, error) {
	rand.Seed(time.Now().UnixNano())
	random := rand.Intn(highLevelConnCount)
	eliminatedPid := cm.highLevelConn[random].pid
	for conn := range cm.highLevelConn[random].conn {
		go func(connToClose network.Conn) {
			_ = connToClose.Close()
		}(conn)
	}
	if random == highLevelConnCount-1 {
		cm.highLevelConn = cm.highLevelConn[:random]
	} else {
		cm.highLevelConn = append(cm.highLevelConn[:random], cm.highLevelConn[random+1:]...)
	}
	return eliminatedPid, nil
}

func (cm *PeerConnManager) eliminateConnectionsRandom(isHighLevel bool) (peer.ID, error) {
	hCount := len(cm.highLevelConn)
	lCount := len(cm.lowLevelConn)
	if hCount+lCount >= cm.maxSize {
		if lCount > 0 {
			eliminatedPid, err := cm.closeLowLevelConnRandom(lCount)
			if err != nil {
				return "", err
			}
			fmt.Printf("[PeerConnManager] eliminate connections"+
				"(strategy:Random, is high-level:%v, eliminated pid:%s)", isHighLevel, eliminatedPid)
			return eliminatedPid, nil
		} else {
			if !isHighLevel {
				return "", eliminatedHighLevelConnBugError
			}
			eliminatedPid, err := cm.closeHighLevelConnRandom(hCount)
			if err != nil {
				return "", err
			}
			fmt.Printf("[PeerConnManager] eliminate connections"+
				"(strategy:Random, is high-level:%v, eliminated pid:%s)", isHighLevel, eliminatedPid)
			return eliminatedPid, nil
		}
	}
	return "", nil
}

func (cm *PeerConnManager) closeLowLevelConnFirst() (peer.ID, error) {
	eliminatedPid := cm.lowLevelConn[0].pid
	for conn := range cm.lowLevelConn[0].conn {
		go func(connToClose network.Conn) {
			_ = connToClose.Close()
		}(conn)
	}
	cm.lowLevelConn = cm.lowLevelConn[1:]
	return eliminatedPid, nil
}

func (cm *PeerConnManager) closeHighLevelConnFirst() (peer.ID, error) {
	eliminatedPid := cm.highLevelConn[0].pid
	for conn := range cm.highLevelConn[0].conn {
		go func(connToClose network.Conn) {
			_ = connToClose.Close()
		}(conn)
	}
	cm.highLevelConn = cm.highLevelConn[1:]
	return eliminatedPid, nil
}

func (cm *PeerConnManager) eliminateConnectionsFIFO(isHighLevel bool) (peer.ID, error) {
	hCount := len(cm.highLevelConn)
	lCount := len(cm.lowLevelConn)
	if hCount+lCount >= cm.maxSize {
		if lCount > 0 {
			eliminatedPid, err := cm.closeLowLevelConnFirst()
			if err != nil {
				return "", err
			}
			fmt.Printf("[PeerConnManager] eliminate connections"+
				"(strategy:FIFO, is high-level:%v, eliminated pid:%s)", isHighLevel, eliminatedPid)
			return eliminatedPid, nil
		} else {
			if !isHighLevel {
				return "", eliminatedHighLevelConnBugError
			}
			eliminatedPid, err := cm.closeHighLevelConnFirst()
			if err != nil {
				return "", err
			}
			fmt.Printf("[PeerConnManager] eliminate connections"+
				"(strategy:FIFO, is high-level:%v, eliminated pid:%s)", isHighLevel, eliminatedPid)
			return eliminatedPid, nil
		}
	}
	return "", nil
}

func (cm *PeerConnManager) closeLowLevelConnLast(lowLevelConnCount int) (peer.ID, error) {
	idx := lowLevelConnCount - 1
	eliminatedPid := cm.lowLevelConn[idx].pid
	for conn := range cm.lowLevelConn[idx].conn {
		go func(connToClose network.Conn) {
			_ = connToClose.Close()
		}(conn)
	}
	cm.lowLevelConn = cm.lowLevelConn[0:idx]
	return eliminatedPid, nil
}

func (cm *PeerConnManager) closeHighLevelConnLast(highLevelConnCount int) (peer.ID, error) {
	idx := highLevelConnCount - 1
	eliminatedPid := cm.highLevelConn[idx].pid
	for conn := range cm.highLevelConn[idx].conn {
		go func(connToClose network.Conn) {
			_ = connToClose.Close()
		}(conn)
	}
	cm.highLevelConn = cm.highLevelConn[0:idx]
	return eliminatedPid, nil
}

func (cm *PeerConnManager) eliminateConnectionsLIFO(isHighLevel bool) (peer.ID, error) {
	hCount := len(cm.highLevelConn)
	lCount := len(cm.lowLevelConn)
	if hCount+lCount >= cm.maxSize {
		if lCount > 0 {
			eliminatedPid, err := cm.closeLowLevelConnLast(lCount)
			if err != nil {
				return "", err
			}
			fmt.Printf("[PeerConnManager] eliminate connections"+
				"(strategy:LIFO, is high-level:%v, eliminated pid:%s)", isHighLevel, eliminatedPid)
			return eliminatedPid, nil
		} else {
			if !isHighLevel {
				return "", eliminatedHighLevelConnBugError
			}
			eliminatedPid, err := cm.closeHighLevelConnLast(hCount)
			if err != nil {
				return "", err
			}
			fmt.Printf("[PeerConnManager] eliminate connections"+
				"(strategy:LIFO, is high-level:%v, eliminated pid:%s)", isHighLevel, eliminatedPid)
			return eliminatedPid, nil
		}
	}
	return "", nil
}

// AddConn add a connection.
func (cm *PeerConnManager) AddConn(pid peer.ID, conn network.Conn) bool {
	cm.cmLock.Lock()
	defer cm.cmLock.Unlock()
	cm.connLatestTime[pid.Pretty()] = time.Now().UnixNano()
	fmt.Printf("[PeerConnManager] add conn(pid:%s)", pid.Pretty())
	isHighLevel := cm.IsHighLevel(pid)
	var pcs *peerConnections
	if isHighLevel {
		connMap, _ := cm.getHighLevelConnections(pid)
		if connMap != nil {
			if _, ok := connMap[conn]; ok {
				fmt.Printf("[PeerConnManager] connection exist(pid:%s). ignored.", pid.Pretty())
				return false
			}
			connMap[conn] = struct{}{}
			return true
		}
		connMap = make(map[network.Conn]struct{})
		connMap[conn] = struct{}{}
		pcs = &peerConnections{
			pid:  pid,
			conn: connMap,
		}
	} else {
		connMap, _ := cm.getLowLevelConnections(pid)
		if connMap != nil {
			if _, ok := connMap[conn]; ok {
				fmt.Printf("[PeerConnManager] connection exist(pid:%s). ignored.", pid.Pretty())
				return false
			}
			connMap[conn] = struct{}{}
			return true
		}
		connMap = make(map[network.Conn]struct{})
		connMap[conn] = struct{}{}
		pcs = &peerConnections{
			pid:  pid,
			conn: connMap,
		}
	}

	if pcs != nil {
		// execute the connection elimination policy
		// if the number of connections is full, one will be eliminated
		ePid, err := cm.eliminateConnections(isHighLevel)
		if err != nil {
			fmt.Printf("[PeerConnManager] eliminate connection failed, %s", err.Error())
			return false
		} else if ePid != "" {
			fmt.Printf("[PeerConnManager] eliminate connection ok(pid:%s)", ePid.Pretty())
		}

		// put the connection object into the connection manager
		if isHighLevel {
			cm.highLevelConn = append(cm.highLevelConn, pcs)
		} else {
			cm.lowLevelConn = append(cm.lowLevelConn, pcs)
		}
	}

	return true
}

// RemoveConn remove a connection.
func (cm *PeerConnManager) RemoveConn(pid peer.ID, conn network.Conn) bool {
	cm.cmLock.Lock()
	defer cm.cmLock.Unlock()
	conns, idx := cm.getHighLevelConnections(pid)
	if idx != -1 {
		for c := range conns {
			if c == conn {
				delete(conns, c)
			}
		}

		if len(conns) == 0 {
			if idx == len(cm.highLevelConn)-1 {
				cm.highLevelConn = cm.highLevelConn[:idx]
			} else {
				cm.highLevelConn = append(cm.highLevelConn[:idx], cm.highLevelConn[idx+1:]...)
			}
		} else {
			cm.highLevelConn[idx] = &peerConnections{
				pid:  pid,
				conn: conns,
			}
		}

		return true
	}
	conns2, idx2 := cm.getLowLevelConnections(pid)
	if idx2 != -1 {
		for c := range conns2 {
			if c == conn {
				delete(conns2, c)
			}
		}

		if len(conns2) == 0 {
			if idx2 == len(cm.lowLevelConn)-1 {
				cm.lowLevelConn = cm.lowLevelConn[:idx2]
			} else {
				cm.lowLevelConn = append(cm.lowLevelConn[:idx2], cm.lowLevelConn[idx2+1:]...)
			}
		} else {
			cm.lowLevelConn[idx2] = &peerConnections{
				pid:  pid,
				conn: conns2,
			}
		}

		return true
	}

	return false
}

// GetConn return a connection for peer.
func (cm *PeerConnManager) GetConn(pid peer.ID) network.Conn {
	cm.cmLock.RLock()
	defer cm.cmLock.RUnlock()
	if m, idx := cm.getHighLevelConnections(pid); idx != -1 {
		for conn := range m {
			return conn
		}
	}
	if m, idx := cm.getLowLevelConnections(pid); idx != -1 {
		for conn := range m {
			return conn
		}
	}
	return nil
}

// GetConns return a connection for peer.
func (cm *PeerConnManager) GetConns(pid peer.ID) []network.Conn {
	cm.cmLock.RLock()
	defer cm.cmLock.RUnlock()
	conns := make([]network.Conn, 0)
	if m, idx := cm.getHighLevelConnections(pid); idx != -1 {
		for conn := range m {
			conns = append(conns, conn)
		}
	}
	if m, idx := cm.getLowLevelConnections(pid); idx != -1 {
		for conn := range m {
			conns = append(conns, conn)
		}
	}
	return conns
}

// IsConnected return true if peer has connected. Otherwise, return false.
func (cm *PeerConnManager) IsConnected(pid peer.ID) bool {
	cm.cmLock.RLock()
	defer cm.cmLock.RUnlock()
	if _, idx := cm.getHighLevelConnections(pid); idx != -1 {
		return true
	}
	if _, idx := cm.getLowLevelConnections(pid); idx != -1 {
		return true
	}
	return false
}

// CanConnect return true if peer can connect to self. Otherwise, return false.
func (cm *PeerConnManager) CanConnect(pid peer.ID) bool {
	cm.cmLock.RLock()
	defer cm.cmLock.RUnlock()
	// allow a connection if it has not been made before
	lastestConnTime, ok := cm.connLatestTime[pid.Pretty()]
	if !ok {
		return true
	}

	// if the connection has been made before, check whether the connection interval is within the legal range
	// the interval is left closed and right open
	// [allowedConnTimeIntervalLower,allowedConnTimeIntervalUpper)
	rand.Seed(time.Now().UnixNano())
	allowedConnTimeInterval := (allowedConnTimeIntervalLower + rand.Intn(allowedConnTimeIntervalUpper-allowedConnTimeIntervalLower)) * 1e9
	if time.Now().UnixNano()-lastestConnTime <= int64(allowedConnTimeInterval) {
		return false
	}

	return true
}

// ConnCount return the count num of connections.
func (cm *PeerConnManager) ConnCount() int {
	cm.cmLock.RLock()
	defer cm.cmLock.RUnlock()
	return len(cm.highLevelConn) + len(cm.lowLevelConn)
}

type nodeStream struct {
	name     string //本节点名称
	pid      string //stream连接的对方节点的pid
	stream   network.Stream
	dataChan chan []byte

	manager *nodeStreamManager
	log     common.Logger

	_stopChan chan struct{}
}

func newNodeStreamHandler(ctx context.Context, n, pid string, s network.Stream, m *nodeStreamManager, log common.Logger) *nodeStream {
	nsh := &nodeStream{
		name:      n,
		pid:       pid,
		dataChan:  make(chan []byte, 1024),
		stream:    s,
		manager:   m,
		log:       log,
		_stopChan: make(chan struct{}),
	}
	return nsh
}

func (nsh *nodeStream) sendingMessages() {
	for {
		select {
		case <-nsh._stopChan:
			nsh.log.Infof("stream to %s stop", nsh.pid)
			return
		case dataBytes := <-nsh.dataChan:
			//前8个字节是长度
			bytesBuffer := bytes.NewBuffer([]byte{})
			binary.Write(bytesBuffer, binary.BigEndian, int64(len(dataBytes)))
			lengthBytes := bytesBuffer.Bytes()
			writeBytes := append(lengthBytes, dataBytes...)
			size, err := nsh.stream.Write(writeBytes)
			if err != nil {
				nsh.log.Errorf("[PeerSendMsgHandler] send the msg failed, err: [%s]", err)
				return
			}
			if size < len(writeBytes) {
				nsh.log.Errorf("[PeerSendMsgHandler] send the msg incompletely, err: [%s]", err)
				return
			}
			nsh.log.Infof("%s stream send %d byte to %s", nsh.name, size, nsh.pid)
		}
	}
}

func (nsh *nodeStream) readingMessages() {
	reader := bufio.NewReader(nsh.stream)
	for {
		select {
		case <-nsh._stopChan:
			return
		default:
		}
		buf := make([]byte, 8)
		size, err := reader.Read(buf)
		if err != nil {
			//nsh.manager._streamErrChan -> dealStreamErr() -> m.node.closeNode(pid)
			if !nsh.checkStreamErr(err) {
				nsh.manager.getStreamErrChan() <- nsh.pid
				return
			}
			nsh.log.Errorf("stream to %s read err: %s", nsh.pid, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if size < 8 {
			nsh.log.Error("can't read msg length, invalid length")
			return
		}
		bytesBuffer := bytes.NewBuffer(buf)
		var l int64
		binary.Read(bytesBuffer, binary.BigEndian, &l)
		length := int(l)
		if length > 1*1024*1024 {
			nsh.log.Error("msg is biger than 1M")
			continue
		}

		nsh.log.Infof("%s stream read a msg(len:%d)", nsh.name, length)
		//TODO:使用内存池libp2p/go-buffer-pool
		buf = make([]byte, length)
		batchSize := 4096
		//result := ln.bytesPool.GetWithLen(length)
		count := 0
		for count < length {
			remainder := length - count
			if remainder < batchSize {
				batchSize = remainder
			}
			zone := buf[count : count+batchSize]
			size, err = reader.Read(zone)
			if err != nil {
				if !nsh.checkStreamErr(err) {
					nsh.manager.getStreamErrChan() <- nsh.pid
					return
				}
				nsh.log.Errorf("stream to %s read err: %s", nsh.pid, err)
				break
			}
			count += size
		}

		if count < length {
			nsh.log.Error("can't read msg complete, continue")
			continue
		}

		go func() {
			//处理消息
			msg := Message{}
			if err := json.Unmarshal(buf, &msg); err != nil {
				nsh.log.Errorf("json unmarshal err: %s", err)
				return
			}
			////方式1：通过注册的Handler处理p2p消息
			//handler, ok := nsh.manager.GetStreamHandler(msg.Type)
			//if !ok {
			//	fmt.Printf("no msgType[%d] handler\n", msg.Type)
			//	return
			//}
			//fmt.Printf("%s-to [%s]-------reading msg-----9\n", nsh.name, nsh.pid)
			//handler.Handle(msg)

			//方式2：通过消息总线处理p2p消息
			nsh.handlingMessages(msg)

		}()

		time.Sleep(10 * time.Millisecond)
	}
}

func (nsh *nodeStream) handlingMessages(msg Message) {
	switch msg.Type.Type() {
	case common.LocalElectMsg:
		nsh.log.Infof("%s recv one elect msg from p2p net", nsh.name)
		msgbus.Publish(msg.Topic, msg.Type, msg.Data)
	default:
		fmt.Printf("unknown msg type[%d]\n", msg.Type)
	}
}

// 返回值：stream是否reading或writing继续
func (nsh *nodeStream) checkStreamErr(err error) bool {
	if strings.Contains(err.Error(), "stream reset") {
		return false
	}
	return true
}

func (nsh *nodeStream) close() {
	nsh.stream.Reset()
	close(nsh._stopChan) //停止sendingMsg, readingMsg
	close(nsh.dataChan)
}

func (nsh *nodeStream) getDataChan() chan<- []byte {
	return nsh.dataChan
}

type nodeStreamManager struct {
	node           *P2PNode
	handlers       sync.Map
	streams        sync.Map
	_streamErrChan chan string
	_stopChan      chan struct{}
}

func newNodeStreamManager(n *P2PNode) *nodeStreamManager {
	nsm := &nodeStreamManager{
		node:           n,
		_streamErrChan: make(chan string, 5),
		_stopChan:      make(chan struct{}),
	}

	go nsm.dealStreamErr()
	return nsm
}

func (m *nodeStreamManager) DeleteStream(pid string) {
	m.streams.Delete(pid)
}

func (m *nodeStreamManager) AddStream(pid string, stream *nodeStream) {
	m.streams.Store(pid, stream)
}

func (m *nodeStreamManager) GetStream(pid string) (*nodeStream, bool) {
	v, loaded := m.streams.Load(pid)
	if !loaded {
		return nil, false
	}
	r, ok := v.(*nodeStream)
	return r, ok
}

func (m *nodeStreamManager) getStreamErrChan() chan string {
	return m._streamErrChan
}

func (m *nodeStreamManager) dealStreamErr() {
	for {
		select {
		case <-m._stopChan:
			return
		case pid := <-m._streamErrChan:
			m.node.closeNode(pid)
		}
	}
}

// 对方节点discovery中发现本节点后，host.NewStream，本节点将触发本函数
func (m *nodeStreamManager) GetStreamHandlerFunc(pctx context.Context) func(network.Stream) {
	return func(stream network.Stream) {
		pi := stream.Conn().RemotePeer()
		pid := pi.String()
		m.node.log.Infof("%s get a stream from peer[%s]", m.node.cfg.Name, pid)
		if _, ok := m.GetStream(pid); ok {
			m.node.log.Warnf("%s to peer[%s]'s stream handler exist", m.node.cfg.Name, pid)
			return
		}
		m.node.leaderManager.AddPID(pid)
		nsh := newNodeStreamHandler(pctx, m.node.cfg.Name, pid, stream, m, m.node.log)
		m.AddStream(pid, nsh)
		go nsh.readingMessages()
		go nsh.sendingMessages()
	}
}

func (m *nodeStreamManager) RegisterStreamHandler(msgType common.LocalMsgType, handler P2PMessageHandler) {
	if _, ok := m.handlers.Load(msgType); !ok {
		m.handlers.Store(msgType, handler)
	}
}

func (m *nodeStreamManager) GetStreamHandler(msgType common.LocalMsgType) (P2PMessageHandler, bool) {
	h, ok := m.handlers.Load(msgType)
	if !ok {
		return nil, false
	}
	handler, ok := h.(P2PMessageHandler)
	if !ok {
		return nil, false
	}
	return handler, true
}

/*
           nodeStreamManager   nodeStream
              节点（一个通道一个stream）    节点           模块(消息类型)
connection -- stream1         -- streamHandler1   P2PMessageHandler1
           \_ stream2         -- streamHandler2   P2PMessageHandler2

*/
