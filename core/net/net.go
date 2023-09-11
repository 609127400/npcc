package net

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	corecrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"npcc/core/msgbus"

	//drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	//dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	//"github.com/multiformats/go-multiaddr"
	"npcc/common"
	"strings"
	"sync"
)

type discoveryNotifee struct {
	node *P2PNode
}

// HandlePeerFound connects to peers discovered via mDNS. Once they're connected,
func (d *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	pid := pi.ID.String()
	d.node.log.Infof("%s discovered new peer[%s]", d.node.cfg.Name, pid)

	msgbus.Publish("", common.LocalNetMsg_Discovery, pid)
	//更新leader
	d.node.leaderManager.AddPID(pid)

	//这里假设，A能发现B，则B肯定也能发现A。2个节点。若A>B，则A负责Connect，host.NewStream，并启动r、w，
	//B则通过host.SetStreamHandler设定的函数启动r、w
	if strings.Compare(d.node.host.ID().String(), pid) > 0 {
		return
	}

	err := d.node.host.Connect(d.node.ctx, pi)
	if err != nil {
		d.node.log.Errorf("%s error connect to peer[id:%s, addr:%s]: %s", d.node.cfg.Name, pi.ID, pi.Addrs[0].String(), err)
	} else {
		d.node.log.Infof("%s connected to peer[id:%s, addr:%s]", d.node.cfg.Name, pi.ID, pi.Addrs[0].String())
	}

	if _, exist := d.node.streamManager.GetStream(pid); !exist {
		//连接对方节点后，创建NewStream，对方节点中通过host.SetStreamHandler设置的Handler函数将被执行
		stream, err := d.node.host.NewStream(d.node.ctx, pi.ID, protocol.ID(d.node.cfg.ProtocolID))
		if err != nil {
			d.node.log.Errorf("%s new stream to %s err: %s", d.node.cfg.Name, pi.ID, err)
			return
		}

		streamHandler := newNodeStreamHandler(d.node.ctx, d.node.cfg.Name, pid, stream, d.node.streamManager, d.node.log)
		d.node.streamManager.AddStream(pid, streamHandler)
		go streamHandler.readingMessages()
		go streamHandler.sendingMessages()
	} else {
		fmt.Printf("%s already exist %s's stream handler\n", d.node.cfg.Name, pi.ID.String())
	}
}

type connNotifyMsg struct {
	conn network.Conn
	on   bool
}

type P2PNode struct {
	id          peer.ID
	opts        []libp2p.Option
	host        host.Host
	ps          *pubsub.PubSub
	kademliaDHT *dht.IpfsDHT

	topics      sync.Map
	subscribers sync.Map
	ctx         context.Context //TODO：用ctx控制所有小模块的结束
	cfg         *common.P2PNodeConfig
	log         common.Logger
	//本地网络中，ID最大的作为唱票节点。
	//网络中，raft的leader节点作为唱票节点
	leaderManager  *leaderManager
	connManager    *PeerConnManager
	connHandleC    chan *connNotifyMsg
	connSupervisor *ConnSupervisor

	streamManager *nodeStreamManager

	readyChan chan struct{}
}

// createLibp2pOptions create all necessary options for libp2p.
//func (ln *LibP2pNet) createLibp2pOptions() ([]libp2p.Option, error) {
//	ln.log.Info("[Net] creating options...")
//
//	//use default crypto engine, TODO optimize
//	engine.InitCryptoEngine("tjfoc", true)
//
//	prvKey, err := ln.prepareKey()
//	if err != nil {
//		ln.log.Errorf("[Net] prepare key failed, %s", err.Error())
//		return nil, err
//	}
//	connGater := NewConnGater(ln.libP2pHost.connManager, ln.libP2pHost.blackList, ln.libP2pHost.memberStatusValidator, ln.log)
//	listenAddrs := strings.Split(ln.prepare.listenAddr, ",")
//	options := []libp2p.Option{
//		libp2p.Identity(prvKey),
//		libp2p.ListenAddrStrings(listenAddrs...),
//		libp2p.ConnectionGater(connGater),
//		libp2p.EnableRelay(circuit.OptHop),
//		//libp2p.EnableNATService(),
//	}
//	if ln.prepare.isInsecurity {
//		ln.log.Warn("[Net] use insecurity option.")
//		options = append(options, libp2p.NoSecurity)
//		ln.libP2pHost.isTls = false
//	} else {
//		if prvKey.Type().String() == "SM2" {
//			ln.log.Info("[Net] the private key type found[sm2]. use gm tls security.")
//			ln.libP2pHost.isTls = true
//		} else {
//			ln.log.Info("[Net] the private key type found[not sm2]. use normal tls security.")
//			ln.libP2pHost.isTls = true
//		}
//		// tls cert validator
//		ln.libP2pHost.tlsCertValidator = cmtlssupport.NewCertValidator(
//			ln.prepare.pubKeyMode,
//			ln.libP2pHost.memberStatusValidator,
//			ln.libP2pHost.customChainTrustRoots,
//		)
//		ln.libP2pHost.initTlsSubassemblies()
//
//		var tlsCfg *tls.Config
//		if ln.prepare.pubKeyMode {
//			// public key mode
//			ln.log.Info("[Net] public key mode confirmed.")
//			// get private key
//			privateKey, err2 := asym.PrivateKeyFromPEM(ln.prepare.keyBytes, nil)
//			if err2 != nil {
//				return nil, err2
//			}
//			// get public key bytes
//			pubKeyPem, err3 := privateKey.PublicKey().String()
//			if err3 != nil {
//				return nil, err3
//			}
//			// get peer id
//			peerId, err4 := helper.CreateLibp2pPeerIdWithPrivateKey(privateKey)
//			if err4 != nil {
//				return nil, err4
//			}
//			// store peer id
//			ln.libP2pHost.peerIdPubKeyStore.SetPeerPubKey(peerId, []byte(pubKeyPem))
//			// store certIdMap
//			ln.libP2pHost.certPeerIdMapper.Add(pubKeyPem, peerId)
//			// create tls config
//			tlsCfg, err = cmtlssupport.NewTlsConfigWithPubKeyMode(privateKey, ln.libP2pHost.tlsCertValidator)
//			if err != nil {
//				return nil, err
//			}
//		} else {
//			// cert mode
//			ln.log.Info("[Net] certificate mode confirmed.")
//			// create tls certificate
//			var tlsCerts []tls.Certificate
//			tlsCert, peerId, e := cmtlssupport.GetCertAndPeerIdWithKeyPair(ln.prepare.certBytes, ln.prepare.keyBytes)
//			if e != nil {
//				return nil, e
//			}
//			tlsCerts = append(tlsCerts, *tlsCert)
//
//			tlsEncCert, _, e := cmtlssupport.GetCertAndPeerIdWithKeyPair(ln.prepare.encCertBytes, ln.prepare.encKeyBytes)
//			if e == nil && tlsEncCert != nil {
//				tlsCerts = append(tlsCerts, *tlsEncCert)
//				ln.log.Info("[Net] tls enc certificate is set, use gmtls")
//			}
//
//			// store tls cert
//			ln.libP2pHost.peerIdTlsCertStore.SetPeerTlsCert(peerId, tlsCert.Certificate[0])
//			// store certIdMap
//			var tlsCertificate *cmx509.Certificate
//			certBlock, rest := pem.Decode(ln.prepare.certBytes)
//			if certBlock == nil {
//				tlsCertificate, err = cmx509.ParseCertificate(rest)
//				if err != nil {
//					ln.log.Warnf("[Net] [prepare] set cert id map failed, %s", err.Error())
//					return nil, err
//				}
//			} else {
//				tlsCertificate, err = cmx509.ParseCertificate(certBlock.Bytes)
//				if err != nil {
//					ln.log.Warnf("[Net] [prepare] set cert id map failed, %s", err.Error())
//					return nil, err
//				}
//			}
//
//			var certIdBytes []byte
//			certIdBytes, err = cmx509.GetNodeIdFromSm2Certificate(cmx509.OidNodeId, *tlsCertificate)
//			if err != nil {
//				ln.log.Warn("[Net] [prepare] set cert id map failed, %s", err.Error())
//				return nil, err
//			}
//			ln.libP2pHost.certPeerIdMapper.Add(string(certIdBytes), peerId)
//
//			// create tls config
//			tlsCfg, err = cmtlssupport.NewTlsConfigWithCertMode(tlsCerts, ln.libP2pHost.tlsCertValidator)
//			if err != nil {
//				return nil, err
//			}
//		}
//
//		tmp := func() host.Host {
//			return ln.libP2pHost.Host()
//		}
//		tpt := cmtls.New(tlsCfg, tmp, ln.log)
//		options = append(options, libp2p.Security(cmtls.ID, tpt))
//	}
//	ln.log.Info("[Net] options created.")
//	return options, nil
//}

func NewLocalP2PNode(c *common.P2PNodeConfig) *P2PNode {
	n := &P2PNode{}

	n.ctx = context.Background()
	n.cfg = c
	n.readyChan = make(chan struct{})
	n.log = common.GetLogger(common.MODULE_P2PNET)

	privKey, _, err := corecrypto.KeyPairFromStdKey(c.PrivKey)
	if err != nil {
		fmt.Printf("[Net] parse private key to priv key failed, %s", err)
		return nil
	}
	n.opts = []libp2p.Option{
		libp2p.ListenAddrStrings(c.Addr),
		libp2p.Identity(privKey),
	}
	n.streamManager = newNodeStreamManager(n)

	return n
}

func (n *P2PNode) Start() error {
	var err error
	n.host, err = libp2p.New(n.opts...)
	if err != nil {
		panic(err)
	}
	n.id = n.host.ID()

	n.leaderManager = newLeaderManager(n.id.String(), n.log)
	n.leaderManager.AddPID(n.id.String())
	n.host.SetStreamHandler(protocol.ID(n.cfg.ProtocolID), n.streamManager.GetStreamHandlerFunc(n.ctx))

	//n.host.Network().Notify(initNetworkNotifiee(n))
	//n.connManager = NewPeerConnManager()
	//n.connHandleC = make(chan *connNotifyMsg)
	err = n.startDiscovery()
	if err != nil {
		return err
	}

	n.ps, err = pubsub.NewGossipSub(n.ctx, n.host)
	if err != nil {
		panic(err)
	}

	topic, err := n.ps.Join(n.cfg.Topic)
	if err != nil {
		fmt.Println(err)
		return err
	}
	n.topics.Store(n.cfg.Topic, topic)
	sub, err := topic.Subscribe()
	if err != nil {
		return err
	}
	n.subscribers.Store(n.cfg.Topic, sub)

	n.log.Infof("%s be local net peer[%s] start...", n.cfg.Name, n.id.String())

	return nil
}

func (n *P2PNode) startDiscovery() error {
	//mdns discover
	dn := &discoveryNotifee{n}
	mdnsService := mdns.NewMdnsService(n.host, n.cfg.Topic, dn)
	if err := mdnsService.Start(); err != nil {
		panic(err)
	}

	//参看libp2p官方例子
	//dht
	//var err error
	//opts := []dht.Option{dht.Mode(dht.ModeServer)}
	//peers := make([]peer.AddrInfo, 0)
	//if len(n.cfg.Bootstraps) > 0 {
	//	for _, v := range n.cfg.Bootstraps {
	//		addr, err := multiaddr.NewMultiaddr(v)
	//		if err != nil {
	//			panic(err)
	//		}
	//		peer, err := peer.AddrInfoFromP2pAddr(addr)
	//		if err != nil {
	//			panic(err)
	//		}
	//		if peer.ID == n.host.ID() {
	//			continue
	//		}
	//		fmt.Printf("append peer: %s", peer.String())
	//		peers = append(peers, *peer)
	//		n.connManager.AddAsHighLevelPeer(peer.ID)
	//	}
	//	opts = append(opts, dht.BootstrapPeers(peers...))
	//}
	//n.kademliaDHT, err = dht.New(n.ctx, n.host, opts...)
	//if err != nil {
	//	panic(err)
	//}
	//// set as bootstrap
	//if err = n.kademliaDHT.Bootstrap(n.ctx); err != nil {
	//	panic(err)
	//}
	//
	//routingDiscovery := drouting.NewRoutingDiscovery(n.kademliaDHT)
	//dutil.Advertise(n.ctx, routingDiscovery, n.cfg.MsgType)
	//fmt.Println("Successfully announced!")
	//
	//// Now, look for others who have announced
	//// This is like your friend telling you the location to meet you.
	//fmt.Println("Searching for other peers...")
	//peerChan, err := routingDiscovery.FindPeers(n.ctx, n.cfg.MsgType)
	//if err != nil {
	//	panic(err)
	//}
	//
	//for peer := range peerChan {
	//	if peer.ID == n.host.ID() {
	//		continue
	//	}
	//	fmt.Printf("Found peer: %s, connect to it\n", peer)
	//	stream, err := n.host.NewStream(n.ctx, peer.ID, n.protocolID)
	//	if err != nil {
	//		fmt.Printf("Connection failed: %s\n", err)
	//		continue
	//	} else {
	//		fmt.Printf("Connected to: %s\n", peer)
	//		rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
	//		go writeData(rw)
	//		go readData(rw)
	//	}
	//}

	//参考chainmaker

	//n.connSupervisor = newConnSupervisor(n, peers)
	//n.connSupervisor.startSupervising(n.readyChan)

	return nil
}

func (n *P2PNode) Publish(msg Message) error {
	v, ok := n.topics.Load(msg.Topic)
	if !ok {
		return fmt.Errorf("%s topic isn't exist", msg.Topic)
	}
	topic := v.(*pubsub.Topic)
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	fmt.Printf("%s send msg[%s] to topic %s\n", n.id.String(), msgBytes, msg.Topic)
	return topic.Publish(n.ctx, msgBytes)
}

func (n *P2PNode) isConnected(addr string) (bool, peer.ID, error) {
	isConnected := false
	pid, err := peer.Decode(addr) // peerId
	if err != nil {
		return false, pid, err
	}
	isConnected = n.connManager.IsConnected(pid)
	return isConnected, pid, nil
}

// 清楚一个节点相关的连接、资源占用等
func (n *P2PNode) closeNode(pid string) {
	psh, ok := n.streamManager.GetStream(pid)
	if !ok {
		return
	}
	psh.close()
	n.streamManager.DeleteStream(pid)
	n.leaderManager.DelPID(pid)

	n.log.Infof("node[%s] close stream to [%s]", n.cfg.Name, pid)
}

/*
发：msg-> dataChan-> sendingMessages-> psh.stream.Write(writeBytes)-> readHandler.StreamReadHandler

	-> RegisterMessageHandler-> P2PMessageHandler 收
*/
func (n *P2PNode) SendToNodes(addrs []string, msg Message) error {
	//如果addrs为空，则默认发给leader节点
	if addrs == nil {
		leaderID := n.leaderManager.LeaderPID()
		if leaderID == "" {
			return fmt.Errorf("there is no leader pid")
		}
		addrs = []string{leaderID}
	}

	for _, addr := range addrs {
		if addr == n.id.String() {
			n.log.Warn("[Net] can not send msg to self")
			continue
		}
		//connManager未使用
		//isConnected, pid, _ := n.isConnected(addr)
		//if !isConnected {
		//	return fmt.Errorf("[Net] send msg failed, node not connected, nodeId: [%s]", addr)
		//}

		nsh, ok := n.streamManager.GetStream(addr)
		if !ok {
			n.log.Errorf("GetStream err, no stream for peer[%s]", addr)
			return nil
		}

		if nsh == nil {
			return fmt.Errorf("psh is nil")
		}
		dataChan := nsh.getDataChan()
		if dataChan == nil {
			return fmt.Errorf("dataChan is nil")
		}
		dataBytes, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("json marshal msg err: %s", err)
		}

		select {
		case dataChan <- dataBytes:
			n.log.Infof("put the msg into the peer[%s] stream chan", addr)
		default:
			n.log.Errorf("the peer[%s] stream channel is full", addr)
			return fmt.Errorf("the peer stream channel is full")
		}
	}

	return nil
}

// SubscribeWithChainId subscribe the given topic of the target chain which id is
// the given chainId with the given sub-msg handler function.
//func (ln *LibP2pNet) SubscribeWithChainId(chainId string, topic string, handler api.PubSubMsgHandler) error {
//	ln.subscribeLock.Lock()
//	defer ln.subscribeLock.Unlock()
//	topic = chainId + "_" + topic
//	// whether pubsub existed
//	pubsub, ok := ln.getPubSub(chainId)
//	if !ok {
//		return ErrorPubSubNotExist
//	}
//	// whether subscribed
//	if ln.isSubscribed(chainId, topic) { //检查topic是否已被订阅
//		return ErrorTopicSubscribed
//	}
//	topicSub, err := pubsub.Subscribe(topic) // subscribe the topic
//	if err != nil {
//		return err
//	}
//	// add subscribe info
//	topics := ln.getSubscribeTopicMap(chainId)
//	topics.m[topic] = topicSub
//	// run a new goroutine to handle the msg from the topic subscribed.
//	go func() {
//		defer func() {
//			if err := recover(); err != nil {
//				if !ln.isSubscribed(chainId, topic) {
//					return
//				}
//				ln.log.Errorf("[Net] subscribe goroutine recover err, %s", err)
//			}
//		}()
//		ln.topicSubLoop(chainId, topicSub, topic, handler)
//	}()
//	// reload chain pub-sub whitelist
//	ln.reloadChainPubSubWhiteList(chainId)
//	return nil
//}
//func (ln *LibP2pNet) topicSubLoop(
//	chainId string,
//	topicSub *libP2pPubSub.Subscription,
//	topic string,
//	handler api.PubSubMsgHandler) {
//	for {
//		message, err := topicSub.Next(ln.ctx)
//		if err != nil {
//			if err.Error() == "subscription cancelled" {
//				ln.log.Warn("[Net] ", err)
//				break
//			}
//			//logger
//			ln.log.Errorf("[Net] subscribe next failed, %s", err.Error())
//		}
//		if message == nil {
//			return
//		}
//
//		go func(msg *libP2pPubSub.Message) {
//			// if author of the msg is myself , just skip and continue
//			if message.ReceivedFrom == ln.libP2pHost.host.ID() || message.GetFrom() == ln.libP2pHost.host.ID() {
//				return
//			}
//			// if author of the msg not belong to this chain, drop it
//			// if !ln.peerChainIdsRecorder().IsPeerBelongToChain(message.GetFrom().Pretty(), chainId) {
//			// 	return
//			// }
//
//			// if sender of the msg not belong to this chain, drop it
//			if !ln.peerChainIdsRecorder().IsPeerBelongToChain(message.ReceivedFrom.Pretty(), chainId) {
//				return
//			}
//
//			bytes := message.GetData()
//			ln.log.Debugf("[Net] receive subscribed msg(topic:%s), data size:%d", topic, len(bytes))
//			// call handler
//			if err = handler(message.GetFrom().Pretty(), bytes); err != nil {
//				ln.log.Warnf("[Net] call subscribe handler failed, %s ", err)
//			}
//		}(message)
//	}
//}

func (n *P2PNode) Subscribe(t string) (*pubsub.Subscription, error) {
	if v, ok := n.subscribers.Load(t); ok {
		sub := v.(*pubsub.Subscription)
		return sub, nil
	}

	topic, err := n.ps.Join(t)
	if err != nil {
		return nil, err
	}
	n.topics.Store(t, topic)
	sub, err := topic.Subscribe()
	if err != nil {
		return nil, err
	}
	n.subscribers.Store(t, sub)

	return sub, nil
}

// 保留注册制，但当前主要通过msgbus在各个模块间传递消息
func (n *P2PNode) RegisterMessageHandler(msgType common.LocalMsgType, handler P2PMessageHandler) {
	n.streamManager.RegisterStreamHandler(msgType, handler)
}

func (n *P2PNode) ReadLoop(id string) {
	v, ok := n.subscribers.Load(id)
	if !ok {
		return
	}
	sub := v.(*pubsub.Subscription)
	fmt.Printf("%s readLoop[topic: %s] start...\n", n.id.String(), id)
	for {
		msg, err := sub.Next(n.ctx)
		if err != nil {
			fmt.Println(err)
			continue
		}
		// only forward messages delivered by others
		if msg.ReceivedFrom == n.id {
			fmt.Println("recv self msg")
			continue
		}
		cm := new(Message)
		err = json.Unmarshal(msg.Data, cm)
		if err != nil {
			fmt.Println(err)
			continue
		}
		// send valid messages onto the Messages channel
		n.handleMessage(cm)
	}
}

func initNetworkNotifiee(n *P2PNode) network.Notifiee {
	return &network.NotifyBundle{
		ConnectedF: func(_ network.Network, c network.Conn) {
			select {
			case <-n.ctx.Done():
				return
			case <-n.readyChan:
			}

			n.connHandleC <- &connNotifyMsg{
				conn: c,
				on:   true,
			}
		},
		DisconnectedF: func(_ network.Network, c network.Conn) {
			select {
			case <-n.ctx.Done():
				return
			case <-n.readyChan:
			}

			n.connHandleC <- &connNotifyMsg{
				conn: c,
				on:   false,
			}
		},
	}
}

func (n *P2PNode) handleMessage(msg *Message) {
	fmt.Printf("recv msg: %s\n", msg.Data)
}

func (n *P2PNode) ListPeersByChannelID(channelID string) []peer.ID {
	return n.ps.ListPeers(channelID)
}

// 给出已加入的所有通道的所有节点ID
func (n *P2PNode) ListPeers() []peer.ID {
	var ids []peer.ID
	f := func(k, v interface{}) bool {
		t, ok := v.(*pubsub.Topic)
		if !ok {
			return false
		}
		mem := t.ListPeers()
		ids = append(ids, mem...)
		return true
	}
	n.topics.Range(f)
	//TODO:去重
	ids = append(ids, n.id)
	return ids
}

func (n *P2PNode) IsLeader() bool {
	return n.leaderManager.IsLeader()
}

func (n *P2PNode) PID() string {
	return n.host.ID().String()
}

func (n *P2PNode) Name() string {
	return n.cfg.Name
}

func (n *P2PNode) Stop() {

}
