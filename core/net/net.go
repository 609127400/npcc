package net

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"sync"
)

type Message struct {
	T     int
	Topic string
	Data  []byte
}

func MakeMessage(topic string, data []byte) Message {
	return Message{1, topic, data}
}

type discoveryNotifee struct {
	h host.Host
}

// HandlePeerFound connects to peers discovered via mDNS. Once they're connected,
func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	fmt.Printf("discovered new peer %s\n", pi.ID.String())
	err := n.h.Connect(context.Background(), pi)
	if err != nil {
		fmt.Printf("error connecting to peer %s: %s\n", pi.ID.String(), err)
	}
}

type NodeConfig struct {
	addr string
}

type Node struct {
	id          peer.ID
	host        host.Host
	ps          *pubsub.PubSub
	kademliaDHT *dht.IpfsDHT

	topics      sync.Map
	subscribers sync.Map
	ctx         context.Context
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

func InitLocalNodeWithTopic(t string) *Node {
	n := &Node{}

	var err error
	n.ctx = context.Background()
	opt := libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0")
	n.host, err = libp2p.New(opt)
	if err != nil {
		panic(err)
	}
	n.host.Network().Notify(initNetworkNotifiee(n))

	n.ps, err = pubsub.NewGossipSub(n.ctx, n.host)
	if err != nil {
		panic(err)
	}

	//discover
	mdnsService := mdns.NewMdnsService(n.host, "npcc-local-mdns", &discoveryNotifee{h: n.host})
	if err = mdnsService.Start(); err != nil {
		panic(err)
	}
	options := []dht.Option{dht.Mode(dht.ModeServer)}
	//if len(bootstraps) > 0 {
	//	options = append(options, dht.BootstrapPeers(bootstraps...))
	//}
	// new kademlia DHT
	n.kademliaDHT, err = dht.New(n.ctx, n.host, options...)
	if err != nil {
		panic(err)
	}
	// set as bootstrap
	if err = n.kademliaDHT.Bootstrap(n.ctx); err != nil {
		panic(err)
	}

	n.id = n.host.ID()
	topic, err := n.ps.Join(t)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	n.topics.Store(t, topic)
	sub, err := topic.Subscribe()
	if err != nil {
		return nil
	}
	n.subscribers.Store(t, sub)
	return n
}

func (n *Node) Publish(msg Message) error {
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

func (n *Node) SendToNodes(addr []string, msg Message) error {
	//n.ps.ListPeers()
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

func (n *Node) Subscribe(id string) (*pubsub.Subscription, error) {
	if v, ok := n.subscribers.Load(id); ok {
		sub := v.(*pubsub.Subscription)
		return sub, nil
	}

	topic, err := n.ps.Join(id)
	if err != nil {
		return nil, err
	}
	n.topics.Store(id, topic)
	sub, err := topic.Subscribe()
	if err != nil {
		return nil, err
	}
	n.subscribers.Store(id, sub)

	return sub, nil
}

func (n *Node) ReadLoop(id string) {
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

func initNetworkNotifiee(n *Node) network.Notifiee {
	return &network.NotifyBundle{
		ConnectedF: func(_ network.Network, c network.Conn) {
			fmt.Printf("[Host-%s] connecting %s...\n", n.id.String(), c.ID())
		},
		DisconnectedF: func(_ network.Network, c network.Conn) {
			fmt.Printf("[Host-%s] disconnecting %s...\n", n.id.String(), c.ID())
		},
	}
}

func (n *Node) handleMessage(msg *Message) {
	fmt.Printf("recv msg: %s\n", msg.Data)
}

func (n *Node) ListPeers(id string) []peer.ID {
	return n.ps.ListPeers(id)
}

func (n *Node) Stop() {

}
