package net

import (
	"fmt"
	"github.com/libp2p/go-libp2p/core/peer"
	"sync"
	"time"
)

const (
	// DefaultTryTimes is the default try times. Max timeout is 10m10s.
	DefaultTryTimes = 15
	// DefaultTryTimesAfterMaxTime is the default try times after max timeout, which is 90 days.
	DefaultTryTimesAfterMaxTime = 6 * 24 * 90
)

// ConnSupervisor is a connections supervisor.
type ConnSupervisor struct {
	node              *P2PNode
	peerAddrInfos     []peer.AddrInfo
	peerAddrInfosLock sync.RWMutex
	signal            bool
	signalLock        sync.RWMutex
	startUp           bool
	tryConnectLock    sync.Mutex
	allConnected      bool

	tryTimes  int
	actuators map[peer.ID]*tryToDialActuator
}

func (cs *ConnSupervisor) getSignal() bool {
	cs.signalLock.RLock()
	defer cs.signalLock.RUnlock()
	return cs.signal
}

func (cs *ConnSupervisor) setSignal(signal bool) {
	cs.signalLock.Lock()
	defer cs.signalLock.Unlock()
	cs.signal = signal
}

// newConnSupervisor create a new ConnSupervisor.
func newConnSupervisor(n *P2PNode, peerAddrInfos []peer.AddrInfo) *ConnSupervisor {
	return &ConnSupervisor{
		node:          n,
		peerAddrInfos: peerAddrInfos,
		startUp:       false,
		allConnected:  false,
		tryTimes:      DefaultTryTimes,
		actuators:     make(map[peer.ID]*tryToDialActuator),
	}
}

// getPeerAddrInfos get the addr infos of the peers for supervising.
func (cs *ConnSupervisor) getPeerAddrInfos() []peer.AddrInfo {
	cs.peerAddrInfosLock.RLock()
	defer cs.peerAddrInfosLock.RUnlock()
	return cs.peerAddrInfos
}

// refreshPeerAddrInfos refresh the addr infos of the peers for supervising.
func (cs *ConnSupervisor) refreshPeerAddrInfos(peerAddrInfos []peer.AddrInfo) {
	cs.peerAddrInfosLock.Lock()
	defer cs.peerAddrInfosLock.Unlock()
	cs.peerAddrInfos = peerAddrInfos
}

// startSupervising start a goroutine to supervise connections.
func (cs *ConnSupervisor) startSupervising(readySignal chan struct{}) {
	if cs.startUp {
		return
	}
	cs.setSignal(true)
	go func() {
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("%s\n", err)
			}
		}()
		cs.startUp = true
		timer := time.NewTimer(10 * time.Second)
		select {
		case <-readySignal:
		case <-timer.C:
		}
		for cs.getSignal() {
			//if cs.host.connManager.ConnCount() < len(cs.getPeerAddrInfos()) {
			cs.try()
			//}
			time.Sleep(5 * time.Second)
		}
		cs.startUp = false
	}()
}

func (cs *ConnSupervisor) try() {
	if len(cs.peerAddrInfos) > 0 {
		cs.tryConnectLock.Lock()
		defer cs.tryConnectLock.Unlock()
		peerAddrInfos := cs.getPeerAddrInfos()
		count := len(peerAddrInfos)
		connectedCount := 0
		for _, peerInfo := range cs.getPeerAddrInfos() {
			if cs.node.host.ID() == peerInfo.ID || cs.node.connManager.IsConnected(peerInfo.ID) {
				connectedCount++
				if connectedCount == count && !cs.allConnected {
					fmt.Printf("[ConnSupervisor] all necessary peers connected.\n")
					cs.allConnected = true
				}
				_, ok := cs.actuators[peerInfo.ID]
				if ok {
					delete(cs.actuators, peerInfo.ID)
				}
				continue
			}
			cs.allConnected = false
			ac, ok := cs.actuators[peerInfo.ID]
			if !ok || ac.finish {
				cs.actuators[peerInfo.ID] = newTryToDialActuator(peerInfo, cs, cs.tryTimes)
				ac = cs.actuators[peerInfo.ID]
			}
			go ac.run()
		}

	}
}

type tryToDialActuator struct {
	peerInfo  peer.AddrInfo
	fibonacci []int64
	idx       int
	giveUp    bool
	finish    bool
	statC     chan struct{}

	cs *ConnSupervisor
}

func fibonacciArray(n int) []int64 {
	res := make([]int64, n, n)
	for i := 0; i < n; i++ {
		if i <= 1 {
			res[i] = 1
		} else {
			res[i] = res[i-1] + res[i-2]
		}
	}
	return res
}

func newTryToDialActuator(peerInfo peer.AddrInfo, cs *ConnSupervisor, tryTimes int) *tryToDialActuator {
	return &tryToDialActuator{
		peerInfo:  peerInfo,
		fibonacci: fibonacciArray(tryTimes),
		idx:       0,
		giveUp:    false,
		finish:    false,
		statC:     make(chan struct{}, 1),
		cs:        cs,
	}
}

func (a *tryToDialActuator) run() {
	select {
	case a.statC <- struct{}{}:
		defer func() {
			<-a.statC
		}()
	default:
		return
	}
	if a.giveUp || a.finish {
		return
	}
	for {
		if !a.cs.startUp {
			break
		}
		if a.cs.node.connManager.IsConnected(a.peerInfo.ID) {
			a.finish = true
			break
		}
		fmt.Printf("[ConnSupervisor] try to connect(peer:%s)\n", a.peerInfo)
		var err error
		if err = a.cs.node.host.Connect(a.cs.node.ctx, a.peerInfo); err == nil {
			fmt.Printf("[ConnSupervisor] connect ok\n")
			a.finish = true
			break
		}
		fmt.Printf("[ConnSupervisor] try to connect to peer failed(peer: %s, times: %d),%s\n",
			a.peerInfo, a.idx+1, err.Error())
		a.idx = a.idx + 1
		// will give up when over 90days
		if a.idx > DefaultTryTimesAfterMaxTime {
			fmt.Printf("[ConnSupervisor] can not connect to peer, give it up. (peer:%s)\n", a.peerInfo)
			a.giveUp = true
			break
		}
		var timeout time.Duration
		if a.idx >= len(a.fibonacci) {
			// use max timeout
			timeout = time.Duration(a.fibonacci[len(a.fibonacci)-1]) * time.Second
		} else {
			timeout = time.Duration(a.fibonacci[a.idx]) * time.Second
		}
		time.Sleep(timeout)
	}
}

// stopSupervising stop supervising.
func (cs *ConnSupervisor) stopSupervising() {
	cs.setSignal(false)
}

// nolint
// handleChanNewPeerFound handle the new peer found which got from discovery.
func (cs *ConnSupervisor) handleChanNewPeerFound(peerChan <-chan peer.AddrInfo) {
	go func() {
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("[ConnSupervisor.handleChanNewPeerFound] recover err, %s\n", err)
			}
		}()
		for p := range peerChan {
			cs.tryConnectLock.Lock()
			if p.ID == cs.node.host.ID() || cs.node.connManager.IsConnected(p.ID) {
				cs.tryConnectLock.Unlock()
				continue
			}
			err := cs.node.host.Connect(cs.node.ctx, p)
			if err != nil {
				fmt.Printf("[ConnSupervisor] new connection connect failed"+
					"(remote peer id:%s, remote addr:%s),%s\n", p.ID.String(), p.Addrs[0].String(), err.Error())
			} else {
				fmt.Printf("[ConnSupervisor] new connection connected(remote peer id:%s, remote addr:%s)\n",
					p.ID.String(), p.Addrs[0].String())
			}
			cs.tryConnectLock.Unlock()
		}
	}()
}
