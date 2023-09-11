package net

import (
	"npcc/common"
	"strings"
	"sync"
)

type nodeInfo struct {
	pid string
}

type leaderManager struct {
	nodePID string
	nodeSeq []nodeInfo
	mutex   sync.RWMutex
	log     common.Logger
}

func newLeaderManager(nodePID string, log common.Logger) *leaderManager {
	return &leaderManager{
		nodePID: nodePID,
		log:     log,
	}
}

func (lm *leaderManager) AddPID(pid string) string {
	lm.mutex.Lock()
	defer lm.mutex.Unlock()

	l := len(lm.nodeSeq)
	info := nodeInfo{pid}

	if l == 0 {
		lm.nodeSeq = append(lm.nodeSeq, info)
		lm.log.Infof("leader changed: [%s] to [%s]", "", pid)
		return pid
	}

	oldLeader := lm.nodeSeq[0].pid
	newNodes := []nodeInfo{}
	i := 0
	save := true
	for i < l {
		ret := strings.Compare(pid, lm.nodeSeq[i].pid)
		if ret == 0 {
			//有重复的，不存储
			return lm.nodeSeq[0].pid
		}
		if ret > 0 && save {
			newNodes = append(newNodes, info)
			save = false
			continue
		}
		newNodes = append(newNodes, lm.nodeSeq[i])
		i++
	}
	if newNodes[0].pid != oldLeader {
		lm.log.Infof("leader changed: [%s] to [%s]", oldLeader, newNodes[0].pid)
	}
	lm.nodeSeq = newNodes

	return lm.nodeSeq[0].pid
}

func (lm *leaderManager) DelPID(pid string) string {
	lm.mutex.Lock()
	defer lm.mutex.Unlock()

	if len(lm.nodeSeq) == 0 {
		return ""
	}

	oldLeader := lm.nodeSeq[0].pid
	newNodes := []nodeInfo{}
	for _, n := range lm.nodeSeq {
		if n.pid == pid {
			continue
		}
		newNodes = append(newNodes, n)
	}
	lm.nodeSeq = newNodes
	if len(lm.nodeSeq) == 0 {
		lm.log.Infof("leader changed: [%s] to [%s]", oldLeader, "")
		return ""
	}
	if lm.nodeSeq[0].pid != oldLeader {
		lm.log.Infof("leader changed: [%s] to [%s]", oldLeader, lm.nodeSeq[0].pid)
	}

	return lm.nodeSeq[0].pid
}

func (lm *leaderManager) LeaderPID() string {
	lm.mutex.RLock()
	defer lm.mutex.RUnlock()

	if len(lm.nodeSeq) == 0 {
		return ""
	}
	return lm.nodeSeq[0].pid
}

func (lm *leaderManager) IsLeader() bool {
	lm.mutex.RLock()
	defer lm.mutex.RUnlock()

	if len(lm.nodeSeq) == 0 {
		return false
	}

	return lm.nodeSeq[0].pid == lm.nodePID
}
