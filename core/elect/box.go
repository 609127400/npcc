package elect

import (
	"bytes"
	"fmt"
	"npcc/common"
	"npcc/pbgo"
	"sync"
	"sync/atomic"
	"time"
)

const (
	BoxStatus_Unvalid    uint32 = 0 //box未初始化，不可使用，等待Start，
	BoxStatus_Working    uint32 = 1 //box运行中，可以AddID和Vote
	BoxStatus_WaitReport uint32 = 2 //当轮选举结束，等待report
	BoxStatus_Reported   uint32 = 3 //上轮的选举数据已report，或者stop，box可以reset，reset后将重置为BoxStatus_Unvalid
)

type VoteSpec struct {
	votes []*pbgo.Vote //具体的每一票
	num   int          //票数
}

type ElectReport struct {
	Role       string
	Epoch      int
	Winner     string
	DetailForm []byte
}

type AutoCalloutHandler func([]byte) error

type Box struct {
	role  string               //选举箱针对的选举目标（角色）
	votes map[string]*VoteSpec //被投票人id->票数
	mutex sync.RWMutex         //用于锁votes和idNum

	calloutHandler AutoCalloutHandler
	strategy       ElectStrategy
	stopChan       chan struct{}
	log            common.Logger

	_startTime string
	_stopTime  string
	_timer     *time.Timer
	_epoch     int    //第几届选举，TODO:从链上获取
	_winner    string //当届选举的获胜者
	_status    atomic.Uint32
	_onceStart sync.Once
	_onceStop  sync.Once
}

func newBox(role string, s ElectStrategy, log common.Logger, ch AutoCalloutHandler) *Box {
	box := &Box{
		role:           role,
		votes:          make(map[string]*VoteSpec),
		strategy:       s,
		stopChan:       make(chan struct{}, 1),
		log:            log,
		calloutHandler: ch,
	}
	box._status.Store(BoxStatus_Unvalid)
	return box
}

func (b *Box) AddID(id string) {
	if b._status.Load() != BoxStatus_Working {
		b.log.Warn("box is not on working, can't add id")
		return
	}

	b.mutex.Lock()
	if _, ok := b.votes[id]; !ok {
		b.votes[id] = nil
	}
	b.mutex.Unlock()
}

func (b *Box) Vote(v *pbgo.Vote) error {
	s := b._status.Load()
	if s != BoxStatus_Working {
		return fmt.Errorf("box status[%d] is not on working, can't vote", s)
	}

	//TODO:查看票的epoch：leader负责收集票，则leader的Vote肯定是和自己epoch保持一致的
	//其它转发过来的Vote，则比较一下epoch是否已过期，或超前

	b.mutex.Lock()
	defer b.mutex.Unlock()
	if vs, ok := b.votes[v.Id]; ok && vs != nil {
		for idx, oldv := range vs.votes {
			if oldv.Voter == v.Voter {
				b.log.Warnf("voter[%s] revote for %s", v.Voter, v.Id)
				vs.votes[idx] = v
				return nil
			}
		}
		vs.votes = append(vs.votes, v)
		vs.num++
	} else {
		//如果投的这个人不存在，则新建一个。可能的问题：恶意投票不存在的人
		vs := &VoteSpec{}
		vs.num = 1
		vs.votes = append(vs.votes, v)
		b.votes[v.Id] = vs
	}

	return nil
}

// 在第一次投票时创建Box，并启动
// 或者经manager的Start调用启动
func (b *Box) start() {
	s := b._status.Load()
	if s != BoxStatus_Unvalid {
		b.log.Errorf("box is not startable, status[%d]", s)
		return
	}

	startFun := func() {
		b._status.Store(BoxStatus_Working)
		b._startTime = time.Now().Format(time.RFC822)

		go func() {
			b._timer = time.NewTimer(time.Duration(b.strategy.period) * time.Minute)
			select {
			case <-b._timer.C:
				b.log.Infof("Box[%s] epoch[%d] elect time over", b.role, b._epoch)
				b._stopTime = time.Now().Format(time.RFC822)
				b._status.Store(BoxStatus_WaitReport)

				b.mutex.Lock()
				report, err := b.report()
				b.mutex.Unlock()

				if err == nil {
					err = b.calloutHandler(report.DetailForm)
					if err != nil {
						b.log.Errorf("Box[%s] epoch[%d] elect auto report err: %s", b.role, b._epoch, err)
						//TODO:是否重试？
					}
					b.log.Infof("Box[%s] epoch[%d] reset", b.role, b._epoch)
					b.reset()
				} else {
					b.log.Errorf("Box[%s] epoch[%d] elect auto report err: %s", b.role, b._epoch, err)
				}
			case <-b.stopChan:
				b.log.Infof("Box[%s] epoch[%d] elect stop", b.role, b._epoch)
			}
		}()
	}

	b._onceStart.Do(startFun)
}

// 唱票，主动stop当前轮次的
func (b *Box) stopAndReport() (*ElectReport, error) {
	s := b._status.Load()
	if s != BoxStatus_Working {
		return nil, fmt.Errorf("box is not stopable, status[%d]", s)
	}
	b._onceStop.Do(func() {
		close(b.stopChan)
		b._status.Store(BoxStatus_WaitReport)
		b.log.Infof("box[%s] stopped, wait report", b.role)
	})

	b.mutex.Lock()
	report, err := b.report()
	b.mutex.Unlock()

	return report, err
}

func (b *Box) winner() (string, int) {
	var winner string
	var count int
	var plural bool

	for id, vs := range b.votes {
		if vs == nil || vs.num == 0 {
			continue
		}
		//等票数大于策略的，且从中选出得票数最多的
		if b.strategy.Match(vs.num, vs.num) {
			if winner == "" || vs.num > count {
				winner = id
				count = vs.num
				plural = false
			} else if vs.num == count {
				plural = true
			}
		}
	}

	if plural {
		b.log.Warn("there are more than one winner, that is no winner")
		return "", 0
	}
	return winner, count
}

func (b *Box) report() (*ElectReport, error) {
	s := b._status.Load()
	if s != BoxStatus_WaitReport {
		return nil, fmt.Errorf("box is not reportable, status[%d]", s)
	}
	report := &ElectReport{}

	winner, num := b.winner()
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte("|---------Elect Specification---------|\n"))
	buf.Write([]byte(fmt.Sprintf("Elect Target:\t%s\n", b.role)))
	buf.Write([]byte(fmt.Sprintf("Start Time  :\t%s\n", b._startTime)))
	buf.Write([]byte(fmt.Sprintf("Stop  Time:\t%s\n", b._stopTime)))
	buf.Write([]byte(fmt.Sprintf("Candidate Num:\t%d\n", int(b.strategy.numOfMember))))
	buf.Write([]byte(fmt.Sprintf("Winner:\t%s\n", winner)))
	buf.Write([]byte(fmt.Sprintf("Vote Num:\t%d\n", num)))
	buf.Write([]byte(fmt.Sprintf("Vote List:\n")))
	for _, vs := range b.votes {
		for i, v := range vs.votes {
			buf.Write([]byte(fmt.Sprintf("%d\t voter:%s, voter's pubkey:%s, "+
				"vote for id:%s, vote for role:%s, voter's sign:%s\n",
				i, v.Voter, v.Pubkey, v.Id, v.Role, v.Signature)))
		}
	}

	buf.Write([]byte(fmt.Sprintf("|-------------------------------------|\n")))

	b._winner = winner
	b._status.Store(BoxStatus_Reported)

	report.Role = b.role
	report.Epoch = b._epoch
	report.Winner = winner
	report.DetailForm = buf.Bytes()

	return report, nil
}

func (b *Box) check() (*ElectReport, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	s := b._status.Load()
	if s == BoxStatus_Unvalid || s == BoxStatus_Reported {
		return nil, fmt.Errorf("box is not reportable, status[%d]", s)
	}

	report := &ElectReport{}
	buf := bytes.NewBuffer(nil)
	num := 0
	for _, vs := range b.votes {
		num += vs.num
	}

	buf.Write([]byte("|---------Elect Specification---------|\n"))
	buf.Write([]byte(fmt.Sprintf("Elect Target:\t%s\n", b.role)))
	buf.Write([]byte(fmt.Sprintf("Start Time  :\t%s\n", b._startTime)))
	buf.Write([]byte(fmt.Sprintf("Stop  Time:\t%s\n", b._stopTime)))
	buf.Write([]byte(fmt.Sprintf("Candidate Num:\t%d\n", int(b.strategy.numOfMember))))
	buf.Write([]byte(fmt.Sprintf("Winner:\tnot finish\n")))
	buf.Write([]byte(fmt.Sprintf("Vote Num:\t%d\n", num)))
	buf.Write([]byte(fmt.Sprintf("Vote List:\n")))
	for _, vs := range b.votes {
		for i, v := range vs.votes {
			buf.Write([]byte(fmt.Sprintf("%d\t voter:%s, voter's pubkey:%s, "+
				"vote for id:%s, vote for role:%s, voter's sign:%s\n",
				i, v.Voter, v.Pubkey, v.Id, v.Role, v.Signature)))
		}
	}

	buf.Write([]byte(fmt.Sprintf("|-------------------------------------|\n")))
	report.Role = b.role
	report.Epoch = b._epoch
	report.DetailForm = buf.Bytes()

	return report, nil
}

func (b *Box) reset() {
	s := b._status.Load()
	if s != BoxStatus_Reported {
		b.log.Errorf("box is not resetable, status[%d]", s)
		return
	}

	b.stopChan = make(chan struct{}, 1)
	b.votes = make(map[string]*VoteSpec)
	b._timer.Stop()
	b._startTime = ""
	b._stopTime = ""

	b._onceStart = sync.Once{}
	b._onceStop = sync.Once{}
	b._epoch++ //b._winner不重置，epoch++

	b._status.Store(BoxStatus_Unvalid) //最后再初始化
	b.start()
}

type ElectStrategy struct {
	obtainPer   float64  //得票率
	votePer     float64  //投票率
	specialVote []string //必须有的一些投票，暂不使用
	numOfMember float64  //全体成员的个数
	period      int      //一个选举周期持续的时间
}

func (es *ElectStrategy) Match(numOfVote, numOfObtain int) bool {
	if float64(numOfVote)/es.numOfMember < es.votePer {
		return false
	}
	if float64(numOfObtain)/es.numOfMember < es.obtainPer {
		return false
	}
	return true
}

type ElectBoxManager struct {
	boxes          map[string]*Box          //Role->*Box，在第一次投票时自动创建并启动
	strategies     map[string]ElectStrategy //Role->
	mutex          sync.RWMutex
	calloutHandler func([]byte) error
	log            common.Logger
}

func NewElectBoxManager(ch AutoCalloutHandler, log common.Logger) *ElectBoxManager {
	bm := &ElectBoxManager{}
	bm.boxes = make(map[string]*Box)
	bm.strategies = make(map[string]ElectStrategy)

	bm.strategies["DEPUTY_TO_NPC"] = ElectStrategy{0.5, 0.5, nil, 10, 6000}
	bm.strategies["MEM_NPC_PRESI"] = ElectStrategy{0.5, 0.5, nil, 10, 6000}
	bm.strategies["MEM_NPC_COMMITTEE"] = ElectStrategy{0.5, 0.5, nil, 10, 6000}
	bm.calloutHandler = ch
	bm.log = log
	return bm
}

func (bm *ElectBoxManager) AddIDToAllBox(id string) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	for _, box := range bm.boxes {
		box.AddID(id)
	}
}

func (bm *ElectBoxManager) Vote(vt *pbgo.Vote) error {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	role, ok := pbgo.Vote_Role_name[int32(vt.Role)]
	if !ok {
		return fmt.Errorf("not support the role %s", vt.Role)
	}

	box, ok := bm.boxes[role]
	if ok {
		return box.Vote(vt)
	} else {
		if !mockCheckIdentityToStartElect() {
			return fmt.Errorf("identity[%s] no right to start one elect[%d]", vt.Voter, vt.Role)
		}

		s, ok := bm.strategies[role]
		if !ok {
			return fmt.Errorf("no strategy for role[%s]", vt.Role)
		}
		box := newBox(role, s, bm.log, bm.calloutHandler)
		box.start()
		bm.boxes[role] = box
		if err := box.Vote(vt); err != nil {
			return fmt.Errorf("vote err: %s", err)
		}
	}
	return nil
}

func (bm *ElectBoxManager) StopAndReport(role string) (*ElectReport, error) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	box, ok := bm.boxes[role]
	if !ok {
		return nil, fmt.Errorf("no box for role[%s]", role)
	}

	return box.stopAndReport()
}

func (bm *ElectBoxManager) Check(role string) (*ElectReport, error) {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	box, ok := bm.boxes[role]
	if !ok {
		return nil, fmt.Errorf("no box for role[%s]", role)
	}

	return box.check()
}

func (bm *ElectBoxManager) Reset(role string) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	box, ok := bm.boxes[role]
	if ok {
		box.reset()
	}
}
