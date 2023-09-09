package msgbus

import (
	"fmt"
	"npcc/common"
	"sync"
	"sync/atomic"
)

var defaultTopicSize int = 100

type BusMessage struct {
	MsgType common.LocalMsgType
	ChainID string
	Msg     interface{}
}

type Subscriber interface {
	HandleMsgFromMsgBus(msg *BusMessage) error
}

type MessageBus interface {
	Register(topic common.LocalMsgType, sub Subscriber)
	UnRegister(topic common.LocalMsgType, sub Subscriber)
	Publish(channelID string, t common.LocalMsgType, payload interface{})
	Reset()
}

type Topic interface {
	Register(sub Subscriber)
	UnRegister(sub Subscriber)
	Publish(msg *BusMessage)
	Stop()
}

type topicImpl struct {
	msgChan chan *BusMessage
	subs    atomic.Value //[]Subscriber
	mutex   sync.RWMutex

	stop chan struct{}
}

func newTopic(size int) Topic {
	t := &topicImpl{
		msgChan: make(chan *BusMessage, size),
		stop:    make(chan struct{}, 1),
	}
	t.subs.Store([]Subscriber{})
	go t.handlePublish()
	return t
}

func (t *topicImpl) Register(sub Subscriber) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	subs := t.subs.Load().([]Subscriber)
	//去重
	for _, s := range subs {
		if s == sub {
			return
		}
	}
	newSubs := append(subs, sub)
	t.subs.Store(newSubs)
}

func (t *topicImpl) UnRegister(sub Subscriber) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	subs := t.subs.Load().([]Subscriber)
	for i, s := range subs {
		if s == sub {
			newSubs := append(subs[:i], subs[i+1:]...)
			t.subs.Store(newSubs)
			return
		}
	}
}

func (t *topicImpl) Publish(msg *BusMessage) {
	t.msgChan <- msg
}

// stop 协程handlePublish()
func (t *topicImpl) Stop() {
	t.stop <- struct{}{}
	close(t.msgChan)
}

func (t *topicImpl) handlePublish() {
	for {
		select {
		case <-t.stop:
			return
		case msg := <-t.msgChan:
			subs := t.subs.Load().([]Subscriber)
			for _, sub := range subs {
				go sub.HandleMsgFromMsgBus(msg)
			}
		}
	}
}

type messageBusImpl struct {
	topics sync.Map //BusMsgType->MsgType
}

func newMessageBus() MessageBus {
	return &messageBusImpl{}
}

func (mb *messageBusImpl) Register(topic common.LocalMsgType, sub Subscriber) {
	firstClassTopic := topic.Type()
	if v, ok := mb.topics.Load(firstClassTopic); ok {
		t := v.(Topic)
		t.Register(sub)
		return
	}
	t := newTopic(defaultTopicSize)
	t.Register(sub)
	mb.topics.Store(firstClassTopic, t)
}

func (mb *messageBusImpl) UnRegister(topic common.LocalMsgType, sub Subscriber) {
	firstClassTopic := topic.Type()
	v, ok := mb.topics.Load(firstClassTopic)
	if !ok {
		return
	}
	t := v.(Topic)
	t.UnRegister(sub)
}

func (mb *messageBusImpl) Publish(channelID string, topic common.LocalMsgType, msg interface{}) {
	firstClassTopic := topic.Type()
	v, ok := mb.topics.Load(firstClassTopic)
	if !ok {
		fmt.Printf("unsupport topic[%d] for this msg\n", firstClassTopic)
		return
	}
	t := v.(Topic)
	//即便消息过多，依然一直多协程等待
	busMsg := &BusMessage{topic, channelID, msg}
	go t.Publish(busMsg)
}

func (mb *messageBusImpl) Reset() {
	stopFun := func(k, v interface{}) bool {
		t := v.(Topic)
		t.Stop()
		return true
	}
	mb.topics.Range(stopFun)
	mb.topics = sync.Map{}
}

var singletonMessageBus MessageBus
var once sync.Once

func InitMessageBus() MessageBus {
	once.Do(func() {
		singletonMessageBus = newMessageBus()
	})
	return singletonMessageBus
}

func Register(topic common.LocalMsgType, sub Subscriber) {
	singletonMessageBus.Register(topic, sub)
}

func UnRegister(topic common.LocalMsgType, sub Subscriber) {
	singletonMessageBus.UnRegister(topic, sub)
}

func Publish(channelID string, topic common.LocalMsgType, msg interface{}) {
	singletonMessageBus.Publish(channelID, topic, msg)
}

func Reset() {
	singletonMessageBus.Reset()
}
