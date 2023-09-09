package net

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNet(t *testing.T) {
	topic := "test1"
	n1 := NewLocalP2PNode(topic)
	n2 := NewLocalP2PNode(topic)

	go func() {
		n2.ReadLoop(topic)
	}()

	//留给彼此发现的时间，节点发现后，发消息对方才能收到
	time.Sleep(time.Second)
	msg := Message{1, topic, []byte("123")}
	err := n1.Publish(msg)
	assert.Equal(t, nil, err)

	time.Sleep(1000 * time.Second)
}
