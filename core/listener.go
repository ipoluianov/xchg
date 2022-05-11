package core

import (
	"errors"
	"sync"
	"time"
)

type Listener struct {
	id                   string
	maxMessagesQueueSize int
	maxMessageDataSize   int
	messages             []*Message
	mtx                  sync.Mutex
	lastGetDT            time.Time
}

func NewListener(id string) *Listener {
	var c Listener
	c.id = id
	c.messages = make([]*Message, 0)
	c.maxMessagesQueueSize = 10
	c.maxMessageDataSize = 1024 * 1024
	return &c
}

func (c *Listener) PushMessage(data []byte) error {
	return c.Push(NewMessage(data))
}

func (c *Listener) Push(message *Message) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if len(c.messages) >= c.maxMessagesQueueSize {
		return errors.New("queue overflow")
	}
	if len(message.Data) > c.maxMessageDataSize {
		return errors.New("too much data")
	}

	c.messages = append(c.messages, message)

	return nil
}

func (c *Listener) Pull() (message *Message, valid bool) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.lastGetDT = time.Now()
	if len(c.messages) > 0 {
		message = c.messages[0]
		c.messages = c.messages[1:]
		valid = true
	}
	return
}

func (c *Listener) LastGetDT() time.Time {
	return c.lastGetDT
}
