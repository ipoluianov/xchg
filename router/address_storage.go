package router

import (
	"sync"
	"time"
)

type AddressStorage struct {
	mtx         sync.Mutex
	TouchDT     time.Time
	maxMessages int
	messages    []*Message
}

func NewAddressStorage() *AddressStorage {
	var c AddressStorage
	c.maxMessages = 1000
	c.messages = make([]*Message, 0, c.maxMessages+1)
	c.TouchDT = time.Now()
	return &c
}

func (c *AddressStorage) Clear() {
	now := time.Now()
	c.mtx.Lock()
	oldMessages := c.messages
	c.messages = make([]*Message, 0, len(oldMessages))
	for _, m := range oldMessages {
		if now.Sub(m.TouchDT) < 5*time.Second {
			c.messages = append(c.messages, m)
		}
	}
	c.mtx.Unlock()
}

func (c *AddressStorage) MessagesCount() (count int) {
	c.mtx.Lock()
	count = len(c.messages)
	c.mtx.Unlock()
	return
}

func (c *AddressStorage) Put(id uint64, frame []byte) {
	c.mtx.Lock()
	msg := NewMessage(id, frame)
	c.messages = append(c.messages, msg)
	if len(c.messages) > c.maxMessages {
		c.messages = c.messages[1:]
	}
	c.TouchDT = time.Now()
	c.mtx.Unlock()
}

func (c *AddressStorage) GetMessage(afterId uint64, maxSize uint64) (data []byte, lastId uint64, count int) {

	data = make([]byte, 0)
	lastId = afterId
	count = 0
	sendAll := false
	c.mtx.Lock()

	if len(c.messages) > 0 {
		if afterId > c.messages[len(c.messages)-1].id {
			afterId = c.messages[0].id
			sendAll = true
		}
	}

	for _, m := range c.messages {
		if m.id > afterId || sendAll {
			if len(data)+len(m.data) < int(maxSize) {
				data = append(data, m.data...)
				lastId = m.id
				count++
			}
		}
	}

	if len(data) == 0 && len(c.messages) > 0 {
		if afterId > c.messages[len(c.messages)-1].id {
			lastId = c.messages[0].id
		}
	}
	c.mtx.Unlock()
	return
}
