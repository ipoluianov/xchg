package router

import "time"

type Message struct {
	id      uint64
	data    []byte
	TouchDT time.Time
}

func NewMessage(id uint64, data []byte) *Message {
	var c Message
	c.id = id
	c.data = data
	c.TouchDT = time.Now()
	return &c
}
