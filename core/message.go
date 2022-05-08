package core

import "time"

type Message struct {
	dt   time.Time
	Data []byte
}

func NewMessage(data []byte) *Message {
	var c Message
	c.dt = time.Now()
	c.Data = data
	return &c
}
