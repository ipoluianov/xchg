package core

import "time"

type Request struct {
	// Request
	transactionId uint64
	dt            time.Time
	Data          []byte

	// Response
	ResponseReceived bool
	ResponseData     []byte
}

func NewMessage(transactionId uint64, data []byte) *Request {
	var c Request
	c.dt = time.Now()
	c.transactionId = transactionId
	c.Data = data
	return &c
}
