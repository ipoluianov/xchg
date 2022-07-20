package core

import "time"

type Transaction struct {
	// Request
	transactionId uint64
	dt            time.Time
	Data          []byte

	// Response
	ResponseReceivedCh chan struct{}
	ResponseReceived   bool
	ResponseData       []byte
}

func NewTransaction(transactionId uint64, data []byte) *Transaction {
	var c Transaction
	c.dt = time.Now()
	c.transactionId = transactionId
	c.Data = data
	c.ResponseReceivedCh = make(chan struct{})
	return &c
}
