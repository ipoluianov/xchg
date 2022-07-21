package core

import "time"

type Transaction struct {
	// Request
	transactionId uint64
	dt            time.Time
	Data          []byte
	signature     uint32

	// Response
	ResponseReceived bool
	ResponseData     []byte
	binConnection    BinConnection
}

func NewTransaction(transactionId uint64, data []byte, binConnection BinConnection, signature uint32) *Transaction {
	var c Transaction
	c.dt = time.Now()
	c.transactionId = transactionId
	c.binConnection = binConnection
	c.signature = signature
	c.Data = data
	return &c
}
