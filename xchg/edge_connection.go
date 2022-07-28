package xchg

import (
	"errors"
	"time"
)

type EdgeConnection struct {
	Connection
	chStopWorker chan interface{}
}

func NewEdgeConnection() *EdgeConnection {
	var c EdgeConnection
	return &c
}

func (c *EdgeConnection) processTransaction(transaction *Transaction) {
	switch transaction.protocolVersion {
	case 0x01:
		switch transaction.function {
		default:
			c.sendError(transaction, errors.New("wrong function"))
		}
	default:
		c.sendError(transaction, errors.New("wrong protocol version"))
	}
}

func (c *EdgeConnection) thWorker() {
	stopping := false
	ticker := time.NewTicker(5000 * time.Millisecond)
	for !stopping {
		var transaction *Transaction
		select {
		case transaction = <-c.chTransactionProcessor:
			c.processTransaction(transaction)
		case <-c.chStopWorker:
			stopping = true
		case <-ticker.C:
			c.backgroundOperations()
		}
	}
	ticker.Stop()
}

func (c *EdgeConnection) backgroundOperations() {
}
