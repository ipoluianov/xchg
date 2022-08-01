package xchg

import (
	"errors"
)

type EdgeConnection struct {
	Connection
	chStopWorker chan interface{}
}

func NewEdgeConnection() *EdgeConnection {
	var c EdgeConnection
	return &c
}

func (c *EdgeConnection) ProcessTransaction(transaction *Transaction) {
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
