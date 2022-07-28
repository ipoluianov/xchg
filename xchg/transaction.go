package xchg

import (
	"encoding/binary"
	"errors"
	"time"
)

type Transaction struct {
	// Header - 32 bytes
	signature          byte
	protocolVersion    byte
	function           byte
	code               byte
	frameLen           uint32
	targetConnectionId uint64
	transactionId      uint64
	reserved           uint64
	data               []byte

	// State
	dt                   time.Time
	connection           *Connection
	standbyTransactionId uint64
}

func NewResponseTransaction(originalTransaction *Transaction, code byte, data []byte) *Transaction {
	var c Transaction
	c.signature = 0xAA
	c.protocolVersion = 0x01
	c.function = originalTransaction.function
	c.code = code
	c.targetConnectionId = originalTransaction.connection.id
	c.transactionId = originalTransaction.transactionId
	c.reserved = originalTransaction.reserved
	c.data = data
	return &c
}

func Parse(frame []byte) (tr *Transaction, err error) {
	if len(frame) < HeaderSize ||
		frame[0] != 0xAA ||
		frame[1] != 0x01 {
		err = errors.New("wrong frame")
	}

	tr = &Transaction{}
	tr.signature = frame[0]
	tr.protocolVersion = frame[1]
	tr.function = frame[2]
	tr.code = frame[3]
	tr.frameLen = binary.LittleEndian.Uint32(frame[4:])
	tr.targetConnectionId = binary.BigEndian.Uint64(frame[8:])
	tr.transactionId = binary.BigEndian.Uint64(frame[16:])
	tr.data = make([]byte, len(frame)-HeaderSize)
	copy(tr.data, frame[HeaderSize:])
	return
}

func (c *Transaction) marshal() (result []byte) {
	result = make([]byte, HeaderSize+len(c.data))
	result[0] = 0xAA // Signature
	result[1] = c.protocolVersion
	result[2] = c.function
	result[3] = c.code
	binary.LittleEndian.PutUint32(result[4:], c.frameLen)
	binary.LittleEndian.PutUint64(result[8:], c.targetConnectionId)
	binary.LittleEndian.PutUint64(result[16:], c.transactionId)
	copy(result[HeaderSize:], c.data)
	return
}
