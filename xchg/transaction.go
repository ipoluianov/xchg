package xchg

import (
	"encoding/binary"
	"errors"
	"time"
)

type Transaction struct {
	// Header - 32 bytes
	signature       byte
	protocolVersion byte
	frameType       byte
	recevied1       byte
	frameLen        uint32
	eid             uint64
	transactionId   uint64
	sessionId       uint64
	data            []byte

	// State
	dt                   time.Time
	connection           *Connection
	standbyTransactionId uint64
	complete             bool
	err                  error
}

func NewTransaction(frameType byte, code byte, targetEID uint64, transactionId uint64, sessionId uint64, data []byte) *Transaction {
	var c Transaction
	c.signature = 0xAA
	c.protocolVersion = 0x01
	c.frameType = frameType
	c.recevied1 = code
	c.eid = targetEID
	c.transactionId = transactionId
	c.sessionId = sessionId
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
	tr.frameType = frame[2]
	tr.recevied1 = frame[3]
	tr.frameLen = binary.LittleEndian.Uint32(frame[4:])
	tr.eid = binary.LittleEndian.Uint64(frame[8:])
	tr.transactionId = binary.LittleEndian.Uint64(frame[16:])
	tr.data = make([]byte, int(tr.frameLen)-HeaderSize)
	copy(tr.data, frame[HeaderSize:])
	return
}

func (c *Transaction) marshal() (result []byte) {
	c.frameLen = uint32(32 + len(c.data))
	result = make([]byte, HeaderSize+len(c.data))
	result[0] = 0xAA // Signature
	result[1] = c.protocolVersion
	result[2] = c.frameType
	result[3] = c.recevied1
	binary.LittleEndian.PutUint32(result[4:], c.frameLen)
	binary.LittleEndian.PutUint64(result[8:], c.eid)
	binary.LittleEndian.PutUint64(result[16:], c.transactionId)
	copy(result[HeaderSize:], c.data)
	return
}
