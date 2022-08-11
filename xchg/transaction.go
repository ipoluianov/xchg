package xchg

import (
	"encoding/binary"
	"errors"
	"time"
)

type Transaction struct {
	// Header - 32 bytes
	Signature       byte
	ProtocolVersion byte
	FrameType       byte
	Recevied1       byte
	FrameLen        uint32
	EID             uint64
	TransactionId   uint64
	SessionId       uint64
	Data            []byte

	// State
	dt                   time.Time
	ResponseSender       TransactionSender
	StandbyTransactionId uint64

	complete bool
	result   []byte
	err      error
}

func NewTransaction(frameType byte, code byte, targetEID uint64, transactionId uint64, sessionId uint64, data []byte) *Transaction {
	var c Transaction
	c.Signature = 0xAA
	c.ProtocolVersion = 0x01
	c.FrameType = frameType
	c.Recevied1 = code
	c.EID = targetEID
	c.TransactionId = transactionId
	c.SessionId = sessionId
	c.Data = data
	return &c
}

func Parse(frame []byte) (tr *Transaction, err error) {
	if len(frame) < HeaderSize ||
		frame[0] != 0xAA ||
		frame[1] != 0x01 {
		err = errors.New("wrong frame")
	}

	tr = &Transaction{}
	tr.Signature = frame[0]
	tr.ProtocolVersion = frame[1]
	tr.FrameType = frame[2]
	tr.Recevied1 = frame[3]
	tr.FrameLen = binary.LittleEndian.Uint32(frame[4:])
	tr.EID = binary.LittleEndian.Uint64(frame[8:])
	tr.TransactionId = binary.LittleEndian.Uint64(frame[16:])
	tr.SessionId = binary.LittleEndian.Uint64(frame[24:])
	tr.Data = make([]byte, int(tr.FrameLen)-HeaderSize)
	copy(tr.Data, frame[HeaderSize:])
	return
}

func (c *Transaction) marshal() (result []byte) {
	c.FrameLen = uint32(32 + len(c.Data))
	result = make([]byte, HeaderSize+len(c.Data))
	result[0] = 0xAA // Signature
	result[1] = c.ProtocolVersion
	result[2] = c.FrameType
	result[3] = c.Recevied1
	binary.LittleEndian.PutUint32(result[4:], c.FrameLen)
	binary.LittleEndian.PutUint64(result[8:], c.EID)
	binary.LittleEndian.PutUint64(result[16:], c.TransactionId)
	binary.LittleEndian.PutUint64(result[24:], c.SessionId)
	copy(result[HeaderSize:], c.Data)
	return
}
