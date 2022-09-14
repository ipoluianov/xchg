package xchg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

type Transaction struct {
	// Transport Header - 8 bytes
	FrameType byte
	Status    byte
	Reserved2 byte
	Reserved3 byte
	Reserved4 uint32

	// Call header - 32 bytes
	TransactionId uint64
	SessionId     uint64
	Reserved5     uint64
	Offset        uint32
	TotalSize     uint32

	// Data
	Data []byte

	// Execution Result
	BeginDT         time.Time
	ReceivedDataLen int
	Complete        bool
	Result          []byte
	Err             error
}

const (
	TransactionHeaderSize = 40

	FrameTypeCall     = byte(0x10)
	FrameTypeResponse = byte(0x11)
)

func NewTransaction(frameType byte, transactionId uint64, sessionId uint64, offset int, totalSize int, data []byte) *Transaction {
	var c Transaction
	c.FrameType = frameType
	c.Status = 0
	c.Reserved2 = 0
	c.Reserved3 = 0
	c.Reserved4 = 0

	c.TransactionId = transactionId
	c.SessionId = sessionId
	c.Reserved5 = 0
	c.Offset = uint32(offset)
	c.TotalSize = uint32(totalSize)
	c.Data = data
	return &c
}

func Parse(frame []byte) (tr *Transaction, err error) {
	if len(frame) < TransactionHeaderSize || (frame[0] != 0x10 && frame[0] != 0x11) {
		err = errors.New("wrong frame")
		return
	}

	tr = &Transaction{}
	tr.FrameType = frame[0]
	tr.Status = frame[1]
	tr.Reserved2 = frame[2]
	tr.Reserved3 = frame[3]
	tr.Reserved4 = binary.LittleEndian.Uint32(frame[4:])
	tr.TransactionId = binary.LittleEndian.Uint64(frame[8:])
	tr.SessionId = binary.LittleEndian.Uint64(frame[16:])
	tr.Reserved5 = binary.LittleEndian.Uint64(frame[24:])
	tr.Offset = binary.LittleEndian.Uint32(frame[32:])
	tr.TotalSize = binary.LittleEndian.Uint32(frame[36:])
	tr.Data = make([]byte, len(frame)-TransactionHeaderSize)
	copy(tr.Data, frame[TransactionHeaderSize:])
	return
}

func (c *Transaction) Marshal() (result []byte) {
	//c.FrameLen = uint32(TransactionHeaderSize + len(c.Data))
	result = make([]byte, TransactionHeaderSize+len(c.Data))
	result[0] = c.FrameType // Signature
	result[1] = c.Status
	result[2] = c.Reserved2
	result[3] = c.Reserved3
	binary.LittleEndian.PutUint32(result[4:], c.Reserved4)

	binary.LittleEndian.PutUint64(result[8:], c.TransactionId)
	binary.LittleEndian.PutUint64(result[16:], c.SessionId)
	binary.LittleEndian.PutUint64(result[24:], c.Reserved5)
	binary.LittleEndian.PutUint32(result[32:], c.Offset)
	binary.LittleEndian.PutUint32(result[36:], c.TotalSize)
	copy(result[TransactionHeaderSize:], c.Data)
	return
}

func (c *Transaction) String() string {
	res := fmt.Sprint(c.TransactionId) + "t:" + fmt.Sprint(c.FrameType) + " dl:" + fmt.Sprint(len(c.Data))
	return res
}
