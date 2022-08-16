package xchg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

type Transaction struct {
	// Header - 32 bytes + Data
	Signature       byte
	ProtocolVersion byte
	FrameType       byte
	Reserved        byte
	FrameLen        uint32
	SID             uint64
	TransactionId   uint64
	SessionId       uint64
	Data            []byte

	// Routing Data
	ResponseSender        TransactionSender
	OriginalTransactionId uint64
	BeginDT               time.Time
	AddressSrc            string
	AddressDest           string

	// Execution Result
	Complete bool
	Result   []byte
	Err      error
}

const (
	TransactionHeaderSize = 32
)

const (
	FrameInit1 = byte(0x01) // 1 -> 2: [addr1]
	FrameInit2 = byte(0x02) // 2 -> 1: [addr2]
	FrameInit3 = byte(0x03) // 2 -> 1: [enc(secret2, addr1)] // client, prove it is you
	FrameInit4 = byte(0x04) // 1 -> 2: [enc(secret2, addr2)] // it is me, client
	FrameInit5 = byte(0x05) // 1 -> 2: [enc(secret1, addr2)] // xchg,prove it is you
	FrameInit6 = byte(0x06) // 2 -> 1: [enc(secret1, addr1)] // it is me, xchg

	FrameResolveAddress  = byte(0x10) // 1 -> 2: [addr3]
	FrameResolvedAddress = byte(0x11) // 2 -> 1: [sid3]

	FrameCall     = byte(0x20) // 1 -> 2: [sid3][call_frame] --- 2 -> 3: [call_frame]
	FrameResponse = byte(0x21) // 3 -> 2: [response_frame] --- 2 -> 1: [response_frame]
	FrameError    = byte(0xFF)
)

func NewTransaction(frameType byte, targetSID uint64, transactionId uint64, sessionId uint64, data []byte) *Transaction {
	var c Transaction
	c.Signature = 0xAA
	c.ProtocolVersion = 0x01
	c.FrameType = frameType
	c.Reserved = 0
	c.SID = targetSID
	c.TransactionId = transactionId
	c.SessionId = sessionId
	c.Data = data
	return &c
}

func Parse(frame []byte) (tr *Transaction, err error) {
	if len(frame) < TransactionHeaderSize ||
		frame[0] != 0xAA ||
		frame[1] != 0x01 {
		err = errors.New(ERR_XCHG_TR_WRONG_FRAME)
	}

	tr = &Transaction{}
	tr.Signature = frame[0]
	tr.ProtocolVersion = frame[1]
	tr.FrameType = frame[2]
	tr.Reserved = frame[3]
	tr.FrameLen = binary.LittleEndian.Uint32(frame[4:])
	tr.SID = binary.LittleEndian.Uint64(frame[8:])
	tr.TransactionId = binary.LittleEndian.Uint64(frame[16:])
	tr.SessionId = binary.LittleEndian.Uint64(frame[24:])
	tr.Data = make([]byte, int(tr.FrameLen)-TransactionHeaderSize)
	copy(tr.Data, frame[TransactionHeaderSize:])
	return
}

func (c *Transaction) marshal() (result []byte) {
	c.FrameLen = uint32(32 + len(c.Data))
	result = make([]byte, TransactionHeaderSize+len(c.Data))
	result[0] = 0xAA // Signature
	result[1] = c.ProtocolVersion
	result[2] = c.FrameType
	result[3] = c.Reserved
	binary.LittleEndian.PutUint32(result[4:], c.FrameLen)
	binary.LittleEndian.PutUint64(result[8:], c.SID)
	binary.LittleEndian.PutUint64(result[16:], c.TransactionId)
	binary.LittleEndian.PutUint64(result[24:], c.SessionId)
	copy(result[TransactionHeaderSize:], c.Data)
	return
}

func (c *Transaction) String() string {
	res := fmt.Sprint(c.TransactionId) + ":[" + c.AddressSrc + "]-[" + c.AddressDest + "] t:" + fmt.Sprint(c.FrameType) + " dl:" + fmt.Sprint(len(c.Data))
	return res
}
