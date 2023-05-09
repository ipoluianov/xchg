package xchg

import (
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
	"time"
)

type Transaction struct {
	// Transport Header - 8 bytes
	Length    uint32 // 0
	CRC       uint32 // 4
	FrameType byte   // 8

	// Call header - 32 bytes
	TransactionId uint64
	SessionId     uint64
	Offset        uint32
	TotalSize     uint32

	// 30 bytes - Source Address
	SrcAddress [AddressBytesSize]byte
	// 30 bytes - Source Address
	DestAddress [AddressBytesSize]byte

	// 28 bytes
	Appendix [28]byte

	// Data
	Data []byte

	FromLocalNode bool

	// Execution Result
	BeginDT        time.Time
	ReceivedFrames []*Transaction
	//ReceivedDataLen int
	Complete bool
	Result   []byte
	Err      error
}

const (
	TransactionHeaderSize = 128

	FrameTypeCall     = byte(0x10)
	FrameTypeResponse = byte(0x11)
)

func NewTransaction(frameType byte, srcAddress string, destAddress string, transactionId uint64, sessionId uint64, offset int, totalSize int, data []byte) *Transaction {
	var c Transaction
	c.Length = uint32(TransactionHeaderSize + len(data))
	c.CRC = 0
	c.FrameType = frameType

	c.TransactionId = transactionId
	c.SessionId = sessionId
	c.Offset = uint32(offset)
	c.TotalSize = uint32(totalSize)

	if strings.HasPrefix(srcAddress, "#") {
		srcAddress = srcAddress[1:]
	}

	if strings.HasPrefix(destAddress, "#") {
		destAddress = destAddress[1:]
	}

	srcAddressBS, err := base32.StdEncoding.DecodeString(strings.ToUpper(srcAddress))
	if err == nil && len(srcAddressBS) == 30 {
		copy(c.SrcAddress[:], srcAddressBS)
	}

	destAddressBS, err := base32.StdEncoding.DecodeString(strings.ToUpper(destAddress))
	if err == nil && len(destAddressBS) == 30 {
		copy(c.DestAddress[:], destAddressBS)
	}

	c.Data = data

	c.ReceivedFrames = make([]*Transaction, 0)
	return &c
}

func (c *Transaction) SrcAddressString() string {
	return "#" + base32.StdEncoding.EncodeToString(c.SrcAddress[:])
}

func (c *Transaction) DestAddressString() string {
	return "#" + base32.StdEncoding.EncodeToString(c.DestAddress[:])
}

func Parse(frame []byte) (tr *Transaction, err error) {
	if len(frame) < TransactionHeaderSize {
		err = errors.New("wrong frame")
		return
	}

	tr = &Transaction{}
	tr.Length = binary.LittleEndian.Uint32(frame[0:])
	tr.CRC = binary.LittleEndian.Uint32(frame[4:])
	tr.FrameType = frame[8]

	tr.TransactionId = binary.LittleEndian.Uint64(frame[16:])
	tr.SessionId = binary.LittleEndian.Uint64(frame[24:])
	tr.Offset = binary.LittleEndian.Uint32(frame[32:])
	tr.TotalSize = binary.LittleEndian.Uint32(frame[36:])

	copy(tr.SrcAddress[:], frame[40:])
	copy(tr.DestAddress[:], frame[70:])
	copy(tr.Appendix[:], frame[100:])

	tr.Data = make([]byte, len(frame)-TransactionHeaderSize)
	copy(tr.Data, frame[TransactionHeaderSize:])

	return
}

func (c *Transaction) Marshal() (result []byte) {
	result = make([]byte, TransactionHeaderSize+len(c.Data))

	binary.LittleEndian.PutUint32(result[0:], uint32(len(result))) // Length
	binary.LittleEndian.PutUint32(result[4:], 0)                   // CRC
	result[8] = c.FrameType

	binary.LittleEndian.PutUint64(result[16:], c.TransactionId)
	binary.LittleEndian.PutUint64(result[24:], c.SessionId)
	binary.LittleEndian.PutUint32(result[32:], c.Offset)
	binary.LittleEndian.PutUint32(result[36:], c.TotalSize)

	copy(result[40:], c.SrcAddress[:])
	copy(result[70:], c.DestAddress[:])
	copy(result[100:], c.Appendix[:])

	copy(result[TransactionHeaderSize:], c.Data)

	binary.LittleEndian.PutUint32(result[4:], crc32.Checksum(result, crc32.IEEETable))

	return
}

func (c *Transaction) String() string {
	res := fmt.Sprint(c.TransactionId) + "t:" + fmt.Sprint(c.FrameType) + " dl:" + fmt.Sprint(len(c.Data))
	return res
}

func (c *Transaction) AppendReceivedData(transaction *Transaction) {
	if len(c.ReceivedFrames) < 1000 {
		found := false
		for _, trvTr := range c.ReceivedFrames {
			if trvTr.Offset == transaction.Offset {
				found = true
			}
		}
		if !found {
			c.ReceivedFrames = append(c.ReceivedFrames, transaction)
		}
	}

	if transaction.FromLocalNode {
		c.FromLocalNode = true
	}

	receivedDataLen := 0
	for _, trvTr := range c.ReceivedFrames {
		receivedDataLen += int(len(trvTr.Data))
	}

	if receivedDataLen == int(transaction.TotalSize) {
		if len(c.Result) != int(transaction.TotalSize) {
			c.Result = make([]byte, transaction.TotalSize)
		}
		for _, trvTr := range c.ReceivedFrames {
			copy(c.Result[trvTr.Offset:], trvTr.Data)
		}
		c.Complete = true
	}
}
