package xchg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipoluianov/gomisc/logger"
)

type Connection struct {
	internalId string
	conn       net.Conn

	mtxBaseConnection     sync.Mutex
	mtxBaseConnectionSend sync.Mutex

	closed bool
	host   string

	processor ITransactionProcessor

	started  bool
	stopping bool

	receivedBytes  uint64
	sentBytes      uint64
	receivedFrames uint64
	sentFrames     uint64

	totalPerformanceCounters *ConnectionsPerformanceCounters

	configMaxFrameSize int

	incomingData       []byte
	incomingDataOffset int
}

type ConnectionState struct {
	Host           string `json:"host"`
	ReceivedBytes  uint64 `json:"received_bytes"`
	SentBytes      uint64 `json:"sent_bytes"`
	ReceivedFrames uint64 `json:"received_frames"`
	SentFrames     uint64 `json:"sent_frames"`

	Connected bool `json:"connected"`
	Started   bool `json:"started"`
	Stopping  bool `json:"stopping"`
}

type ITransactionProcessor interface {
	Connected()
	ProcessTransaction(transaction *Transaction)
	Disconnected()
}

type TransactionSender interface {
	Send(transaction *Transaction) (err error)
}

type ConnectionsPerformanceCounters struct {
	InTrafficCounter  uint64 `json:"in_traffic_counter"`
	OutTrafficCounter uint64 `json:"out_traffic_counter"`
	Init1Counter      uint64 `json:"init1_counter"`
	Init4Counter      uint64 `json:"init4_counter"`
	Init5Counter      uint64 `json:"init5_counter"`
}

func NewConnection() *Connection {
	var c Connection
	return &c
}

func (c *Connection) InitIncomingConnection(conn net.Conn, processor ITransactionProcessor, internalId string, totalPerformanceCounters *ConnectionsPerformanceCounters) {
	c.mtxBaseConnection.Lock()
	defer c.mtxBaseConnection.Unlock()
	if totalPerformanceCounters == nil {
		c.totalPerformanceCounters = &ConnectionsPerformanceCounters{}
	} else {
		c.totalPerformanceCounters = totalPerformanceCounters
	}

	c.internalId = internalId
	if c.started {
		logger.Println("[ERROR]", "Connection::initIncomingConnection", "already started")
		return
	}
	c.configMaxFrameSize = 128 * 1024

	c.processor = processor
	c.conn = conn
}

func (c *Connection) InitOutgoingConnection(host string, processor ITransactionProcessor, internalId string) {
	c.mtxBaseConnection.Lock()
	defer c.mtxBaseConnection.Unlock()
	c.totalPerformanceCounters = &ConnectionsPerformanceCounters{}
	c.internalId = internalId
	if c.started {
		logger.Println("[ERROR]", "Connection::InitOutgoingConnection", "already started")
		return
	}
	c.configMaxFrameSize = 128 * 1024

	c.processor = processor
	c.host = host
}

func (c *Connection) Dispose() {
	c.mtxBaseConnection.Lock()
	c.processor = nil
	c.mtxBaseConnection.Unlock()

	c.Stop()

	c.mtxBaseConnection.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.mtxBaseConnection.Unlock()
}

func (c *Connection) IsClosed() bool {
	return c.closed
}

func (c *Connection) IsOutgoing() bool {
	c.mtxBaseConnection.Lock()
	defer c.mtxBaseConnection.Unlock()
	return len(c.host) > 0
}

func (c *Connection) IsIncoming() bool {
	c.mtxBaseConnection.Lock()
	defer c.mtxBaseConnection.Unlock()
	return len(c.host) == 0
}

func (c *Connection) Start() {
	c.mtxBaseConnection.Lock()
	defer c.mtxBaseConnection.Unlock()
	if c.started {
		logger.Println("[ERROR]", "Connection::Start", "already started")
		return
	}
	c.stopping = false
	go c.thReceive()
}

func (c *Connection) Stop() {
	c.mtxBaseConnection.Lock()
	if !c.started {
		//logger.Println("[ERROR]", "Connection::Stop", "already stopped")
		c.mtxBaseConnection.Unlock()
		return
	}
	c.stopping = true
	if c.conn != nil {
		c.conn.Close()
	}
	c.mtxBaseConnection.Unlock()

	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		c.mtxBaseConnection.Lock()
		if !c.started {
			c.mtxBaseConnection.Unlock()
			break
		}
		c.mtxBaseConnection.Unlock()
	}

	c.mtxBaseConnection.Lock()
	if c.started {
		logger.Println("[ERROR]", "Connection::Stop", "timeout")
	}
	c.stopping = false
	c.mtxBaseConnection.Unlock()
}

func (c *Connection) callProcessorConnected() {
	c.mtxBaseConnection.Lock()
	processor := c.processor
	c.mtxBaseConnection.Unlock()
	if processor != nil {
		processor.Connected()
	}
}

func (c *Connection) disconnect() {
	c.mtxBaseConnection.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	processor := c.processor
	c.mtxBaseConnection.Unlock()

	if processor != nil {
		processor.Disconnected()
	}

	c.mtxBaseConnection.Lock()
	c.closed = true
	c.mtxBaseConnection.Unlock()
}

func (c *Connection) ReceivedBytes() uint64 {
	return atomic.LoadUint64(&c.receivedBytes)
}

func (c *Connection) SentBytes() uint64 {
	return atomic.LoadUint64(&c.sentBytes)
}

func (c *Connection) ReceivedFrames() uint64 {
	return atomic.LoadUint64(&c.receivedFrames)
}

func (c *Connection) SentFrames() uint64 {
	return atomic.LoadUint64(&c.sentFrames)
}

var count = 0

func (c *Connection) thReceive() {
	c.mtxBaseConnection.Lock()
	c.started = true
	c.mtxBaseConnection.Unlock()

	var n int
	var err error
	c.incomingDataOffset = 0
	c.adjustInputBufferDown(c.incomingDataOffset)

	for !c.stopping {
		if c.conn == nil {
			var conn net.Conn
			fmt.Println("connecting ", c.host, c.internalId)
			conn, err = net.Dial("tcp", c.host)
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				fmt.Println("connecting error ", c.host)
				continue
			}
			fmt.Println("connecting ok ", c.host)
			c.incomingDataOffset = 0
			c.adjustInputBufferDown(c.incomingDataOffset)
			c.callProcessorConnected()

			c.mtxBaseConnection.Lock()
			c.conn = conn
			c.mtxBaseConnection.Unlock()
		}

		//fmt.Println("reading ", c.host)
		n, err = c.conn.Read(c.incomingData[c.incomingDataOffset:])
		if c.stopping {
			logger.Println("[-]", "Connection::thReceive", "stopping", c.internalId)
			break
		}
		if n < 1 || err != nil {
			logger.Println("[-]", "Connection::thReceive", "n < 1 || err: ", err, c.internalId)
			if c.IsIncoming() {
				break
			} else {
				c.disconnect()
				continue
			}
		}
		//logger.Println("[-]", "Connection::thReceive", "received bytes:", n, c.internalId)

		atomic.AddUint64(&c.receivedBytes, uint64(n))
		atomic.AddUint64(&c.totalPerformanceCounters.InTrafficCounter, uint64(n))

		c.incomingDataOffset += n
		processedLen := 0
		frames := 0
		for {
			// Find Signature
			for processedLen < c.incomingDataOffset && c.incomingData[processedLen] != 0xAA {
				processedLen++
			}

			restBytes := c.incomingDataOffset - processedLen
			if restBytes < TransactionHeaderSize {
				break
			}

			frameLen := int(binary.LittleEndian.Uint32(c.incomingData[processedLen+4:]))
			if frameLen < TransactionHeaderSize || frameLen > c.configMaxFrameSize {
				err = errors.New(ERR_XCHG_CONN_WRONG_FRAME_SIZE)
				break
			}

			c.adjustInputBufferUp(frameLen)

			if restBytes < frameLen {
				break
			}

			atomic.AddUint64(&c.receivedFrames, 1)

			var transaction *Transaction
			transaction, err = Parse(c.incomingData[processedLen:])
			if err == nil {
				c.mtxBaseConnection.Lock()
				if c.processor != nil {
					//logger.Println("[-]", "Connection::thReceive", "received frame:", transaction.FrameType, c.internalId)
					go c.processor.ProcessTransaction(transaction)
				}
				c.mtxBaseConnection.Unlock()
			}

			processedLen += frameLen
			frames++
		}

		if err != nil {
			if c.IsIncoming() {
				break
			} else {
				c.disconnect()
				continue
			}
		}

		for i := processedLen; i < c.incomingDataOffset; i++ {
			c.incomingData[i-processedLen] = c.incomingData[i]
		}
		c.incomingDataOffset -= processedLen
	}

	c.disconnect()

	c.mtxBaseConnection.Lock()
	c.started = false
	c.mtxBaseConnection.Unlock()
}

func (c *Connection) adjustInputBufferUp(needSize int) {
	if len(c.incomingData) >= needSize {
		return
	}
	pSize := needSize + (4096 - (needSize % 4096))
	if pSize == len(c.incomingData) {
		return
	}
	newBuffer := make([]byte, pSize)
	copy(newBuffer, c.incomingData)
	c.incomingData = newBuffer
}

func (c *Connection) adjustInputBufferDown(needSize int) {
	pSize := needSize + (4096 - (needSize % 4096))
	if pSize == len(c.incomingData) {
		return
	}
	newBuffer := make([]byte, pSize)
	copy(newBuffer, c.incomingData)
	c.incomingData = newBuffer
}

func (c *Connection) SendError(transaction *Transaction, err error) {
	logger.Println("[-]", "Connection::SendError", "error:", err, c.internalId)
	c.Send(NewTransaction(FrameError, transaction.SID, transaction.TransactionId, 0, []byte(err.Error())))
}

func (c *Connection) Send(transaction *Transaction) (err error) {
	var conn net.Conn
	c.mtxBaseConnection.Lock()
	conn = c.conn
	c.mtxBaseConnection.Unlock()

	if conn == nil {
		err = errors.New(ERR_XCHG_CONN_NO_CONNECTION)
		return
	}

	frame := transaction.marshal()

	var n int
	c.mtxBaseConnectionSend.Lock()
	sentBytes := 0
	for sentBytes < len(frame) {
		n, err = conn.Write(frame[sentBytes:])
		if err != nil {
			logger.Println("[-]", "Connection::Send", "error:", err)
			break
		}
		if n < 1 {
			logger.Println("[-]", "Connection::Send", "n < 1")
			break
		}
		sentBytes += n
	}

	if sentBytes != len(frame) {
		err = errors.New(ERR_XCHG_CONN_SENDING_ERROR)
	}
	c.mtxBaseConnectionSend.Unlock()
	atomic.AddUint64(&c.sentBytes, uint64(sentBytes))
	atomic.AddUint64(&c.totalPerformanceCounters.OutTrafficCounter, uint64(sentBytes))
	atomic.AddUint64(&c.sentFrames, 1)
	return
}

func (c *Connection) State() (state ConnectionState) {
	c.mtxBaseConnection.Lock()
	defer c.mtxBaseConnection.Unlock()
	state.Host = c.host
	state.ReceivedBytes = c.receivedBytes
	state.ReceivedFrames = c.receivedFrames
	state.SentBytes = c.sentBytes
	state.SentFrames = c.sentFrames
	state.Connected = c.conn != nil
	state.Started = c.started
	state.Stopping = c.stopping
	return
}
