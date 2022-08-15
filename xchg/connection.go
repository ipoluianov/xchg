package xchg

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipoluianov/gomisc/logger"
)

type Connection struct {
	conn net.Conn

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

	configMaxFrameSize int
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

func NewConnection() *Connection {
	var c Connection
	return &c
}

func (c *Connection) InitIncomingConnection(conn net.Conn, processor ITransactionProcessor) {
	c.mtxBaseConnection.Lock()
	defer c.mtxBaseConnection.Unlock()
	if c.started {
		logger.Println("[ERROR]", "Connection::initIncomingConnection", "already started")
		return
	}
	c.configMaxFrameSize = 100 * 1024

	c.processor = processor
	c.conn = conn
}

func (c *Connection) InitOutgoingConnection(host string, processor ITransactionProcessor) {
	c.mtxBaseConnection.Lock()
	defer c.mtxBaseConnection.Unlock()
	if c.started {
		logger.Println("[ERROR]", "Connection::InitOutgoingConnection", "already started")
		return
	}
	c.configMaxFrameSize = 100 * 1024

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
		logger.Println("[ERROR]", "Connection::Stop", "already stopped")
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
	if c.processor != nil {
		c.processor.Connected()
	}
	c.mtxBaseConnection.Unlock()
}

func (c *Connection) disconnect() {
	c.mtxBaseConnection.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
		if c.processor != nil {
			c.processor.Disconnected()
		}
	}
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

func (c *Connection) thReceive() {
	c.mtxBaseConnection.Lock()
	c.started = true
	c.mtxBaseConnection.Unlock()

	var n int
	var err error
	incomingData := make([]byte, c.configMaxFrameSize)
	incomingDataOffset := 0

	for !c.stopping {
		if c.conn == nil {
			//fmt.Println("connecting to", c.host)
			c.conn, err = net.Dial("tcp", c.host)
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				//fmt.Println("connecting to", c.host, " timeout")
				continue
			}
			incomingData = make([]byte, c.configMaxFrameSize)
			incomingDataOffset = 0
			c.callProcessorConnected()
			//fmt.Println("connecting to", c.host, " OK")
		}

		n, err = c.conn.Read(incomingData[incomingDataOffset:])
		if c.stopping {
			break
		}
		if n < 0 || err != nil {
			if c.IsIncoming() {
				break
			} else {
				c.disconnect()
				continue
			}
		}

		atomic.AddUint64(&c.receivedBytes, uint64(n))

		incomingDataOffset += n
		processedLen := 0
		frames := 0
		for {
			// Find Signature
			for processedLen < incomingDataOffset && incomingData[processedLen] != 0xAA {
				processedLen++
			}

			restBytes := incomingDataOffset - processedLen
			if restBytes < TransactionHeaderSize {
				break
			}

			frameLen := int(binary.LittleEndian.Uint32(incomingData[processedLen+4:]))
			if frameLen < TransactionHeaderSize || frameLen > c.configMaxFrameSize {
				err = errors.New(ERR_XCHG_CONN_WRONG_FRAME_SIZE)
				break
			}

			if restBytes < frameLen {
				break
			}

			atomic.AddUint64(&c.receivedFrames, 1)

			var transaction *Transaction
			transaction, err = Parse(incomingData[processedLen:])
			if err == nil {
				c.mtxBaseConnection.Lock()
				if c.processor != nil {
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

		for i := processedLen; i < incomingDataOffset; i++ {
			incomingData[i-processedLen] = incomingData[i]
		}
		incomingDataOffset -= processedLen
	}

	c.disconnect()

	c.mtxBaseConnection.Lock()
	c.started = false
	c.mtxBaseConnection.Unlock()
}

func (c *Connection) SendError(transaction *Transaction, err error) {
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
			break
		}
		if n < 1 {
			break
		}
		sentBytes += n
	}

	if sentBytes != len(frame) {
		err = errors.New(ERR_XCHG_CONN_SENDING_ERROR)
	}
	c.mtxBaseConnectionSend.Unlock()
	atomic.AddUint64(&c.sentBytes, uint64(sentBytes))
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

const (
	ERR_XCHG_CONN_WRONG_FRAME_SIZE = "{ERR_XCHG_CONN_WRONG_FRAME_SIZE}"
	ERR_XCHG_CONN_NO_CONNECTION    = "{ERR_XCHG_CONN_NO_CONNECTION}"
	ERR_XCHG_CONN_SENDING_ERROR    = "{ERR_XCHG_CONN_SENDING_ERROR}"
)
