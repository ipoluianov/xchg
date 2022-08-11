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
		logger.Println("connection", "initIncomingConnection", "already started")
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
		logger.Println("connection", "initOutgoingConnection", "already started")
		return
	}
	c.configMaxFrameSize = 100 * 1024

	c.processor = processor
	c.host = host
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
		logger.Println("connection", "stop", "already started")
		return
	}
	c.stopping = false
	go c.thReceive()
}

func (c *Connection) Stop() {
	c.mtxBaseConnection.Lock()
	logger.Println("connection", "stop", "begin")
	if !c.started {
		logger.Println("connection", "stop", "already stopped")
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
		logger.Println("connection", "stop", "timeout")
	} else {
		logger.Println("connection", "stop", "success")
	}
	c.stopping = false
	c.mtxBaseConnection.Unlock()

	logger.Println("connection", "stop", "end")
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
			c.conn, err = net.Dial("tcp", c.host)
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			incomingData = make([]byte, c.configMaxFrameSize)
			incomingDataOffset = 0
			c.callProcessorConnected()
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
			if restBytes < HeaderSize {
				break
			}

			frameLen := int(binary.LittleEndian.Uint32(incomingData[processedLen+4:]))
			if frameLen < HeaderSize || frameLen > c.configMaxFrameSize {
				err = errors.New("wrong frame size")
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
	//fmt.Println("SendError:", err)
	c.Send(NewTransaction(FrameError, transaction.Recevied1, transaction.EID, transaction.TransactionId, 0, []byte(err.Error())))
}

func (c *Connection) Send(transaction *Transaction) (err error) {
	var conn net.Conn

	c.mtxBaseConnection.Lock()
	conn = c.conn
	c.mtxBaseConnection.Unlock()

	if conn == nil {
		err = errors.New("no connection")
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
		err = errors.New("sending error")
	}
	c.mtxBaseConnectionSend.Unlock()
	atomic.AddUint64(&c.sentBytes, uint64(sentBytes))
	atomic.AddUint64(&c.sentFrames, 1)
	return
}
