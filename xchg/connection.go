package xchg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ipoluianov/gomisc/logger"
)

type Connection struct {
	id   uint64
	conn net.Conn

	mtxBaseConnection     sync.Mutex
	mtxBaseConnectionSend sync.Mutex

	closed bool
	host   string

	config    ConnectionConfig
	processor ITransactionProcessor

	started  bool
	stopping bool
}

type ITransactionProcessor interface {
	Connected()
	ProcessTransaction(transaction *Transaction)
	Disconnected()
}

type ConnectionConfig struct {
	MaxFrameSize   int `json:"max_frame_size"`
	MaxAddressSize int `json:"max_address_size"`
}

func (c *ConnectionConfig) Init() {
	c.MaxAddressSize = 1024
	c.MaxFrameSize = 100 * 1024
}

func (c *ConnectionConfig) Check() (err error) {
	if c.MaxAddressSize < 1 || c.MaxAddressSize > 1024*1024 {
		err = errors.New("wrong Connection.MaxAddressSize")
	}

	if c.MaxFrameSize < 1 || c.MaxFrameSize > 1024*1024 {
		err = errors.New("wrong Connection.MaxFrameSize")
	}
	return
}

func NewConnection() *Connection {
	var c Connection
	return &c
}

func (c *Connection) initIncomingConnection(conn net.Conn, processor ITransactionProcessor) {
	c.mtxBaseConnection.Lock()
	defer c.mtxBaseConnection.Unlock()
	if c.started {
		logger.Println("connection", "initIncomingConnection", "already started")
		return
	}

	c.processor = processor
	c.config.Init()
	c.conn = conn
}

func (c *Connection) initOutgoingConnection(host string, processor ITransactionProcessor) {
	c.mtxBaseConnection.Lock()
	defer c.mtxBaseConnection.Unlock()
	if c.started {
		logger.Println("connection", "initOutgoingConnection", "already started")
		return
	}

	c.processor = processor
	c.config.Init()
	c.host = host
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

func (c *Connection) thReceive() {
	c.mtxBaseConnection.Lock()
	c.started = true
	c.mtxBaseConnection.Unlock()

	logger.Println("connection", "th_receive", "begin")

	var n int
	var err error
	incomingData := make([]byte, c.config.MaxFrameSize)
	incomingDataOffset := 0

	for !c.stopping {
		if c.conn == nil {
			fmt.Println("connecting ...")
			c.conn, err = net.Dial("tcp", c.host)
			if err != nil {
				fmt.Println("connecting ... error")
				time.Sleep(100 * time.Millisecond)
				continue
			}
			incomingData = make([]byte, c.config.MaxFrameSize)
			incomingDataOffset = 0
			fmt.Println("connecting ... ok")
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
			if frameLen < HeaderSize || frameLen > c.config.MaxFrameSize {
				err = errors.New("wrong frame size")
				break
			}

			if restBytes < frameLen {
				break
			}

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

	logger.Println("connection", "th_receive", "end")
}

func (c *Connection) sendError(transaction *Transaction, err error) {
	fmt.Println("SendError:", err)
	c.send(NewTransaction(FrameError, transaction.recevied1, transaction.eid, transaction.transactionId, 0, []byte(err.Error())))
}

func (c *Connection) send(transaction *Transaction) (err error) {
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
	return
}
