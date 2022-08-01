package xchg

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/ipoluianov/gomisc/logger"
)

type Connection struct {
	id      uint64
	conn    net.Conn
	mtx     sync.Mutex
	mtxSend sync.Mutex
	closed  bool
	host    string

	config    ConnectionConfig
	processor ITransactionProcessor

	started  bool
	stopping bool
}

type ITransactionProcessor interface {
	ProcessTransaction(transaction *Transaction)
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

func (c *Connection) initIncomingConnection(conn net.Conn) {
	c.config.Init()
	c.conn = conn
}

func (c *Connection) startConnectionBase() {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.started {
		logger.Println("connection", "stop", "already started")
		return
	}
	go c.thReceive()
}

func (c *Connection) stopConnectionBase() {
	c.mtx.Lock()
	logger.Println("connection", "stop", "begin")
	if !c.started {
		logger.Println("connection", "stop", "already stopped")
		c.mtx.Unlock()
		return
	}
	if c.conn != nil {
		c.conn.Close()
	}
	c.mtx.Unlock()

	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		c.mtx.Lock()
		if !c.started {
			c.mtx.Unlock()
			break
		}
		c.mtx.Unlock()
	}

	c.mtx.Lock()
	if c.started {
		logger.Println("connection", "stop", "timeout")
	} else {
		logger.Println("connection", "stop", "success")
	}
	c.mtx.Unlock()

	logger.Println("connection", "stop", "end")
}

func (c *Connection) thReceive() {
	c.mtx.Lock()
	c.started = true
	c.mtx.Unlock()

	logger.Println("connection", "th_receive", "begin")

	var n int
	var err error
	incomingData := make([]byte, c.config.MaxFrameSize)
	incomingDataOffset := 0

	for {
		n, err = c.conn.Read(incomingData[incomingDataOffset:])
		if c.stopping {
			break
		}
		if n < 0 {
			break
		}
		if err != nil {
			break
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
				c.mtx.Lock()
				if c.processor != nil {
					go c.processor.ProcessTransaction(transaction)
				}
				c.mtx.Unlock()
			}

			processedLen += frameLen
			frames++
		}

		if err != nil {
			break
		}

		for i := processedLen; i < incomingDataOffset; i++ {
			incomingData[i-processedLen] = incomingData[i]
		}
		incomingDataOffset -= processedLen
	}

	if c.conn != nil {
		c.conn.Close()
	}
	c.conn = nil

	c.mtx.Lock()
	c.started = false
	c.mtx.Unlock()

	logger.Println("connection", "th_receive", "end")
}

func (c *Connection) sendError(transaction *Transaction, err error) {
	transaction.code = FrameCodeError
	transaction.data = []byte(err.Error())
	c.send(transaction)
}

func (c *Connection) send(transaction *Transaction) (err error) {
	var conn net.Conn

	c.mtx.Lock()
	conn = c.conn
	c.mtx.Unlock()

	if conn == nil {
		return
	}

	frame := transaction.marshal()

	var n int
	c.mtxSend.Lock()
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
		err = errors.New("sending response error")
	}
	c.mtxSend.Unlock()
	return
}
