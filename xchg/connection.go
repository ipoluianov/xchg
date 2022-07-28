package xchg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

type Connection struct {
	id       uint64
	conn     net.Conn
	mtx      sync.Mutex
	mtxSend  sync.Mutex
	started  bool
	stopping bool
	closed   bool
	host     string

	config                 ConnectionConfig
	chTransactionProcessor chan *Transaction
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

func (c *Connection) initAcceptedConnection() {
	c.config.Init()
	c.chTransactionProcessor = make(chan *Transaction, 10)
}

func (c *Connection) startConnectionBase() {
	c.mtx.Lock()
	if !c.started {
		go c.thReceive()
		c.started = true
	}
	c.mtx.Unlock()
}

func (c *Connection) stopConnectionBase() {
	c.mtx.Lock()
	if !c.stopping {
		c.stopping = true
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil
		}
	}
	c.mtx.Unlock()
}

func (c *Connection) thReceive() {
	fmt.Println("thReceive started")
	var n int
	var err error
	incomingData := make([]byte, c.config.MaxFrameSize)
	incomingDataOffset := 0

	for {
		n, err = c.conn.Read(incomingData[incomingDataOffset:])
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
				c.chTransactionProcessor <- transaction
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

	c.closed = true
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
