package binserver

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"

	"github.com/ipoluianov/xchg/core"
)

type Connection struct {
	conn         net.Conn
	core         *core.Core
	mtx          sync.Mutex
	mtxSend      sync.Mutex
	started      bool
	stopping     bool
	closed       bool
	maxFrameSize int
}

func NewConnection(conn net.Conn, core *core.Core) *Connection {
	var c Connection
	c.conn = conn
	c.core = core
	c.maxFrameSize = 1024 * 1024 // TODO:
	return &c
}

func (c *Connection) Start() {
	c.mtx.Lock()
	if !c.started {
		go c.thReceive()
		c.started = true
	}
	c.mtx.Unlock()
}

func (c *Connection) Stop() {
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
	var n int
	var err error
	incomingData := make([]byte, c.maxFrameSize)
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
			if restBytes < 8 {
				break
			}

			// Get header
			signature := binary.LittleEndian.Uint32(incomingData[processedLen:])
			_ = signature
			frameLen := int(binary.LittleEndian.Uint32(incomingData[processedLen+4:]))

			// Check frame size
			if frameLen < 8 || frameLen > c.maxFrameSize {
				// ERROR: wrong frame size
				err = errors.New("wrong frame size")
				break
			}

			if restBytes < frameLen {
				break
			}

			frame := make([]byte, frameLen-8)
			copy(frame, incomingData[processedLen+8:processedLen+frameLen])
			go c.thProcessFrame(signature, c.conn, frame)

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

func (c *Connection) thProcessFrame(signature uint32, conn net.Conn, frame []byte) {
	var err error
	var n int
	ctx := context.Background()

	var processResult []byte
	var result []byte
	processResult, err = c.core.ProcessFrame(ctx, frame)

	if err != nil {
		errString := []byte(err.Error())
		responseLen := 9 + len(errString)
		result = make([]byte, responseLen)
		binary.LittleEndian.PutUint32(result, signature)
		binary.LittleEndian.PutUint32(result[4:], uint32(responseLen))
		result[8] = 1 // Error
		copy(result[9:], errString)
	} else {
		responseLen := 9 + len(processResult)
		result = make([]byte, responseLen)
		binary.LittleEndian.PutUint32(result, signature)
		binary.LittleEndian.PutUint32(result[4:], uint32(responseLen))
		result[8] = 0 // Success
		copy(result[9:], processResult)
	}

	c.mtxSend.Lock()
	sentBytes := 0
	for sentBytes < len(result) {
		n, err = conn.Write(result[sentBytes:])
		if err != nil {
			break
		}
		if n < 1 {
			break
		}
		sentBytes += n
	}

	if sentBytes != len(result) {
		err = errors.New("sending response error")
	}
	c.mtxSend.Unlock()
}
