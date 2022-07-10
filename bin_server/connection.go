package binserver

import (
	"context"
	"encoding/binary"
	"net"
	"sync"

	"github.com/ipoluianov/xchg/core"
)

type Connection struct {
	conn         net.Conn
	core         *core.Core
	mtx          sync.Mutex
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
		if n < 1 {
			break
		}
		if err != nil {
			break
		}
		incomingDataOffset += n
		processedLen := 0
		for {
			// Find Signature
			for processedLen < incomingDataOffset && incomingData[processedLen] != 0xAA {
				processedLen++
			}
			// Find valid frame
			if processedLen < incomingDataOffset-8 && incomingData[processedLen] == 0xAA {
				frameLen := int(binary.LittleEndian.Uint32(incomingData[processedLen+4:]))

				if frameLen < 8 || frameLen > c.maxFrameSize {
					processedLen++
					continue
				}

				if frameLen > len(incomingData[processedLen:]) {
					break // Not enough data
				}

				frame := make([]byte, frameLen)
				copy(frame, incomingData[processedLen:processedLen+frameLen])
				processedLen += frameLen

				ctx := context.Background()

				var result []byte
				result, err = c.core.ProcessFrame(ctx, frame)
				c.conn.Write(result)
			}
		}
	}
	c.closed = true
}
