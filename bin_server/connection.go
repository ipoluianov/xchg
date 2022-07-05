package binserver

import (
	"encoding/binary"
	"net"
)

type Connection struct {
	conn net.Conn
}

func NewConnection(conn net.Conn) *Connection {
	var c Connection
	c.conn = conn
	return &c
}

func (c *Connection) Start() {
	go c.thReceive()
}

func (c *Connection) Stop() {
}

func (c *Connection) thReceive() {
	var n int
	var err error
	incomingData := make([]byte, 0) // Max Frame size
	rcvBuffer := make([]byte, 1024)
	for {
		n, err = c.conn.Read(rcvBuffer)
		if n < 1 {
			break
		}
		if err != nil {
			break
		}
		incomingData = append(incomingData, rcvBuffer[:n]...)
		processedLen := 0
		for {
			// Find Signature
			for processedLen < len(incomingData) && incomingData[processedLen] != 0xAA {
				processedLen++
			}
			if processedLen < len(incomingData)-8 && incomingData[processedLen] == 0xAA {
				frameLen := binary.LittleEndian.Uint32(incomingData[processedLen:])
				if frameLen < 8 || frameLen > 100*1024 {
					processedLen++
					continue
				}
				if int(frameLen) <= len(incomingData[processedLen:]) {
					processedLen += int(frameLen)
				}
			}
		}
	}
}
