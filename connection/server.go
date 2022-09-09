package connection

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type Server struct {
	privateKey *rsa.PrivateKey

	// Sync
	mtx sync.Mutex

	// State
	started  bool
	stopping bool
}

const (
	UDP_PORT          = 8484
	INPUT_BUFFER_SIZE = 1024 * 1024
)

func NewConnection() *Server {
	var c Server
	return &c
}

func (c *Server) Start() {
}

func (c *Server) Stop() {
}

func (c *Server) thReceive() {
	var err error
	var conn net.PacketConn

	fmt.Println("started")

	c.started = true
	buffer := make([]byte, INPUT_BUFFER_SIZE)

	conn, err = net.ListenPacket("udp", ":")
	if err != nil {
		c.mtx.Lock()
		c.started = false
		c.stopping = false
		c.mtx.Unlock()
		fmt.Println("net.ListenPacket error:", err)
		return
	}

	var n int
	var addr net.Addr

	for {
		c.mtx.Lock()
		stopping := c.stopping
		c.mtx.Unlock()
		if stopping {
			break
		}

		err = conn.SetReadDeadline(time.Now().Add(1000 * time.Millisecond))
		if err != nil {
			c.mtx.Lock()
			c.started = false
			c.stopping = false
			c.mtx.Unlock()
			fmt.Println("conn.SetReadDeadline error:", err)
			return
		}

		n, addr, err = conn.ReadFrom(buffer)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			c.backgroundOperations()
			continue
		}

		if err != nil {
			c.mtx.Lock()
			c.started = false
			c.stopping = false
			c.mtx.Unlock()
			fmt.Println("conn.ReadFrom error:", err)
			return
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if ok {
			frame := make([]byte, n)
			copy(frame, buffer[:n])
			go c.processFrame(conn, udpAddr, frame)
		} else {
			fmt.Println("unknown address type")
		}
	}

	fmt.Println("stoppped")
	c.mtx.Lock()
	c.started = false
	c.stopping = false
	c.mtx.Unlock()
}

func (c *Server) sendError(conn net.PacketConn, sourceAddress *net.UDPAddr, originalFrame []byte, errorCode byte) {
	var responseFrame [8]byte
	copy(responseFrame[:], originalFrame[:8])
	responseFrame[1] = errorCode
	_, _ = conn.WriteTo(responseFrame[:], sourceAddress)
}

func (c *Server) sendResponse(conn net.PacketConn, sourceAddress *net.UDPAddr, originalFrame []byte, responseFrame []byte) {
	copy(responseFrame, originalFrame[:8])
	responseFrame[1] = 0x00
	_, _ = conn.WriteTo(responseFrame, sourceAddress)
}

func (c *Server) backgroundOperations() {
	c.mtx.Lock()
	c.mtx.Unlock()
}

func (c *Server) processFrame(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	fmt.Println("processFrame", sourceAddress, frame)
	if len(frame) < 8 {
		return
	}

	frameType := frame[0]
	switch frameType {
	case 0x00:
		c.processFrame00(conn, sourceAddress, frame)
	case 0x10:
		c.processFrame10(conn, sourceAddress, frame)
	}
}

func (c *Server) processFrame00(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	c.sendResponse(conn, sourceAddress, frame, make([]byte, 8))
}

func (c *Server) processFrame10(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	// Call
	c.sendResponse(conn, sourceAddress, frame, make([]byte, 8))
}

func (c *Server) processFrame11(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	// Response received
	c.sendResponse(conn, sourceAddress, frame, make([]byte, 8))
}
