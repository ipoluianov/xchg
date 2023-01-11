package xchg

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type PeerUdp struct {
	mtx            sync.Mutex
	peerProcessor  PeerProcessor
	currentUDPPort int
	conn           net.PacketConn
	localAddressBS []byte

	enabled  bool
	started  bool
	stopping bool
}

func NewPeerUdp() *PeerUdp {
	var c PeerUdp
	c.enabled = true
	return &c
}

func (c *PeerUdp) Start(peerProcessor PeerProcessor, localAddressBS []byte) (err error) {
	if !c.enabled {
		return
	}
	c.mtx.Lock()
	if c.started {
		c.mtx.Unlock()
		err = errors.New("already started")
		return
	}
	c.peerProcessor = peerProcessor
	c.mtx.Unlock()
	go c.thUdpServer()
	return
}

func (c *PeerUdp) Stop() (err error) {
	c.mtx.Lock()
	if !c.started {
		c.mtx.Unlock()
		err = errors.New("already stopped")
		return
	}
	c.stopping = true
	started := c.started
	c.mtx.Unlock()

	dtBegin := time.Now()
	for started {
		time.Sleep(100 * time.Millisecond)
		c.mtx.Lock()
		started = c.started
		c.mtx.Unlock()
		if time.Now().Sub(dtBegin) > 1000*time.Second {
			break
		}
	}
	c.mtx.Lock()
	started = c.started
	c.peerProcessor = nil
	c.mtx.Unlock()

	if started {
		err = errors.New("timeout")
	}

	return
}

func (c *PeerUdp) Conn() (conn net.PacketConn) {
	c.mtx.Lock()
	conn = c.conn
	c.mtx.Unlock()
	return
}

func (c *PeerUdp) thUdpServer() {
	var err error
	var conn net.PacketConn

	c.started = true

	buffer := make([]byte, INPUT_BUFFER_SIZE)

	var n int
	var addr net.Addr

	for {
		// Stopping
		c.mtx.Lock()
		stopping := c.stopping
		conn = c.conn
		c.mtx.Unlock()
		if stopping {
			break
		}

		// UDP port management
		if conn == nil {
			// Open any UDP port in diapason PEER_UDP_START_PORT:PEER_UDP_END_PORT
			for i := PEER_UDP_START_PORT; i < PEER_UDP_END_PORT; i++ {
				fmt.Println("trying open port " + fmt.Sprint(i))
				conn, err = net.ListenPacket("udp", ":"+fmt.Sprint(i))
				if err == nil {
					c.mtx.Lock()
					udpConn := conn.(*net.UDPConn)
					err = udpConn.SetReadBuffer(1 * 1024 * 1024)
					if err == nil {
						c.conn = conn
						c.currentUDPPort = i
					} else {
						fmt.Println("SetReadBuffer error")
						conn.Close()
						conn = nil
					}
					c.mtx.Unlock()
					break
				}
			}

			if conn == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			fmt.Println("UDP Opened", conn.LocalAddr())
		}

		err = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			c.mtx.Lock()
			conn.Close()
			conn = nil
			c.conn = nil
			c.mtx.Unlock()
			continue
		}

		n, addr, err = conn.ReadFrom(buffer)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			// Background operations
			continue
		}

		if err != nil {
			time.Sleep(100 * time.Millisecond)
			c.mtx.Lock()
			conn.Close()
			conn = nil
			c.conn = nil
			c.mtx.Unlock()
			continue
		}
		udpAddr, ok := addr.(*net.UDPAddr)

		////////////////////////////////////////
		// Test
		if (time.Now().Unix() % 30) < 15 {
			continue
		}
		////////////////////////////////////////

		if ok {
			frame := make([]byte, n)
			copy(frame, buffer[:n])

			c.mtx.Lock()
			peerProcessor := c.peerProcessor
			c.mtx.Unlock()
			if peerProcessor != nil {
				responseFrames := peerProcessor.processFrame(conn, udpAddr, "", frame)
				for _, f := range responseFrames {
					conn.WriteTo(f.Marshal(), udpAddr)
				}
			}
		}
	}

	c.mtx.Lock()
	c.stopping = false
	c.started = false
	c.mtx.Unlock()
}
