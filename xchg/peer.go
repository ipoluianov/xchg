package xchg

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type Peer struct {
	mtx          sync.Mutex
	privateKey   *rsa.PrivateKey
	localAddress string
	started      bool
	stopping     bool
	conn         net.PacketConn
	network      *Network

	// Client
	remotePeers map[string]*RemotePeer

	// Server
	incomingTransactions  map[string]*Transaction
	sessionsById          map[uint64]*Session
	authNonces            *Nonces
	nextSessionId         uint64
	processor             ServerProcessor
	lastPurgeSessionsTime time.Time

	declareAddressInInternetLastTime time.Time
}

type ServerProcessor interface {
	ServerProcessorAuth(authData []byte) (err error)
	ServerProcessorCall(function string, parameter []byte) (response []byte, err error)
}

const (
	UDP_PORT          = 8484
	INPUT_BUFFER_SIZE = 1024 * 1024
)

type Session struct {
	id           uint64
	aesKey       []byte
	lastAccessDT time.Time
	snakeCounter *SnakeCounter
}

const (
	PEER_UDP_START_PORT = 42000
	PEER_UDP_END_PORT   = 42100
)

func NewPeer(privateKey *rsa.PrivateKey) *Peer {
	var c Peer
	c.remotePeers = make(map[string]*RemotePeer)
	c.incomingTransactions = make(map[string]*Transaction)
	c.authNonces = NewNonces(100)
	c.sessionsById = make(map[uint64]*Session)
	c.nextSessionId = 1
	c.network = NewNetworkLocalhost()

	c.privateKey = privateKey
	if c.privateKey == nil {
		c.privateKey, _ = GenerateRSAKey()
	}
	c.localAddress = AddressForPublicKey(&c.privateKey.PublicKey)
	go c.thReceive()
	return &c
}

func (c *Peer) Start() (err error) {
	c.mtx.Lock()
	if c.started {
		c.mtx.Unlock()
		err = errors.New("already started")
		return
	}
	c.mtx.Unlock()
	return
}

func (c *Peer) Stop() (err error) {
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
	c.mtx.Unlock()

	if started {
		err = errors.New("timeout")
	}

	return
}

func (c *Peer) Network() *Network {
	return c.network
}

func (c *Peer) SetProcessor(processor ServerProcessor) {
	c.processor = processor
}

func (c *Peer) thReceive() {
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
				conn, err = net.ListenPacket("udp", ":"+fmt.Sprint(i))
				if err == nil {
					c.mtx.Lock()
					udpConn := conn.(*net.UDPConn)
					err = udpConn.SetReadBuffer(1 * 1024 * 1024)
					if err == nil {
						c.conn = conn
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
			c.purgeSessions()
			c.declareAddressInInternet(conn)
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
		if ok {
			frame := make([]byte, n)
			copy(frame, buffer[:n])
			go c.processFrame(conn, udpAddr, frame)
		}
	}

	c.mtx.Lock()
	c.stopping = false
	c.started = false
	c.mtx.Unlock()
}
