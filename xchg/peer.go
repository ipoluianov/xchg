package xchg

import (
	"crypto/rsa"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/ipoluianov/xchg/router"
)

type PeerTransport interface {
	Start(peerProcessor PeerProcessor, localAddressBS []byte) error
	Stop() error
}

type Peer struct {
	mtx          sync.Mutex
	privateKey   *rsa.PrivateKey
	localAddress string
	started      bool
	stopping     bool
	network      *Network

	peerTransports []PeerTransport

	// Client
	remotePeers map[string]*RemotePeer

	// Server
	incomingTransactions  map[string]*Transaction
	sessionsById          map[uint64]*Session
	authNonces            *Nonces
	nextSessionId         uint64
	processor             ServerProcessor
	lastPurgeSessionsTime time.Time

	httpServer1 *router.HttpServer
	httpServer2 *router.HttpServer

	router1 *router.Router
	router2 *router.Router
}

type PeerProcessor interface {
	processFrame(conn net.PacketConn, sourceAddress *net.UDPAddr, routerHost string, frame []byte) (responseFrames []*Transaction)
}

type ServerProcessor interface {
	ServerProcessorAuth(authData []byte) (err error)
	ServerProcessorCall(authData []byte, function string, parameter []byte) (response []byte, err error)
}

const (
	UDP_PORT          = 8484
	INPUT_BUFFER_SIZE = 1024 * 1024
)

type Session struct {
	id           uint64
	aesKey       []byte
	authData     []byte
	lastAccessDT time.Time
	snakeCounter *SnakeCounter
}

const (
	PEER_UDP_START_PORT = 42000
	PEER_UDP_END_PORT   = 42500
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

	// Create peer transports
	c.peerTransports = make([]PeerTransport, 0)

	return &c
}

func (c *Peer) Start(enableLocalRouter bool) (err error) {
	c.mtx.Lock()
	if c.started {
		c.mtx.Unlock()
		err = errors.New("already started")
		return
	}
	c.mtx.Unlock()

	c.updateHttpPeers()
	for _, transport := range c.peerTransports {
		transport.Start(c, AddressBSForPublicKey(&c.privateKey.PublicKey))
	}

	if enableLocalRouter {

		c.router1 = router.NewRouter()
		c.router1.Start()

		c.router2 = router.NewRouter()
		c.router2.Start()

		c.httpServer1 = router.NewHttpServer()
		c.httpServer1.Start(c.router1, 42001)

		c.httpServer2 = router.NewHttpServer()
		c.httpServer2.Start(c.router1, 42002)
	}

	go c.thWork()
	return
}

func (c *Peer) updateHttpPeers() {
	c.network, _ = NetworkContainerLoadFromInternet()
	// c.network = NewNetworkLocalhost()

	routerHosts := c.network.GetNodesAddressesByAddress(c.localAddress)
	for _, h := range routerHosts {
		peerHttp := NewPeerHttp(c.network, h)
		c.peerTransports = append(c.peerTransports, peerHttp)
	}
}

func (c *Peer) Stop() (err error) {
	c.mtx.Lock()
	if !c.started {
		c.mtx.Unlock()
		err = errors.New("already stopped")
		return
	}

	for _, transport := range c.peerTransports {
		transport.Stop()
	}

	c.stopping = true
	started := c.started
	c.mtx.Unlock()

	if c.router1 != nil {
		c.router1.Stop()
		c.router1 = nil
	}

	if c.router2 != nil {
		c.router2.Stop()
		c.router2 = nil
	}

	if c.httpServer1 != nil {
		c.httpServer1.Stop()
		c.httpServer1 = nil
	}

	if c.httpServer2 != nil {
		c.httpServer2.Stop()
		c.httpServer2 = nil
	}

	dtBegin := time.Now()
	for started {
		time.Sleep(100 * time.Millisecond)
		c.mtx.Lock()
		started = c.started
		c.mtx.Unlock()

		if time.Since(dtBegin) > 1000*time.Millisecond {
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

func (c *Peer) thWork() {
	c.started = true
	for {
		// Stopping
		c.mtx.Lock()
		stopping := c.stopping
		c.mtx.Unlock()
		if stopping {
			break
		}

		c.purgeSessions()
		time.Sleep(100 * time.Millisecond)
	}
}
