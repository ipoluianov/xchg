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
	mtx            sync.Mutex
	privateKey     *rsa.PrivateKey
	localAddress   string
	started        bool
	stopping       bool
	network        *Network
	useLocalRouter bool

	peerTransports []PeerTransport

	udpEnabled  bool
	httpEnabled bool

	// Client
	remotePeers map[string]*RemotePeer

	// Server
	incomingTransactions  map[string]*Transaction
	sessionsById          map[uint64]*Session
	authNonces            *Nonces
	nextSessionId         uint64
	processor             ServerProcessor
	lastPurgeSessionsTime time.Time

	router *router.Router
}

type PeerProcessor interface {
	processFrame(conn net.PacketConn, sourceAddress *net.UDPAddr, routerHost string, frame []byte) (responseFrames []*Transaction)
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
	PEER_UDP_END_PORT   = 42500
)

func NewPeer(privateKey *rsa.PrivateKey) *Peer {
	var c Peer
	c.remotePeers = make(map[string]*RemotePeer)
	c.incomingTransactions = make(map[string]*Transaction)
	c.authNonces = NewNonces(100)
	c.sessionsById = make(map[uint64]*Session)
	c.nextSessionId = 1
	c.udpEnabled = true
	c.httpEnabled = true
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

func (c *Peer) StartUDPOnly() error {
	c.udpEnabled = true
	c.httpEnabled = false
	return c.Start()
}

func (c *Peer) StartHttpOnly() error {
	c.udpEnabled = false
	c.httpEnabled = true
	return c.Start()
}

func (c *Peer) StartHttpOnlyLocalRouter() error {
	c.udpEnabled = false
	c.httpEnabled = true
	c.useLocalRouter = true
	return c.Start()
}

func (c *Peer) Start() (err error) {
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

	c.router = router.NewRouter()
	c.router.Start()

	go c.thWork()
	return
}

func (c *Peer) updateHttpPeers() {
	if c.httpEnabled {
		if !c.useLocalRouter {
			c.network, _ = NetworkContainerLoadFromInternet()
		} else {
			c.network = NewNetworkLocalhost()
		}
		routerHosts := c.network.GetNodesAddressesByAddress(c.localAddress)
		for _, h := range routerHosts {
			peerHttp := NewPeerHttp(c.network, h)
			//peerHttp.Start(c, )
			c.peerTransports = append(c.peerTransports, peerHttp)
		}
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

	if c.router != nil {
		c.router.Stop()
		c.router = nil
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

func (c *Peer) IsUdpEnabled() bool {
	return c.udpEnabled
}

func (c *Peer) IsHttpEnabled() bool {
	return c.httpEnabled
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
