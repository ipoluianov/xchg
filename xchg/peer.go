package xchg

import (
	"crypto/rsa"
	"errors"
	"net"
	"sync"
	"time"
)

type Peer struct {
	mtx          sync.Mutex
	privateKey   *rsa.PrivateKey
	localAddress string
	started      bool
	stopping     bool
	network      *Network

	peerUdp   *PeerUdp
	peersHttp []*PeerHttp

	udpEnabled  bool
	httpEnabled bool

	// Client
	remotePeers map[string]*RemotePeer

	gettingFromInternet   bool
	lastReceivedMessageId uint64

	// Server
	incomingTransactions  map[string]*Transaction
	sessionsById          map[uint64]*Session
	authNonces            *Nonces
	nextSessionId         uint64
	processor             ServerProcessor
	lastPurgeSessionsTime time.Time

	declareAddressInInternetLastTime time.Time
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
	PEER_UDP_END_PORT   = 45900
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
	//c.network = NewNetworkLocalhost()
	c.network = NewNetworkDefault()

	c.privateKey = privateKey
	if c.privateKey == nil {
		c.privateKey, _ = GenerateRSAKey()
	}
	c.localAddress = AddressForPublicKey(&c.privateKey.PublicKey)

	c.peerUdp = NewPeerUdp()
	//c.peerHttp = NewPeerHttp(c.network)
	c.peersHttp = make([]*PeerHttp, 0)

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

func (c *Peer) Start() (err error) {
	c.mtx.Lock()
	if c.started {
		c.mtx.Unlock()
		err = errors.New("already started")
		return
	}
	c.mtx.Unlock()

	if c.udpEnabled {
		c.peerUdp.Start(c)
	}

	if c.httpEnabled {
		routerHosts := c.network.GetNodesAddressesByAddress(c.localAddress)
		for _, h := range routerHosts {
			peerHttp := NewPeerHttp(c.network, h)
			peerHttp.Start(c, AddressBSForPublicKey(&c.privateKey.PublicKey))
			c.peersHttp = append(c.peersHttp, peerHttp)
		}
	}

	go c.thWork()

	return
}

func (c *Peer) Stop() (err error) {
	c.mtx.Lock()
	if !c.started {
		c.mtx.Unlock()
		err = errors.New("already stopped")
		return
	}

	if c.udpEnabled {
		c.peerUdp.Stop()
	}
	if c.httpEnabled {
		for _, p := range c.peersHttp {
			p.Stop()
		}
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
		if time.Now().Sub(dtBegin) > 1000*time.Millisecond {
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
