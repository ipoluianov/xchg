package xchg

import (
	"bytes"
	"crypto/rsa"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"

	"github.com/ipoluianov/xchg/router"
)

type PeerTransport interface {
	Start(peerProcessor PeerProcessor, localAddressBS []byte) error
	Stop() error
}

type Logger interface {
	Println(v ...interface{})
}

type Peer struct {
	mtx          sync.Mutex
	privateKey   *rsa.PrivateKey
	localAddress string
	started      bool
	stopping     bool
	network      *Network

	httpClient     *http.Client
	httpClientLong *http.Client

	longPollingDelay time.Duration

	localAddressBS []byte

	logger         Logger
	routerStatRead map[string]int

	//peerTransports []PeerTransport

	gettingFromInternet   map[string]bool
	lastReceivedMessageId map[string]uint64

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

	udpConn *net.UDPConn
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

func NewPeer(privateKey *rsa.PrivateKey, logger Logger) *Peer {
	var c Peer
	c.logger = logger
	c.remotePeers = make(map[string]*RemotePeer)
	c.incomingTransactions = make(map[string]*Transaction)
	c.authNonces = NewNonces(100)
	c.sessionsById = make(map[uint64]*Session)
	c.nextSessionId = 1
	c.network = NewNetworkLocalhost()
	c.lastReceivedMessageId = make(map[string]uint64)

	c.routerStatRead = make(map[string]int)

	c.gettingFromInternet = make(map[string]bool)
	c.longPollingDelay = 12 * time.Second

	c.privateKey = privateKey
	if c.privateKey == nil {
		c.privateKey, _ = GenerateRSAKey()
	}
	c.localAddress = AddressForPublicKey(&c.privateKey.PublicKey)

	{
		tr := &http.Transport{}
		jar, _ := cookiejar.New(nil)
		c.httpClient = &http.Client{Transport: tr, Jar: jar}
		c.httpClient.Timeout = 2 * time.Second
	}

	{
		tr := &http.Transport{}
		jar, _ := cookiejar.New(nil)
		c.httpClientLong = &http.Client{Transport: tr, Jar: jar}
		c.httpClientLong.Timeout = c.longPollingDelay
	}

	// Create peer transports
	//c.peerTransports = make([]PeerTransport, 0)

	return &c
}

func (c *Peer) Start(enableLocalRouter bool) (err error) {
	c.logger.Println("Peer::Start")
	c.mtx.Lock()
	if c.started {
		c.mtx.Unlock()
		err = errors.New("already started")
		return
	}
	c.mtx.Unlock()

	c.localAddressBS = AddressBSForPublicKey(&c.privateKey.PublicKey)

	c.updateHttpPeers()

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
	//go c.thUDP()
	return
}

func (c *Peer) updateHttpPeers() {
	c.logger.Println("Peer::updateHttpPeers")

	network, _ := NetworkContainerLoadFromInternet()
	c.logger.Println("Network container", network.Name)

	c.mtx.Lock()
	if network != nil {
		if network.Timestamp > c.network.Timestamp {
			c.network = network
			c.logger.Println("Peer::updateHttpPeers", "new network detected", network.Name)
		}
	}
	c.mtx.Unlock()
}

func (c *Peer) Stop() (err error) {
	c.logger.Println("Peer::Stop")

	c.mtx.Lock()
	if !c.started {
		c.mtx.Unlock()
		err = errors.New("already stopped")
		return
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

/*
	func (c *Peer) thUDP() {
		c.logger.Println("UDR started")
		addr, _ := net.ResolveUDPAddr("udp", ":8585")
		var err error
		c.udpConn, err = net.ListenUDP("udp", addr)
		if err != nil {
			c.logger.Println("ERROR:", err)
			return
		}

		for !c.stopping {
			buffer := make([]byte, 4000)
			c.logger.Println("UDR reading ...", addr)
			bytesRead, remoteAddr, err := c.udpConn.ReadFromUDP(buffer)
			if err != nil {
				c.logger.Println("ReadFromUDP error:", err)
				break
			}
			incoming := string(buffer[0:bytesRead])
			c.processFrame("UDP", buffer[0:bytesRead])
			c.logger.Println("RECEIVED UDP", incoming, "from", remoteAddr.String())
		}

		if c.udpConn != nil {
			c.udpConn.Close()
		}
	}
*/
func (c *Peer) Network() *Network {
	return c.network
}

func (c *Peer) SetProcessor(processor ServerProcessor) {
	c.processor = processor
}

func (c *Peer) thWork() {
	c.started = true
	lastNetworkUpdateDT := time.Now()
	lastPurgeSessionsDT := time.Now()
	lastStatDT := time.Now()
	lastDeclareUDPPointDT := time.Now()
	for {
		// Stopping
		c.mtx.Lock()
		stopping := c.stopping
		c.mtx.Unlock()
		if stopping {
			break
		}

		go c.getFramesFromInternet()

		if time.Since(lastPurgeSessionsDT) > 5*time.Second {
			c.purgeSessions()
			lastPurgeSessionsDT = time.Now()
		}

		if time.Since(lastNetworkUpdateDT) > 30*time.Second {
			c.updateHttpPeers()
			lastNetworkUpdateDT = time.Now()
		}

		if time.Since(lastStatDT) > 10*time.Second {
			c.fixStat()
			lastStatDT = time.Now()
		}

		if time.Since(lastDeclareUDPPointDT) > 10*time.Second {
			//c.declareUDPPoint()
			lastDeclareUDPPointDT = time.Now()
		}

		time.Sleep(10 * time.Millisecond)

		//fmt.Println(c.network)
	}
}

func (c *Peer) fixStat() {
	c.mtx.Lock()
	c.logger.Println("-------STAT------")
	for key, value := range c.routerStatRead {
		c.logger.Println("Router read", key, "=", value)
	}
	c.logger.Println()
	c.mtx.Unlock()
}

/*
	func (c *Peer) declareUDPPoint() {
		c.logger.Println("-------DECLARE UDP------")
		c.mtx.Lock()
		network := c.network
		c.mtx.Unlock()

		if network == nil {
			return
		}

		if c.udpConn == nil {
			c.logger.Println("c.udpConn == nil")
			return
		}

		routers := network.GetNodesAddressesByAddress(c.localAddress)
		for _, router := range routers {
			//signalAddress := "x03.gazer.cloud:8484"
			remote, _ := net.ResolveUDPAddr("udp", router)
			bytesWritten, err := c.udpConn.WriteTo([]byte(c.localAddress), remote)
			if err != nil {
				c.logger.Println("UDP send error:", err)
			}
			c.logger.Println(bytesWritten, " bytes written")
		}
	}
*/
func (c *Peer) getFramesFromRouter(router string) {
	/////////////////////////////////////////////
	c.mtx.Lock()
	processing := c.gettingFromInternet[router]
	c.mtx.Unlock()
	if processing {
		return
	}
	c.mtx.Lock()
	c.gettingFromInternet[router] = true
	c.mtx.Unlock()
	defer func() {
		c.mtx.Lock()
		c.gettingFromInternet[router] = false
		c.mtx.Unlock()
	}()
	/////////////////////////////////////////////
	//c.logger.Println("Peer::getFramesFromRouter", router)
	c.mtx.Lock()
	c.routerStatRead[router]++
	c.mtx.Unlock()

	// Get message
	{
		c.mtx.Lock()
		fromMessageId := c.lastReceivedMessageId[router]
		c.mtx.Unlock()
		getMessageRequest := make([]byte, 16+30)
		binary.LittleEndian.PutUint64(getMessageRequest[0:], fromMessageId)
		binary.LittleEndian.PutUint64(getMessageRequest[8:], 1024*1024)
		copy(getMessageRequest[16:], c.localAddressBS)

		// fmt.Println("GETTING from", router)
		res, err := c.httpCall(c.httpClientLong, router, "r", getMessageRequest)
		if err != nil {
			//fmt.Println("HTTP Error: ", err)
			return
		}
		if len(res) >= 8 {
			lastReceivedMessageId := binary.LittleEndian.Uint64(res[0:])

			c.mtx.Lock()

			c.lastReceivedMessageId[router] = lastReceivedMessageId
			c.mtx.Unlock()

			offset := 8

			responses := make([]*Transaction, 0)
			responsesCount := 0

			framesCount := 0

			for offset < len(res) {
				if offset+128 <= len(res) {
					frameLen := int(binary.LittleEndian.Uint32(res[offset:]))
					if offset+frameLen <= len(res) {
						framesCount++
						responseFrames := c.processFrame(router, res[offset:offset+frameLen])
						responses = append(responses, responseFrames...)
						responsesCount += len(responseFrames)
					} else {
						break
					}
					offset += frameLen
				} else {
					break
				}
			}
			//c.logger.Println("Received frames:", framesCount)
			if len(responses) > 0 {
				for _, f := range responses {
					c.send(f.Marshal(), f.FromLocalNode)
				}
			}
		}
	}

}

func (c *Peer) getFramesFromInternet() {
	c.mtx.Lock()
	network := c.network
	c.mtx.Unlock()

	if network == nil {
		return
	}

	routers := network.GetNodesAddressesByAddress(c.localAddress)
	for _, router := range routers {
		c.getFramesFromRouter(router)
	}
}

func (c *Peer) send(frame []byte, onlyToLocalRouter bool) {
	addr := "#" + strings.ToLower(base32.StdEncoding.EncodeToString(frame[70:70+30]))
	addrs := c.network.GetNodesAddressesByAddress(addr)
	if onlyToLocalRouter {
		addrs = c.network.GetLocalNodes()
	}
	//countHosts := len(addrs)/2 + 1
	countHosts := len(addrs)
	for i := 0; i < countHosts; i++ {
		routerHost := addrs[i]
		go c.httpCall(c.httpClient, routerHost, "w", frame)
	}
}

func (c *Peer) httpCall(httpClient *http.Client, routerHost string, function string, frame []byte) (result []byte, err error) {
	if len(routerHost) == 0 {
		return
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	{
		fw, _ := writer.CreateFormField("d")
		frame64 := base64.StdEncoding.EncodeToString(frame)
		fw.Write([]byte(frame64))
	}
	writer.Close()

	addr := "http://" + routerHost

	response, err := c.Post(httpClient, addr+"/api/"+function, writer.FormDataContentType(), &body, "https://"+addr)

	if err != nil {
		return
	} else {
		var content []byte
		content, err = ioutil.ReadAll(response.Body)
		if err != nil {
			response.Body.Close()
			return
		}
		result, err = base64.StdEncoding.DecodeString(string(content))
		response.Body.Close()
	}
	return
}

func (c *Peer) Post(httpClient *http.Client, url, contentType string, body io.Reader, host string) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return httpClient.Do(req)
}

func (c *Peer) Call(remoteAddress string, authData string, function string, data []byte, timeout time.Duration) (result []byte, err error) {
	c.mtx.Lock()
	remotePeer, remotePeerOk := c.remotePeers[remoteAddress]
	if !remotePeerOk || remotePeer == nil {
		remotePeer = NewRemotePeer(remoteAddress, authData, c.privateKey)
		c.remotePeers[remoteAddress] = remotePeer
	}
	network := c.network
	c.mtx.Unlock()
	result, err = remotePeer.Call(network, function, data, timeout)
	return
}
