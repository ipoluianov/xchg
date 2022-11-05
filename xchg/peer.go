package xchg

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"sync"
	"time"
)

type Peer struct {
	mtx            sync.Mutex
	privateKey     *rsa.PrivateKey
	localAddress   string
	started        bool
	stopping       bool
	conn           net.PacketConn
	network        *Network
	currentUDPPort int

	// Client
	remotePeers map[string]*RemotePeer

	httpClient     *http.Client
	httpClientLong *http.Client

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
	//c.network = NewNetworkLocalhost()
	c.network = NewNetworkDefault()

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
		c.httpClientLong.Timeout = 12 * time.Second
	}

	c.privateKey = privateKey
	if c.privateKey == nil {
		c.privateKey, _ = GenerateRSAKey()
	}
	c.localAddress = AddressForPublicKey(&c.privateKey.PublicKey)
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
	go c.thReceive()
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
			c.purgeSessions()
			go c.getFramesFromInternet("127.0.0.1:8084")
			//c.declareAddressInInternet(conn)
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
			responseFrames := c.processFrame(conn, udpAddr, "", frame)
			for _, f := range responseFrames {
				conn.WriteTo(f.Marshal(), udpAddr)
			}
		}
	}

	c.mtx.Lock()
	c.stopping = false
	c.started = false
	c.mtx.Unlock()
}

func (c *Peer) getFramesFromInternet(routerHost string) {
	// Just one calling
	if c.gettingFromInternet {
		return
	}
	c.gettingFromInternet = true
	defer func() {
		c.gettingFromInternet = false
	}()

	// Get message
	{
		getMessageRequest := make([]byte, 16+30)
		binary.LittleEndian.PutUint64(getMessageRequest[0:], c.lastReceivedMessageId)
		binary.LittleEndian.PutUint64(getMessageRequest[8:], 1024*1024)
		copy(getMessageRequest[16:], AddressBSForPublicKey(&c.privateKey.PublicKey))

		//transaction := NewTransaction(0x06, AddressForPublicKey(&c.privateKey.PublicKey), "", 0, 0, 0, 0, getMessageRequest)
		res, err := c.httpCall(c.httpClientLong, routerHost, "r", getMessageRequest)
		if err != nil {
			return
		}
		if len(res) >= 8 {
			c.lastReceivedMessageId = binary.LittleEndian.Uint64(res[0:])
			//fmt.Println("RECEIVED ID:", c.lastReceivedMessageId)

			offset := 8

			responses := make([]*Transaction, 0)
			responsesCount := 0

			for offset < len(res) {
				if offset+128 <= len(res) {
					frameLen := int(binary.LittleEndian.Uint32(res[offset:]))
					if offset+frameLen <= len(res) {
						responseFrames := c.processFrame(c.conn, nil, routerHost, res[offset:offset+frameLen])
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
			if len(responses) > 0 {
				//fmt.Println("RESPONSE SIZE", len(responses), responsesCount)
				for _, f := range responses {
					c.httpCall(c.httpClient, "127.0.0.1:8084", "w", f.Marshal())
				}
			}
		}
	}
}

func (c *Peer) httpCall(httpClient *http.Client, routerHost string, function string, frame []byte) (result []byte, err error) {
	if len(routerHost) == 0 {
		return
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	{
		fw, _ := writer.CreateFormField("fn")
		fw.Write([]byte(function))
	}
	{
		fw, _ := writer.CreateFormField("d")
		frame64 := base64.StdEncoding.EncodeToString(frame)
		fw.Write([]byte(frame64))
	}
	writer.Close()

	addr := "http://" + routerHost

	response, err := c.Post(httpClient, addr+"/api/"+function, writer.FormDataContentType(), &body, "https://"+addr)

	if err != nil {
		//fmt.Println("HTTP error:", err)
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
	req.Header.Set("Origin", host)
	return httpClient.Do(req)
}
