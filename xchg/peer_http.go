package xchg

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"
)

type PeerHttp struct {
	mtx           sync.Mutex
	peerProcessor PeerProcessor

	started  bool
	stopping bool
	enabled  bool

	longPollingDelay time.Duration

	network *Network

	localAddressBS []byte

	routerHost string

	gettingFromInternet   bool
	lastReceivedMessageId uint64
	httpClient            *http.Client
	httpClientLong        *http.Client
}

func NewPeerHttp(network *Network, routerHost string) *PeerHttp {
	var c PeerHttp
	c.enabled = true
	c.network = network
	c.routerHost = routerHost
	c.longPollingDelay = 12 * time.Second

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

	return &c
}

func (c *PeerHttp) Start(peerProcessor PeerProcessor, localAddressBS []byte) (err error) {
	if !c.enabled {
		return
	}

	c.localAddressBS = localAddressBS

	c.mtx.Lock()
	if c.started {
		c.mtx.Unlock()
		err = errors.New("already started")
		return
	}
	c.peerProcessor = peerProcessor
	c.mtx.Unlock()
	go c.thWork()
	return
}

func (c *PeerHttp) Stop() (err error) {
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

func (c *PeerHttp) thWork() {
	c.started = true
	for {
		// Stopping
		c.mtx.Lock()
		stopping := c.stopping
		c.mtx.Unlock()
		if stopping {
			break
		}

		c.getFramesFromInternet(c.routerHost)
		time.Sleep(5 * time.Millisecond)
	}
}

func (c *PeerHttp) getFramesFromInternet(routerHost string) {
	// Just one calling
	if c.gettingFromInternet {
		return
	}
	c.gettingFromInternet = true
	defer func() {
		c.gettingFromInternet = false
	}()

	c.mtx.Lock()
	peerProcessor := c.peerProcessor
	c.mtx.Unlock()
	if peerProcessor == nil {
		return
	}

	// Get message
	{
		getMessageRequest := make([]byte, 16+30)
		binary.LittleEndian.PutUint64(getMessageRequest[0:], c.lastReceivedMessageId)
		binary.LittleEndian.PutUint64(getMessageRequest[8:], 1024*1024)
		copy(getMessageRequest[16:], c.localAddressBS)

		res, err := c.httpCall(c.httpClientLong, routerHost, "r", getMessageRequest)
		if err != nil {
			//fmt.Println("HTTP Error: ", err)
			return
		}
		if len(res) >= 8 {
			c.lastReceivedMessageId = binary.LittleEndian.Uint64(res[0:])

			offset := 8

			responses := make([]*Transaction, 0)
			responsesCount := 0

			for offset < len(res) {
				if offset+128 <= len(res) {
					frameLen := int(binary.LittleEndian.Uint32(res[offset:]))
					if offset+frameLen <= len(res) {
						responseFrames := peerProcessor.processFrame(nil, nil, routerHost, res[offset:offset+frameLen])
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
				for _, f := range responses {
					//c.httpCall(c.httpClient, routerHost, "w", f.Marshal())
					c.send(f.Marshal())
				}
			}
		}
	}
}

func (c *PeerHttp) send(frame []byte) {
	addr := "#" + strings.ToLower(base32.StdEncoding.EncodeToString(frame[70:70+30]))
	addrs := c.network.GetNodesAddressesByAddress(addr)
	//countHosts := len(addrs)/2 + 1
	countHosts := len(addrs)
	for i := 0; i < countHosts; i++ {
		routerHost := addrs[i]
		//fmt.Println("Router host:", routerHost)
		go c.httpCall(c.httpClient, routerHost, "w", frame)
	}
}

func (c *PeerHttp) httpCall(httpClient *http.Client, routerHost string, function string, frame []byte) (result []byte, err error) {
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

func (c *PeerHttp) Post(httpClient *http.Client, url, contentType string, body io.Reader, host string) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Origin", host)
	return httpClient.Do(req)
}
