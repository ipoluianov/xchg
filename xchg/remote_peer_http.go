package xchg

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"
)

type RemotePeerHttp struct {
	mtx                          sync.Mutex
	network                      *Network
	nonces                       *Nonces
	httpClient                   *http.Client
	privateKey                   *rsa.PrivateKey
	routerHost                   string
	remoteAddress                string
	lastResetConnectionPointerDT time.Time
}

func NewRemotePeerHttp(nonces *Nonces, network *Network, remoteAddress string, privateKey *rsa.PrivateKey) *RemotePeerHttp {
	var c RemotePeerHttp
	c.network = network
	c.nonces = nonces
	c.remoteAddress = remoteAddress
	c.privateKey = privateKey
	tr := &http.Transport{}
	jar, _ := cookiejar.New(nil)
	c.httpClient = &http.Client{Transport: tr, Jar: jar}
	c.httpClient.Timeout = 2 * time.Second
	c.routerHost = ""
	return &c
}

func (c *RemotePeerHttp) Send(frame []byte) error {
	//fmt.Println("HTTP SEND")

	beginWaiting := time.Now()
	for time.Now().Sub(beginWaiting) < 300*time.Millisecond {
		if len(c.routerHost) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	_, err := c.httpCall(c.routerHost, "w", frame)
	//fmt.Println("HTTP SEND END")
	return err
}

func (c *RemotePeerHttp) Check() {
	go c.checkInternetConnectionPoint()
}

func (c *RemotePeerHttp) ResetConnectionPoint() {
	c.mtx.Lock()
	now := time.Now()
	if now.Sub(c.lastResetConnectionPointerDT) > 2*time.Second {
		if c.routerHost != "" {
			fmt.Println("ResetConnectionPoint")
		}
		c.routerHost = ""
		c.lastResetConnectionPointerDT = now
	}
	c.mtx.Unlock()
}

func (c *RemotePeerHttp) SetConnectionPoint(routerHost string) {
	c.routerHost = routerHost
}

func (c *RemotePeerHttp) checkInternetConnectionPoint() (err error) {
	c.mtx.Lock()
	routerHost := c.routerHost
	c.mtx.Unlock()
	if routerHost != "" {
		return
	}

	nonce := c.nonces.Next()
	addressBS := []byte(c.remoteAddress)
	transaction := NewTransaction(0x20, AddressForPublicKey(&c.privateKey.PublicKey), c.remoteAddress, 0, 0, 0, 0, nil)
	transaction.Data = make([]byte, 16+len(addressBS))
	copy(transaction.Data[0:], nonce[:])
	copy(transaction.Data[16:], addressBS)

	routerHost = c.getNextRouter()
	fmt.Println("Trying router", routerHost)
	c.httpCall(routerHost, "w", transaction.Marshal())
	return
}

func (c *RemotePeerHttp) getNextRouter() string {
	addrs := c.network.GetNodesAddressesByAddress(c.remoteAddress)
	if len(addrs) == 0 {
		return ""
	}
	return addrs[0]
}

func (c *RemotePeerHttp) httpCall(routerHost string, function string, frame []byte) (result []byte, err error) {
	// Waiting for router host

	if len(routerHost) == 0 {
		return
	}

	if len(frame) < 128 {
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

	response, err := c.Post(addr+"/api/"+function, writer.FormDataContentType(), &body, "https://"+addr)

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

func (c *RemotePeerHttp) Post(url, contentType string, body io.Reader, host string) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Origin", host)
	return c.httpClient.Do(req)
}
