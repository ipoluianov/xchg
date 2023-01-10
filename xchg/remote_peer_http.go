package xchg

import (
	"bytes"
	"encoding/base64"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"
)

type RemotePeerHttp struct {
	mtx sync.Mutex
	//network    *Network
	httpClient *http.Client

	lastResetConnectionPointerDT time.Time
}

func NewRemotePeerHttp() *RemotePeerHttp {
	var c RemotePeerHttp
	tr := &http.Transport{}
	jar, _ := cookiejar.New(nil)
	c.httpClient = &http.Client{Transport: tr, Jar: jar}
	c.httpClient.Timeout = 1 * time.Second
	return &c
}

func (c *RemotePeerHttp) Send(peerContext PeerContext, network *Network, tr *Transaction) (err error) {
	addrs := network.GetNodesAddressesByAddress(tr.DestAddressString())
	for _, a := range addrs {
		go c.httpCall(a, "w", tr.Marshal())
	}
	return
}

func (c *RemotePeerHttp) SetRemoteUDPAddress(udpAddress *net.UDPAddr) {
}

func (c *RemotePeerHttp) Check(peerContext PeerContext, frame20 *Transaction, network *Network, remotePublicKeyExists bool) error {
	if remotePublicKeyExists {
		return nil
	}
	go c.checkInternetConnectionPoint(frame20, network)
	return nil
}

func (c *RemotePeerHttp) DeclareError(peerContext PeerContext) {
}

func (c *RemotePeerHttp) checkInternetConnectionPoint(frame20 *Transaction, network *Network) (err error) {
	addrs := network.GetNodesAddressesByAddress(frame20.DestAddressString())
	for _, a := range addrs {
		go c.httpCall(a, "w", frame20.Marshal())
	}

	return
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

	response, err := c.Post(addr+"/api/"+function, writer.FormDataContentType(), &body, addr)

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
	return c.httpClient.Do(req)
}
