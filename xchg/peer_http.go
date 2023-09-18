package xchg

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
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
		if time.Now().Sub(dtBegin) > 1000*time.Millisecond {
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

		time.Sleep(5 * time.Millisecond)
	}
	c.started = false
}
