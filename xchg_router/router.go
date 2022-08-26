package xchg_router

import (
	"crypto/rsa"
	"errors"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/gomisc/logger"
	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_network"
)

type Router struct {
	mtxRouter sync.Mutex

	nextConnectionId     uint64
	connectionsByAddress map[string]*RouterConnection
	connectionsById      map[uint64]*RouterConnection

	config RouterConfig

	// Local Address
	localPublicKey    *rsa.PublicKey
	localPublicKeyBS  []byte
	localPrivateKey   *rsa.PrivateKey
	localPrivateKeyBS []byte
	localAddress      string

	httpServer   *HttpServer
	routerServer *RouterServer
	network      *xchg_network.Network

	chWorking chan interface{}

	mtxPerformance          sync.Mutex
	performanceLastDT       time.Time
	performanceCounters     RouterPerformanceCounters
	performanceLastCounters RouterPerformanceCounters
	performance             RouterPerformance
	state                   RouterState
}

type RouterState struct {
	NextConnectionId          uint64 `json:"next_connection_id"`
	ConnectionsCount          int    `json:"connections_count"`
	ConnectionsByAddressCount int    `json:"connections_by_address_count"`

	Connections []RouterConnectionState `json:"connections"`
}

type RouterPerformanceCounters struct {
	HttpRequestsCounter uint64 `json:"http_requests_counter"`
	HttpGetStateCounter uint64 `json:"http_get_state_counter"`
	HttpGetPerfCounter  uint64 `json:"http_get_perf_counter"`

	ServerAcceptCounter uint64 `json:"server_accept_counter"`

	ConnectionsPerformanceCounters xchg.ConnectionsPerformanceCounters
}

type RouterPerformance struct {
	HttpRequestsRate uint64 `json:"http_requests_rate"`
	HttpGetStateRate uint64 `json:"http_get_state_rate"`
	HttpGetPerfRate  uint64 `json:"http_get_perf_rate"`

	ServerAcceptRate     uint64 `json:"server_accept_rate"`
	ServerInTrafficRate  uint64 `json:"server_in_traffic_rate"`
	ServerOutTrafficRate uint64 `json:"server_out_traffic_rate"`

	Init1Rate uint64 `json:"init1_rate"`
	Init4Rate uint64 `json:"init4_rate"`
	Init5Rate uint64 `json:"init5_rate"`
}

func NewRouter(localAddress *rsa.PrivateKey, config RouterConfig, network *xchg_network.Network) *Router {
	var c Router

	if localAddress != nil {
		c.localPrivateKey = localAddress
		c.localPrivateKeyBS = crypt_tools.RSAPrivateKeyToDer(localAddress)
		c.localPublicKey = &localAddress.PublicKey
		c.localPublicKeyBS = crypt_tools.RSAPublicKeyToDer(c.localPublicKey)
		c.localAddress = xchg.AddressForPublicKey(c.localPublicKey)
	}
	c.network = network

	c.init()
	c.routerServer = NewRouterServer(config.BinServerPort, &c)
	c.httpServer = NewHttpServer(config.HttpServerPort, &c)
	return &c
}

func (c *Router) init() {
	c.nextConnectionId = 1
	c.connectionsByAddress = make(map[string]*RouterConnection)
	c.connectionsById = make(map[uint64]*RouterConnection)
}

func (c *Router) Start() (err error) {
	logger.Println("[i]", "Router::Start", "begin")
	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()

	if c.chWorking != nil {
		err = errors.New(xchg.ERR_XCHG_ROUTER_ALREADY_STARTED)
		logger.Println("[ERROR]", "Router::Start", err.Error())
		return
	}

	c.init()

	c.chWorking = make(chan interface{})

	go c.thWorker()

	c.httpServer.Start()
	c.routerServer.Start()
	logger.Println("[i]", "Router::Start", "end")
	return
}

func (c *Router) Stop() (err error) {
	logger.Println("[i]", "Router::Stop", "begin")

	c.routerServer.Stop()
	c.httpServer.Stop()

	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()

	if c.chWorking == nil {
		err = errors.New(xchg.ERR_XCHG_ROUTER_IS_NOT_STARTED)
		logger.Println("[ERROR]", "Router::Stop", err.Error())
		return
	}

	logger.Println("[i]", "Router::Stop", "stopping")
	close(c.chWorking)
	logger.Println("[i]", "Router::Stop", "waiting")

	for i := 0; i < 100; i++ {
		if c.chWorking == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c.chWorking != nil {
		logger.Println("[ERROR]", "Router::Stop", "waiting TIMEOUT")
	} else {
		logger.Println("[i]", "Router::Stop", "waiting OK")
	}

	logger.Println("[i]", "Router::Stop", "closing incoming connections")
	for _, conn := range c.connectionsById {
		conn.Stop()
	}

	c.init()

	logger.Println("[i]", "Router::Stop", "end")
	return
}

func (c *Router) LocalPublicKeyBS() []byte {
	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()
	return c.localPublicKeyBS
}

func (c *Router) AddConnection(conn net.Conn) {
	atomic.AddUint64(&c.performanceCounters.ServerAcceptCounter, 1)
	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()
	if c.chWorking == nil {
		return
	}

	connection := NewRouterConnection(conn, c, c.localPrivateKey, &c.performanceCounters.ConnectionsPerformanceCounters)
	connId := c.nextConnectionId
	c.nextConnectionId++
	connection.id = connId
	c.connectionsById[connection.id] = connection
	connection.Start()
}

func (c *Router) getConnectionByAddress(address string) (foundConnection *RouterConnection) {
	if len(address) != xchg.AddressSize {
		return
	}
	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()
	if c.chWorking == nil {
		return
	}
	conn, ok := c.connectionsByAddress[address]
	if ok {
		foundConnection = conn
	}
	return
}

func (c *Router) getConnectionById(connectionId uint64) (result *RouterConnection) {
	c.mtxRouter.Lock()
	if c.chWorking == nil {
		c.mtxRouter.Unlock()
		return
	}
	conn, ok := c.connectionsById[connectionId]
	c.mtxRouter.Unlock()
	if ok {
		result = conn
	}
	return
}

func (c *Router) getConnectionCount() int {
	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()
	if c.chWorking == nil {
		return 0
	}
	count := len(c.connectionsById)
	return count
}

func (c *Router) setAddressForConnection(connection *RouterConnection, address string) {
	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()
	if c.chWorking == nil {
		return
	}
	if len(address) != xchg.AddressSize {
		return
	}
	c.connectionsByAddress[address] = connection
}

func (c *Router) updatePerformance() {
	now := time.Now()
	if now.Sub(c.performanceLastDT) < 900*time.Millisecond {
		return
	}

	c.mtxPerformance.Lock()
	defer c.mtxPerformance.Unlock()
	durationSec := now.Sub(c.performanceLastDT).Seconds()
	var counters RouterPerformanceCounters

	counters.HttpRequestsCounter = atomic.LoadUint64(&c.performanceCounters.HttpRequestsCounter)
	counters.HttpGetStateCounter = atomic.LoadUint64(&c.performanceCounters.HttpGetStateCounter)
	counters.HttpGetPerfCounter = atomic.LoadUint64(&c.performanceCounters.HttpGetPerfCounter)
	counters.ServerAcceptCounter = atomic.LoadUint64(&c.performanceCounters.ServerAcceptCounter)
	counters.ConnectionsPerformanceCounters.InTrafficCounter = atomic.LoadUint64(&c.performanceCounters.ConnectionsPerformanceCounters.InTrafficCounter)
	counters.ConnectionsPerformanceCounters.OutTrafficCounter = atomic.LoadUint64(&c.performanceCounters.ConnectionsPerformanceCounters.OutTrafficCounter)
	counters.ConnectionsPerformanceCounters.Init1Counter = atomic.LoadUint64(&c.performanceCounters.ConnectionsPerformanceCounters.Init1Counter)
	counters.ConnectionsPerformanceCounters.Init4Counter = atomic.LoadUint64(&c.performanceCounters.ConnectionsPerformanceCounters.Init4Counter)
	counters.ConnectionsPerformanceCounters.Init5Counter = atomic.LoadUint64(&c.performanceCounters.ConnectionsPerformanceCounters.Init5Counter)

	c.performance.HttpRequestsRate = uint64(math.Round(float64(counters.HttpRequestsCounter-c.performanceLastCounters.HttpRequestsCounter) / durationSec))
	c.performance.HttpGetStateRate = uint64(math.Round(float64(counters.HttpGetStateCounter-c.performanceLastCounters.HttpGetStateCounter) / durationSec))
	c.performance.HttpGetPerfRate = uint64(math.Round(float64(counters.HttpGetPerfCounter-c.performanceLastCounters.HttpGetPerfCounter) / durationSec))
	c.performance.ServerAcceptRate = uint64(math.Round(float64(counters.ServerAcceptCounter-c.performanceLastCounters.ServerAcceptCounter) / durationSec))
	c.performance.ServerInTrafficRate = uint64(math.Round(float64(counters.ConnectionsPerformanceCounters.InTrafficCounter-c.performanceLastCounters.ConnectionsPerformanceCounters.InTrafficCounter) / durationSec))
	c.performance.ServerOutTrafficRate = uint64(math.Round(float64(counters.ConnectionsPerformanceCounters.OutTrafficCounter-c.performanceLastCounters.ConnectionsPerformanceCounters.OutTrafficCounter) / durationSec))
	c.performance.Init1Rate = uint64(math.Round(float64(counters.ConnectionsPerformanceCounters.Init1Counter-c.performanceLastCounters.ConnectionsPerformanceCounters.Init1Counter) / durationSec))
	c.performance.Init4Rate = uint64(math.Round(float64(counters.ConnectionsPerformanceCounters.Init4Counter-c.performanceLastCounters.ConnectionsPerformanceCounters.Init4Counter) / durationSec))
	c.performance.Init5Rate = uint64(math.Round(float64(counters.ConnectionsPerformanceCounters.Init5Counter-c.performanceLastCounters.ConnectionsPerformanceCounters.Init5Counter) / durationSec))

	c.performanceLastCounters = counters
	c.performanceLastDT = now
}

func (c *Router) thWorker() {
	logger.Println("[i]", "Router::thWorker", "begin")
	ticker := time.NewTicker(1000 * time.Millisecond)
	working := true
	for working {
		select {
		case <-c.chWorking:
			working = false
		case <-ticker.C:
		}

		if working {
			c.updatePerformance()

			c.mtxRouter.Lock()
			now := time.Now()
			for id, conn := range c.connectionsById {
				if conn.IsClosed() {
					connByAddr, connByAddrFound := c.connectionsByAddress[conn.ConfirmedRemoteAddress()]
					if connByAddrFound {
						if connByAddr.id == conn.id {
							delete(c.connectionsByAddress, conn.ConfirmedRemoteAddress())
						}
					}

					delete(c.connectionsById, id)
				}

				if now.Sub(conn.createdDT) > 3*time.Second && len(conn.ConfirmedRemoteAddress()) == 0 {
					conn.Stop()
				}
			}
			c.mtxRouter.Unlock()
		}
	}
	logger.Println("[i]", "Router::thWorker", "end")
	c.chWorking = nil
}

func (c *Router) State() (state RouterState) {
	atomic.AddUint64(&c.performanceCounters.HttpGetStateCounter, 1)
	return
}

func (c *Router) Performance() (state RouterPerformance) {
	atomic.AddUint64(&c.performanceCounters.HttpGetPerfCounter, 1)
	c.mtxPerformance.Lock()
	defer c.mtxPerformance.Unlock()
	state = c.performance
	return
}

func (c *Router) AddHttpRequestsCounter() {
	atomic.AddUint64(&c.performanceCounters.HttpRequestsCounter, 1)
}
