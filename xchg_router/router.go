package xchg_router

import (
	"crypto/rsa"
	"errors"
	"net"
	"sort"
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

	nextTransactionId uint64
	transactions      map[uint64]*xchg.Transaction

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

	statStateCounter                                 uint64
	statAddConnectionCounter                         uint64
	statGetConnectionByAddressCounter                uint64
	statGetConnectionByAddressErrAddressSizeCounter  uint64
	statGetConnectionByAddressFoundCounter           uint64
	statGetConnectionByAddressNotFoundCounter        uint64
	statGetConnectionByIdCounter                     uint64
	statGetConnectionByIdFoundCounter                uint64
	statGetConnectionByIdNotFoundCounter             uint64
	statSetAddressForConnectionCounter               uint64
	statSetAddressForConnectionErrAddressSizeCounter uint64
	statBeginTransactionCounter                      uint64
	statSetResponseCounter                           uint64
	statSetResponseErrNoTransactionCounter           uint64
	statWorkerCounter                                uint64
	statWorkerRemoveConnectionCounter                uint64
	statWorkerRemoveTransactionCounter               uint64
	statWorkerStopConnectionByInitTimeoutCounter     uint64

	chWorking chan interface{}
}

type RouterState struct {
	NextConnectionId          uint64 `json:"next_connection_id"`
	NextTransactionId         uint64 `json:"next_transaction_id"`
	ConnectionsCount          int    `json:"connections_count"`
	ConnectionsByAddressCount int    `json:"connections_by_address_count"`
	TransactionsCount         int    `json:"transactions_count"`

	Server RouterServerState `json:"server"`

	StatStateCounter                                 uint64 `json:"stat_state_counter"`
	StatAddConnectionCounter                         uint64 `json:"stat_add_connection_counter"`
	StatGetConnectionByAddressCounter                uint64 `json:"stat_get_connection_by_address_counter"`
	StatGetConnectionByAddressErrAddressSizeCounter  uint64 `json:"stat_get_connection_by_address_err_addr_size_counter"`
	StatGetConnectionByAddressFoundCounter           uint64 `json:"stat_get_connection_by_address_found_counter"`
	StatGetConnectionByAddressNotFoundCounter        uint64 `json:"stat_get_connection_by_address_not_found_counter"`
	StatGetConnectionByIdCounter                     uint64 `json:"stat_get_connection_by_id_counter"`
	StatGetConnectionByIdFoundCounter                uint64 `json:"stat_get_connection_by_id_found_counter"`
	StatGetConnectionByIdNotFoundCounter             uint64 `json:"stat_get_connection_by_id_not_found_counter"`
	StatSetAddressForConnectionCounter               uint64 `json:"stat_set_address_for_connection_counter"`
	StatSetAddressForConnectionErrAddressSizeCounter uint64 `json:"stat_set_address_for_connection_err_addr_size_counter"`
	StatBeginTransactionCounter                      uint64 `json:"stat_begin_transaction_counter"`
	StatSetResponseCounter                           uint64 `json:"stat_set_response_counter"`
	StatSetResponseErrNoTransactionCounter           uint64 `json:"stat_set_response_err_no_transaction_counter"`
	StatWorkerCounter                                uint64 `json:"stat_worker_counter"`
	StatWorkerRemoveConnectionCounter                uint64 `json:"stat_worker_remove_connection_counter"`
	StatWorkerRemoveTransactionCounter               uint64 `json:"stat_worker_remove_transaction_counter"`
	StatWorkerStopConnectionByInitTimeoutCounter     uint64 `json:"stat_worker_stop_connection_by_init_timeout_counter"`

	Connections  []RouterConnectionState `json:"connections"`
	Transactions []string                `json:"transactions"`
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

	c.nextTransactionId = 1
	c.transactions = make(map[uint64]*xchg.Transaction)
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
	atomic.AddUint64(&c.statAddConnectionCounter, 1)
	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()
	if c.chWorking == nil {
		return
	}

	connection := NewRouterConnection(conn, c, c.localPrivateKey)
	connId := c.nextConnectionId
	c.nextConnectionId++
	connection.id = connId
	c.connectionsById[connection.id] = connection
	connection.Start()
}

func (c *Router) getConnectionByAddress(address string) (foundConnection *RouterConnection) {
	atomic.AddUint64(&c.statGetConnectionByAddressCounter, 1)
	if len(address) != xchg.AddressSize {
		atomic.AddUint64(&c.statGetConnectionByAddressErrAddressSizeCounter, 1)
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
		atomic.AddUint64(&c.statGetConnectionByAddressFoundCounter, 1)
	} else {
		atomic.AddUint64(&c.statGetConnectionByAddressNotFoundCounter, 1)
	}
	return
}

func (c *Router) getConnectionById(connectionId uint64) (result *RouterConnection) {
	atomic.AddUint64(&c.statGetConnectionByIdCounter, 1)
	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()
	if c.chWorking == nil {
		return
	}
	conn, ok := c.connectionsById[connectionId]
	if ok {
		atomic.AddUint64(&c.statGetConnectionByIdFoundCounter, 1)
		result = conn
	} else {
		atomic.AddUint64(&c.statGetConnectionByIdNotFoundCounter, 1)
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
	atomic.AddUint64(&c.statSetAddressForConnectionCounter, 1)
	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()
	if c.chWorking == nil {
		return
	}
	if len(address) != xchg.AddressSize {
		atomic.AddUint64(&c.statSetAddressForConnectionErrAddressSizeCounter, 1)
		return
	}
	c.connectionsByAddress[address] = connection
}

func (c *Router) beginTransaction(transaction *xchg.Transaction) {
	atomic.AddUint64(&c.statBeginTransactionCounter, 1)
	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()
	if c.chWorking == nil {
		return
	}
	innerTransactionId := c.nextTransactionId
	c.nextTransactionId++
	transaction.OriginalTransactionId = transaction.TransactionId
	transaction.TransactionId = innerTransactionId
	transaction.BeginDT = time.Now()
	c.transactions[innerTransactionId] = transaction
	return
}

func (c *Router) SetResponse(transaction *xchg.Transaction) {
	atomic.AddUint64(&c.statSetResponseCounter, 1)
	c.mtxRouter.Lock()
	if c.chWorking == nil {
		c.mtxRouter.Unlock()
		return
	}
	originalTransaction, ok := c.transactions[transaction.TransactionId]
	if !ok || originalTransaction == nil {
		atomic.AddUint64(&c.statSetResponseErrNoTransactionCounter, 1)
		c.mtxRouter.Unlock()
		return
	}
	delete(c.transactions, transaction.TransactionId)
	c.mtxRouter.Unlock()

	transaction.TransactionId = originalTransaction.OriginalTransactionId
	originalTransaction.ResponseSender.Send(xchg.NewTransaction(xchg.FrameResponse, 0, transaction.TransactionId, originalTransaction.SessionId, transaction.Data))
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
			atomic.AddUint64(&c.statWorkerCounter, 1)
			c.mtxRouter.Lock()
			now := time.Now()
			for id, conn := range c.connectionsById {
				if conn.IsClosed() {
					atomic.AddUint64(&c.statWorkerRemoveConnectionCounter, 1)
					delete(c.connectionsByAddress, conn.ConfirmedRemoteAddress())
					delete(c.connectionsById, id)
				}

				if now.Sub(conn.createdDT) > 3*time.Second && len(conn.ConfirmedRemoteAddress()) == 0 {
					atomic.AddUint64(&c.statWorkerStopConnectionByInitTimeoutCounter, 1)
					conn.Stop()
				}
			}
			for key, t := range c.transactions {
				duration := now.Sub(t.BeginDT)
				if duration > 3*time.Second {
					atomic.AddUint64(&c.statWorkerRemoveTransactionCounter, 1)
					delete(c.transactions, key)
				}
			}
			c.mtxRouter.Unlock()
		}
	}
	logger.Println("[i]", "Router::thWorker", "end")
	c.chWorking = nil
}

func (c *Router) State() (state RouterState) {
	atomic.AddUint64(&c.statStateCounter, 1)
	c.mtxRouter.Lock()
	state.NextConnectionId = c.nextConnectionId
	state.NextTransactionId = c.nextTransactionId

	state.ConnectionsCount = len(c.connectionsById)
	state.ConnectionsByAddressCount = len(c.connectionsByAddress)
	state.Connections = make([]RouterConnectionState, 0, len(c.connectionsById))
	state.Transactions = make([]string, 0, len(c.transactions))
	connections := make([]*RouterConnection, 0, len(c.connectionsById))
	for _, conn := range c.connectionsById {
		connections = append(connections, conn)
	}
	state.TransactionsCount = len(c.transactions)
	transactions := make([]*xchg.Transaction, 0, len(c.transactions))
	for _, t := range c.transactions {
		transactions = append(transactions, t)
	}
	routerServer := c.routerServer
	c.mtxRouter.Unlock()

	for _, conn := range connections {
		state.Connections = append(state.Connections, conn.State())
	}
	sort.Slice(state.Connections, func(i, j int) bool {
		return state.Connections[i].Id < state.Connections[j].Id
	})

	sort.Slice(transactions, func(i, j int) bool {
		return transactions[i].TransactionId < transactions[j].TransactionId
	})

	for _, t := range transactions {
		state.Transactions = append(state.Transactions, t.String())
	}
	state.Server = routerServer.State()

	state.StatStateCounter = atomic.LoadUint64(&c.statStateCounter)
	state.StatAddConnectionCounter = atomic.LoadUint64(&c.statAddConnectionCounter)
	state.StatGetConnectionByAddressCounter = atomic.LoadUint64(&c.statGetConnectionByAddressCounter)
	state.StatGetConnectionByAddressErrAddressSizeCounter = atomic.LoadUint64(&c.statGetConnectionByAddressErrAddressSizeCounter)
	state.StatGetConnectionByAddressFoundCounter = atomic.LoadUint64(&c.statGetConnectionByAddressFoundCounter)
	state.StatGetConnectionByAddressNotFoundCounter = atomic.LoadUint64(&c.statGetConnectionByAddressNotFoundCounter)
	state.StatGetConnectionByIdCounter = atomic.LoadUint64(&c.statGetConnectionByIdCounter)
	state.StatGetConnectionByIdFoundCounter = atomic.LoadUint64(&c.statGetConnectionByIdFoundCounter)
	state.StatGetConnectionByIdNotFoundCounter = atomic.LoadUint64(&c.statGetConnectionByIdNotFoundCounter)
	state.StatSetAddressForConnectionCounter = atomic.LoadUint64(&c.statSetAddressForConnectionCounter)
	state.StatSetAddressForConnectionErrAddressSizeCounter = atomic.LoadUint64(&c.statSetAddressForConnectionErrAddressSizeCounter)
	state.StatBeginTransactionCounter = atomic.LoadUint64(&c.statBeginTransactionCounter)
	state.StatSetResponseCounter = atomic.LoadUint64(&c.statSetResponseCounter)
	state.StatSetResponseErrNoTransactionCounter = atomic.LoadUint64(&c.statSetResponseErrNoTransactionCounter)
	state.StatWorkerCounter = atomic.LoadUint64(&c.statWorkerCounter)
	state.StatWorkerRemoveConnectionCounter = atomic.LoadUint64(&c.statWorkerRemoveConnectionCounter)
	state.StatWorkerRemoveTransactionCounter = atomic.LoadUint64(&c.statWorkerRemoveTransactionCounter)
	state.StatWorkerStopConnectionByInitTimeoutCounter = atomic.LoadUint64(&c.statWorkerStopConnectionByInitTimeoutCounter)

	return
}
