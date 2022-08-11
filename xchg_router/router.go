package xchg_router

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/gomisc/logger"
	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_network"
)

type Router struct {
	mtxRouter sync.Mutex

	nextConnectionId     uint64
	connections          []*RouterConnection
	connectionsByAddress map[string]*RouterConnection
	connectionsById      map[uint64]*RouterConnection

	nextTransactionId uint64
	transactions      map[uint64]*xchg.Transaction

	config RouterConfig

	// Local Address
	localAddress           *rsa.PublicKey
	localAddressBS         []byte
	localAddress64         string
	localAddressHex        string
	localAddressPrivate    *rsa.PrivateKey
	localAddressPrivateBS  []byte
	localAddressPrivate64  string
	localAddressPrivateHex string

	httpServer   *HttpServer
	routerServer *RouterServer
	network      *xchg_network.Network

	chWorking chan interface{}
}

func NewRouter(localAddress *rsa.PrivateKey, config RouterConfig, network *xchg_network.Network) *Router {
	var c Router

	if localAddress != nil {
		c.localAddressPrivate = localAddress
		c.localAddressPrivateBS = crypt_tools.RSAPrivateKeyToDer(localAddress)
		c.localAddressPrivate64 = crypt_tools.RSAPrivateKeyToBase64(localAddress)
		c.localAddressPrivateHex = crypt_tools.RSAPrivateKeyToHex(localAddress)
		c.localAddressBS = crypt_tools.RSAPublicKeyToDer(&localAddress.PublicKey)
		c.localAddress64 = crypt_tools.RSAPublicKeyToBase64(&localAddress.PublicKey)
		c.localAddressHex = crypt_tools.RSAPublicKeyToHex(&localAddress.PublicKey)
	}
	c.network = network

	c.init()
	c.routerServer = NewRouterServer(config.BinServerPort, &c)
	c.httpServer = NewHttpServer(config.HttpServerPort, &c)
	return &c
}

func (c *Router) init() {
	c.nextConnectionId = 1
	c.connections = make([]*RouterConnection, 0)
	c.connectionsByAddress = make(map[string]*RouterConnection)
	c.connectionsById = make(map[uint64]*RouterConnection)

	c.nextTransactionId = 1
	c.transactions = make(map[uint64]*xchg.Transaction)
}

func (c *Router) Start() (err error) {
	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()

	if c.chWorking != nil {
		err = errors.New("router is already started")
		logger.Println(err)
		return
	}

	c.init()

	c.chWorking = make(chan interface{})

	go c.thWorker()

	logger.Println("router started")
	c.httpServer.Start()
	c.routerServer.Start()
	return
}

func (c *Router) Stop() (err error) {
	c.routerServer.Stop()
	c.httpServer.Stop()

	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()

	if c.chWorking == nil {
		err = errors.New("router is not started")
		logger.Println(err)
		return
	}

	logger.Println("router stopping")
	close(c.chWorking)
	logger.Println("router stopping - waiting")

	for i := 0; i < 100; i++ {
		if c.chWorking == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c.chWorking != nil {
		logger.Println("router stopping - timeout")
	} else {
		logger.Println("router stopping - waiting - ok")
	}

	logger.Println("router stopping - closing incoming connections")
	for _, conn := range c.connections {
		conn.Stop()
	}

	c.init()

	logger.Println("router stopped")
	return
}

func (c *Router) LocalAddressBS() []byte {
	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()
	return c.localAddressBS
}

func (c *Router) AddConnection(conn net.Conn) {
	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()
	if c.chWorking == nil {
		return
	}

	connection := NewRouterConnection(conn, c, c.localAddressPrivate)
	connId := c.nextConnectionId
	c.nextConnectionId++
	connection.id = connId
	c.connections = append(c.connections, connection)
	c.connectionsById[connection.id] = connection
	connection.Start()
}

func (c *Router) getConnectionByAddress(address []byte) (foundConnection *RouterConnection) {
	if len(address) < 1 || len(address) > 1024 {
		return
	}
	addr58 := base58.Encode(address)

	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()
	if c.chWorking == nil {
		return
	}
	conn, ok := c.connectionsByAddress[addr58]
	if ok {
		foundConnection = conn
	}
	return
}

func (c *Router) getConnectionById(connectionId uint64) (result *RouterConnection) {
	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()
	if c.chWorking == nil {
		return
	}
	conn, ok := c.connectionsById[connectionId]
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
	count := len(c.connections)
	return count
}

func (c *Router) setAddressForConnection(connection *RouterConnection, address58 string) {
	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()
	if c.chWorking == nil {
		return
	}
	if len(address58) == 0 {
		return
	}
	c.connectionsByAddress[address58] = connection
}

func (c *Router) beginTransaction(transaction *xchg.Transaction) (err error) {
	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()
	if c.chWorking == nil {
		return
	}
	innerTransactionId := c.nextConnectionId
	c.nextConnectionId++
	transaction.OriginalTransactionId = transaction.TransactionId
	transaction.TransactionId = innerTransactionId
	c.transactions[innerTransactionId] = transaction
	return
}

func (c *Router) sendTransactionToConnection(transaction *xchg.Transaction) (err error) {
	connection := c.getConnectionById(transaction.TransactionId)
	if connection == nil {
		err = errors.New("connection not found")
		return
	}
	connection.Send(transaction)
	return
}

func (c *Router) SetResponse(transaction *xchg.Transaction) {
	c.mtxRouter.Lock()
	if c.chWorking == nil {
		c.mtxRouter.Unlock()
		return
	}
	originalTransaction, ok := c.transactions[transaction.TransactionId]
	if !ok || originalTransaction == nil {
		c.mtxRouter.Unlock()
		return
	}
	c.mtxRouter.Unlock()

	transaction.TransactionId = originalTransaction.OriginalTransactionId
	originalTransaction.ResponseSender.Send(xchg.NewTransaction(xchg.FrameResponse, 0, transaction.TransactionId, originalTransaction.SessionId, transaction.Data))
}

func (c *Router) thWorker() {
	logger.Println("router", "th_worker", "started")
	ticker := time.NewTicker(1000 * time.Millisecond)
	working := true
	for working {
		select {
		case <-c.chWorking:
			working = false
		case <-ticker.C:
		}

		if working {
			c.mtxRouter.Lock()
			for i, conn := range c.connections {
				if conn.IsClosed() {
					c.connections = append(c.connections[:i], c.connections[i+1:]...)
					delete(c.connectionsByAddress, conn.ConfirmedRemoteAddress())
					delete(c.connectionsById, conn.id)
					break
				}
			}
			c.mtxRouter.Unlock()
		}
	}
	logger.Println("router", "th_worker", "stopped")
	c.chWorking = nil
}

func (c *Router) DebugInfo() (result string) {
	type StatResult struct {
		NextConnectionId          uint64
		ConnectionsCount          int
		ConnectionsByAddressCount int
		ConnectionsByIdCount      int

		NextTransactionId    uint64
		TransactionsCount    int
		Connections          []*RouterConnection
		ConnectionsByAddress map[string]*RouterConnection
		ConnectionsById      map[uint64]*RouterConnection
		Transactions         map[uint64]*xchg.Transaction
	}

	c.mtxRouter.Lock()
	defer c.mtxRouter.Unlock()

	var r StatResult
	r.NextConnectionId = c.nextConnectionId
	r.ConnectionsCount = len(c.connections)
	r.ConnectionsByAddressCount = len(c.connectionsByAddress)
	r.ConnectionsByIdCount = len(c.connectionsById)
	r.NextTransactionId = c.nextTransactionId
	r.TransactionsCount = len(c.transactions)

	r.Connections = c.connections
	r.ConnectionsByAddress = c.connectionsByAddress
	r.ConnectionsById = c.connectionsById
	r.Transactions = c.transactions

	bs, _ := json.MarshalIndent(r, "", " ")
	result = string(bs)

	return
}
