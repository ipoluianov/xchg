package xchg

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
)

type Router struct {
	mtx sync.Mutex

	nextConnectionId     uint64
	connections          []*RouterConnection
	connectionsByAddress map[string]*RouterConnection
	connectionsById      map[uint64]*RouterConnection

	nextTransactionId uint64
	transactions      map[uint64]*Transaction

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

	chWorking chan interface{}
}

type RouterConfig struct {
	MaxConnectionCount      int `json:"max_connection_count"`
	MaxConnectionCountPerIP int `json:"max_connection_count_per_ip"`
}

func (c *RouterConfig) Init() {
	c.MaxConnectionCount = 1000
	c.MaxConnectionCountPerIP = 10
}

func (c *RouterConfig) Check() (err error) {
	if c.MaxConnectionCount < 1 || c.MaxConnectionCount > 100000 {
		err = errors.New("wrong Server.RouterServer")
	}
	if c.MaxConnectionCountPerIP < 1 || c.MaxConnectionCountPerIP > 1024*1024 {
		err = errors.New("wrong Server.MaxConnectionCountPerIP")
	}
	return
}

func (c *RouterConfig) Log() {
	logger.Println("router starting")
	logger.Println("router config", "MaxConnectionCount =", c.MaxConnectionCount)
	logger.Println("router config", "MaxConnectionCountPerIP =", c.MaxConnectionCountPerIP)
}

func NewRouter(localAddress *rsa.PrivateKey) *Router {
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

	c.Init()
	return &c
}

func (c *Router) Init() {
	c.nextConnectionId = 1
	c.connections = make([]*RouterConnection, 0)
	c.connectionsByAddress = make(map[string]*RouterConnection)
	c.connectionsById = make(map[uint64]*RouterConnection)

	c.nextTransactionId = 1
	c.transactions = make(map[uint64]*Transaction)
}

func (c *Router) Start() (err error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.chWorking != nil {
		err = errors.New("router is already started")
		logger.Println(err)
		return
	}

	c.Init()

	c.config.Log()

	c.chWorking = make(chan interface{})

	go c.thWorker()

	logger.Println("router started")
	return
}

func (c *Router) Stop() (err error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

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

	c.Init()

	logger.Println("router stopped")
	return
}

func (c *Router) LocalAddressBS() []byte {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.localAddressBS
}

func (c *Router) AddConnection(conn net.Conn) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
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

func (c *Router) getConnectionByAddress(address []byte) (result *RouterConnection) {
	if len(address) < 1 || len(address) > 1024 {
		return
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.chWorking == nil {
		return
	}

	addr58 := base58.Encode(address)
	conn, ok := c.connectionsByAddress[addr58]
	if ok {
		result = conn
	}
	return
}

func (c *Router) getConnectionById(connectionId uint64) (result *RouterConnection) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
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
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.chWorking == nil {
		return 0
	}

	count := len(c.connections)
	return count
}

func (c *Router) setAddressForConnection(connection *RouterConnection) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.chWorking == nil {
		return
	}

	address := connection.address58()
	if len(address) == 0 {
		return
	}

	c.connectionsByAddress[string(address)] = connection
	//fmt.Println("Router - setAddressForConnection")
}

func (c *Router) beginTransaction(transaction *Transaction) (err error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.chWorking == nil {
		return
	}

	innerTransactionId := c.nextConnectionId
	c.nextConnectionId++
	transaction.standbyTransactionId = transaction.transactionId
	transaction.transactionId = innerTransactionId
	c.transactions[innerTransactionId] = transaction
	return
}

func (c *Router) sendTransactionToConnection(transaction *Transaction) (err error) {
	connection := c.getConnectionById(transaction.transactionId)
	if connection == nil {
		err = errors.New("connection not found")
		return
	}
	connection.send(transaction)
	return
}

func (c *Router) SetResponse(transaction *Transaction) {
	c.mtx.Lock()
	if c.chWorking == nil {
		c.mtx.Unlock()
		return
	}

	originalTransaction, ok := c.transactions[transaction.transactionId]
	if !ok || originalTransaction == nil {
		c.mtx.Unlock()
		return
	}

	c.mtx.Unlock()

	transaction.transactionId = originalTransaction.standbyTransactionId
	originalTransaction.connection.send(NewTransaction(FrameResponse, 0, 0, transaction.transactionId, 0, transaction.data))
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
			c.mtx.Lock()
			for i, conn := range c.connections {
				if conn.closed {
					c.connections = append(c.connections[:i], c.connections[i+1:]...)
					delete(c.connectionsByAddress, conn.address58())
					delete(c.connectionsById, conn.id)
					break
				}
			}
			c.mtx.Unlock()
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
		Transactions         map[uint64]*Transaction
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

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
