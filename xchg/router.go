package xchg

import (
	"errors"
	"net"
	"sync"
	"time"

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

func NewRouter() *Router {
	var c Router
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
	logger.Println("router stopped")
	return
}

func (c *Router) AddConnection(conn net.Conn) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.chWorking == nil {
		return
	}

	connection := NewRouterConnection(conn, c)
	connId := c.nextConnectionId
	c.nextConnectionId++
	connection.id = connId
	c.connections = append(c.connections, connection)
	c.connectionsById[connection.id] = connection
	connection.Start()
}

func (c *Router) getConnectionByAddress(address []byte) (result *RouterConnection) {
	if len(address) < 1 || len(address) < 1024 {
		return
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.chWorking == nil {
		return
	}

	conn, ok := c.connectionsByAddress[string(address)]
	if !ok {
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
	if !ok {
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

	address := connection.address()
	if len(address) == 0 {
		return
	}

	c.connectionsByAddress[string(address)] = connection
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
	originalTransaction.connection.send(transaction)
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
			logger.Println("router", "th_worker", "process")
			found := true
			for found {
				found = false
				for i, conn := range c.connections {
					if conn.closed {
						found = true
						c.connections = append(c.connections[:i], c.connections[i+1:]...)
						break
					}
				}
			}
			c.mtx.Unlock()
		}
	}
	logger.Println("router", "th_worker", "stopped")
	c.chWorking = nil
}
