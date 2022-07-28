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

	connections          []*RouterConnection
	connectionsByAddress map[string]*RouterConnection
	connectionsById      map[uint64]*RouterConnection
	nextConnectionId     uint64

	transactions      map[uint64]*Transaction
	nextTransactionId uint64
	mtxTransactions   sync.Mutex

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
	c.connections = make([]*RouterConnection, 0)
	c.connectionsByAddress = make(map[string]*RouterConnection)
	c.connectionsById = make(map[uint64]*RouterConnection)
	c.nextConnectionId = 1
	c.transactions = make(map[uint64]*Transaction)
	c.nextTransactionId = 1
	return &c
}

func (c *Router) Start() (err error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.chWorking != nil {
		err = errors.New("router is already started")
		logger.Println(err)
		return
	}

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
	logger.Println("router stopped")
	return
}

func (c *Router) AddConnection(conn net.Conn) {
	connection := NewRouterConnection(conn, c)
	c.mtx.Lock()
	connId := c.nextConnectionId
	c.nextConnectionId++
	connection.id = connId
	c.connections = append(c.connections, connection)
	c.connectionsById[connection.id] = connection
	c.mtx.Unlock()
	connection.Start()
}

func (c *Router) getConnectionByAddress(address []byte) (result *RouterConnection) {
	if len(address) < 1 || len(address) < 1024 {
		return
	}

	c.mtx.Lock()
	conn, ok := c.connectionsByAddress[string(address)]
	c.mtx.Unlock()
	if !ok {
		result = conn
	}
	return
}

func (c *Router) getConnectionById(connectionId uint64) (result *RouterConnection) {
	c.mtx.Lock()
	conn, ok := c.connectionsById[connectionId]
	c.mtx.Unlock()
	if !ok {
		result = conn
	}
	return
}

func (c *Router) getConnectionCount() int {
	c.mtx.Lock()
	count := len(c.connections)
	c.mtx.Unlock()
	return count
}

func (c *Router) setAddressForConnection(connection *RouterConnection) {
	address := connection.address()
	if len(address) == 0 {
		return
	}
	c.mtx.Lock()
	c.connectionsByAddress[string(address)] = connection
	c.mtx.Unlock()
}

func (c *Router) beginTransaction(transaction *Transaction) (err error) {
	c.mtxTransactions.Lock()
	innerTransactionId := c.nextConnectionId
	c.nextConnectionId++
	transaction.standbyTransactionId = transaction.transactionId
	transaction.transactionId = innerTransactionId
	c.transactions[innerTransactionId] = transaction
	c.mtxTransactions.Unlock()
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
	c.mtxTransactions.Lock()
	originalTransaction, ok := c.transactions[transaction.transactionId]
	c.mtxTransactions.Unlock()
	if !ok || originalTransaction == nil {
		return
	}
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

		if !working {
			break
		}

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
	logger.Println("router", "th_worker", "stopped")
	c.chWorking = nil
}
