package xchg

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/ipoluianov/gomisc/logger"
)

type RouterServer struct {
	mtx       sync.Mutex
	listener  net.Listener
	router    *Router
	chWorking chan interface{}
	config    RouterServerConfig
}

type RouterServerConfig struct {
	MaxConnectionCount      int `json:"max_connection_count"`
	MaxConnectionCountPerIP int `json:"max_connection_count_per_ip"`
}

func (c *RouterServerConfig) Init() {
	c.MaxConnectionCount = 1000
	c.MaxConnectionCountPerIP = 10
}

func (c *RouterServerConfig) Check() (err error) {
	if c.MaxConnectionCount < 1 || c.MaxConnectionCount > 100000 {
		err = errors.New("wrong Server.RouterServer")
	}
	if c.MaxConnectionCountPerIP < 1 || c.MaxConnectionCountPerIP > 1024*1024 {
		err = errors.New("wrong Server.MaxConnectionCountPerIP")
	}
	return
}

func (c *RouterServerConfig) Log() {
	logger.Println("router_server starting")
	logger.Println("router_server config", "MaxConnectionCount =", c.MaxConnectionCount)
	logger.Println("router_server config", "MaxConnectionCountPerIP =", c.MaxConnectionCountPerIP)
}

func NewRouterServer(conf Config, router *Router) *RouterServer {
	var c RouterServer
	c.config = conf.RouterServer
	c.router = router
	return &c
}

func (c *RouterServer) Start() (err error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.chWorking != nil {
		err = errors.New("router_server is already started")
		logger.Println(err)
		return
	}

	c.config.Log()

	c.chWorking = make(chan interface{})

	go c.thListen()

	logger.Println("router_server started")
	return
}

func (c *RouterServer) Stop() (err error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.chWorking == nil {
		err = errors.New("router_server is not started")
		logger.Println(err)
		return
	}

	logger.Println("router_server stopping")
	close(c.chWorking)
	c.listener.Close()
	logger.Println("router_server stopping - waiting")

	for i := 0; i < 100; i++ {
		if c.chWorking == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c.chWorking != nil {
		logger.Println("router_server stopping - timeout")
	} else {
		logger.Println("router_server stopping - waiting - ok")
	}
	logger.Println("router_server stopped")
	return
}

func (c *RouterServer) thListen() {
	logger.Println("router_server_th started")
	var err error
	c.listener, err = net.Listen("tcp", ":8484")
	if err != nil {
		logger.Println("router_server_th listen error", err)
	} else {
		var conn net.Conn
		working := true
		for working {
			conn, err = c.listener.Accept()
			if err != nil {
				select {
				case <-c.chWorking:
					working = false
					break
				default:
					logger.Println("router_server_th accept error", err)
				}
			} else {
				c.router.AddConnection(conn)
			}
			if !working {
				break
			}
		}
	}
	logger.Println("router_server_th stopped")
	c.chWorking = nil
}
