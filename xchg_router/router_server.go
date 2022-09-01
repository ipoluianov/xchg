package xchg_router

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ipoluianov/gomisc/logger"
	"github.com/ipoluianov/xchg/xchg"
)

type RouterServer struct {
	mtx         sync.Mutex
	listener    net.Listener
	listenerUDP *net.UDPConn
	router      *Router
	port        int
	chWorking   chan interface{}
}

func NewRouterServer(port int, router *Router) *RouterServer {
	var c RouterServer
	c.port = port
	c.router = router
	return &c
}

func (c *RouterServer) Start() (err error) {
	logger.Println("[i]", "RouterServer::Start", "begin")
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.chWorking != nil {
		err = errors.New(xchg.ERR_XCHG_ROUTER_SERVER_ALREADY_STARTED)
		logger.Println("[ERROR]", "RouterServer::Start", err.Error())
		return
	}

	c.chWorking = make(chan interface{})

	go c.thListen()
	go c.thListenUDP()

	logger.Println("[i]", "RouterServer::Start", "end")
	return
}

func (c *RouterServer) Stop() (err error) {
	logger.Println("[i]", "RouterServer::Stop", "begin")
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.chWorking == nil {
		err = errors.New(xchg.ERR_XCHG_ROUTER_SERVER_IS_NOT_STARTED)
		logger.Println("[ERROR]", "RouterServer::Stop", err.Error())
		return
	}

	logger.Println("[i]", "RouterServer::Stop", "stopping")
	close(c.chWorking)
	c.listener.Close()
	logger.Println("[i]", "RouterServer::Stop", "waiting")

	for i := 0; i < 100; i++ {
		if c.chWorking == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c.chWorking != nil {
		logger.Println("[ERROR]", "RouterServer::Stop", "timeout")
	} else {
		logger.Println("[i]", "RouterServer::Stop", "waiting OK")
	}
	logger.Println("[i]", "RouterServer::Stop", "end")
	return
}

func (c *RouterServer) thListen() {
	logger.Println("[i]", "RouterServer::thListen", "begin")
	var err error
	address := ":" + fmt.Sprint(c.port)
	logger.Println("[i]", "RouterServer::thListen", "listen point:", address)
	c.listener, err = net.Listen("tcp", address)
	if err != nil {
		logger.Error("[ERROR]", "RouterServer::thListen", "net.Listen error:", err)
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
					logger.Error("[ERROR]", "RouterServer::thListen", "listener.Accept error:", err)
				}
			} else {
				c.router.AddConnection(conn)
			}
			if !working {
				break
			}
		}
	}
	logger.Println("[i]", "RouterServer::thListen", "end")
	c.chWorking = nil
}

func (c *RouterServer) thListenUDP() {
	buffer := make([]byte, 4096)
	logger.Println("[i]", "RouterServer::thListenUDP", "begin")
	var err error
	address := net.UDPAddr{
		Port: 8484,
		IP:   net.ParseIP("0.0.0.0"),
	}
	logger.Println("[i]", "RouterServer::thListenUDP", "listen point:", address)
	c.listenerUDP, err = net.ListenUDP("udp", &address)
	if err != nil {
		logger.Error("[ERROR]", "RouterServer::thListenUDP", "net.Listen error:", err)
	} else {
		working := true
		for working {
			var n int
			var remoteAddr *net.UDPAddr
			logger.Println("[-]", "RouterServer::thListenUDP", "reading ...")
			n, remoteAddr, err = c.listenerUDP.ReadFromUDP(buffer)
			logger.Println("[-]", "RouterServer::thListenUDP", "reading result", n, remoteAddr, err)
			if err != nil {
				break
			}
			c.router.UDPReceived(buffer[:n], remoteAddr.IP, remoteAddr.Port)
			c.listenerUDP.WriteTo([]byte("HELLO FROM ROUTER:"+fmt.Sprint(n)), remoteAddr)
		}
	}
	logger.Println("[i]", "RouterServer::thListenUDP", "end")
	c.chWorking = nil
}
