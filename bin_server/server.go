package binserver

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ipoluianov/xchg/core"
)

type Server struct {
	mtx                     sync.Mutex
	connections             []*Connection
	core                    *core.Core
	stopBackgroundRoutineCh chan struct{}
}

func NewServer(core *core.Core) *Server {
	var c Server
	c.core = core
	c.connections = make([]*Connection, 0)
	return &c
}

func (c *Server) Start() {
	c.stopBackgroundRoutineCh = make(chan struct{})
	go c.thListen()
	go c.backgroundOperations()
}

func (c *Server) Stop() {
	close(c.stopBackgroundRoutineCh)
}

func (c *Server) thListen() {
	var listener net.Listener
	var err error
	listener, err = net.Listen("tcp", ":8484")
	if err != nil {
		fmt.Println(err)
		return
	}
	var conn net.Conn
	for {
		conn, err = listener.Accept()
		if err != nil {
			break
		}
		connection := NewConnection(conn, c.core)
		c.mtx.Lock()
		c.connections = append(c.connections, connection)
		c.mtx.Unlock()
		connection.Start()
	}
}

func (c *Server) backgroundOperations() {
	ticker := time.NewTicker(1000 * time.Millisecond)
	for {
		select {
		case <-c.stopBackgroundRoutineCh:
			return
		case <-ticker.C:
		}

		c.mtx.Lock()

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
