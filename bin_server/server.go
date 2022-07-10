package binserver

import (
	"fmt"
	"net"
	"sync"

	"github.com/ipoluianov/xchg/core"
)

type Server struct {
	mtx         sync.Mutex
	connections []*Connection
	core        *core.Core
}

func NewServer(core *core.Core) *Server {
	var c Server
	c.core = core
	c.connections = make([]*Connection, 0)
	return &c
}

func (c *Server) Start() {
	go c.thListen()
}

func (c *Server) Stop() {

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
