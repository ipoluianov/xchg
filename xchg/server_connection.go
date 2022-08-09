package xchg

import (
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ipoluianov/gomisc/crypt_tools"
)

type ServerConnection struct {
	mtxServerConnection sync.Mutex
	edgeConnections     map[string]*EdgeConnection
	privateKey58        string

	sessionsById          map[uint64]*Session
	nextSessionId         uint64
	lastPurgeSessionsTime time.Time
	callback              func(ev ServerEvent) ([]byte, error)
}

func NewServerConnection(privateKey58 string, callback func(ev ServerEvent) ([]byte, error)) *ServerConnection {
	var c ServerConnection
	c.privateKey58 = privateKey58
	c.callback = callback
	privateKey, _ := crypt_tools.RSAPrivateKeyFromDer(base58.Decode(c.privateKey58))
	c.edgeConnections = make(map[string]*EdgeConnection)
	eConn := NewEdgeConnection("localhost:8484", privateKey)
	c.edgeConnections["localhost:8484"] = eConn
	eConn.Start()
	return &c
}

func (c *ServerConnection) getEdgeConnection() *EdgeConnection {
	return c.edgeConnections["localhost:8484"]
}

func (c *ServerConnection) purgeSessions() {
	now := time.Now()
	c.mtxServerConnection.Lock()
	if now.Sub(c.lastPurgeSessionsTime).Seconds() > 5*60 {
		fmt.Println("Purging sessions")
		for sessionId, session := range c.sessionsById {
			if now.Sub(session.lastAccessDT).Seconds() > 30 {
				fmt.Println("Removing session", sessionId)
				delete(c.sessionsById, sessionId)
			}
		}
		c.lastPurgeSessionsTime = time.Now()
	}
	c.mtxServerConnection.Unlock()
}
