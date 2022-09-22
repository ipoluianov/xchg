package xchg

import (
	"errors"
	"time"
)

func (c *Peer) Call(remoteAddress string, authData string, function string, data []byte, timeout time.Duration) (result []byte, err error) {
	c.mtx.Lock()
	conn := c.conn
	if conn == nil {
		c.mtx.Unlock()
		err = errors.New("no connection")
		return
	}
	remotePeer, remotePeerOk := c.remotePeers[remoteAddress]
	if !remotePeerOk || remotePeer == nil {
		remotePeer = NewRemotePeer(remoteAddress, authData, c.privateKey, c.network)
		c.remotePeers[remoteAddress] = remotePeer
	}
	c.mtx.Unlock()
	result, err = remotePeer.Call(conn, function, data, timeout)
	return
}
