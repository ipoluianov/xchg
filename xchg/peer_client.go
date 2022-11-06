package xchg

import (
	"time"
)

func (c *Peer) Call(remoteAddress string, authData string, function string, data []byte, timeout time.Duration) (result []byte, err error) {
	c.mtx.Lock()
	remotePeer, remotePeerOk := c.remotePeers[remoteAddress]
	if !remotePeerOk || remotePeer == nil {
		remotePeer = NewRemotePeer(remoteAddress, authData, c.privateKey, c.network)
		c.remotePeers[remoteAddress] = remotePeer
	}
	c.mtx.Unlock()
	conn := c.peerUdp.Conn()
	result, err = remotePeer.Call(conn, function, data, timeout)
	return
}
