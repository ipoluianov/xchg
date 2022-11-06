package xchg

import (
	"time"
)

func (c *Peer) Call(remoteAddress string, authData string, function string, data []byte, timeout time.Duration) (result []byte, err error) {
	c.mtx.Lock()
	remotePeer, remotePeerOk := c.remotePeers[remoteAddress]
	if !remotePeerOk || remotePeer == nil {
		remotePeer = NewRemotePeer(c, remoteAddress, authData, c.privateKey, c.network)
		c.remotePeers[remoteAddress] = remotePeer
	}
	c.mtx.Unlock()
	result, err = remotePeer.Call(function, data, timeout)
	return
}
