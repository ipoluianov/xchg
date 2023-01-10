package xchg

import (
	"net"
	"time"
)

type PeerContext struct {
	udpConn net.PacketConn
	network *Network
}

func (c *Peer) Call(remoteAddress string, authData string, function string, data []byte, timeout time.Duration) (result []byte, err error) {
	c.mtx.Lock()
	remotePeer, remotePeerOk := c.remotePeers[remoteAddress]
	if !remotePeerOk || remotePeer == nil {
		remotePeer = NewRemotePeer(remoteAddress, authData, c.privateKey, c.network)
		c.remotePeers[remoteAddress] = remotePeer
	}
	var peerContext PeerContext
	peerContext.udpConn = c.UDPConn()
	peerContext.network = c.network
	c.mtx.Unlock()
	result, err = remotePeer.Call(peerContext, function, data, timeout)
	return
}
