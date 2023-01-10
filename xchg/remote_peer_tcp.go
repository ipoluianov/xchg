package xchg

import (
	"errors"
	"net"
	"sync"
)

type RemotePeerTcp struct {
	mtx                  sync.Mutex
	allowLocalConnection bool
}

func NewRemotePeerTcp() *RemotePeerTcp {
	var c RemotePeerTcp
	c.allowLocalConnection = true
	return &c
}

func (c *RemotePeerTcp) Check(peerContext PeerContext, frame20 *Transaction, network *Network, remotePublicKeyExists bool) error {
	return nil
}

func (c *RemotePeerTcp) DeclareError(peerContext PeerContext) {
}

func (c *RemotePeerTcp) Send(peerContext PeerContext, network *Network, tr *Transaction) error {
	return errors.New("not implemented")
}

func (c *RemotePeerTcp) SetRemoteUDPAddress(udpAddress *net.UDPAddr) {
}
