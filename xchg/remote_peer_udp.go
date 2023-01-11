package xchg

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"time"
)

type RemotePeerUdp struct {
	mtx              sync.Mutex
	remoteUDPAddress *net.UDPAddr
}

func NewRemotePeerUdp() *RemotePeerUdp {
	var c RemotePeerUdp
	return &c
}

func (c *RemotePeerUdp) Send(peerContext PeerContext, network *Network, tr *Transaction) error {
	if peerContext.udpConn == nil {
		return errors.New("no UDP endpoint")
	}

	c.mtx.Lock()
	remoteUDPAddress := c.remoteUDPAddress
	c.mtx.Unlock()

	if c.remoteUDPAddress == nil {
		return errors.New("no LAN connection point")
	}

	_, err := peerContext.udpConn.WriteTo(tr.Marshal(), remoteUDPAddress)
	return err
}

func (c *RemotePeerUdp) Check(peerContext PeerContext, frame20 *Transaction, network *Network, remotePublicKeyExists bool) error {
	if peerContext.udpConn == nil {
		return errors.New("no UDP connection point")
	}
	c.mtx.Lock()
	remoteUDPAddress := c.remoteUDPAddress
	c.mtx.Unlock()
	if remoteUDPAddress != nil {
		return nil
	}
	go c.checkLANConnectionPoint(peerContext, frame20)
	c.mtx.Lock()
	result := c.remoteUDPAddress != nil
	c.mtx.Unlock()
	if !result {
		return errors.New("not ready")
	}
	return nil
}

func (c *RemotePeerUdp) SetRemoteUDPAddress(udpAddress *net.UDPAddr) {
	c.mtx.Lock()
	c.remoteUDPAddress = udpAddress
	c.mtx.Unlock()
}

func (c *RemotePeerUdp) Id() string {
	return "udp"
}

func (c *RemotePeerUdp) DeclareError(peerContext PeerContext, sentViaTransportMap map[string]struct{}) {
	_, ok := sentViaTransportMap[c.Id()]
	if ok {
		c.mtx.Lock()
		c.remoteUDPAddress = nil
		c.mtx.Unlock()
	}
}

func (c *RemotePeerUdp) checkLANConnectionPoint(peerContext PeerContext, frame20 *Transaction) (err error) {
	if peerContext.udpConn == nil {
		return
	}

	c.mtx.Lock()
	remoteUDPAddress := c.remoteUDPAddress
	c.mtx.Unlock()
	if remoteUDPAddress != nil {
		return
	}

	for i := PEER_UDP_START_PORT; i < PEER_UDP_END_PORT; i++ {
		c.mtx.Lock()
		remoteUDPAddress = c.remoteUDPAddress
		c.mtx.Unlock()
		if remoteUDPAddress != nil {
			break
		}

		var broadcastAddress *net.UDPAddr
		//fmt.Println("send to " + fmt.Sprint(i))
		broadcastAddress, err = net.ResolveUDPAddr("udp4", "127.0.0.1:"+strconv.FormatInt(int64(i), 10))
		if err != nil {
			break
		}
		_, err = peerContext.udpConn.WriteTo(frame20.Marshal(), broadcastAddress)
		if err != nil {
			break
		}
		time.Sleep(1 * time.Millisecond)
	}
	return
}
