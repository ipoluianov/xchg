package xchg

import (
	"crypto/rsa"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"
)

type RemotePeerUdp struct {
	mtx                  sync.Mutex
	nonces               *Nonces
	privateKey           *rsa.PrivateKey
	remoteAddress        string
	allowLocalConnection bool
	lanConnectionPoint   *net.UDPAddr
}

func NewRemotePeerUdp(nonces *Nonces, remoteAddress string, privateKey *rsa.PrivateKey) *RemotePeerUdp {
	var c RemotePeerUdp
	c.nonces = nonces
	c.remoteAddress = remoteAddress
	c.privateKey = privateKey
	c.allowLocalConnection = true
	return &c
}

func (c *RemotePeerUdp) Send(conn net.PacketConn, frame []byte) error {
	c.mtx.Lock()
	lanConnectionPoint := c.lanConnectionPoint
	c.mtx.Unlock()

	if c.lanConnectionPoint == nil {
		return errors.New("no LAN connection point")
	}

	_, err := conn.WriteTo(frame, lanConnectionPoint)
	return err
}

func (c *RemotePeerUdp) IsValid() (result bool) {
	c.mtx.Lock()
	result = c.lanConnectionPoint != nil
	c.mtx.Unlock()
	return
}

func (c *RemotePeerUdp) Check(conn net.PacketConn) {
	go c.checkLANConnectionPoint(conn)
}

func (c *RemotePeerUdp) SetConnectionPoint(udpAddress *net.UDPAddr) {
	c.mtx.Lock()
	c.lanConnectionPoint = udpAddress
	c.mtx.Unlock()
}

func (c *RemotePeerUdp) ResetConnectionPoint() {
	c.mtx.Lock()
	c.lanConnectionPoint = nil
	c.mtx.Unlock()
}

func (c *RemotePeerUdp) checkLANConnectionPoint(conn net.PacketConn) (err error) {
	if !c.allowLocalConnection {
		return
	}

	c.mtx.Lock()
	lanConnectionPoint := c.lanConnectionPoint
	c.mtx.Unlock()
	if lanConnectionPoint != nil {
		return
	}

	nonce := c.nonces.Next()

	addressBS := []byte(c.remoteAddress)

	transaction := NewTransaction(0x20, AddressForPublicKey(&c.privateKey.PublicKey), c.remoteAddress, 0, 0, 0, 0, nil)
	transaction.Data = make([]byte, 16+len(addressBS))
	copy(transaction.Data[0:], nonce[:])
	copy(transaction.Data[16:], addressBS)

	for i := PEER_UDP_START_PORT; i < PEER_UDP_END_PORT; i++ {
		c.mtx.Lock()
		lanConnectionPoint = c.lanConnectionPoint
		c.mtx.Unlock()
		if lanConnectionPoint != nil {
			break
		}

		var broadcastAddress *net.UDPAddr
		//fmt.Println("send to " + fmt.Sprint(i))
		broadcastAddress, err = net.ResolveUDPAddr("udp4", "127.0.0.1:"+strconv.FormatInt(int64(i), 10))
		if err != nil {
			break
		}
		_, err = conn.WriteTo(transaction.Marshal(), broadcastAddress)
		if err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return
}
