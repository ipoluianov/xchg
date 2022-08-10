package xchg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"sync"

	"github.com/ipoluianov/gomisc/crypt_tools"
)

type RouterConnection struct {
	Connection
	mtxRouterConnection sync.Mutex
	router              *Router

	localSecretBytes []byte

	// Remote Address
	remotePublicKey        *rsa.PublicKey
	confirmedRemoteAddress string

	// Local Address
	privateKey *rsa.PrivateKey

	configMaxAddressSize int

	init1Received bool
	init4Received bool
	init5Received bool
}

func NewRouterConnection(conn net.Conn, router *Router, privateKey *rsa.PrivateKey) *RouterConnection {
	var c RouterConnection
	c.configMaxAddressSize = 1024
	c.router = router
	c.privateKey = privateKey
	c.localSecretBytes = make([]byte, 32)
	rand.Read(c.localSecretBytes)
	c.initIncomingConnection(conn, &c)
	return &c
}

func (c *RouterConnection) Id() uint64 {
	c.mtxRouterConnection.Lock()
	defer c.mtxRouterConnection.Unlock()
	return c.id
}

func (c *RouterConnection) ProcessTransaction(transaction *Transaction) {
	switch transaction.protocolVersion {
	case 0x01:
		switch transaction.frameType {
		case FrameInit1:
			c.processInit1(transaction)
		case FrameInit4:
			c.processInit4(transaction)
		case FrameInit5:
			c.processInit5(transaction)
		case FrameResolveAddress:
			c.processResolveAddress(transaction)
		case FrameCall:
			c.processCall(transaction)
		case FrameResponse:
			c.processResponse(transaction)
		default:
			c.sendError(transaction, errors.New("wrong function"))
		}
	default:
		c.sendError(transaction, errors.New("wrong protocol version"))
	}
}

func (c *RouterConnection) Connected() {
}

func (c *RouterConnection) Disconnected() {
}

func (c *RouterConnection) ConfirmedRemoteAddress() string {
	c.mtxRouterConnection.Lock()
	defer c.mtxRouterConnection.Unlock()
	return c.confirmedRemoteAddress
}

func (c *RouterConnection) processInit1(transaction *Transaction) {
	var err error

	if len(transaction.data) > c.configMaxAddressSize {
		c.sendError(transaction, errors.New("wrong address size"))
		return
	}

	// Parse PublicKey-DER
	var rsaPublicKey *rsa.PublicKey
	rsaPublicKey, err = x509.ParsePKCS1PublicKey(transaction.data)
	if err != nil {
		c.sendError(transaction, err)
		return
	}

	c.mtxRouterConnection.Lock()
	c.remotePublicKey = rsaPublicKey
	localAddressBS := c.router.localAddressBS
	localSecretBytes := c.localSecretBytes
	c.mtxRouterConnection.Unlock()

	// Send Init2 (my address)
	c.send(NewTransaction(FrameInit2, 0, 0, 0, 0, localAddressBS))

	// Send Init3
	{
		var encryptedLocalSecret []byte
		encryptedLocalSecret, err = rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, localSecretBytes)
		if err != nil {
			c.sendError(transaction, err)
			return
		}
		c.send(NewTransaction(FrameInit3, 0, 0, 0, 0, encryptedLocalSecret))
	}
}

func (c *RouterConnection) processInit4(transaction *Transaction) {
	c.mtxRouterConnection.Lock()
	privateKey := c.privateKey
	localSecretBytes := c.localSecretBytes
	remotePublicKey := c.remotePublicKey
	c.mtxRouterConnection.Unlock()

	receivedSecretBytes, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, transaction.data)
	if err != nil {
		return
	}
	if len(receivedSecretBytes) != len(localSecretBytes) {
		return
	}
	for i := 0; i < len(localSecretBytes); i++ {
		if localSecretBytes[i] != receivedSecretBytes[i] {
			return
		}
	}
	c.mtxRouterConnection.Lock()
	c.init4Received = true
	confirmedRemoteAddress := crypt_tools.RSAPublicKeyToBase58(remotePublicKey)
	c.confirmedRemoteAddress = confirmedRemoteAddress
	c.mtxRouterConnection.Unlock()

	c.router.setAddressForConnection(c, confirmedRemoteAddress)
}

func (c *RouterConnection) processInit5(transaction *Transaction) {
	c.mtxRouterConnection.Lock()
	privateKey := c.privateKey
	remotePublicKey := c.remotePublicKey
	c.mtxRouterConnection.Unlock()

	var err error
	var remoteSecretBytes []byte
	remoteSecretBytes, err = rsa.DecryptPKCS1v15(rand.Reader, privateKey, transaction.data)
	if err != nil {
		return
	}

	remoteSecretBytesEcrypted, err := rsa.EncryptPKCS1v15(rand.Reader, remotePublicKey, remoteSecretBytes)
	if err == nil {
		c.send(NewTransaction(FrameInit6, 0, 0, 0, 0, remoteSecretBytesEcrypted))
	}
}

func (c *RouterConnection) processResolveAddress(transaction *Transaction) {
	connection := c.router.getConnectionByAddress(transaction.data)
	if connection == nil {
		c.sendError(transaction, errors.New("address not found"))
		return
	}
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, connection.Id())
	c.send(NewTransaction(FrameResponse, 0, 0, transaction.transactionId, 0, data))
}

func (c *RouterConnection) processCall(transaction *Transaction) {
	var err error
	connection := c.router.getConnectionById(transaction.eid)
	if connection == nil {
		c.sendError(transaction, errors.New("connection not found"))
		return
	}

	err = c.router.beginTransaction(transaction)
	if err != nil {
		c.sendError(transaction, err)
		return
	}
	transaction.connection = c
	connection.send(transaction)
}

func (c *RouterConnection) processResponse(transaction *Transaction) {
	c.router.SetResponse(transaction)
}
