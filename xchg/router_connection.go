package xchg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/ipoluianov/gomisc/crypt_tools"
)

type RouterConnection struct {
	Connection
	mtxRouterConnection     sync.Mutex
	router                  *Router
	stopBackgroundRoutineCh chan struct{}

	localSecretBytes  []byte
	remoteSecretBytes []byte

	// Remote Address
	remoteAddress    *rsa.PublicKey
	remoteAddressBS  []byte
	remoteAddress64  string
	remoteAddressHex string

	// Local Address
	localAddress           *rsa.PublicKey
	localAddressBS         []byte
	localAddress64         string
	localAddressHex        string
	localAddressPrivate    *rsa.PrivateKey
	localAddressPrivateBS  []byte
	localAddressPrivate64  string
	localAddressPrivateHex string

	init1Received bool
	init4Received bool
	init5Received bool
}

func NewRouterConnection(conn net.Conn, router *Router, localAddress *rsa.PrivateKey) *RouterConnection {
	var c RouterConnection
	c.router = router

	if localAddress != nil {
		c.localAddressPrivate = localAddress
		c.localAddressPrivateBS = crypt_tools.RSAPrivateKeyToDer(localAddress)
		c.localAddressPrivate64 = crypt_tools.RSAPrivateKeyToBase64(localAddress)
		c.localAddressPrivateHex = crypt_tools.RSAPrivateKeyToHex(localAddress)
		c.localAddressBS = crypt_tools.RSAPublicKeyToDer(&localAddress.PublicKey)
		c.localAddress64 = crypt_tools.RSAPublicKeyToBase64(&localAddress.PublicKey)
		c.localAddressHex = crypt_tools.RSAPublicKeyToHex(&localAddress.PublicKey)
	}

	c.initIncomingConnection(conn, &c)
	c.Connected()
	return &c
}

func (c *RouterConnection) addressBS() []byte {
	if c.init4Received {
		return c.remoteAddressBS
	}
	return nil
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
		default:
			c.sendError(transaction, errors.New("wrong function"))
		}
	default:
		c.sendError(transaction, errors.New("wrong protocol version"))
	}
}

func (c *RouterConnection) Connected() {
	// Generate new secret bytes for every connection
	c.mtxRouterConnection.Lock()
	c.localSecretBytes = make([]byte, 32)
	rand.Read(c.localSecretBytes)
	c.mtxRouterConnection.Unlock()
}

func (c *RouterConnection) Disconnected() {
}

func (c *RouterConnection) processInit1(transaction *Transaction) {
	var err error

	fmt.Println("processInit1")

	if len(transaction.data) > c.config.MaxAddressSize {
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

	c.remoteAddress = rsaPublicKey
	c.remoteAddressBS = crypt_tools.RSAPublicKeyToDer(rsaPublicKey)
	c.remoteAddress64 = crypt_tools.RSAPublicKeyToBase64(rsaPublicKey)
	c.remoteAddressHex = crypt_tools.RSAPublicKeyToHex(rsaPublicKey)

	// Send Init2 (my address)
	{
		c.send(NewTransaction(FrameInit2, 0, 0, 0, 0, c.router.localAddressBS))
	}

	// Send Init3
	{
		var encryptedLocalSecret []byte
		encryptedLocalSecret, err = rsa.EncryptPKCS1v15(rand.Reader, c.remoteAddress, c.localSecretBytes)
		if err != nil {
			c.sendError(transaction, err)
			return
		}
		c.send(NewTransaction(FrameInit3, 0, 0, 0, 0, encryptedLocalSecret))
	}

}

func (c *RouterConnection) processInit4(transaction *Transaction) {
	fmt.Println("processInit4")
	localSecretBytes, err := rsa.DecryptPKCS1v15(rand.Reader, c.localAddressPrivate, transaction.data)
	if err != nil {
		return
	}
	if len(localSecretBytes) != len(c.localSecretBytes) {
		return
	}
	for i := 0; i < len(c.localSecretBytes); i++ {
		if c.localSecretBytes[i] != localSecretBytes[i] {
			return
		}
	}
	c.init4Received = true
	c.router.setAddressForConnection(c)
}

func (c *RouterConnection) processInit5(transaction *Transaction) {
	fmt.Println("processInit5")
	var err error
	c.remoteSecretBytes, err = rsa.DecryptPKCS1v15(rand.Reader, c.localAddressPrivate, transaction.data)
	if err != nil {
		return
	}

	remoteSecretBytesEcrypted, err := rsa.EncryptPKCS1v15(rand.Reader, c.remoteAddress, c.remoteSecretBytes)
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

	transaction.data = make([]byte, 8)
	binary.LittleEndian.PutUint64(transaction.data, connection.id)
	c.send(transaction)
}

func (c *RouterConnection) processCall(transaction *Transaction) {
	var err error
	connection := c.router.getConnectionById(transaction.eid)
	if connection == nil {
		c.sendError(transaction, errors.New("connection not found"))
	}

	err = c.router.beginTransaction(transaction)
	if err != nil {
		c.sendError(transaction, err)
	}
}
