package xchg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
)

type RouterConnection struct {
	Connection
	router                  *Router
	secretBytes             []byte
	declaredAddress         []byte
	confirmedAddress        []byte
	stopBackgroundRoutineCh chan struct{}
}

func NewRouterConnection(conn net.Conn, router *Router) *RouterConnection {
	var c RouterConnection
	c.router = router
	c.initIncomingConnection(conn)
	return &c
}

func (c *RouterConnection) Start() {
	c.startConnectionBase()
}

func (c *RouterConnection) Stop() {
	c.stopConnectionBase()
}

func (c *RouterConnection) address() []byte {
	return c.confirmedAddress
}

func (c *RouterConnection) processTransaction(transaction *Transaction) {
	switch transaction.protocolVersion {
	case 0x01:
		switch transaction.function {
		case FuncPing:
			c.processPing(transaction)
		case FuncResolveAddress:
			c.processResolveAddress(transaction)
		case FuncCall:
			c.processCall(transaction)
		case FuncSend:
			c.processSend(transaction)
		case FuncDeclareAddr:
			c.processDeclareAddr(transaction)
		case FuncConfirmAddr:
			c.processConfirmAddr(transaction)
		case FuncResponse:
			c.processResponse(transaction)
		default:
			c.sendError(transaction, errors.New("wrong function"))
		}
	default:
		c.sendError(transaction, errors.New("wrong protocol version"))
	}
}

func (c *RouterConnection) processPing(transaction *Transaction) {
	transaction.code = FrameCodeSuccess
	c.send(transaction)
}

func (c *RouterConnection) processResolveAddress(transaction *Transaction) {
	connection := c.router.getConnectionByAddress(transaction.data)
	if connection == nil {
		c.sendError(transaction, errors.New("address not found"))
		return
	}

	transaction.data = make([]byte, 8)
	binary.LittleEndian.PutUint64(transaction.data, connection.id)
	transaction.code = FrameCodeSuccess
	c.send(transaction)
}

func (c *RouterConnection) processCall(transaction *Transaction) {
	var err error
	if len(transaction.data) < 8 {
		c.sendError(transaction, errors.New("wrong frame"))
		return
	}
	connectionId := binary.LittleEndian.Uint64(transaction.data)
	connection := c.router.getConnectionById(connectionId)
	if connection == nil {
		c.sendError(transaction, errors.New("connection not found"))
	}

	err = c.router.beginTransaction(transaction)
	if err != nil {
		c.sendError(transaction, err)
	}
}

func (c *RouterConnection) processSend(transaction *Transaction) {
	if len(transaction.data) < 8 {
		c.sendError(transaction, errors.New("wrong frame"))
		return
	}

	c.router.sendTransactionToConnection(transaction)
	c.send(NewResponseTransaction(transaction, FrameCodeSuccess, nil))
}

func (c *RouterConnection) processDeclareAddr(transaction *Transaction) {
	var err error

	if len(transaction.data) > c.config.MaxAddressSize {
		c.sendError(transaction, errors.New("wrong address size"))
		return
	}

	// Generate new secret bytes for every query
	c.mtx.Lock()
	c.secretBytes = make([]byte, 32)
	rand.Read(c.secretBytes)
	c.mtx.Unlock()

	// Parse PublicKey-DER
	var rsaPublicKey *rsa.PublicKey
	rsaPublicKey, err = x509.ParsePKCS1PublicKey(transaction.data)
	if err != nil {
		c.sendError(transaction, err)
		return
	}

	// Encrypt AES key by PublicKey
	var encryptedResponse []byte
	encryptedResponse, err = rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, c.secretBytes)
	if err != nil {
		c.sendError(transaction, err)
		return
	}

	c.declaredAddress = transaction.data

	// Success
	transaction.code = FrameCodeSuccess
	transaction.data = encryptedResponse
	c.send(transaction)
}

func (c *RouterConnection) processConfirmAddr(transaction *Transaction) {
	if len(transaction.data) != len(c.secretBytes) {
		c.sendError(transaction, errors.New("wrong secret bytes"))
		return
	}
	for i := 0; i < len(transaction.data); i++ {
		if transaction.data[i] != c.secretBytes[i] {
			c.sendError(transaction, errors.New("wrong secret bytes"))
			return
		}
	}

	c.confirmedAddress = c.declaredAddress
	c.declaredAddress = nil

	c.router.setAddressForConnection(c)
}

func (c *RouterConnection) processResponse(transaction *Transaction) {
	c.router.SetResponse(transaction)
}
