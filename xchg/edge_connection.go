package xchg

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ipoluianov/gomisc/crypt_tools"
)

type EdgeConnection struct {
	node string

	connection *Connection

	started  bool
	stopping bool

	mtxEdgeConnection sync.Mutex

	// Local Address
	localAddress        *rsa.PublicKey
	localAddressPrivate *rsa.PrivateKey

	xchgNodePublicKey *rsa.PublicKey

	// State

	localSecretBytes  []byte
	remoteSecretBytes []byte

	outgoingTransactions map[uint64]*Transaction
	nextTransactionId    uint64

	// Initialization
	init1Sent     bool
	init2Received bool
	init3Received bool
	init4Sent     bool
	init5Sent     bool
	init6Received bool

	processor EdgeConnectionProcessor
}

type EdgeConnectionProcessor interface {
	OnEdgeConnected(edgeConnection *EdgeConnection)
	OnEdgeDissonnected(edgeConnection *EdgeConnection)
	OnEdgeReceivedCall(edgeConnection *EdgeConnection, sessionId uint64, data []byte) (response []byte)
}

func NewEdgeConnection(xchgNode string, localAddress *rsa.PrivateKey) *EdgeConnection {
	var c EdgeConnection

	c.node = xchgNode
	c.connection = NewConnection()
	c.connection.initOutgoingConnection(c.node, &c)
	c.nextTransactionId = 1
	c.outgoingTransactions = make(map[uint64]*Transaction)

	if localAddress != nil {
		c.localAddressPrivate = localAddress
		c.localAddress = &c.localAddressPrivate.PublicKey
	}

	c.fastReset()
	return &c
}

func (c *EdgeConnection) SetProcessor(processor EdgeConnectionProcessor) {
	c.processor = processor
}

func (c *EdgeConnection) Start() {
	if c.localAddressPrivate == nil {
		return
	}
	c.started = true
	c.stopping = false
	c.connection.Start()
	go c.thBackground()
}

func (c *EdgeConnection) Stop() {
	c.stopping = true
	c.connection.Stop()
}

func (c *EdgeConnection) reset() {
	c.waitDurationOrStopping(500 * time.Millisecond)
	c.fastReset()
}

func (c *EdgeConnection) fastReset() {
	c.mtxEdgeConnection.Lock()

	c.init1Sent = false
	c.init2Received = false
	c.init3Received = false
	c.init4Sent = false
	c.init5Sent = false
	c.init6Received = false

	c.localSecretBytes = make([]byte, 32) // Generate new secret bytes for every connection
	rand.Read(c.localSecretBytes)

	for _, t := range c.outgoingTransactions {
		if !t.complete {
			t.err = errors.New("EdgeConnection connection loss")
			t.complete = true
		}
	}

	c.mtxEdgeConnection.Unlock()
}

func (c *EdgeConnection) Connected() {
	c.reset()
}

func (c *EdgeConnection) Disconnected() {
	c.reset()
}

func (c *EdgeConnection) waitDurationOrStopping(duration time.Duration) {
	dtBegin := time.Now()
	for time.Now().Sub(dtBegin).Milliseconds() < duration.Milliseconds() && !c.stopping {
		time.Sleep(100)
	}
}

func (c *EdgeConnection) ProcessTransaction(transaction *Transaction) {
	switch transaction.protocolVersion {
	case 0x01:
		switch transaction.frameType {
		case FrameInit2:
			c.processInit2(transaction)
		case FrameInit3:
			c.processInit3(transaction)
		case FrameInit6:
			c.processInit6(transaction)

		case FrameCall:
			c.processCall(transaction)
		case FrameResponse:
			c.processResponse(transaction)
		case FrameError:
			c.processError(transaction)
		}
	default:
		c.connection.sendError(transaction, errors.New("wrong protocol version"))
	}
}

func (c *EdgeConnection) processInit2(transaction *Transaction) {
	var err error
	c.xchgNodePublicKey, err = crypt_tools.RSAPublicKeyFromDer(transaction.data)
	if err != nil {
		return
	}
	c.init2Received = true
}

func (c *EdgeConnection) processInit3(transaction *Transaction) {
	var err error
	c.remoteSecretBytes, err = rsa.DecryptPKCS1v15(rand.Reader, c.localAddressPrivate, transaction.data)
	if err != nil {
		return
	}
	c.init3Received = true
}

func (c *EdgeConnection) processInit6(transaction *Transaction) {
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
	c.init6Received = true
}

func (c *EdgeConnection) processError(transaction *Transaction) {
	c.setTransactionResponse(transaction.transactionId, nil, errors.New(string(transaction.data)))
	c.reset()
}

func (c *EdgeConnection) processCall(transaction *Transaction) {
	var processor EdgeConnectionProcessor
	c.mtxEdgeConnection.Lock()
	processor = c.processor
	c.mtxEdgeConnection.Unlock()
	if processor != nil {
		resp := processor.OnEdgeReceivedCall(c, transaction.sessionId, transaction.data)
		c.connection.send(NewTransaction(FrameResponse, 0, 0, transaction.transactionId, 0, resp))
	}
}

func (c *EdgeConnection) processResponse(transaction *Transaction) {
	c.setTransactionResponse(transaction.transactionId, transaction.data, nil)
}

func (c *EdgeConnection) setTransactionResponse(transactionId uint64, data []byte, err error) {
	c.mtxEdgeConnection.Lock()
	defer c.mtxEdgeConnection.Unlock()

	if t, ok := c.outgoingTransactions[transactionId]; ok {
		t.result = data
		t.err = err
		t.complete = true
	}
}

func (c *EdgeConnection) thBackground() {
	for !c.stopping {
		c.checkConnection()
		c.waitDurationOrStopping(100 * time.Millisecond)
	}
}

func (c *EdgeConnection) checkConnection() {
	c.mtxEdgeConnection.Lock()
	defer c.mtxEdgeConnection.Unlock()

	if !c.init1Sent {
		c.init1Sent = true
		c.connection.send(NewTransaction(FrameInit1, 0, 0, 0, 0, crypt_tools.RSAPublicKeyToDer(c.localAddress)))
		return
	}

	if c.init3Received && !c.init4Sent {
		c.init4Sent = true
		remoteSecretBytesEcrypted, err := rsa.EncryptPKCS1v15(rand.Reader, c.xchgNodePublicKey, c.remoteSecretBytes)
		if err == nil {
			c.connection.send(NewTransaction(FrameInit4, 0, 0, 0, 0, remoteSecretBytesEcrypted))
		}
		return
	}

	if c.init2Received && !c.init5Sent {
		c.init5Sent = true
		localSecretBytesEcrypted, err := rsa.EncryptPKCS1v15(rand.Reader, c.xchgNodePublicKey, c.localSecretBytes)
		if err == nil {
			c.connection.send(NewTransaction(FrameInit5, 0, 0, 0, 0, localSecretBytesEcrypted))
		}
		return
	}
}

func (c *EdgeConnection) Call(address string, sessionId uint64, frame []byte) (result []byte, err error) {
	res, err := c.executeTransaction(FrameResolveAddress, 0, 0, base58.Decode(address), 1000*time.Millisecond)
	if err != nil {
		return nil, err
	}
	if len(res) != 8 {
		return nil, errors.New("EdgeConnection wrong server response")
	}

	eid := binary.LittleEndian.Uint64(res)

	result, err = c.executeTransaction(FrameCall, eid, sessionId, frame, 1000*time.Millisecond)
	return
}

func (c *EdgeConnection) executeTransaction(frameType byte, targetEID uint64, sessionId uint64, data []byte, timeout time.Duration) (result []byte, err error) {
	// Get transaction ID
	var transactionId uint64
	c.mtxEdgeConnection.Lock()
	transactionId = c.nextTransactionId
	c.nextTransactionId++

	// Create transaction
	t := NewTransaction(frameType, 0, targetEID, transactionId, sessionId, data)
	c.outgoingTransactions[transactionId] = t
	c.mtxEdgeConnection.Unlock()

	// Send transaction
	err = c.connection.send(t)
	if err != nil {
		c.mtxEdgeConnection.Lock()
		delete(c.outgoingTransactions, t.transactionId)
		c.mtxEdgeConnection.Unlock()
		return
	}

	// Wait for response
	waitingDurationInMilliseconds := timeout.Milliseconds()
	waitingTick := int64(10)
	waitingIterationCount := waitingDurationInMilliseconds / waitingTick
	for i := int64(0); i < waitingIterationCount; i++ {
		if t.complete {
			// Transaction complete
			c.mtxEdgeConnection.Lock()
			delete(c.outgoingTransactions, t.transactionId)
			c.mtxEdgeConnection.Unlock()

			// Error recevied
			if t.err != nil {
				result = nil
				err = t.err
				return
			}

			// Success
			result = t.result
			err = nil
			return
		}
		time.Sleep(time.Duration(waitingTick) * time.Millisecond)
	}

	// Clear transactions map
	c.mtxEdgeConnection.Lock()
	delete(c.outgoingTransactions, t.transactionId)
	c.mtxEdgeConnection.Unlock()

	return nil, errors.New("EdgeConnection timeout")
}
