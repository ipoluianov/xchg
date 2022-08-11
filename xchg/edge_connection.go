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

	mtxEdgeConnection sync.Mutex
	connection        *Connection

	started  bool
	stopping bool

	// Local Address
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey

	// Remote Address
	remotePublicKey *rsa.PublicKey

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
	c.connection.InitOutgoingConnection(c.node, &c)
	c.nextTransactionId = 1
	c.outgoingTransactions = make(map[uint64]*Transaction)

	if localAddress != nil {
		c.privateKey = localAddress
		c.publicKey = &c.privateKey.PublicKey
	}

	c.fastReset()
	return &c
}

func (c *EdgeConnection) SetProcessor(processor EdgeConnectionProcessor) {
	c.mtxEdgeConnection.Lock()
	defer c.mtxEdgeConnection.Unlock()
	c.processor = processor
}

func (c *EdgeConnection) Start() {
	if c.privateKey == nil {
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

func (c *EdgeConnection) WaitForConnection(timeout time.Duration) bool {
	waitingDurationInMilliseconds := timeout.Milliseconds()
	waitingTick := int64(10)
	waitingIterationCount := waitingDurationInMilliseconds / waitingTick
	for i := int64(0); i < waitingIterationCount; i++ {
		if c.init6Received {
			return true
		}
		time.Sleep(time.Duration(waitingTick) * time.Millisecond)
	}
	return false
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
	switch transaction.ProtocolVersion {
	case 0x01:
		switch transaction.FrameType {
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
		c.connection.SendError(transaction, errors.New("wrong protocol version"))
	}
}

func (c *EdgeConnection) processInit2(transaction *Transaction) {
	c.mtxEdgeConnection.Lock()
	defer c.mtxEdgeConnection.Unlock()

	var err error
	c.remotePublicKey, err = crypt_tools.RSAPublicKeyFromDer(transaction.Data)
	if err != nil {
		return
	}
	c.init2Received = true
}

func (c *EdgeConnection) processInit3(transaction *Transaction) {
	c.mtxEdgeConnection.Lock()
	defer c.mtxEdgeConnection.Unlock()

	var err error
	c.remoteSecretBytes, err = rsa.DecryptPKCS1v15(rand.Reader, c.privateKey, transaction.Data)
	if err != nil {
		return
	}
	c.init3Received = true
}

func (c *EdgeConnection) processInit6(transaction *Transaction) {
	c.mtxEdgeConnection.Lock()
	defer c.mtxEdgeConnection.Unlock()

	localSecretBytes, err := rsa.DecryptPKCS1v15(rand.Reader, c.privateKey, transaction.Data)
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
	c.setTransactionResponse(transaction.TransactionId, nil, errors.New(string(transaction.Data)))
	c.reset()
}

func (c *EdgeConnection) processCall(transaction *Transaction) {
	var processor EdgeConnectionProcessor
	c.mtxEdgeConnection.Lock()
	processor = c.processor
	c.mtxEdgeConnection.Unlock()
	if processor != nil {
		resp := processor.OnEdgeReceivedCall(c, transaction.SessionId, transaction.Data)
		c.connection.Send(NewTransaction(FrameResponse, 0, 0, transaction.TransactionId, 0, resp))
	}
}

func (c *EdgeConnection) processResponse(transaction *Transaction) {
	c.setTransactionResponse(transaction.TransactionId, transaction.Data, nil)
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
		if !c.init6Received {
			c.waitDurationOrStopping(10 * time.Millisecond)
		} else {
			c.waitDurationOrStopping(100 * time.Millisecond)
		}
	}
}

func (c *EdgeConnection) checkConnection() {
	c.mtxEdgeConnection.Lock()
	defer c.mtxEdgeConnection.Unlock()

	if !c.init1Sent {
		c.init1Sent = true
		c.connection.Send(NewTransaction(FrameInit1, 0, 0, 0, 0, crypt_tools.RSAPublicKeyToDer(c.publicKey)))
		return
	}

	if c.init3Received && !c.init4Sent {
		c.init4Sent = true
		remoteSecretBytesEcrypted, err := rsa.EncryptPKCS1v15(rand.Reader, c.remotePublicKey, c.remoteSecretBytes)
		if err == nil {
			c.connection.Send(NewTransaction(FrameInit4, 0, 0, 0, 0, remoteSecretBytesEcrypted))
		}
		return
	}

	if c.init2Received && !c.init5Sent {
		c.init5Sent = true
		localSecretBytesEcrypted, err := rsa.EncryptPKCS1v15(rand.Reader, c.remotePublicKey, c.localSecretBytes)
		if err == nil {
			c.connection.Send(NewTransaction(FrameInit5, 0, 0, 0, 0, localSecretBytesEcrypted))
		}
		return
	}
}

func (c *EdgeConnection) RequestEID(address string) (eid uint64, err error) {
	res, err := c.executeTransaction(FrameResolveAddress, 0, 0, base58.Decode(address), 1000*time.Millisecond)
	if err != nil {
		return 0, err
	}
	if len(res) != 8 {
		return 0, errors.New("EdgeConnection wrong server response")
	}
	eid = binary.LittleEndian.Uint64(res)
	return
}

func (c *EdgeConnection) Call(eid uint64, sessionId uint64, frame []byte) (result []byte, err error) {
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
	err = c.connection.Send(t)
	if err != nil {
		c.mtxEdgeConnection.Lock()
		delete(c.outgoingTransactions, t.TransactionId)
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
			delete(c.outgoingTransactions, t.TransactionId)
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
	delete(c.outgoingTransactions, t.TransactionId)
	c.mtxEdgeConnection.Unlock()

	return nil, errors.New("EdgeConnection timeout")
}
