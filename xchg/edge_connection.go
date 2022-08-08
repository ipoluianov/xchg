package xchg

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
)

type EdgeConnection struct {
	Connection

	mtxEdgeConnection sync.Mutex

	node string

	// Local Address
	localAddress           *rsa.PublicKey
	localAddressBS         []byte
	localAddress64         string
	localAddressHex        string
	localAddressPrivate    *rsa.PrivateKey
	localAddressPrivateBS  []byte
	localAddressPrivate64  string
	localAddressPrivateHex string

	sessionsById          map[uint64]*Session
	lastPurgeSessionsTime time.Time

	// Destanation Address
	destanationAddress    *rsa.PublicKey
	destanationAddressBS  []byte
	destanationAddress64  string
	destanationAddressHex string

	// State
	remoteServerHostingIP string
	sessionId             uint64

	localSecretBytes  []byte
	remoteSecretBytes []byte

	outgoingTransactions map[uint64]*Transaction
	nextTransactionId    uint64

	// Initialization
	eid uint64

	init1Sent     bool
	init2Received bool
	init3Received bool
	init4Sent     bool
	init5Sent     bool
	init6Received bool
}

type Session struct {
	id           uint64
	aesKey       []byte
	lastAccessDT time.Time
}

func NewEdgeConnection(xchgNode string, localAddress *rsa.PrivateKey, authString string) *EdgeConnection {
	var c EdgeConnection

	c.node = xchgNode
	c.initOutgoingConnection(c.node, &c)
	c.eid = 0
	c.nextTransactionId = 1
	c.outgoingTransactions = make(map[uint64]*Transaction)

	if localAddress != nil {
		c.localAddressPrivate = localAddress
		c.localAddressPrivateBS = crypt_tools.RSAPrivateKeyToDer(localAddress)
		c.localAddressPrivate64 = crypt_tools.RSAPrivateKeyToBase64(localAddress)
		c.localAddressPrivateHex = crypt_tools.RSAPrivateKeyToHex(localAddress)
		c.localAddressBS = crypt_tools.RSAPublicKeyToDer(&localAddress.PublicKey)
		c.localAddress64 = crypt_tools.RSAPublicKeyToBase64(&localAddress.PublicKey)
		c.localAddressHex = crypt_tools.RSAPublicKeyToHex(&localAddress.PublicKey)
	}

	c.fastReset()
	go c.thBackground()
	return &c
}

func (c *EdgeConnection) reset() {
	c.waitDurationOrStopping(500 * time.Millisecond)
	c.fastReset()
}

func (c *EdgeConnection) fastReset() {
	c.mtxEdgeConnection.Lock()
	c.eid = 0

	c.init1Sent = false
	c.init2Received = false
	c.init3Received = false
	c.init4Sent = false
	c.init5Sent = false
	c.init6Received = false

	c.localSecretBytes = make([]byte, 32) // Generate new secret bytes for every connection
	rand.Read(c.localSecretBytes)

	for _, t := range c.outgoingTransactions {
		t.err = errors.New("connection loss")
		t.complete = true
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
		c.sendError(transaction, errors.New("wrong protocol version"))
	}
}

func (c *EdgeConnection) processInit2(transaction *Transaction) {
	var err error
	c.destanationAddress, err = crypt_tools.RSAPublicKeyFromDer(transaction.data)
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
	c.reset()
}

func (c *EdgeConnection) processCall(transaction *Transaction) {
}

func (c *EdgeConnection) processResponse(transaction *Transaction) {
}

func (c *EdgeConnection) thBackground() {
	for !c.stopping {
		c.checkConnection()
		c.waitDurationOrStopping(1000 * time.Millisecond)
	}
}

func (c *EdgeConnection) checkConnection() {
	c.mtxEdgeConnection.Lock()
	if !c.init1Sent {
		c.init1Sent = true
		c.send(NewTransaction(FrameInit1, 0, 0, 0, 0, c.localAddressBS))
		return
	}

	if c.init3Received && !c.init4Sent {
		c.init4Sent = true
		remoteSecretBytesEcrypted, err := rsa.EncryptPKCS1v15(rand.Reader, c.destanationAddress, c.remoteSecretBytes)
		if err == nil {
			c.send(NewTransaction(FrameInit3, 0, 0, 0, 0, remoteSecretBytesEcrypted))
		}
		return
	}

	if c.init2Received && !c.init5Sent {
		c.init5Sent = true
		localSecretBytesEcrypted, err := rsa.EncryptPKCS1v15(rand.Reader, c.destanationAddress, c.localSecretBytes)
		if err == nil {
			c.send(NewTransaction(FrameInit3, 0, 0, 0, 0, localSecretBytesEcrypted))
		}
		return
	}
}

func (c *EdgeConnection) executeTransaction(function byte, targetEID uint64, sessionId uint64, data []byte, timeout time.Duration) (result []byte, err error) {
	// Get transaction ID
	var transactionId uint64
	c.mtxEdgeConnection.Lock()
	transactionId = c.nextTransactionId
	c.nextTransactionId++

	// Create transaction
	t := NewTransaction(function, 0, targetEID, transactionId, sessionId, data)
	c.outgoingTransactions[transactionId] = t
	c.mtxEdgeConnection.Unlock()

	// Send transaction
	err = c.send(t)
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
			result = t.data
			err = nil
			return
		}
		time.Sleep(time.Duration(waitingTick) * time.Millisecond)
	}

	// Clear transactions map
	c.mtxEdgeConnection.Lock()
	delete(c.outgoingTransactions, t.transactionId)
	c.mtxEdgeConnection.Unlock()

	return nil, errors.New("timeout")
}

func (c *EdgeConnection) purgeSessions() {
	now := time.Now()
	c.mtxEdgeConnection.Lock()
	if now.Sub(c.lastPurgeSessionsTime).Seconds() > 5*60 {
		fmt.Println("Purging sessions")
		for sessionId, session := range c.sessionsById {
			if now.Sub(session.lastAccessDT).Seconds() > 30 {
				fmt.Println("Removing session", sessionId)
				delete(c.sessionsById, sessionId)
			}
		}
		c.lastPurgeSessionsTime = time.Now()
	}
	c.mtxEdgeConnection.Unlock()
}
