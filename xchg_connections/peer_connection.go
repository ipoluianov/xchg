package xchg_connections

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/xchg/xchg"
)

type PeerConnection struct {
	node string

	mtxEdgeConnection sync.Mutex
	connection        *xchg.Connection

	started  bool
	stopping bool

	// Local Address
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey

	// Remote Address
	remotePublicKey *rsa.PublicKey

	localSecretBytes  []byte
	remoteSecretBytes []byte

	outgoingTransactions map[uint64]*xchg.Transaction
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
	OnEdgeConnected(edgeConnection *PeerConnection)
	OnEdgeDissonnected(edgeConnection *PeerConnection)
	OnEdgeReceivedCall(edgeConnection *PeerConnection, sessionId uint64, data []byte) (response []byte)
}

func NewPeerConnection(xchgNode string, localAddress *rsa.PrivateKey) *PeerConnection {
	var c PeerConnection

	c.node = xchgNode
	c.connection = xchg.NewConnection()
	c.connection.InitOutgoingConnection(c.node, &c)
	c.nextTransactionId = 1
	c.outgoingTransactions = make(map[uint64]*xchg.Transaction)

	if localAddress != nil {
		c.privateKey = localAddress
		c.publicKey = &c.privateKey.PublicKey
	}

	c.fastReset()
	return &c
}

func (c *PeerConnection) SetProcessor(processor EdgeConnectionProcessor) {
	c.mtxEdgeConnection.Lock()
	defer c.mtxEdgeConnection.Unlock()
	c.processor = processor
}

func (c *PeerConnection) Start() {
	if c.privateKey == nil {
		return
	}
	c.started = true
	c.stopping = false
	c.connection.Start()
	go c.thBackground()
}

func (c *PeerConnection) Stop() {
	c.stopping = true
	c.connection.Stop()
}

func (c *PeerConnection) WaitForConnection(timeout time.Duration) bool {
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

func (c *PeerConnection) reset() {
	c.waitDurationOrStopping(500 * time.Millisecond)
	c.fastReset()
}

func (c *PeerConnection) fastReset() {
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
		if !t.Complete {
			t.Err = errors.New(ERR_XCHG_PEER_CONN_LOSS)
			t.Complete = true
		}
	}

	c.mtxEdgeConnection.Unlock()
}

func (c *PeerConnection) Connected() {
	c.reset()
	fmt.Println("connected")
}

func (c *PeerConnection) Disconnected() {
	c.reset()
}

func (c *PeerConnection) waitDurationOrStopping(duration time.Duration) {
	dtBegin := time.Now()
	for time.Now().Sub(dtBegin).Milliseconds() < duration.Milliseconds() && !c.stopping {
		time.Sleep(100)
	}
}

func (c *PeerConnection) ProcessTransaction(transaction *xchg.Transaction) {
	fmt.Println("ProcessTransaction", transaction.FrameType)
	switch transaction.ProtocolVersion {
	case 0x01:
		switch transaction.FrameType {
		case xchg.FrameInit2:
			c.processInit2(transaction)
		case xchg.FrameInit3:
			c.processInit3(transaction)
		case xchg.FrameInit6:
			c.processInit6(transaction)

		case xchg.FrameCall:
			c.processCall(transaction)
		case xchg.FrameResponse:
			c.processResponse(transaction)
		case xchg.FrameError:
			c.processError(transaction)
		}
	default:
		c.connection.SendError(transaction, errors.New(ERR_XCHG_PEER_CONN_WRONG_PROT_VERSION))
	}
}

func (c *PeerConnection) processInit2(transaction *xchg.Transaction) {
	c.mtxEdgeConnection.Lock()
	defer c.mtxEdgeConnection.Unlock()

	var err error
	c.remotePublicKey, err = crypt_tools.RSAPublicKeyFromDer(transaction.Data)
	if err != nil {
		return
	}
	c.init2Received = true
}

func (c *PeerConnection) processInit3(transaction *xchg.Transaction) {
	c.mtxEdgeConnection.Lock()
	defer c.mtxEdgeConnection.Unlock()

	var err error
	c.remoteSecretBytes, err = rsa.DecryptPKCS1v15(rand.Reader, c.privateKey, transaction.Data)
	if err != nil {
		return
	}
	c.init3Received = true
}

func (c *PeerConnection) processInit6(transaction *xchg.Transaction) {
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

func (c *PeerConnection) processError(transaction *xchg.Transaction) {
	err := errors.New(ERR_XCHG_PEER_CONN_RCVD_ERR + ":" + string(transaction.Data))
	c.setTransactionResponse(transaction.TransactionId, nil, err)
	c.reset()
}

func (c *PeerConnection) processCall(transaction *xchg.Transaction) {
	var processor EdgeConnectionProcessor
	c.mtxEdgeConnection.Lock()
	processor = c.processor
	c.mtxEdgeConnection.Unlock()
	if processor != nil {
		resp := processor.OnEdgeReceivedCall(c, transaction.SessionId, transaction.Data)
		c.connection.Send(xchg.NewTransaction(xchg.FrameResponse, 0, transaction.TransactionId, 0, resp))
	}
}

func (c *PeerConnection) processResponse(transaction *xchg.Transaction) {
	c.setTransactionResponse(transaction.TransactionId, transaction.Data, nil)
}

func (c *PeerConnection) setTransactionResponse(transactionId uint64, data []byte, err error) {
	c.mtxEdgeConnection.Lock()
	defer c.mtxEdgeConnection.Unlock()

	if t, ok := c.outgoingTransactions[transactionId]; ok {
		t.Result = data
		t.Err = err
		t.Complete = true
	}
}

func (c *PeerConnection) thBackground() {
	for !c.stopping {
		c.checkConnection()
		if !c.init6Received {
			c.waitDurationOrStopping(10 * time.Millisecond)
		} else {
			c.waitDurationOrStopping(100 * time.Millisecond)
		}
	}
}

func (c *PeerConnection) checkConnection() {
	c.mtxEdgeConnection.Lock()
	defer c.mtxEdgeConnection.Unlock()

	if !c.init1Sent {
		c.init1Sent = true
		c.connection.Send(xchg.NewTransaction(xchg.FrameInit1, 0, 0, 0, crypt_tools.RSAPublicKeyToDer(c.publicKey)))
		return
	}

	if c.init2Received && c.init3Received && !c.init4Sent && c.remotePublicKey != nil {
		c.init4Sent = true
		remoteSecretBytesEcrypted, err := rsa.EncryptPKCS1v15(rand.Reader, c.remotePublicKey, c.remoteSecretBytes)
		if err == nil {
			c.connection.Send(xchg.NewTransaction(xchg.FrameInit4, 0, 0, 0, remoteSecretBytesEcrypted))
		}
		return
	}

	if c.init2Received && !c.init5Sent && c.remotePublicKey != nil {
		c.init5Sent = true
		localSecretBytesEcrypted, err := rsa.EncryptPKCS1v15(rand.Reader, c.remotePublicKey, c.localSecretBytes)
		if err == nil {
			c.connection.Send(xchg.NewTransaction(xchg.FrameInit5, 0, 0, 0, localSecretBytesEcrypted))
		}
		return
	}
}

func (c *PeerConnection) RequestSID(address string) (sid uint64, err error) {
	res, err := c.executeTransaction(xchg.FrameResolveAddress, 0, 0, base58.Decode(address), 1000*time.Millisecond)
	if err != nil {
		return 0, err
	}
	if len(res) != 8 {
		return 0, errors.New(ERR_XCHG_PEER_CONN_REQ_SID_SIZE)
	}
	sid = binary.LittleEndian.Uint64(res)
	return
}

func (c *PeerConnection) Call(sid uint64, sessionId uint64, frame []byte) (result []byte, err error) {
	result, err = c.executeTransaction(xchg.FrameCall, sid, sessionId, frame, 1000*time.Millisecond)
	return
}

func (c *PeerConnection) executeTransaction(frameType byte, targetSID uint64, sessionId uint64, data []byte, timeout time.Duration) (result []byte, err error) {
	// Get transaction ID
	var transactionId uint64
	c.mtxEdgeConnection.Lock()
	transactionId = c.nextTransactionId
	c.nextTransactionId++

	// Create transaction
	t := xchg.NewTransaction(frameType, targetSID, transactionId, sessionId, data)
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
		if t.Complete {
			// Transaction complete
			c.mtxEdgeConnection.Lock()
			delete(c.outgoingTransactions, t.TransactionId)
			c.mtxEdgeConnection.Unlock()

			// Error recevied
			if t.Err != nil {
				result = nil
				err = t.Err
				return
			}

			// Success
			result = t.Result
			err = nil
			return
		}
		time.Sleep(time.Duration(waitingTick) * time.Millisecond)
	}

	// Clear transactions map
	c.mtxEdgeConnection.Lock()
	delete(c.outgoingTransactions, t.TransactionId)
	c.mtxEdgeConnection.Unlock()

	return nil, errors.New(ERR_XCHG_PEER_CONN_TR_TIMEOUT)
}

const (
	ERR_XCHG_PEER_CONN_LOSS               = "{ERR_XCHG_PEER_CONN_LOSS}"
	ERR_XCHG_PEER_CONN_TR_TIMEOUT         = "{ERR_XCHG_PEER_CONN_TR_TIMEOUT}"
	ERR_XCHG_PEER_CONN_REQ_SID_SIZE       = "{ERR_XCHG_PEER_CONN_REQ_SID_SIZE}"
	ERR_XCHG_PEER_CONN_WRONG_PROT_VERSION = "{ERR_XCHG_PEER_CONN_WRONG_PROT_VERSION}"
	ERR_XCHG_PEER_CONN_RCVD_ERR           = "{ERR_XCHG_PEER_CONN_RCVD_ERR}"
)
