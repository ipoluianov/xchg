package xchg_connections

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/xchg/xchg"
)

type PeerConnection struct {
	internalId string
	node       string

	mtxEdgeConnection sync.Mutex
	connection        *xchg.Connection

	started  bool
	stopping bool

	// Local Address
	publicKey    *rsa.PublicKey
	privateKey   *rsa.PrivateKey
	localAddress string

	// Remote Address
	remotePublicKey *rsa.PublicKey
	remoteAddress   string

	localSecretBytes  []byte
	remoteSecretBytes []byte

	incomingTransactions map[string]*xchg.Transaction

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

type PeerConnectionState struct {
	BaseConnection xchg.ConnectionState

	LocalAddress  string
	RemoveAddress string

	Started  bool
	Stopping bool

	ActiveTransactionsCount int
	NextTransactionId       uint64

	Init1Sent     bool
	Init2Received bool
	Init3Received bool
	Init4Sent     bool
	Init5Sent     bool
	Init6Received bool
}

type EdgeConnectionProcessor interface {
	onEdgeConnected(edgeConnection *PeerConnection)
	onEdgeDissonnected(edgeConnection *PeerConnection)
	onEdgeReceivedCall(edgeConnection *PeerConnection, sessionId uint64, data []byte) (response []byte)
}

func NewPeerConnection(xchgNode string, localAddress *rsa.PrivateKey, processor EdgeConnectionProcessor, internalId string) *PeerConnection {
	var c PeerConnection

	c.internalId = internalId

	c.node = xchgNode
	c.connection = xchg.NewConnection()
	c.connection.InitOutgoingConnection(c.node, &c, "peer/"+c.internalId)
	c.nextTransactionId = 1
	c.outgoingTransactions = make(map[uint64]*xchg.Transaction)
	c.incomingTransactions = make(map[string]*xchg.Transaction)
	c.processor = processor

	if localAddress != nil {
		c.privateKey = localAddress
		c.publicKey = &c.privateKey.PublicKey
	}

	c.fastReset()
	return &c
}

func (c *PeerConnection) Dispose() {
	c.processor = nil
	c.mtxEdgeConnection.Lock()
	connection := c.connection
	c.mtxEdgeConnection.Unlock()
	if connection != nil {
		c.connection.Dispose()
		c.mtxEdgeConnection.Lock()
		c.connection = nil
		c.mtxEdgeConnection.Unlock()
	}
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

func (c *PeerConnection) IsConnected() bool {
	return c.init6Received
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
			t.Err = errors.New(xchg.ERR_XCHG_PEER_CONN_LOSS)
			t.Complete = true
		}
	}

	c.mtxEdgeConnection.Unlock()
}

func (c *PeerConnection) Connected() {
	c.fastReset()
}

func (c *PeerConnection) Disconnected() {
	c.fastReset()
}

func (c *PeerConnection) waitDurationOrStopping(duration time.Duration) {
	dtBegin := time.Now()
	for time.Now().Sub(dtBegin).Milliseconds() < duration.Milliseconds() && !c.stopping {
		time.Sleep(100)
	}
}

func (c *PeerConnection) ProcessTransaction(transaction *xchg.Transaction) {
	//fmt.Println("ProcessTransaction", transaction.FrameType)
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
		c.connection.SendError(transaction, errors.New(xchg.ERR_XCHG_PEER_CONN_WRONG_PROT_VERSION))
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
	err := errors.New(xchg.ERR_XCHG_PEER_CONN_RCVD_ERR + ":" + string(transaction.Data))
	c.setTransactionResponseError(transaction.TransactionId, err)
	c.reset()
}

func (c *PeerConnection) processCall(transaction *xchg.Transaction) {
	var processor EdgeConnectionProcessor
	c.mtxEdgeConnection.Lock()
	processor = c.processor
	var incomingTransaction *xchg.Transaction

	var ok bool
	incomingTransactionCode := fmt.Sprint(transaction.SID, "-", transaction.TransactionId)
	if incomingTransaction, ok = c.incomingTransactions[incomingTransactionCode]; !ok {
		incomingTransaction = xchg.NewTransaction(transaction.FrameType, transaction.SID, transaction.TransactionId, transaction.SessionId, make([]byte, 0))
		incomingTransaction.Offset = 0
		incomingTransaction.TotalSize = transaction.TotalSize
		c.incomingTransactions[incomingTransactionCode] = incomingTransaction
	}

	if len(incomingTransaction.Data) != int(incomingTransaction.TotalSize) {
		incomingTransaction.Data = make([]byte, int(incomingTransaction.TotalSize))
	}
	copy(incomingTransaction.Data[transaction.Offset:], transaction.Data)
	incomingTransaction.ReceivedDataLen += len(transaction.Data)

	if incomingTransaction.ReceivedDataLen < int(incomingTransaction.TotalSize) {
		c.mtxEdgeConnection.Unlock()
		return
	}
	delete(c.incomingTransactions, incomingTransactionCode)
	c.mtxEdgeConnection.Unlock()

	if processor != nil {
		resp := processor.onEdgeReceivedCall(c, incomingTransaction.SessionId, incomingTransaction.Data)
		trResponse := xchg.NewTransaction(xchg.FrameResponse, incomingTransaction.SID, incomingTransaction.TransactionId, incomingTransaction.SessionId, resp)

		offset := 0
		blockSize := 1024
		for offset < len(trResponse.Data) {
			currentBlockSize := blockSize
			restDataLen := len(trResponse.Data) - offset
			if restDataLen < currentBlockSize {
				currentBlockSize = restDataLen
			}

			blockTransaction := xchg.NewTransaction(trResponse.FrameType, trResponse.SID, trResponse.TransactionId, trResponse.SessionId, trResponse.Data[offset:offset+currentBlockSize])
			blockTransaction.Offset = uint32(offset)
			blockTransaction.TotalSize = uint32(len(trResponse.Data))

			err := c.connection.Send(blockTransaction)
			if err != nil {
				break
			}
			offset += currentBlockSize
		}
	}
}

func (c *PeerConnection) processResponse(transaction *xchg.Transaction) {
	c.setTransactionResponse(transaction)
}

func (c *PeerConnection) setTransactionResponseError(transactionId uint64, err error) {
	c.mtxEdgeConnection.Lock()
	defer c.mtxEdgeConnection.Unlock()

	if t, ok := c.outgoingTransactions[transactionId]; ok {
		t.Result = make([]byte, 0)
		t.Err = err
		t.Complete = true
	}
}

func (c *PeerConnection) setTransactionResponse(transaction *xchg.Transaction) {
	c.mtxEdgeConnection.Lock()
	defer c.mtxEdgeConnection.Unlock()

	if t, ok := c.outgoingTransactions[transaction.TransactionId]; ok {
		if transaction.Err == nil {
			if len(t.Result) != int(transaction.TotalSize) {
				t.Result = make([]byte, transaction.TotalSize)
			}
			copy(t.Result[transaction.Offset:], transaction.Data)
			t.ReceivedDataLen += len(transaction.Data)
			if t.ReceivedDataLen >= int(transaction.TotalSize) {
				t.Complete = true
			}
		} else {
			t.Result = transaction.Data
			t.Err = transaction.Err
			t.Complete = true
		}
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

func (c *PeerConnection) checkConnection() (connectionIsReady bool) {
	var err error

	c.mtxEdgeConnection.Lock()
	connection := c.connection
	init1Sent := c.init1Sent
	init2Received := c.init2Received
	init3Received := c.init3Received
	init4Sent := c.init4Sent
	init5Sent := c.init5Sent
	init6Received := c.init6Received
	remotePublicKey := c.remotePublicKey
	remoteSecretBytes := c.remoteSecretBytes
	c.mtxEdgeConnection.Unlock()
	if connection == nil {
		return
	}

	if !init1Sent {
		err = connection.Send(xchg.NewTransaction(xchg.FrameInit1, 0, 0, 0, crypt_tools.RSAPublicKeyToDer(c.publicKey)))
		if err == nil {
			c.mtxEdgeConnection.Lock()
			c.init1Sent = true
			c.mtxEdgeConnection.Unlock()
		}
		return
	}

	if init2Received && init3Received && !init4Sent && remotePublicKey != nil {
		var remoteSecretBytesEcrypted []byte
		remoteSecretBytesEcrypted, err = rsa.EncryptPKCS1v15(rand.Reader, remotePublicKey, remoteSecretBytes)
		if err == nil {
			err = connection.Send(xchg.NewTransaction(xchg.FrameInit4, 0, 0, 0, remoteSecretBytesEcrypted))
			if err == nil {
				c.mtxEdgeConnection.Lock()
				c.init4Sent = true
				c.mtxEdgeConnection.Unlock()
			}
		}
		return
	}

	if init2Received && !init5Sent && remotePublicKey != nil {
		localSecretBytesEcrypted, err := rsa.EncryptPKCS1v15(rand.Reader, c.remotePublicKey, c.localSecretBytes)
		if err == nil {
			err = connection.Send(xchg.NewTransaction(xchg.FrameInit5, 0, 0, 0, localSecretBytesEcrypted))
			if err == nil {
				c.mtxEdgeConnection.Lock()
				c.init5Sent = true
				c.mtxEdgeConnection.Unlock()
			}
		}
		return
	}

	if init6Received {
		connectionIsReady = true
	}

	return
}

func (c *PeerConnection) ResolveAddress(address string) (sid uint64, publicKey *rsa.PublicKey, err error) {
	res, err := c.executeTransaction(xchg.FrameResolveAddress, 0, 0, []byte(address), 1000*time.Millisecond)
	if err != nil {
		return 0, nil, err
	}
	if len(res) < 8 {
		return 0, nil, errors.New(xchg.ERR_XCHG_PEER_CONN_REQ_SID_SIZE)
	}
	sid = binary.LittleEndian.Uint64(res)
	publicKey, err = crypt_tools.RSAPublicKeyFromDer(res[8:])
	if err != nil {
		return 0, nil, err
	}
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
	offset := 0
	blockSize := 1024
	for offset < len(data) {
		currentBlockSize := blockSize
		restDataLen := len(data) - offset
		if restDataLen < currentBlockSize {
			currentBlockSize = restDataLen
		}

		blockTransaction := xchg.NewTransaction(frameType, targetSID, transactionId, sessionId, data[offset:offset+currentBlockSize])
		blockTransaction.Offset = uint32(offset)
		blockTransaction.TotalSize = uint32(len(data))

		err = c.connection.Send(blockTransaction)
		if err != nil {
			c.mtxEdgeConnection.Lock()
			delete(c.outgoingTransactions, t.TransactionId)
			c.mtxEdgeConnection.Unlock()
			return
		}
		offset += currentBlockSize
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

	return nil, errors.New(xchg.ERR_XCHG_PEER_CONN_TR_TIMEOUT)
}

func (c *PeerConnection) State() (state PeerConnectionState) {
	c.mtxEdgeConnection.Lock()
	defer c.mtxEdgeConnection.Unlock()
	if c.connection != nil {
		state.BaseConnection = c.connection.State()
	}

	state.LocalAddress = c.localAddress
	state.RemoveAddress = c.remoteAddress

	state.Started = c.started
	state.Stopping = c.stopping

	state.ActiveTransactionsCount = len(c.outgoingTransactions)
	state.NextTransactionId = c.nextTransactionId

	state.Init1Sent = c.init1Sent
	state.Init2Received = c.init2Received
	state.Init3Received = c.init3Received
	state.Init4Sent = c.init4Sent
	state.Init5Sent = c.init5Sent
	state.Init6Received = c.init6Received
	return
}
