package xchg_router

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/xchg/xchg"
)

type RouterConnection struct {
	xchg.Connection
	id uint64

	mtxRouterConnection sync.Mutex
	router              *Router

	transactions map[uint64]*xchg.Transaction

	localSecretBytes []byte

	// Remote Address
	remotePublicKey        *rsa.PublicKey
	remotePublicKeyBS      []byte
	confirmedRemoteAddress string

	// Local Address
	privateKey *rsa.PrivateKey

	configMaxAddressSize int

	init1Received bool
	init4Received bool
	init5Received bool

	statSetResponseCounter                 uint64
	statSetResponseErrNoTransactionCounter uint64
	statWorkerRemoveTransactionCounter     uint64
	statBeginTransactionCounter            uint64

	createdDT time.Time
}

type RouterConnectionState struct {
	Id                     uint64 `json:"id"`
	ConfirmedRemoteAddress string `json:"confirmed_remote_address"`
	Init1Received          bool   `json:"init1_received"`
	Init4Received          bool   `json:"init4_received"`
	Init5Received          bool   `json:"init5_received"`

	BaseConnection xchg.ConnectionState `json:"base"`

	StatBeginTransactionCounter            uint64 `json:"stat_begin_transaction_counter"`
	StatSetResponseCounter                 uint64 `json:"stat_set_response_counter"`
	StatSetResponseErrNoTransactionCounter uint64 `json:"stat_set_response_err_no_transaction_counter"`
	StatWorkerRemoveTransactionCounter     uint64 `json:"stat_worker_remove_transaction_counter"`

	NextTransactionId uint64   `json:"next_transaction_id"`
	TransactionsCount int      `json:"transactions_count"`
	Transactions      []string `json:"transactions"`
}

func NewRouterConnection(conn net.Conn, router *Router, privateKey *rsa.PrivateKey) *RouterConnection {
	var c RouterConnection
	c.configMaxAddressSize = 1024
	c.router = router
	c.privateKey = privateKey
	c.localSecretBytes = make([]byte, 32)
	rand.Read(c.localSecretBytes)
	c.InitIncomingConnection(conn, &c, "router")
	c.createdDT = time.Now()
	//c.nextTransactionId = 1
	c.transactions = make(map[uint64]*xchg.Transaction)
	return &c
}

func (c *RouterConnection) Id() uint64 {
	c.mtxRouterConnection.Lock()
	defer c.mtxRouterConnection.Unlock()
	return c.id
}

func (c *RouterConnection) RemotePublicKeyBS() []byte {
	c.mtxRouterConnection.Lock()
	defer c.mtxRouterConnection.Unlock()
	return c.remotePublicKeyBS
}

func (c *RouterConnection) ProcessTransaction(transaction *xchg.Transaction) {
	switch transaction.ProtocolVersion {
	case 0x01:
		switch transaction.FrameType {
		case xchg.FrameInit1:
			c.processInit1(transaction)
		case xchg.FrameInit4:
			c.processInit4(transaction)
		case xchg.FrameInit5:
			c.processInit5(transaction)
		case xchg.FrameResolveAddress:
			c.processResolveAddress(transaction)
		case xchg.FrameCall:
			c.processCall(transaction)
		case xchg.FrameResponse:
			c.processResponse(transaction)
		default:
			c.SendError(transaction, errors.New(xchg.ERR_XCHG_ROUTER_CONN_WRONG_FRAME_TYPE))
		}
	default:
		c.SendError(transaction, errors.New(xchg.ERR_XCHG_ROUTER_CONN_WRONG_PROTOCOL_VERSION))
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

func (c *RouterConnection) processInit1(transaction *xchg.Transaction) {
	var err error

	if len(transaction.Data) > c.configMaxAddressSize {
		c.SendError(transaction, errors.New(xchg.ERR_XCHG_ROUTER_CONN_WRONG_PUBLIC_KEY_SIZE))
		return
	}

	// Parse PublicKey-DER
	var rsaPublicKey *rsa.PublicKey
	rsaPublicKey, err = x509.ParsePKCS1PublicKey(transaction.Data)
	if err != nil {
		c.SendError(transaction, err)
		return
	}

	c.mtxRouterConnection.Lock()
	c.remotePublicKey = rsaPublicKey
	c.remotePublicKeyBS = crypt_tools.RSAPublicKeyToDer(c.remotePublicKey)
	localAddressBS := c.router.localPublicKeyBS
	localSecretBytes := c.localSecretBytes
	c.init1Received = true
	c.mtxRouterConnection.Unlock()

	// Send Init2 (my address)
	c.Send(xchg.NewTransaction(xchg.FrameInit2, 0, 0, 0, localAddressBS))

	// Send Init3
	{
		var encryptedLocalSecret []byte
		encryptedLocalSecret, err = rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, localSecretBytes)
		if err != nil {
			c.SendError(transaction, errors.New(xchg.ERR_XCHG_ROUTER_CONN_ENC+":"+err.Error()))
			return
		}
		c.Send(xchg.NewTransaction(xchg.FrameInit3, 0, 0, 0, encryptedLocalSecret))
	}
}

func (c *RouterConnection) processInit4(transaction *xchg.Transaction) {
	c.mtxRouterConnection.Lock()
	privateKey := c.privateKey
	localSecretBytes := c.localSecretBytes
	remotePublicKey := c.remotePublicKey
	c.mtxRouterConnection.Unlock()

	receivedSecretBytes, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, transaction.Data)
	if err != nil {
		err = errors.New(xchg.ERR_XCHG_ROUTER_CONN_DECR4 + ":" + err.Error())
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
	confirmedRemoteAddress := xchg.AddressForPublicKey(remotePublicKey)
	c.confirmedRemoteAddress = confirmedRemoteAddress
	c.mtxRouterConnection.Unlock()

	c.router.setAddressForConnection(c, confirmedRemoteAddress)
}

func (c *RouterConnection) processInit5(transaction *xchg.Transaction) {
	c.mtxRouterConnection.Lock()
	privateKey := c.privateKey
	remotePublicKey := c.remotePublicKey
	c.mtxRouterConnection.Unlock()

	var err error
	var remoteSecretBytes []byte
	remoteSecretBytes, err = rsa.DecryptPKCS1v15(rand.Reader, privateKey, transaction.Data)
	if err != nil {
		err = errors.New(xchg.ERR_XCHG_ROUTER_CONN_DECR5 + ":" + err.Error())
		return
	}

	c.mtxRouterConnection.Lock()
	c.init5Received = true
	c.mtxRouterConnection.Unlock()

	remoteSecretBytesEcrypted, err := rsa.EncryptPKCS1v15(rand.Reader, remotePublicKey, remoteSecretBytes)
	if err == nil {
		c.Send(xchg.NewTransaction(xchg.FrameInit6, 0, 0, 0, remoteSecretBytesEcrypted))
	}
}

func (c *RouterConnection) processResolveAddress(transaction *xchg.Transaction) {
	connection := c.router.getConnectionByAddress(string(transaction.Data))
	if connection == nil {
		c.SendError(transaction, errors.New(xchg.ERR_XCHG_ROUTER_CONN_NO_ROUTE_TO_PEER))
		return
	}
	publicKey := connection.RemotePublicKeyBS()
	data := make([]byte, 8+len(publicKey))
	binary.LittleEndian.PutUint64(data, connection.Id())
	copy(data[8:], publicKey)
	c.Send(xchg.NewTransaction(xchg.FrameResponse, 0, transaction.TransactionId, 0, data))
}

func (c *RouterConnection) processCall(transaction *xchg.Transaction) {
	connection := c.router.getConnectionById(transaction.SID)
	if connection == nil {
		c.SendError(transaction, errors.New(xchg.ERR_XCHG_ROUTER_CONN_NO_ROUTE_TO_PEER))
		return
	}

	transaction.AddressSrc = c.confirmedRemoteAddress
	transaction.AddressDest = connection.confirmedRemoteAddress
	transaction.SID = c.id // Source SID

	atomic.AddUint64(&c.statBeginTransactionCounter, 1)

	c.mtxRouterConnection.Lock()
	transaction.BeginDT = time.Now()
	transaction.WaitingResponseFromSID = connection.id
	c.transactions[transaction.TransactionId] = transaction
	c.mtxRouterConnection.Unlock()

	transaction.ResponseSender = c
	connection.Send(transaction)
}

func (c *RouterConnection) processResponse(transaction *xchg.Transaction) {
	connection := c.router.getConnectionById(transaction.SID)
	if connection == nil {
		return
	}
	transaction.SID = c.id // Received Response from
	connection.SetResponse(transaction)
}

func (c *RouterConnection) clearTransactions() {
	now := time.Now()
	for key, t := range c.transactions {
		duration := now.Sub(t.BeginDT)
		if duration > 10*time.Second {
			atomic.AddUint64(&c.statWorkerRemoveTransactionCounter, 1)
			delete(c.transactions, key)
		}
	}
}

func (c *RouterConnection) SetResponse(transaction *xchg.Transaction) {
	atomic.AddUint64(&c.statSetResponseCounter, 1)
	c.mtxRouterConnection.Lock()
	originalTransaction, ok := c.transactions[transaction.TransactionId]
	if !ok || originalTransaction == nil {
		atomic.AddUint64(&c.statSetResponseErrNoTransactionCounter, 1)
		c.mtxRouterConnection.Unlock()
		return
	}
	if originalTransaction.WaitingResponseFromSID != transaction.SID {
		c.mtxRouterConnection.Unlock()
		return
	}

	delete(c.transactions, transaction.TransactionId)
	c.mtxRouterConnection.Unlock()

	originalTransaction.ResponseSender.Send(xchg.NewTransaction(xchg.FrameResponse, 0, transaction.TransactionId, transaction.SessionId, transaction.Data))
}

func (c *RouterConnection) State() (state RouterConnectionState) {
	c.mtxRouterConnection.Lock()
	state.Id = c.id
	state.ConfirmedRemoteAddress = c.confirmedRemoteAddress
	state.Init1Received = c.init1Received
	state.Init4Received = c.init4Received
	state.Init5Received = c.init5Received

	state.Transactions = make([]string, 0, len(c.transactions))
	state.TransactionsCount = len(c.transactions)

	state.StatBeginTransactionCounter = atomic.LoadUint64(&c.statBeginTransactionCounter)
	state.StatSetResponseCounter = atomic.LoadUint64(&c.statSetResponseCounter)
	state.StatSetResponseErrNoTransactionCounter = atomic.LoadUint64(&c.statSetResponseErrNoTransactionCounter)
	state.StatWorkerRemoveTransactionCounter = atomic.LoadUint64(&c.statWorkerRemoveTransactionCounter)

	transactions := make([]*xchg.Transaction, 0, len(c.transactions))
	for _, t := range c.transactions {
		transactions = append(transactions, t)
	}

	c.mtxRouterConnection.Unlock()
	sort.Slice(transactions, func(i, j int) bool {
		return transactions[i].TransactionId < transactions[j].TransactionId
	})

	for _, t := range transactions {
		state.Transactions = append(state.Transactions, t.String())
	}

	state.BaseConnection = c.Connection.State()
	return
}
