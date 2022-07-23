package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ipoluianov/gomisc/snake_counter"
	"github.com/ipoluianov/xchg/config"
)

type Listener struct {
	id                   uint64
	publicKey            []byte
	snakeCounter         *snake_counter.SnakeCounter
	maxMessagesQueueSize int
	maxMessageDataSize   int

	nextTransactionId uint64
	unsentRequests    []*Transaction
	sentRequests      map[uint64]*Transaction

	binConnection BinConnection

	//aesKey []byte

	mtx       sync.Mutex
	lastGetDT time.Time

	config config.Config
}

func NewListener(id uint64, publicKey []byte, config config.Config, binConnection BinConnection) *Listener {
	var c Listener
	c.config = config
	c.id = id
	c.binConnection = binConnection
	c.publicKey = publicKey
	c.snakeCounter = snake_counter.NewSnakeCounter(100, 0)
	c.unsentRequests = make([]*Transaction, 0)
	c.sentRequests = make(map[uint64]*Transaction)
	c.maxMessagesQueueSize = config.Core.MaxQueueSize
	c.maxMessageDataSize = config.Core.MaxFrameSize
	return &c
}

func (c *Listener) ExecRequest(transaction *Transaction) (responseData []byte, err error) {
	c.mtx.Lock()
	binConnection := c.binConnection
	sentDirect := false

	// Direct send
	if binConnection != nil && binConnection.IsValid() {
		framesBS := make([]byte, 12+len(transaction.Data))
		binary.LittleEndian.PutUint32(framesBS[0:], uint32(len(transaction.Data)+12)) // Size of chunk
		binary.LittleEndian.PutUint64(framesBS[4:], transaction.transactionId)        // Transaction ID
		copy(framesBS[12:], transaction.Data)                                         // Data
		//framesBS, err = crypt_tools.EncryptAESGCM(framesBS, c.aesKey)
		//if err == nil {
		c.sentRequests[transaction.transactionId] = transaction
		c.mtx.Unlock()
		binConnection.Send(framesBS, 0x000000AA, nil)

		sentDirect = true
		//}
	}

	if !sentDirect {
		// Send via Queue
		if len(c.unsentRequests) >= c.maxMessagesQueueSize {
			c.mtx.Unlock()
			err = errors.New("queue overflow")
			return
		}
		if len(transaction.Data) > c.maxMessageDataSize {
			c.mtx.Unlock()
			err = errors.New("too much data: " + fmt.Sprint(len(transaction.Data)))
			return
		}
		c.unsentRequests = append(c.unsentRequests, transaction)
		c.mtx.Unlock()
	}

	return
}

func (c *Listener) SetResponse(transactionId uint64, responseData []byte) {
	c.mtx.Lock()
	tr, ok := c.sentRequests[transactionId]
	if ok && tr != nil {
		tr.ResponseData = responseData
		tr.ResponseReceived = true

		if tr.binConnection != nil {
			//fmt.Println("SetResp", tr.signature, responseData)
			tr.binConnection.Send(responseData, tr.signature, nil)
		}
		delete(c.sentRequests, tr.transactionId)
	}
	c.mtx.Unlock()
}

func (c *Listener) Pull(maxResponseSizeBytes int) (messages []*Transaction) {
	messages = make([]*Transaction, 0)
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.lastGetDT = time.Now()

	summarySize := 0
	processedTransactions := 0
	for _, t := range c.unsentRequests {
		if summarySize+len(t.Data) > maxResponseSizeBytes {
			break
		}
		summarySize += len(t.Data)
		messages = append(messages, t)
		c.sentRequests[t.transactionId] = t
		processedTransactions++
	}
	c.unsentRequests = c.unsentRequests[processedTransactions:]

	return
}

func (c *Listener) LastGetDT() time.Time {
	return c.lastGetDT
}
