package core

import (
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

	aesKey []byte

	mtx       sync.Mutex
	lastGetDT time.Time

	config config.Config
}

func NewListener(id uint64, publicKey []byte, config config.Config) *Listener {
	var c Listener
	c.config = config
	c.id = id
	c.publicKey = publicKey
	c.snakeCounter = snake_counter.NewSnakeCounter(100, 0)
	c.unsentRequests = make([]*Transaction, 0)
	c.sentRequests = make(map[uint64]*Transaction)
	c.maxMessagesQueueSize = config.Core.MaxQueueSize
	c.maxMessageDataSize = config.Core.MaxFrameSize
	return &c
}

func (c *Listener) ExecRequest(msg *Transaction) (responseData []byte, err error) {
	err = c.Push(msg)
	if err != nil {
		return
	}

	timeout := 3 * time.Second
	waitingDurationInMilliseconds := timeout.Milliseconds()
	waitingTick := int64(10)
	waitingIterationCount := waitingDurationInMilliseconds / waitingTick

	for i := int64(0); i < waitingIterationCount; i++ {
		if msg.ResponseReceived {
			responseData = msg.ResponseData
			break
		}
		time.Sleep(time.Duration(waitingTick) * time.Millisecond)
	}

	if responseData == nil {
		err = errors.New("xchg<->server - call timeout")
	}

	c.mtx.Lock()
	delete(c.sentRequests, msg.transactionId)
	c.mtx.Unlock()

	return
}

func (c *Listener) Push(message *Transaction) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if len(c.unsentRequests) >= c.maxMessagesQueueSize {
		return errors.New("queue overflow")
	}
	if len(message.Data) > c.maxMessageDataSize {
		return errors.New("too much data: " + fmt.Sprint(len(message.Data)))
	}

	c.unsentRequests = append(c.unsentRequests, message)

	return nil
}

func (c *Listener) SetResponse(transactionId uint64, responseData []byte) {
	c.mtx.Lock()
	// find request
	tr, ok := c.sentRequests[transactionId]
	if ok && tr != nil {
		tr.ResponseData = responseData
		tr.ResponseReceived = true
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
