package core

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

type Listener struct {
	id                   uint64
	publicKey            []byte
	lastCounter          uint64
	maxMessagesQueueSize int
	maxMessageDataSize   int

	nextTransactionId uint64
	unsentRequests    []*Request
	sentRequests      []*Request

	mtx       sync.Mutex
	lastGetDT time.Time
}

func NewListener(id uint64, publicKey []byte) *Listener {
	var c Listener
	c.id = id
	c.publicKey = publicKey
	c.lastCounter = 0
	c.unsentRequests = make([]*Request, 0)
	c.sentRequests = make([]*Request, 0)
	c.maxMessagesQueueSize = 10
	c.maxMessageDataSize = 10 * 1024 * 1024
	return &c
}

func (c *Listener) ExecRequest(msg *Request) (responseData []byte, err error) {
	err = c.Push(msg)
	if err != nil {
		return
	}

	timeout := 3 * time.Second
	waitingDurationInMilliseconds := timeout.Milliseconds()
	waitingTick := int64(100)
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
	for i, req := range c.unsentRequests {
		if req.transactionId == msg.transactionId {
			c.unsentRequests = append(c.unsentRequests[:i], c.unsentRequests[i+1:]...)
			break
		}
	}
	for i, req := range c.sentRequests {
		if req.transactionId == msg.transactionId {
			c.sentRequests = append(c.sentRequests[:i], c.sentRequests[i+1:]...)
			break
		}
	}
	c.mtx.Unlock()

	return
}

func (c *Listener) Push(message *Request) error {
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
	for _, req := range c.sentRequests {
		if req.transactionId == transactionId {
			//fmt.Println("Listener SetResponse", transactionId)
			req.ResponseData = responseData
			req.ResponseReceived = true
			//c.messages = append(c.messages[:reqIndex], c.messages[reqIndex+1])
			break
		}
	}
	c.mtx.Unlock()
}

func (c *Listener) Pull() (message *Request) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.lastGetDT = time.Now()
	if len(c.unsentRequests) > 0 {
		message = c.unsentRequests[0]
		c.unsentRequests = c.unsentRequests[1:]
		c.sentRequests = append(c.sentRequests, message)
	}
	return
}

func (c *Listener) LastGetDT() time.Time {
	return c.lastGetDT
}
