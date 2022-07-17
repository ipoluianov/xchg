package core

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
)

type CallStat struct {
	Received           int64 `json:"received"`
	ErrorsDataLen      int64 `json:"errors_data_len"`
	ErrorsNoListener   int64 `json:"errors_no_listener"`
	Processed          int64 `json:"processed"`
	ProcessedWithError int64 `json:"processed_with_error"`
}

// Call remote function
// Frame:
// LID = [0:8]
// Data = [8:]
func (c *Core) Call(_ context.Context, data []byte) (response []byte, err error) {
	c.mtx.Lock()
	c.statistics.Call.Received++
	c.mtx.Unlock()

	// Get LID
	if len(data) < 8 {
		err = errors.New("len(data) < 8")
		c.mtx.Lock()
		c.statistics.Call.ErrorsDataLen++
		c.mtx.Unlock()
		return
	}
	LID := binary.LittleEndian.Uint64(data)

	// Get data
	transactionData := data[8:]

	// Find Listener by LID
	var lFound bool
	var l *Listener
	c.mtx.Lock()
	l, lFound = c.listenersByIndex[LID]
	c.mtx.Unlock()

	// No listener found
	if !lFound || l == nil {
		err = errors.New("no listener found")
		c.mtx.Lock()
		c.statistics.Call.ErrorsNoListener++
		c.mtx.Unlock()
		return
	}

	// Make transaction
	c.mtx.Lock()
	transactionId := c.nextTransactionId
	c.nextTransactionId++
	c.mtx.Unlock()
	msg := NewTransaction(transactionId, transactionData)

	// Run transaction
	response, err = l.ExecRequest(msg)

	// Check transaction execution result
	c.mtx.Lock()
	if err == nil {
		c.statistics.Call.Processed++
	} else {
		c.statistics.Call.ProcessedWithError++
	}
	c.mtx.Unlock()

	if len(response) == 0 {
		fmt.Println("NULL RESPO")
	}

	return
}
