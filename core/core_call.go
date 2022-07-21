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
func (c *Core) Call(_ context.Context, data []byte, binConnection BinConnection, signature uint32) (response []byte, err error) {
	c.mtx.Lock()
	c.statistics.Call.Received++
	transactionId := c.nextTransactionId
	c.nextTransactionId++

	// Get LID
	if len(data) < 8 {
		err = errors.New("len(data) < 8")
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
	l, lFound = c.listenersByIndex[LID]

	// No listener found
	if !lFound || l == nil {
		err = errors.New("#NO_LISTENER_FOUND#" + fmt.Sprint(LID))
		c.statistics.Call.ErrorsNoListener++
		c.mtx.Unlock()
		return
	}
	c.mtx.Unlock()

	// Make transaction
	msg := NewTransaction(transactionId, transactionData, binConnection, signature)

	// Run transaction
	response, err = l.ExecRequest(msg)

	// Check transaction execution result
	if err != nil {
		c.mtx.Lock()
		c.statistics.Call.ProcessedWithError++
		c.mtx.Unlock()
	}

	return
}
