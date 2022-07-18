package core

import (
	"context"
	"encoding/binary"
	"errors"
	"time"
)

type CallStat struct {
	Received           int64 `json:"received"`
	ErrorsDataLen      int64 `json:"errors_data_len"`
	ErrorsNoListener   int64 `json:"errors_no_listener"`
	Processed          int64 `json:"processed"`
	ProcessedWithError int64 `json:"processed_with_error"`

	TempDuration float64 `json:"duration"`
}

// Call remote function
// Frame:
// LID = [0:8]
// Data = [8:]
func (c *Core) Call(_ context.Context, data []byte) (response []byte, err error) {
	dt1 := time.Now()
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
	dt2 := time.Now()

	// Run transaction
	response, err = l.ExecRequest(msg)

	dt3 := time.Now()
	// Check transaction execution result
	c.mtx.Lock()
	if err == nil {
		c.statistics.Call.Processed++
	} else {
		c.statistics.Call.ProcessedWithError++
	}
	dt4 := time.Now()
	d1 := dt2.Sub(dt1)
	d2 := dt4.Sub(dt3)
	dSec := d1.Seconds() + d2.Seconds()
	c.statistics.Call.TempDuration = dSec * 1000000.0
	c.mtx.Unlock()

	return
}
