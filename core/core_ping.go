package core

import (
	"context"
	"encoding/binary"
	"errors"
)

type PingStat struct {
	Received      int64 `json:"received"`
	ErrorsNoRoute int64 `json:"errors_no_route"`
	Success       int64 `json:"success"`
}

// Find server with PublicKey and return its LID
// Frame:
// PublicKey = [0:]
// Response:
// LID = [0:8]
func (c *Core) Ping(_ context.Context, data []byte) (result []byte, err error) {
	var l *Listener
	listenerFound := false
	c.mtx.Lock()
	c.statistics.Ping.Received++
	l, listenerFound = c.listenersByAddr[string(data)]
	if !listenerFound {
		err = errors.New("no route to host")
		c.statistics.Ping.ErrorsNoRoute++
	} else {
		result = make([]byte, 8)
		binary.LittleEndian.PutUint64(result, l.id) // LID
		c.statistics.Ping.Success++
	}
	c.mtx.Unlock()
	return
}
