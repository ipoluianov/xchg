package core

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/ipoluianov/gomisc/crypt_tools"
)

type PutStat struct {
	Received         int64 `json:"received"`
	ErrorsDataLen1   int64 `json:"errors_datalen_1"`
	ErrorsNoListener int64 `json:"errors_no_listener"`
	ErrorsDecrypt    int64 `json:"errors_decrypt"`
	ErrorsDataLen2   int64 `json:"errors_datalen_2"`
	Success          int64 `json:"success"`
}

// Put server response for transaction
// Frame:
//
func (c *Core) Put(_ context.Context, data []byte) (err error) {
	c.mtx.Lock()
	c.statistics.Put.Received++
	c.mtx.Unlock()

	// Get LID
	if len(data) < 8 {
		err = errors.New("len(data) < 8")
		c.mtx.Lock()
		c.statistics.Put.ErrorsDataLen1++
		c.mtx.Unlock()
		return
	}
	LID := binary.LittleEndian.Uint64(data)

	// Find listener
	var lFound bool
	var l *Listener
	c.mtx.Lock()
	l, lFound = c.listenersByIndex[LID]
	c.mtx.Unlock()
	if !lFound || l == nil {
		err = errors.New("no listener found")
		c.mtx.Lock()
		c.statistics.Put.ErrorsNoListener++
		c.mtx.Unlock()
		return
	}

	// Calculate AES-keyby PublicKey
	aesKey := c.calcAddrKey(l.publicKey)

	// Decrypt response
	encryptedData := data[8:]
	var decryptedData []byte
	decryptedData, err = crypt_tools.DecryptAESGCM(encryptedData, aesKey)
	if err != nil {
		c.mtx.Lock()
		c.statistics.Put.ErrorsDecrypt++
		c.mtx.Unlock()
		return
	}

	// Get Transaction ID
	if len(decryptedData) < 8 {
		err = errors.New("len(decryptedData) < 8")
		c.mtx.Lock()
		c.statistics.Put.ErrorsDataLen2++
		c.mtx.Unlock()
		return
	}
	transactionId := binary.LittleEndian.Uint64(decryptedData)

	// Set response
	l.SetResponse(transactionId, decryptedData[8:])

	// Success
	c.mtx.Lock()
	c.statistics.Put.Success++
	c.mtx.Unlock()
	return
}
