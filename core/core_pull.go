package core

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
)

type PullStat struct {
	Received         int64 `json:"received"`
	ErrorsDataLen1   int64 `json:"errors_datalen_1"`
	ErrorsNoListener int64 `json:"errors_no_listener"`
	ErrorsDecrypt    int64 `json:"errors_decrypt"`
	ErrorsDataLen2   int64 `json:"errors_datalen_2"`
	ErrorsWrongNonce int64 `json:"errors_wrong_nonce"`
	ErrorsEncrypt    int64 `json:"errors_encrypt"`
}

// Get next Transactions for processing
// Using by servers
// Frame:
// LID = [0:8]
// EncryptedData = [8:]
//
// EncryptedData:
// Nonce = [0:8]
// Max Bytes Count = [8:12]
func (c *Core) Pull(ctx context.Context, data []byte) (result []byte, err error) {
	c.mtx.Lock()
	c.statistics.Pull.Received++
	c.mtx.Unlock()

	// Get LID
	if len(data) < 8 {
		err = errors.New("len(data) < 8")
		c.mtx.Lock()
		c.statistics.Pull.ErrorsDataLen1++
		c.mtx.Unlock()
		return
	}
	LID := binary.LittleEndian.Uint64(data)

	// Get listener
	var lFound bool
	var l *Listener
	c.mtx.Lock()
	l, lFound = c.listenersByIndex[LID]
	c.mtx.Unlock()

	// No listener found
	if !lFound || l == nil {
		err = errors.New("no listener found")
		c.mtx.Lock()
		c.statistics.Pull.ErrorsNoListener++
		c.mtx.Unlock()
		return
	}

	// Calculate AES key for the PublicKey of the Listener
	aesKey := c.calcAddrKey(l.publicKey)

	// Get encrypted data
	encryptedData := data[8:]

	// Decrypt data
	var request []byte
	request, err = crypt_tools.DecryptAESGCM(encryptedData, aesKey)
	if err != nil {
		c.mtx.Lock()
		c.statistics.Pull.ErrorsDecrypt++
		c.mtx.Unlock()
		return
	}

	// Get fields
	if len(request) < 12 {
		err = errors.New("len(request) < 12")
		c.mtx.Lock()
		c.statistics.Pull.ErrorsDataLen2++
		c.mtx.Unlock()
		return
	}
	nonce := binary.LittleEndian.Uint64(request)
	maxResponseSizeBytes := int(binary.LittleEndian.Uint32(request[8:]))
	_ = maxResponseSizeBytes

	// Test nonce
	err = l.snakeCounter.TestAndDeclare(int(nonce))
	if err != nil {
		c.mtx.Lock()
		c.statistics.Pull.ErrorsWrongNonce++
		c.mtx.Unlock()
		return nil, errors.New("wrong nonce")
	}

	// Prepare time durations
	waitingDurationInMilliseconds := int64(c.config.Http.LongPollingTimeoutMs)
	waitingTick := int64(20)
	waitingIterationCount := waitingDurationInMilliseconds / waitingTick

	// Get enqueued transactions
	var frames []*Transaction
	for i := int64(0); i < waitingIterationCount; i++ {
		frames = l.Pull(maxResponseSizeBytes)
		if ctx.Err() != nil {
			break
		}
		if len(frames) < 1 {
			time.Sleep(time.Duration(waitingTick) * time.Millisecond)
			continue
		}
		break
	}

	// Serialize transactions
	{
		sizeOfResponse := 0
		// Calculate size of buffer
		for _, frame := range frames {
			sizeOfResponse += 4               // Size of chunk, including this field
			sizeOfResponse += 8               // Transaction ID
			sizeOfResponse += len(frame.Data) // Data
		}
		framesBS := make([]byte, sizeOfResponse)

		// Put transactions to the buffer
		offset := 0
		for _, frame := range frames {
			binary.LittleEndian.PutUint32(framesBS[offset:], uint32(len(frame.Data)+12)) // Size of chunk
			binary.LittleEndian.PutUint64(framesBS[offset+4:], frame.transactionId)      // Transaction ID

			copy(framesBS[offset+12:], frame.Data) // Data

			// Increment Offset
			offset += 12              // Header
			offset += len(frame.Data) // Data
		}

		// Encrypt response
		result, err = crypt_tools.EncryptAESGCM(framesBS, aesKey)
		if err != nil {
			c.mtx.Lock()
			c.statistics.Pull.ErrorsEncrypt++
			c.mtx.Unlock()
			return
		}
	}

	return
}
