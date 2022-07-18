package core

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/ipoluianov/gomisc/crypt_tools"
)

type Init2Stat struct {
	Received                int64 `json:"received"`
	ErrorsDataLen1          int64 `json:"errors_datalen_1"`
	ErrorsDataLen2          int64 `json:"errors_datalen_2"`
	ErrorsDataLen3          int64 `json:"errors_datalen_3"`
	ErrorsDataLen4          int64 `json:"errors_datalen_4"`
	ErrorsAESDecrypt        int64 `json:"errors_aes_decrypt"`
	ErrorsPublicKeyMismatch int64 `json:"errors_pk_mismatch"`
	ErrorsAESEncrypt        int64 `json:"errors_aes_encrypt"`
	Success                 int64 `json:"success"`
}

// Initialization of Server - second stage
// Frame:
// OpenPublicKeyLen = [0:4]
// OpenPublicKey = [4:OpenPublicKeyLen + 4]
// EncryptedPublicKey = [OpenPublicKeyLen + 4:]
// Response 16 bytes:
// LID = [0:8]
// Nonce = [8:16]
func (c *Core) Init2(_ context.Context, data []byte) (result []byte, err error) {
	c.mtx.Lock()
	c.statistics.Init2.Received++
	c.mtx.Unlock()

	// Get PublicKey length
	if len(data) < 4 {
		err = errors.New("wrong data len (< 4)")
		c.mtx.Lock()
		c.statistics.Init2.ErrorsDataLen1++
		c.mtx.Unlock()
		return
	}
	publicKeyLength := binary.LittleEndian.Uint32(data)

	// Get PublicKey
	data = data[4:]
	if len(data) < int(publicKeyLength) {
		err = errors.New("wrong data len (< publicKeyLength)")
		c.mtx.Lock()
		c.statistics.Init2.ErrorsDataLen2++
		c.mtx.Unlock()
		return
	}
	publicKey := data[0:publicKeyLength]

	// Getting EncryptedPublicKey
	encryptedPublicKey := data[publicKeyLength:]
	if len(encryptedPublicKey) < 1 {
		err = errors.New("len(encryptedPublicKey) < 1")
		c.mtx.Lock()
		c.statistics.Init2.ErrorsDataLen3++
		c.mtx.Unlock()
		return
	}

	// Decrypting EncryptedPublicKey
	aesKey := c.calcAddrKey(publicKey)
	var decryptedPublicKey []byte
	decryptedPublicKey, err = crypt_tools.DecryptAESGCM(encryptedPublicKey, aesKey)
	if err != nil {
		c.mtx.Lock()
		c.statistics.Init2.ErrorsAESDecrypt++
		c.mtx.Unlock()
		return
	}

	// Check PublicKey length
	if len(decryptedPublicKey) != len(publicKey) {
		err = errors.New("len(decryptedPublicKey) != len(publicKey)")
		c.mtx.Lock()
		c.statistics.Init2.ErrorsDataLen4++
		c.mtx.Unlock()
		return
	}

	// Check PublicKey Content
	for i := 0; i < len(publicKey); i++ {
		if decryptedPublicKey[i] != publicKey[i] {
			err = errors.New("decryptedPublicKey != publicKey")
			c.mtx.Lock()
			c.statistics.Init2.ErrorsPublicKeyMismatch++
			c.mtx.Unlock()
			return
		}
	}

	// The ownership of the public key has been proven
	// Searching listener
	c.mtx.Lock()
	listenerFound := false
	var l *Listener
	l, listenerFound = c.listenersByAddr[string(publicKey)]
	if !listenerFound {
		c.nextListenerId++
		listenerId := c.nextListenerId
		l = NewListener(listenerId, publicKey, c.config)
		c.listenersByAddr[string(publicKey)] = l
		c.listenersByIndex[listenerId] = l
		l.aesKey = aesKey
	}

	c.mtx.Unlock()

	// Everything is OK - sending response
	result = make([]byte, 16)

	binary.LittleEndian.PutUint64(result[0:], l.id) // LID

	binary.LittleEndian.PutUint64(result[8:], uint64(l.snakeCounter.LastProcessed())) // Initial NONCE

	result, err = crypt_tools.EncryptAESGCM(result, aesKey)
	if err != nil {
		c.mtx.Lock()
		c.statistics.Init2.ErrorsAESEncrypt++
		c.mtx.Unlock()
		return
	}

	// Success
	c.mtx.Lock()
	c.statistics.Init2.Success++
	c.mtx.Unlock()
	return
}
