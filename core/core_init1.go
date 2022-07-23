package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"github.com/ipoluianov/gomisc/logger"
)

type Init1Stat struct {
	Received                int64 `json:"received"`
	ErrorsMaxListenersCount int64 `json:"errors_max_listeners_count"`
	ErrorsParsePublicKey    int64 `json:"errors_parse_pk"`
	ErrorsEncryptAES        int64 `json:"errors_encrypt_aes"`
}

type InitCandidate struct {
	Secret uint64
}

// Initialization of Server - first stage
// XCHG sends special AES-key encrypted by received PublicKey
// If Server realy has PrivateKey for its PublicKey - session AES-key will be decrypted
// AES-key = SHA256(PublicKey + ServerNonce)
// ServerNonce - is generated once at start of xchg
// For this instance of process - AES keys for the same PublicKeys are equal
// Frame:
// PublicKey = [0:]
func (c *Core) Init1(_ context.Context, data []byte) (result []byte, err error) {
	// Check MaxListenersCount
	c.mtx.Lock()
	c.statistics.Init1.Received++
	if len(c.listenersByIndex) >= c.config.Core.MaxListenersCount {
		result = make([]byte, 0)
		err = errors.New("max listeners count")
		c.statistics.Init1.ErrorsMaxListenersCount++
		c.mtx.Unlock()
		return
	}
	c.mtx.Unlock()

	// Get public key
	publicKey := data

	c.mtxInitCandidates.Lock()
	secretBytes := make([]byte, 8)
	rand.Read(secretBytes)
	secretInt := binary.LittleEndian.Uint64(secretBytes)
	c.initCandidates[hex.EncodeToString(publicKey)] = secretInt
	c.initCandidateTimes[hex.EncodeToString(publicKey)] = time.Now()
	c.mtxInitCandidates.Unlock()

	secretBytes = append(secretBytes, publicKey...)

	// Calculate AES key by PublicKey
	addrSecret := c.calcAddrKey(secretBytes)

	// Parse PublicKey-DER
	var rsaPublicKey *rsa.PublicKey
	rsaPublicKey, err = x509.ParsePKCS1PublicKey(publicKey)
	if err != nil {
		c.mtx.Lock()
		c.statistics.Init1.ErrorsParsePublicKey++
		c.mtx.Unlock()
		logger.Println(err)
		return
	}

	// Encrypt AES key by PublicKey
	result, err = rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, addrSecret)
	if err != nil {
		c.mtx.Lock()
		c.statistics.Init1.ErrorsEncryptAES++
		c.mtx.Unlock()
		logger.Println(err)
		return
	}

	return
}
