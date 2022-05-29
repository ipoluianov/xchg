package core

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/ipoluianov/gomisc/logger"
	"github.com/ipoluianov/xchg/config"
	"io"
	"sync"
	"time"
)

type Core struct {
	mtx                sync.Mutex
	config             config.Config
	listeners          map[string]*Listener
	stopPurgeRoutineCh chan struct{}

	serverSecret []byte

	statReceivedWriteBytes    int
	statReceivedWriteRequests int
	statReceivedReadBytes     int
	statReceivedReadRequests  int
	statReceivedPingBytes     int
	statReceivedPingRequests  int
	statReceivedInfoBytes     int
	statReceivedInfoRequests  int
}

func NewCore(conf config.Config) *Core {
	var c Core
	c.config = conf
	c.listeners = make(map[string]*Listener)
	c.serverSecret = make([]byte, 32)
	_, _ = rand.Read(c.serverSecret)
	return &c
}

func (c *Core) Start() {
	// sweeper
	c.stopPurgeRoutineCh = make(chan struct{})
	go c.purgeRoutine()
}

func (c *Core) Stop() {
	close(c.stopPurgeRoutineCh)
}

func (c *Core) GenerateAndEncryptSymmetricKeyForNode(addr string, nodePublicKey string) (result string, err error) {
	var publicKeyBS []byte
	publicKeyBS, err = base64.StdEncoding.DecodeString(nodePublicKey)
	if err != nil {
		return
	}

	var rsaPublicKey *rsa.PublicKey
	rsaPublicKey, err = x509.ParsePKCS1PublicKey(publicKeyBS)
	if err != nil {
		return
	}

	addrSecret := c.calcAddrKey(addr)
	addrSecretHex := base64.StdEncoding.EncodeToString(addrSecret)
	fmt.Println("---------", addrSecretHex)
	var encBytes []byte
	encBytes, err = rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, []byte(addrSecretHex))
	if err != nil {
		return
	}
	encBytes64 := base64.StdEncoding.EncodeToString(encBytes)
	result = encBytes64
	return
}

func (c *Core) calcAddrKey(addr string) []byte {
	addrSecretForSHA := make([]byte, len(c.serverSecret)+len(addr))
	copy(addrSecretForSHA, c.serverSecret)
	copy(addrSecretForSHA[len(c.serverSecret):], addr)
	addrSecretCalculated := sha256.Sum256(addrSecretForSHA)
	return addrSecretCalculated[:]
}

func (c *Core) Read(ctx context.Context, address string, data string, timeout time.Duration) (message *Message, err error) {

	aesKey := c.calcAddrKey(address)
	var encryptedMessage []byte
	encryptedMessage, err = base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	var counterBS []byte
	counterBS, err = c.decryptAES(encryptedMessage, aesKey)
	if err != nil {
		return nil, err
	}
	if len(counterBS) != 8 {
		return nil, errors.New("wrong counter len")
	}
	counter := binary.LittleEndian.Uint64(counterBS)

	// find core
	listenerFound := false
	var l *Listener
	c.mtx.Lock()
	l, listenerFound = c.listeners[address]
	if !listenerFound {
		l = NewListener(address)
		c.listeners[address] = l
	}
	c.statReceivedReadRequests++
	c.mtx.Unlock()

	fmt.Println("counter", counter, l.lastCounter)
	if counter <= l.lastCounter {
		return nil, errors.New("[wrong counter]")
	}
	l.lastCounter = counter

	var valid bool

	waitingDurationInMilliseconds := timeout.Milliseconds()
	waitingTick := int64(100)
	waitingIterationCount := waitingDurationInMilliseconds / waitingTick

	for i := int64(0); i < waitingIterationCount; i++ {
		message, valid = l.Pull()
		if ctx.Err() != nil {
			break
		}

		if !valid {
			time.Sleep(time.Duration(waitingTick) * time.Millisecond)
			continue
		}
		break
	}

	if message != nil {
		//fmt.Println("XCHG - excData after read", message.Data, aesKey)
		message.Data, err = c.encryptAES(message.Data, aesKey)
		if err != nil {
			panic(err)
		}

		message.Data = []byte(base64.StdEncoding.EncodeToString(message.Data))

		c.mtx.Lock()
		c.statReceivedReadBytes += len(message.Data)
		c.mtx.Unlock()
	}

	if !valid {
		err = nil
	}
	return
}

func (c *Core) encryptAES(decryptedMessage []byte, key []byte) (encryptedMessage []byte, err error) {
	var ch cipher.Block
	ch, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var gcm cipher.AEAD
	gcm, err = cipher.NewGCM(ch)
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	encryptedMessage = gcm.Seal(nonce, nonce, decryptedMessage, nil)
	return
}

func (c *Core) decryptAES(message []byte, key []byte) (decryptedMessage []byte, err error) {
	fmt.Println("AES KEY:", key)
	fmt.Println("AES MESSAGE:", message, len(message))
	ch, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("111", err)
		return nil, err
	}
	gcm, err := cipher.NewGCM(ch)
	if err != nil {
		fmt.Println("222", err)
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(message) < nonceSize {
		return nil, errors.New("wrong nonce")
	}
	nonce, ciphertext := message[:nonceSize], message[nonceSize:]
	decryptedMessage, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println("3331", err)
		return nil, err
	}
	return
}

func (c *Core) Write(_ context.Context, address string, data []byte) (err error) {
	// find core
	listenerFound := false
	var listener *Listener
	c.mtx.Lock()
	listener, listenerFound = c.listeners[address]
	c.statReceivedWriteBytes += len(data)
	c.statReceivedWriteRequests++
	c.mtx.Unlock()

	// push message
	if listenerFound && listener != nil {
		fmt.Println("XCHG --- write - ok")
		err = listener.PushMessage(data)
	} else {
		fmt.Println("XCHG --- write - no listener")
		err = errors.New("no route to host")
	}
	return
}

func (c *Core) Ping(_ context.Context, address string) (listenerInfo string, err error) {
	var l *Listener
	listenerFound := false
	c.mtx.Lock()
	l, listenerFound = c.listeners[address]
	if !listenerFound {
		err = errors.New("no route to host")
	} else {
		listenerInfo = l.LastGetDT().String()
	}

	//c.statReceivedPingBytes = 0
	c.statReceivedPingRequests++

	c.mtx.Unlock()
	return
}

type Info struct {
	DT            time.Time `json:"dt"`
	ListenerCount int       `json:"lc"`

	StatReceivedWriteBytes    int `json:"stat_received_write_bytes"`
	StatReceivedWriteRequests int `json:"stat_received_write_requests"`
	StatReceivedReadBytes     int `json:"stat_received_read_bytes"`
	StatReceivedReadRequests  int `json:"stat_received_read_requests"`
	StatReceivedPingBytes     int `json:"stat_received_ping_bytes"`
	StatReceivedPingRequests  int `json:"stat_received_ping_requests"`
	StatReceivedInfoBytes     int `json:"stat_received_info_bytes"`
	StatReceivedInfoRequests  int `json:"stat_received_info_requests"`
}

func (c *Core) Info(_ context.Context) (info Info, err error) {
	c.mtx.Lock()
	info.DT = time.Now()
	info.ListenerCount = len(c.listeners)
	info.StatReceivedWriteBytes = c.statReceivedWriteBytes
	info.StatReceivedWriteRequests = c.statReceivedWriteRequests
	info.StatReceivedReadBytes = c.statReceivedReadBytes
	info.StatReceivedReadRequests = c.statReceivedReadRequests
	info.StatReceivedPingBytes = c.statReceivedPingBytes
	info.StatReceivedPingRequests = c.statReceivedPingRequests
	info.StatReceivedInfoBytes = c.statReceivedInfoBytes
	info.StatReceivedInfoRequests = c.statReceivedInfoRequests
	c.statReceivedInfoRequests++
	c.mtx.Unlock()
	return
}

func (c *Core) purgeRoutine() {
	ticker := time.NewTicker(time.Duration(c.config.Core.PurgeIntervalMs) * time.Millisecond)
	for {
		select {
		case <-c.stopPurgeRoutineCh:
			return
		case <-ticker.C:
		}

		c.mtx.Lock()
		for id, l := range c.listeners {
			if time.Now().Sub(l.LastGetDT()) > time.Duration(c.config.Core.KeepDataTimeMs)*time.Millisecond {
				logger.Println("purging", id)
				delete(c.listeners, id)
			}
		}

		c.mtx.Unlock()
	}
}
