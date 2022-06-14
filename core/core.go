package core

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ipoluianov/gomisc/logger"
	"github.com/ipoluianov/xchg/config"
	"io"
	"sync"
	"time"
)

type Core struct {
	mtx              sync.Mutex
	config           config.Config
	listenersByAddr  map[string]*Listener
	listenersByIndex map[uint64]*Listener
	calls            map[uint64]*Request

	nextListenerId    uint64
	nextTransactionId uint64

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
	c.listenersByAddr = make(map[string]*Listener)
	c.listenersByIndex = make(map[uint64]*Listener)
	c.serverSecret = make([]byte, 32)
	c.calls = make(map[uint64]*Request)
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

func (c *Core) InitServer1(_ context.Context, data []byte) (result []byte, err error) {
	fmt.Println("InitServer1")
	publicKey := data
	addrSecret := c.calcAddrKey(publicKey)
	fmt.Println("AES: ", hex.EncodeToString(addrSecret))

	var rsaPublicKey *rsa.PublicKey
	rsaPublicKey, err = x509.ParsePKCS1PublicKey(publicKey)
	if err != nil {
		logger.Println(err)
		return
	}
	result, err = rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, addrSecret)
	if err != nil {
		logger.Println(err)
		return
	}

	return
}

func (c *Core) InitServer2(_ context.Context, data []byte) (result []byte, err error) {
	fmt.Println("InitServer2")
	// Input: [PK_LEN uint32, PK []byte, ENCRYPTED([PK_ENC []byte])]
	// Getting public key
	if len(data) < 4 {
		err = errors.New("wrong data len (< 4)")
		return
	}
	publicKeyLength := binary.LittleEndian.Uint32(data)
	data = data[4:]
	if len(data) < int(publicKeyLength) {
		err = errors.New("wrong data len (< publicKeyLength)")
		return
	}
	publicKey := data[0:publicKeyLength]

	// Getting Encrypted Public Key
	encryptedPublicKey := data[publicKeyLength:]
	if len(encryptedPublicKey) < 1 {
		err = errors.New("len(encryptedPublicKey) < 1")
		return
	}

	// Decrypting public key
	aesKey := c.calcAddrKey(publicKey)
	var decryptedPublicKey []byte
	decryptedPublicKey, err = c.decryptAES(encryptedPublicKey, aesKey)
	if err != nil {
		fmt.Println("AES DECRYPT ERROR:", encryptedPublicKey, hex.EncodeToString(aesKey))
		return
	}

	// Check public key
	if len(decryptedPublicKey) != len(publicKey) {
		err = errors.New("len(decryptedPublicKey) != len(publicKey)")
		return
	}
	for i := 0; i < len(publicKey); i++ {
		if decryptedPublicKey[i] != publicKey[i] {
			err = errors.New("decryptedPublicKey != publicKey")
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
		l = NewListener(listenerId, publicKey)
		c.listenersByAddr[string(publicKey)] = l
		c.listenersByIndex[listenerId] = l
	}
	c.mtx.Unlock()

	// Everything is ok - sending response
	// ENCRYPTED([ID uint64, COUNTER uint64])
	result = make([]byte, 16)
	binary.LittleEndian.PutUint64(result[0:], l.id)
	binary.LittleEndian.PutUint64(result[8:], l.lastCounter)
	result, err = c.encryptAES(result, aesKey)
	if err != nil {
		return
	}

	fmt.Println("Init2 ok", hex.EncodeToString(result))
	return
}

func (c *Core) calcAddrKey(publicKey []byte) []byte {
	addrSecretForSHA := make([]byte, len(c.serverSecret)+len(publicKey))
	copy(addrSecretForSHA, c.serverSecret)
	copy(addrSecretForSHA[len(c.serverSecret):], publicKey)
	addrSecretCalculated := sha256.Sum256(addrSecretForSHA)
	return addrSecretCalculated[:]
}

func (c *Core) GetNextRequest(ctx context.Context, data []byte) (result []byte, err error) {
	fmt.Println("GetNextRequest")
	// Input: [LID uint64, ENCRYPTED([COUNTER])
	if len(data) < 8 {
		err = errors.New("len(data) < 8")
		return
	}

	LID := binary.LittleEndian.Uint64(data)

	var lFound bool
	var l *Listener
	c.mtx.Lock()
	l, lFound = c.listenersByIndex[LID]
	c.mtx.Unlock()

	if !lFound {
		err = errors.New("no listener found")
		return
	}

	aesKey := c.calcAddrKey(l.publicKey)

	encryptedCounter := data[8:]
	var counterBS []byte
	counterBS, err = c.decryptAES(encryptedCounter, aesKey)
	if err != nil {
		return
	}
	if len(counterBS) != 8 {
		err = errors.New("len(counterBS) != 8")
		return
	}
	counter := binary.LittleEndian.Uint64(counterBS)
	if counter <= l.lastCounter {
		return nil, errors.New("[wrong counter]")
	}
	l.lastCounter = counter

	waitingDurationInMilliseconds := int64(c.config.Http.LongPollingTimeoutMs)
	waitingTick := int64(100)
	waitingIterationCount := waitingDurationInMilliseconds / waitingTick

	var request *Request

	for i := int64(0); i < waitingIterationCount; i++ {
		request = l.Pull()
		if ctx.Err() != nil {
			break
		}
		if request == nil {
			time.Sleep(time.Duration(waitingTick) * time.Millisecond)
			continue
		}
		break
	}

	if request != nil {
		// ENCRYPTED(TransactionID uint64, data []byte)
		result = make([]byte, len(request.Data)+8)
		binary.LittleEndian.PutUint64(result, request.transactionId)
		copy(result[8:], request.Data)
		result, err = c.encryptAES(result, aesKey)
		if err != nil {
			return
		}
	}

	//fmt.Println("no data")

	return
}

func (c *Core) PutResponse(_ context.Context, data []byte) (err error) {
	// [LID uint64, ENCRYPTED([TransactionID uint64, data []byte])

	fmt.Println("PutResponse")

	if len(data) < 8 {
		err = errors.New("len(data) < 8")
		fmt.Println("PutResponse1")
		return
	}

	LID := binary.LittleEndian.Uint64(data)

	var lFound bool
	var l *Listener
	c.mtx.Lock()
	l, lFound = c.listenersByIndex[LID]
	c.mtx.Unlock()

	if !lFound {
		fmt.Println("PutResponse2")
		err = errors.New("no listener found")
		return
	}

	aesKey := c.calcAddrKey(l.publicKey)
	//fmt.Println("PutResponse3", aesKey)

	encryptedData := data[8:]
	var decryptedData []byte
	decryptedData, err = c.decryptAES(encryptedData, aesKey)
	if len(decryptedData) < 8 {
		err = errors.New("len(decryptedData) < 8")
		return
	}

	//fmt.Println("PutResponse4", decryptedData)

	transactionId := binary.LittleEndian.Uint64(decryptedData)
	l.SetResponse(transactionId, decryptedData[8:])
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
	//fmt.Println("AES KEY:", key)
	//fmt.Println("AES MESSAGE:", message, len(message))
	ch, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(ch)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(message) < nonceSize {
		return nil, errors.New("wrong nonce")
	}
	nonce, ciphertext := message[:nonceSize], message[nonceSize:]
	decryptedMessage, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return
}

func (c *Core) Call(_ context.Context, data []byte) (response []byte, err error) {
	// [LID uint64, data []byte]

	fmt.Println("CALL")

	if len(data) < 8 {
		err = errors.New("len(data) < 8")
		return
	}

	LID := binary.LittleEndian.Uint64(data)
	fmt.Println("CALL LID", LID)
	var lFound bool
	var l *Listener
	c.mtx.Lock()
	l, lFound = c.listenersByIndex[LID]
	c.mtx.Unlock()

	if !lFound {
		fmt.Println("CALL no LID found", LID)
		err = errors.New("no listener found")
		return
	}

	if lFound && l != nil {
		c.mtx.Lock()
		msg := NewMessage(c.nextTransactionId, data[8:])
		fmt.Println("CALL LID found", LID, c.nextTransactionId)
		c.nextTransactionId++
		c.mtx.Unlock()
		fmt.Println("calling 1")
		response, err = l.ExecRequest(msg)
		fmt.Println("calling 2")
	} else {
		err = errors.New("no route to host")
	}
	return
}

func (c *Core) Ping(_ context.Context, data []byte) (result []byte, err error) {
	//fmt.Println("Ping", base64.StdEncoding.EncodeToString(data))
	//fmt.Println("Public key:", )

	var l *Listener
	listenerFound := false
	c.mtx.Lock()
	l, listenerFound = c.listenersByAddr[string(data)]
	if !listenerFound {
		err = errors.New("no route to host")
		fmt.Println("Ping: no route!!!!!!!!!!")
	} else {
		result = make([]byte, 8)
		binary.LittleEndian.PutUint64(result, l.id)
	}

	/*for _, l = range c.listenersByAddr {
		fmt.Println("Addr:", base64.StdEncoding.EncodeToString(l.publicKey))
	}*/

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
	info.ListenerCount = len(c.listenersByAddr)
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
		for lid, l := range c.listenersByIndex {
			if time.Now().Sub(l.LastGetDT()) > time.Duration(c.config.Core.KeepDataTimeMs)*time.Millisecond {
				logger.Println("purging", lid, l.publicKey)
				delete(c.listenersByIndex, lid)
				delete(c.listenersByAddr, string(l.publicKey))
			}
		}
		c.mtx.Unlock()
	}
}
