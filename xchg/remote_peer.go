package xchg

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type RemotePeer struct {
	mtx           sync.Mutex
	remoteAddress string
	authData      string
	network       *Network

	privateKey      *rsa.PrivateKey
	remotePublicKey *rsa.PublicKey

	nonces *Nonces

	//peer *Peer

	remotePeerHttp *RemotePeerHttp
	remotePeerUdp  *RemotePeerUdp

	findingConnection    bool
	authProcessing       bool
	aesKey               []byte
	sessionId            uint64
	sessionNonceCounter  uint64
	outgoingTransactions map[uint64]*Transaction
	nextTransactionId    uint64
}

func NewRemotePeer(remoteAddress string, authData string, privateKey *rsa.PrivateKey, network *Network) *RemotePeer {
	var c RemotePeer
	//c.peer = peer
	c.privateKey = privateKey
	c.remoteAddress = remoteAddress
	c.authData = authData
	c.outgoingTransactions = make(map[uint64]*Transaction)
	c.nextTransactionId = 1
	c.network = network
	c.nonces = NewNonces(100)

	c.remotePeerHttp = NewRemotePeerHttp(c.nonces, c.network, c.remoteAddress, c.privateKey)
	c.remotePeerUdp = NewRemotePeerUdp(c.nonces, c.remoteAddress, c.privateKey)

	return &c
}

func (c *RemotePeer) RemoteAddress() string {
	return c.remoteAddress
}

func (c *RemotePeer) processFrame(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	frameType := frame[8]

	switch frameType {
	case FrameTypeResponse:
		c.processFrame11(conn, sourceAddress, frame)
	}
}

func (c *RemotePeer) processFrame11(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	transaction, err := Parse(frame)
	if err != nil {
		fmt.Println(err)
		return
	}

	c.mtx.Lock()
	if t, ok := c.outgoingTransactions[transaction.TransactionId]; ok {
		if transaction.Err == nil && transaction.TotalSize < 1024*1024 {
			t.AppendReceivedData(transaction)
		} else {
			t.Result = transaction.Data
			t.Err = transaction.Err
			t.Complete = true
		}
	}
	c.mtx.Unlock()
}

func (c *RemotePeer) setConnectionPoint(udpAddr *net.UDPAddr, routerHost string, publicKey *rsa.PublicKey, nonce []byte, signature []byte) {
	if !c.nonces.Check(nonce) {
		return
	}
	nonceHash := sha256.Sum256(nonce)
	err := rsa.VerifyPSS(publicKey, crypto.SHA256, nonceHash[:], signature, &rsa.PSSOptions{
		SaltLength: 32,
	})
	if err != nil {
		fmt.Println("VerifyPSS error", err)
		return
	}

	c.mtx.Lock()
	if udpAddr != nil {
		c.remotePeerUdp.SetConnectionPoint(udpAddr)
	}
	/*if routerHost != "" {
		c.remotePeerHttp.SetConnectionPoint(routerHost)
	}*/
	c.remotePublicKey = publicKey
	c.mtx.Unlock()
	fmt.Println("Received Address for", c.remoteAddress, "from", udpAddr, routerHost)
}

func (c *RemotePeer) Call(conn net.PacketConn, function string, data []byte, timeout time.Duration) (result []byte, err error) {

	c.mtx.Lock()
	sessionId := c.sessionId
	c.mtx.Unlock()

	c.remotePeerUdp.Check(conn)
	if !c.remotePeerUdp.IsValid() {
		if c.remotePublicKey == nil {
			c.remotePeerHttp.Check()
		}
	}

	if sessionId == 0 {
		err = c.auth(conn, 1000*time.Millisecond)
		if err != nil {
			return
		}
	}

	c.mtx.Lock()
	sessionId = c.sessionId
	aesKey := make([]byte, len(c.aesKey))
	copy(aesKey, c.aesKey)
	c.mtx.Unlock()

	result, err = c.regularCall(conn, function, data, aesKey, timeout)

	return
}

func (c *RemotePeer) auth(conn net.PacketConn, timeout time.Duration) (err error) {
	c.mtx.Lock()
	if c.authProcessing {
		c.mtx.Unlock()
		err = errors.New("auth processing")
		return
	}
	c.authProcessing = true
	c.mtx.Unlock()

	defer func() {
		c.mtx.Lock()
		c.authProcessing = false
		c.mtx.Unlock()
	}()

	var nonce []byte
	nonce, err = c.regularCall(conn, "/xchg-get-nonce", nil, nil, timeout)
	if err != nil {
		err = errors.New(ERR_XCHG_CL_CONN_AUTH_GET_NONCE + ":" + err.Error())
		return
	}
	if len(nonce) != 16 {
		err = errors.New(ERR_XCHG_CL_CONN_AUTH_WRONG_NONCE_LEN)
		return
	}

	c.mtx.Lock()
	localPrivateKey := c.privateKey
	remotePublicKey := c.remotePublicKey
	authData := make([]byte, len(c.authData))
	copy(authData, []byte(c.authData))
	c.mtx.Unlock()

	if c.privateKey == nil {
		err = errors.New(ERR_XCHG_CL_CONN_AUTH_NO_LOCAL_PRIVATE_KEY)
		return
	}

	if remotePublicKey == nil {
		err = errors.New(ERR_XCHG_CL_CONN_AUTH_NO_REMOTE_PUBLIC_KEY)
		//c.requestRemotePublicKey(conn)
		return
	}

	tempAESKey := make([]byte, 32)
	rand.Read(tempAESKey)
	hash := sha256.Sum256(tempAESKey)
	signature, err := rsa.SignPSS(rand.Reader, localPrivateKey, crypto.SHA256, hash[:], &rsa.PSSOptions{
		SaltLength: 32,
	})

	localPublicKeyBS := RSAPublicKeyToDer(&localPrivateKey.PublicKey)

	authFrameSecret := make([]byte, 16+32+256+4+len(localPublicKeyBS)+len(authData))
	copy(authFrameSecret[0:], nonce)
	copy(authFrameSecret[16:], tempAESKey)
	copy(authFrameSecret[16+32:], signature)
	binary.LittleEndian.PutUint32(authFrameSecret[16+32+256:], uint32(len(localPublicKeyBS)))
	copy(authFrameSecret[16+32+256+4:], localPublicKeyBS)
	copy(authFrameSecret[16+32+256+4+len(localPublicKeyBS):], authData)

	var encryptedAuthFrame []byte
	encryptedAuthFrame, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, remotePublicKey, []byte(authFrameSecret), nil)
	if err != nil {
		err = errors.New(ERR_XCHG_CL_CONN_AUTH_ENC + ":" + err.Error())
		return
	}

	var result []byte
	result, err = c.regularCall(conn, "/xchg-auth", encryptedAuthFrame, nil, timeout)
	if err != nil {
		err = errors.New(ERR_XCHG_CL_CONN_AUTH_AUTH + ":" + err.Error())
		return
	}

	result, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, localPrivateKey, result, nil)
	if err != nil {
		err = errors.New(ERR_XCHG_CL_CONN_AUTH_DECR + ":" + err.Error())
		return
	}

	if len(result) != 8+32 {
		err = errors.New(ERR_XCHG_CL_CONN_AUTH_WRONG_AUTH_RESP_LEN)
		return
	}

	c.mtx.Lock()
	c.sessionId = binary.LittleEndian.Uint64(result)
	c.aesKey = make([]byte, 32)
	copy(c.aesKey, result[8:])
	c.mtx.Unlock()

	return
}

func (c *RemotePeer) regularCall(conn net.PacketConn, function string, data []byte, aesKey []byte, timeout time.Duration) (result []byte, err error) {
	if len(function) > 255 {
		err = errors.New(ERR_XCHG_CL_CONN_CALL_WRONG_FUNCTION_LEN)
		return
	}

	encrypted := false

	c.mtx.Lock()
	localPrivateKey := c.privateKey
	c.mtx.Unlock()

	if localPrivateKey == nil {
		err = errors.New(ERR_XCHG_CL_CONN_CALL_NO_LOCAL_PRIVATE_KEY)
		return
	}

	c.mtx.Lock()
	sessionId := c.sessionId
	c.mtx.Unlock()

	c.mtx.Lock()
	sessionNonceCounter := c.sessionNonceCounter
	c.sessionNonceCounter++
	c.mtx.Unlock()

	var frame []byte
	if len(aesKey) == 32 {
		frame = make([]byte, 8+1+len(function)+len(data))
		binary.LittleEndian.PutUint64(frame, sessionNonceCounter)
		frame[8] = byte(len(function))
		copy(frame[9:], function)
		copy(frame[9+len(function):], data)
		frame = PackBytes(frame)
		frame, err = EncryptAESGCM(frame, aesKey)
		if err != nil {
			c.Reset()
			err = errors.New(ERR_XCHG_CL_CONN_CALL_ENC + ":" + err.Error())
			return
		}
		encrypted = true
	} else {
		frame = make([]byte, 1+len(function)+len(data))
		frame[0] = byte(len(function))
		copy(frame[1:], function)
		copy(frame[1+len(function):], data)
	}

	result, err = c.executeTransaction(conn, sessionId, frame, timeout, aesKey)

	if NeedToChangeNode(err) {
		c.Reset()
		return
	}

	if err != nil {
		err = errors.New(ERR_XCHG_CL_CONN_CALL_ERR + ":" + err.Error())
		return
	}

	if encrypted {
		result, err = DecryptAESGCM(result, aesKey)
		if err != nil {
			c.Reset()
			err = errors.New(ERR_XCHG_CL_CONN_CALL_DECRYPT + ":" + err.Error())
			return
		}
		result, err = UnpackBytes(result)
		if err != nil {
			c.Reset()
			err = errors.New(ERR_XCHG_CL_CONN_CALL_UNPACK + ":" + err.Error())
			return
		}
	}

	if len(result) < 1 {
		err = errors.New(ERR_XCHG_CL_CONN_CALL_RESP_LEN)
		c.Reset()
		return
	}

	if result[0] == 0 {
		// Success response
		result = result[1:]
		err = nil
		return
	}

	if result[0] == 1 {
		// Error response
		err = errors.New(ERR_XCHG_CL_CONN_CALL_FROM_PEER + ":" + string(result[1:]))
		if NeedToMakeSession(err) {
			// Any server error - make new session
			c.sessionId = 0
		}
		result = nil
		return
	}

	err = errors.New(ERR_XCHG_CL_CONN_CALL_RESP_STATUS_BYTE)
	c.Reset()
	return
}

func (c *RemotePeer) Reset() {
	c.mtx.Lock()
	c.reset()
	c.mtx.Unlock()
}

func (c *RemotePeer) reset() {
	c.sessionId = 0
	c.aesKey = nil
}

func (c *RemotePeer) executeTransaction(conn net.PacketConn, sessionId uint64, data []byte, timeout time.Duration, aesKeyOriginal []byte) (result []byte, err error) {
	// Get transaction ID
	var transactionId uint64
	c.mtx.Lock()
	transactionId = c.nextTransactionId
	c.nextTransactionId++

	// Create transaction
	t := NewTransaction(FrameTypeCall, AddressForPublicKey(&c.privateKey.PublicKey), c.remoteAddress, transactionId, sessionId, 0, len(data), data)
	c.outgoingTransactions[transactionId] = t
	c.mtx.Unlock()

	// Send transaction
	offset := 0
	blockSize := 1024
	for offset < len(data) {
		currentBlockSize := blockSize
		restDataLen := len(data) - offset
		if restDataLen < currentBlockSize {
			currentBlockSize = restDataLen
		}

		blockTransaction := NewTransaction(FrameTypeCall, AddressForPublicKey(&c.privateKey.PublicKey), c.remoteAddress, transactionId, sessionId, offset, len(data), data[offset:offset+currentBlockSize])
		frame := blockTransaction.Marshal()

		//c.sendFrame(frame)

		err = c.remotePeerUdp.Send(conn, frame)
		if err != nil {
			err = c.remotePeerHttp.Send(frame)
		}

		if err != nil {
			c.mtx.Lock()
			delete(c.outgoingTransactions, t.TransactionId)
			c.mtx.Unlock()
			return
		}
		offset += currentBlockSize
		//fmt.Println("executeTransaction send ", currentBlockSize, c.internalId)
	}

	// Wait for response
	waitingDurationInMilliseconds := timeout.Milliseconds()
	waitingTick := int64(10)
	waitingIterationCount := waitingDurationInMilliseconds / waitingTick
	for i := int64(0); i < waitingIterationCount; i++ {
		if t.Complete {
			// Transaction complete
			c.mtx.Lock()
			delete(c.outgoingTransactions, t.TransactionId)
			c.mtx.Unlock()

			// Error recevied
			if t.Err != nil {
				result = nil
				err = t.Err
				return
			}

			// Success
			result = t.Result
			err = nil
			return
		}
		time.Sleep(time.Duration(waitingTick) * time.Millisecond)
	}

	// Clear transactions map
	c.mtx.Lock()
	delete(c.outgoingTransactions, t.TransactionId)
	c.mtx.Unlock()

	c.remotePeerUdp.ResetConnectionPoint()
	//c.remotePeerHttp.ResetConnectionPoint()

	c.mtx.Lock()

	allowResetSession := true
	if len(aesKeyOriginal) == 32 && len(c.aesKey) == 32 {
		for i := 0; i < 32; i++ {
			if aesKeyOriginal[i] != c.aesKey[i] {
				allowResetSession = false
				break
			}
		}
	}

	if allowResetSession {
		c.sessionId = 0
		c.aesKey = nil
	}

	c.mtx.Unlock()

	return nil, errors.New(ERR_XCHG_PEER_CONN_TR_TIMEOUT)
}
