package connection

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/xchg/xchg"
)

type RemotePeer struct {
	mtx           sync.Mutex
	remoteAddress string
	authData      string

	privateKey      *rsa.PrivateKey
	remotePublicKey *rsa.PublicKey

	remoteConnectionPoint *net.UDPAddr
	findingConnection     bool
	authProcessing        bool
	aesKey                []byte
	sessionId             uint64
	sessionNonceCounter   uint64
	outgoingTransactions  map[uint64]*Transaction
	nextTransactionId     uint64
}

func NewRemotePeer(remoteAddress string, authData string, privateKey *rsa.PrivateKey) *RemotePeer {
	var c RemotePeer
	c.privateKey = privateKey
	c.remoteAddress = remoteAddress
	c.authData = authData
	c.outgoingTransactions = make(map[uint64]*Transaction)
	c.nextTransactionId = 1
	return &c
}

func RemoteConnectionPointString(remoteConnectionPoint *net.UDPAddr) string {
	if remoteConnectionPoint == nil {
		return "<nil>"
	}
	return remoteConnectionPoint.String()
}

func (c *RemotePeer) RemoteConnectionPoint() string {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return RemoteConnectionPointString(c.remoteConnectionPoint)
}

func (c *RemotePeer) processFrame(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	frameType := frame[0]

	switch frameType {
	case FrameTypeResponse:
		c.processFrame11(conn, sourceAddress, frame)
	}
}

func (c *RemotePeer) processFrame11(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	transaction, err := Parse(frame)
	if err != nil {
		return
	}
	c.setTransactionResponse(transaction)
}

func (c *RemotePeer) setTransactionResponse(transaction *Transaction) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if t, ok := c.outgoingTransactions[transaction.TransactionId]; ok {
		if transaction.Err == nil {
			if len(t.Result) != int(transaction.TotalSize) {
				t.Result = make([]byte, transaction.TotalSize)
			}
			copy(t.Result[transaction.Offset:], transaction.Data)
			t.ReceivedDataLen += len(transaction.Data)
			if t.ReceivedDataLen >= int(transaction.TotalSize) {
				t.Complete = true
			}
		} else {
			t.Result = transaction.Data
			t.Err = transaction.Err
			t.Complete = true
		}
	}
}

func (c *RemotePeer) sendError(conn net.PacketConn, sourceAddress *net.UDPAddr, originalFrame []byte, errorCode byte) {
	var responseFrame [8]byte
	copy(responseFrame[:], originalFrame[:8])
	responseFrame[1] = errorCode
	_, _ = conn.WriteTo(responseFrame[:], sourceAddress)
}

func (c *RemotePeer) sendResponse(conn net.PacketConn, sourceAddress *net.UDPAddr, originalFrame []byte, responseFrame []byte) {
	copy(responseFrame, originalFrame[:8])
	responseFrame[1] = 0x00
	_, _ = conn.WriteTo(responseFrame, sourceAddress)
}

func (c *RemotePeer) checkRemoteConnectionPoint(conn net.PacketConn) (err error) {
	c.mtx.Lock()
	remoteConnectionPoint := c.remoteConnectionPoint
	c.mtx.Unlock()
	if remoteConnectionPoint != nil {
		return
	}

	addressBS := []byte(c.remoteAddress)
	request := make([]byte, 8+len(addressBS))
	request[0] = 0x20
	copy(request[8:], addressBS)

	for i := PEER_UDP_START_PORT; i < PEER_UDP_END_PORT; i++ {
		c.mtx.Lock()
		remoteConnectionPoint = c.remoteConnectionPoint
		c.mtx.Unlock()
		if remoteConnectionPoint != nil {
			break
		}

		var broadcastAddress *net.UDPAddr
		broadcastAddress, err = net.ResolveUDPAddr("udp4", "255.255.255.255:"+strconv.FormatInt(int64(i), 10))
		if err != nil {
			break
		}
		_, err = conn.WriteTo(request, broadcastAddress)
		if err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return
}

func (c *RemotePeer) setRemoteConnectionPoint(udpAddr *net.UDPAddr, remotePublicKey *rsa.PublicKey) {
	c.mtx.Lock()
	c.remoteConnectionPoint = udpAddr
	c.remotePublicKey = remotePublicKey
	c.mtx.Unlock()
	fmt.Println("Received Address for", c.remoteAddress, "from", udpAddr)
}

func (c *RemotePeer) Call(conn net.PacketConn, function string, data []byte, timeout time.Duration) (result []byte, err error) {

	c.mtx.Lock()
	sessionId := c.sessionId
	remoteConnectionPoint := c.remoteConnectionPoint
	c.mtx.Unlock()

	if conn == nil {
		err = errors.New("no connection")
		return
	}

	if remoteConnectionPoint == nil {
		go c.checkRemoteConnectionPoint(conn)
		err = errors.New("no route to peer")
		return
	}

	if sessionId == 0 {
		err = c.auth(conn, remoteConnectionPoint, 1000*time.Millisecond)
		if err != nil {
			return
		}
	}

	c.mtx.Lock()
	sessionId = c.sessionId
	aesKey := make([]byte, len(c.aesKey))
	copy(aesKey, c.aesKey)
	c.mtx.Unlock()

	result, err = c.regularCall(conn, remoteConnectionPoint, function, data, aesKey, timeout)

	return
}

func (c *RemotePeer) auth(conn net.PacketConn, remoteConnectionPoint *net.UDPAddr, timeout time.Duration) (err error) {
	if conn == nil {
		err = errors.New("no connection")
		return
	}

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
	nonce, err = c.regularCall(conn, remoteConnectionPoint, "/xchg-get-nonce", nil, nil, timeout)
	if err != nil {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_AUTH_GET_NONCE + ":" + err.Error())
		return
	}
	if len(nonce) != 16 {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_AUTH_WRONG_NONCE_LEN)
		return
	}

	c.mtx.Lock()
	localPrivateKey := c.privateKey
	remotePublicKey := c.remotePublicKey
	authData := make([]byte, len(c.authData))
	copy(authData, []byte(c.authData))
	c.mtx.Unlock()
	if c.privateKey == nil {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_AUTH_NO_LOCAL_PRIVATE_KEY)
		return
	}

	localPublicKeyBS := crypt_tools.RSAPublicKeyToDer(&localPrivateKey.PublicKey)

	authFrameSecret := make([]byte, 16+len(authData))
	copy(authFrameSecret, nonce)
	copy(authFrameSecret[16:], []byte(authData))

	var encryptedAuthFrame []byte
	encryptedAuthFrame, err = rsa.EncryptPKCS1v15(rand.Reader, remotePublicKey, []byte(authFrameSecret))
	if err != nil {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_AUTH_ENC + ":" + err.Error())
		return
	}

	authFrame := make([]byte, 4+len(localPublicKeyBS)+len(encryptedAuthFrame))
	binary.LittleEndian.PutUint32(authFrame, uint32(len(localPublicKeyBS)))
	copy(authFrame[4:], localPublicKeyBS)
	copy(authFrame[4+len(localPublicKeyBS):], encryptedAuthFrame)

	var result []byte
	result, err = c.regularCall(conn, remoteConnectionPoint, "/xchg-auth", authFrame, nil, timeout)
	if err != nil {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_AUTH_AUTH + ":" + err.Error())
		return
	}

	result, err = rsa.DecryptPKCS1v15(rand.Reader, localPrivateKey, result)
	if err != nil {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_AUTH_DECR + ":" + err.Error())
		return
	}

	if len(result) != 8+32 {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_AUTH_WRONG_AUTH_RESP_LEN)
		return
	}

	c.mtx.Lock()
	c.sessionId = binary.LittleEndian.Uint64(result)
	c.aesKey = make([]byte, 32)
	copy(c.aesKey, result[8:])
	c.mtx.Unlock()

	return
}

func (c *RemotePeer) regularCall(conn net.PacketConn, remoteConnectionPoint *net.UDPAddr, function string, data []byte, aesKey []byte, timeout time.Duration) (result []byte, err error) {
	if conn == nil {
		err = errors.New("no connection")
		return
	}

	if len(function) > 255 {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_CALL_WRONG_FUNCTION_LEN)
		return
	}

	if remoteConnectionPoint == nil {
		err = errors.New("no route to peer")
		return
	}

	encrypted := false

	c.mtx.Lock()
	localPrivateKey := c.privateKey
	c.mtx.Unlock()

	if localPrivateKey == nil {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_CALL_NO_LOCAL_PRIVATE_KEY)
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
		frame, err = crypt_tools.EncryptAESGCM(frame, aesKey)
		if err != nil {
			c.Reset()
			err = errors.New(xchg.ERR_XCHG_CL_CONN_CALL_ENC + ":" + err.Error())
			return
		}
		encrypted = true
	} else {
		frame = make([]byte, 1+len(function)+len(data))
		frame[0] = byte(len(function))
		copy(frame[1:], function)
		copy(frame[1+len(function):], data)
	}

	result, err = c.executeTransaction(conn, remoteConnectionPoint, sessionId, frame, timeout)

	if xchg.NeedToChangeNode(err) {
		c.Reset()
		return
	}

	if err != nil {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_CALL_ERR + ":" + err.Error())
		return
	}

	if encrypted {
		result, err = crypt_tools.DecryptAESGCM(result, aesKey)
		if err != nil {
			c.Reset()
			err = errors.New(xchg.ERR_XCHG_CL_CONN_CALL_DECRYPT + ":" + err.Error())
			return
		}
		result, err = UnpackBytes(result)
		if err != nil {
			c.Reset()
			err = errors.New(xchg.ERR_XCHG_CL_CONN_CALL_UNPACK + ":" + err.Error())
			return
		}
	}

	if len(result) < 1 {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_CALL_RESP_LEN)
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
		err = errors.New(xchg.ERR_XCHG_CL_CONN_CALL_FROM_PEER + ":" + string(result[1:]))
		if xchg.NeedToMakeSession(err) {
			// Any server error - make new session
			c.sessionId = 0
		}
		result = nil
		return
	}

	err = errors.New(xchg.ERR_XCHG_CL_CONN_CALL_RESP_STATUS_BYTE)
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

func (c *RemotePeer) executeTransaction(conn net.PacketConn, remoteConnectionPoint *net.UDPAddr, sessionId uint64, data []byte, timeout time.Duration) (result []byte, err error) {
	// Get transaction ID
	var transactionId uint64
	c.mtx.Lock()
	transactionId = c.nextTransactionId
	c.nextTransactionId++

	// Create transaction
	t := NewTransaction(FrameTypeCall, transactionId, sessionId, 0, len(data), data)
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

		blockTransaction := NewTransaction(FrameTypeCall, transactionId, sessionId, offset, len(data), data[offset:offset+currentBlockSize])
		frame := blockTransaction.Marshal()

		var n int
		n, err = conn.WriteTo(frame, remoteConnectionPoint)
		if err != nil {
			c.mtx.Lock()
			delete(c.outgoingTransactions, t.TransactionId)
			c.mtx.Unlock()
			return
		}
		if n != len(frame) {
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

	return nil, errors.New(xchg.ERR_XCHG_PEER_CONN_TR_TIMEOUT)
}
