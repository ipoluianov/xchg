package xchg

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strconv"
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

	allowLocalConnection bool
	lanConnectionPoint   *net.UDPAddr
	routerHost           string
	//internetConnectionPoint *net.UDPAddr

	httpClient *http.Client

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
	c.privateKey = privateKey
	c.remoteAddress = remoteAddress
	c.authData = authData
	c.outgoingTransactions = make(map[uint64]*Transaction)
	c.nextTransactionId = 1
	c.network = network
	c.nonces = NewNonces(100)

	c.routerHost = ""

	tr := &http.Transport{}
	jar, _ := cookiejar.New(nil)
	c.httpClient = &http.Client{Transport: tr, Jar: jar}
	c.httpClient.Timeout = 2 * time.Second

	return &c
}

func ConnectionPointString(remoteConnectionPoint *net.UDPAddr) string {
	if remoteConnectionPoint == nil {
		return "<nil>"
	}
	return remoteConnectionPoint.String()
}

/*func (c *RemotePeer) InternetConnectionPoint() string {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return ConnectionPointString(c.internetConnectionPoint)
}*/

func (c *RemotePeer) getNextRouter() string {
	return "127.0.0.1:8084"
}

func (c *RemotePeer) LANConnectionPoint() string {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return ConnectionPointString(c.lanConnectionPoint)
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
	c.mtx.Unlock()
}

func (c *RemotePeer) checkLANConnectionPoint(conn net.PacketConn) (err error) {
	if !c.allowLocalConnection {
		return
	}

	c.mtx.Lock()
	lanConnectionPoint := c.lanConnectionPoint
	c.mtx.Unlock()
	if lanConnectionPoint != nil {
		return
	}

	nonce := c.nonces.Next()

	addressBS := []byte(c.remoteAddress)

	transaction := NewTransaction(0x20, AddressForPublicKey(&c.privateKey.PublicKey), c.remoteAddress, 0, 0, 0, 0, nil)
	transaction.Data = make([]byte, 16+len(addressBS))
	copy(transaction.Data[0:], nonce[:])
	copy(transaction.Data[16:], addressBS)

	for i := PEER_UDP_START_PORT; i < PEER_UDP_END_PORT; i++ {
		c.mtx.Lock()
		lanConnectionPoint = c.lanConnectionPoint
		c.mtx.Unlock()
		if lanConnectionPoint != nil {
			break
		}

		var broadcastAddress *net.UDPAddr
		//fmt.Println("send to " + fmt.Sprint(i))
		broadcastAddress, err = net.ResolveUDPAddr("udp4", "127.0.0.1:"+strconv.FormatInt(int64(i), 10))
		if err != nil {
			break
		}
		err = c.sendFrame(conn, broadcastAddress, transaction.Marshal())
		if err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return
}

func (c *RemotePeer) checkInternetConnectionPoint() (err error) {
	c.mtx.Lock()
	routerHost := c.routerHost
	c.mtx.Unlock()
	if routerHost != "" {
		return
	}

	nonce := c.nonces.Next()

	addressBS := []byte(c.remoteAddress)

	transaction := NewTransaction(0x20, AddressForPublicKey(&c.privateKey.PublicKey), c.remoteAddress, 0, 0, 0, 0, nil)
	transaction.Data = make([]byte, 16+len(addressBS))
	copy(transaction.Data[0:], nonce[:])
	copy(transaction.Data[16:], addressBS)

	c.mtx.Lock()
	routerHost = c.routerHost
	c.mtx.Unlock()
	if routerHost != "" {
		return
	}

	routerHost = c.getNextRouter()
	fmt.Println("Trying router", routerHost)
	c.httpCall(routerHost, transaction.Marshal())
	return
}

func (c *RemotePeer) setLANConnectionPoint(udpAddr *net.UDPAddr, publicKey *rsa.PublicKey, nonce []byte, signature []byte) {
	if !c.nonces.Check(nonce) {
		return
	}

	nonceHash := sha256.Sum256(nonce)
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, nonceHash[:], signature)
	if err != nil {
		return
	}

	c.mtx.Lock()
	c.lanConnectionPoint = udpAddr
	c.remotePublicKey = publicKey
	c.routerHost = "127.0.0.1:8084"
	c.mtx.Unlock()
	fmt.Println("Received Address for", c.remoteAddress, "from", udpAddr)
}

func (c *RemotePeer) setRemotePublicKey(publicKey *rsa.PublicKey) {
	c.mtx.Lock()
	c.remotePublicKey = publicKey
	c.mtx.Unlock()
}

func (c *RemotePeer) requestRemotePublicKey(conn net.PacketConn) {
	fmt.Println("requestRemotePublicKey")
	addressBS := []byte(c.remoteAddress)
	request := make([]byte, 8+len(addressBS))
	request[0] = 0x22
	copy(request[8:], addressBS)

	c.mtx.Lock()
	lanConnectionPoint := c.lanConnectionPoint
	//internetConnectionPoint := c.internetConnectionPoint
	c.mtx.Unlock()

	if lanConnectionPoint != nil {
		c.sendFrame(conn, lanConnectionPoint, request)
	}
}

func (c *RemotePeer) Call(conn net.PacketConn, function string, data []byte, timeout time.Duration) (result []byte, err error) {

	c.mtx.Lock()
	sessionId := c.sessionId
	lanConnectionPoint := c.lanConnectionPoint
	c.mtx.Unlock()

	if conn == nil {
		err = errors.New("no connection")
		return
	}

	if lanConnectionPoint == nil {
		go c.checkLANConnectionPoint(conn)
		go c.checkInternetConnectionPoint()
	}

	/*if lanConnectionPoint == nil {
		err = errors.New("no route to peer")
		return
	}*/

	if sessionId == 0 {
		err = c.auth(conn, lanConnectionPoint, 1000*time.Millisecond)
		if err != nil {
			return
		}
	}

	c.mtx.Lock()
	sessionId = c.sessionId
	aesKey := make([]byte, len(c.aesKey))
	copy(aesKey, c.aesKey)
	c.mtx.Unlock()

	result, err = c.regularCall(conn, lanConnectionPoint, function, data, aesKey, timeout)

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
		c.requestRemotePublicKey(conn)
		return
	}

	localPublicKeyBS := RSAPublicKeyToDer(&localPrivateKey.PublicKey)

	authFrameSecret := make([]byte, 16+len(authData))
	copy(authFrameSecret, nonce)
	copy(authFrameSecret[16:], []byte(authData))

	var encryptedAuthFrame []byte
	encryptedAuthFrame, err = rsa.EncryptPKCS1v15(rand.Reader, remotePublicKey, []byte(authFrameSecret))
	if err != nil {
		err = errors.New(ERR_XCHG_CL_CONN_AUTH_ENC + ":" + err.Error())
		return
	}

	authFrame := make([]byte, 4+len(localPublicKeyBS)+len(encryptedAuthFrame))
	binary.LittleEndian.PutUint32(authFrame, uint32(len(localPublicKeyBS)))
	copy(authFrame[4:], localPublicKeyBS)
	copy(authFrame[4+len(localPublicKeyBS):], encryptedAuthFrame)

	var result []byte
	result, err = c.regularCall(conn, remoteConnectionPoint, "/xchg-auth", authFrame, nil, timeout)
	if err != nil {
		err = errors.New(ERR_XCHG_CL_CONN_AUTH_AUTH + ":" + err.Error())
		return
	}

	result, err = rsa.DecryptPKCS1v15(rand.Reader, localPrivateKey, result)
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

func (c *RemotePeer) regularCall(conn net.PacketConn, remoteConnectionPoint *net.UDPAddr, function string, data []byte, aesKey []byte, timeout time.Duration) (result []byte, err error) {
	if conn == nil {
		err = errors.New("no connection")
		return
	}

	if len(function) > 255 {
		err = errors.New(ERR_XCHG_CL_CONN_CALL_WRONG_FUNCTION_LEN)
		return
	}

	/*if remoteConnectionPoint == nil {
		err = errors.New("no route to peer")
		return
	}*/

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

	result, err = c.executeTransaction(conn, remoteConnectionPoint, sessionId, frame, timeout)

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

func (c *RemotePeer) sendFrame(conn net.PacketConn, remoteConnectionPoint *net.UDPAddr, frame []byte) (err error) {
	if remoteConnectionPoint != nil {
		var n int
		n, err = conn.WriteTo(frame, remoteConnectionPoint)
		if n != len(frame) {
			err = errors.New("can not send")
		}
	} else {
		c.httpCall(c.routerHost, frame)
	}
	return
}

func (c *RemotePeer) executeTransaction(conn net.PacketConn, remoteConnectionPoint *net.UDPAddr, sessionId uint64, data []byte, timeout time.Duration) (result []byte, err error) {
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

		c.sendFrame(conn, remoteConnectionPoint, frame)
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

	return nil, errors.New(ERR_XCHG_PEER_CONN_TR_TIMEOUT)
}

func (c *RemotePeer) httpCall(routerHost string, frame []byte) (result []byte, err error) {
	if len(routerHost) == 0 {
		return
	}

	if len(frame) < 128 {
		return
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	{
		fw, _ := writer.CreateFormField("fn")
		fw.Write([]byte("d"))
	}
	{
		fw, _ := writer.CreateFormField("d")
		frame64 := base64.StdEncoding.EncodeToString(frame)
		fw.Write([]byte(frame64))
	}
	writer.Close()

	addr := "http://" + routerHost

	response, err := c.Post(addr+"/api/request", writer.FormDataContentType(), &body, "https://"+addr)

	if err != nil {
		fmt.Println("HTTP error:", err)
		return
	} else {
		var content []byte
		content, err = ioutil.ReadAll(response.Body)
		if err != nil {
			response.Body.Close()
			return
		}
		result, err = base64.StdEncoding.DecodeString(string(content))
		response.Body.Close()
	}
	return
}

func (c *RemotePeer) Post(url, contentType string, body io.Reader, host string) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Origin", host)
	return c.httpClient.Do(req)
}
