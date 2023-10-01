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
	"sync"
	"time"
)

type RemotePeerTransport interface {
	Id() string
	Check(frame20 *Transaction, network *Network, remotePublicKeyExists bool) error
	DeclareError(sentViaTransportMap map[string]struct{})
	Send(network *Network, tr *Transaction) error
	SetRemoteUDPAddress(udpAddress *net.UDPAddr)
}

type RemotePeer struct {
	mtx           sync.Mutex
	remoteAddress string
	authData      string
	//network       *Network

	privateKey      *rsa.PrivateKey
	remotePublicKey *rsa.PublicKey

	nonces *Nonces

	httpClient *http.Client

	findingConnection    bool
	authProcessing       bool
	aesKey               []byte
	sessionId            uint64
	sessionNonceCounter  uint64
	outgoingTransactions map[uint64]*Transaction
	nextTransactionId    uint64
}

func NewRemotePeer(remoteAddress string, authData string, privateKey *rsa.PrivateKey) *RemotePeer {
	var c RemotePeer
	c.privateKey = privateKey
	c.remoteAddress = remoteAddress
	c.authData = authData
	c.outgoingTransactions = make(map[uint64]*Transaction)
	c.nextTransactionId = 1
	//c.network = network
	c.nonces = NewNonces(100)

	tr := &http.Transport{}
	jar, _ := cookiejar.New(nil)
	c.httpClient = &http.Client{Transport: tr, Jar: jar}
	c.httpClient.Timeout = 1 * time.Second

	//c.remotePeerTransports = make([]RemotePeerTransport, 2)
	//c.remotePeerTransports[0] = NewRemotePeerHttp()
	return &c
}

func (c *RemotePeer) RemoteAddress() string {
	return c.remoteAddress
}

func (c *RemotePeer) processFrame(routerHost string, frame []byte) {
	frameType := frame[8]

	switch frameType {
	case FrameTypeResponse:
		c.processFrame11(routerHost, frame)
	}
}

func (c *RemotePeer) processFrame11(routerHost string, frame []byte) {
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

func (c *RemotePeer) setConnectionPoint(routerHost string, publicKey *rsa.PublicKey, nonce []byte, signature []byte) {
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
	c.remotePublicKey = publicKey
	c.mtx.Unlock()
	fmt.Println("Received Address for", c.remoteAddress, "from", routerHost)
}

func (c *RemotePeer) Call(network *Network, function string, data []byte, timeout time.Duration) (result []byte, err error) {
	c.mtx.Lock()
	sessionId := c.sessionId
	c.mtx.Unlock()

	// Check transport leyer
	nonce := c.nonces.Next()
	addressBS := []byte(c.remoteAddress)
	transaction := NewTransaction(0x20, AddressForPublicKey(&c.privateKey.PublicKey), c.remoteAddress, 0, 0, 0, 0, nil)
	transaction.Data = make([]byte, 16+len(addressBS))
	copy(transaction.Data[0:], nonce[:])
	copy(transaction.Data[16:], addressBS)

	c.Check(transaction, network, c.remotePublicKey != nil)

	if sessionId == 0 {
		err = c.auth(network, 1000*time.Millisecond)
		if err != nil {
			return
		}
	}

	c.mtx.Lock()
	sessionId = c.sessionId
	aesKey := make([]byte, len(c.aesKey))
	copy(aesKey, c.aesKey)
	c.mtx.Unlock()

	result, err = c.regularCall(network, function, data, aesKey, timeout)

	return
}

func (c *RemotePeer) auth(network *Network, timeout time.Duration) (err error) {
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
	nonce, err = c.regularCall(network, "/xchg-get-nonce", nil, nil, timeout)
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

	localPublicKeyBS := RSAPublicKeyToDer(&localPrivateKey.PublicKey)

	authFrameSecret := make([]byte, 16+len(authData))
	copy(authFrameSecret[0:], nonce)
	copy(authFrameSecret[16:], authData)
	var encryptedAuthFrame []byte
	encryptedAuthFrame, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, remotePublicKey, []byte(authFrameSecret), nil)
	if err != nil {
		err = errors.New(ERR_XCHG_CL_CONN_AUTH_ENC + ":" + err.Error())
		return
	}

	authFrame := make([]byte, 4+len(localPublicKeyBS)+len(encryptedAuthFrame))
	binary.LittleEndian.PutUint32(authFrame[0:], uint32(len(localPublicKeyBS)))
	copy(authFrame[4:], localPublicKeyBS)
	copy(authFrame[4+len(localPublicKeyBS):], encryptedAuthFrame)

	var result []byte
	result, err = c.regularCall(network, "/xchg-auth", authFrame, nil, timeout)
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

func (c *RemotePeer) regularCall(network *Network, function string, data []byte, aesKey []byte, timeout time.Duration) (result []byte, err error) {
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

	result, err = c.executeTransaction(network, sessionId, frame, timeout, aesKey)

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

func (c *RemotePeer) executeTransaction(network *Network, sessionId uint64, data []byte, timeout time.Duration, aesKeyOriginal []byte) (result []byte, err error) {
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
	sentCount := 0
	sendCounter := 0
	offset := 0
	blockSize := 1024
	for offset < len(data) {
		sendCounter++
		currentBlockSize := blockSize
		restDataLen := len(data) - offset
		if restDataLen < currentBlockSize {
			currentBlockSize = restDataLen
		}

		blockTransaction := NewTransaction(FrameTypeCall, AddressForPublicKey(&c.privateKey.PublicKey), c.remoteAddress, transactionId, sessionId, offset, len(data), data[offset:offset+currentBlockSize])

		err = c.Send(network, blockTransaction)
		if err == nil {
			sentCount++
			break
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

	if sendCounter != sentCount {
		return nil, errors.New("no route")
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

	fmt.Println("exec transaction timeout")

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

func (c *RemotePeer) httpCall(routerHost string, function string, frame []byte) (result []byte, err error) {
	// Waiting for router host

	if len(routerHost) == 0 {
		return
	}

	if len(frame) < 128 {
		return
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	{
		fw, _ := writer.CreateFormField("d")
		frame64 := base64.StdEncoding.EncodeToString(frame)
		fw.Write([]byte(frame64))
	}
	writer.Close()

	addr := "http://" + routerHost

	response, err := c.Post(addr+"/api/"+function, writer.FormDataContentType(), &body, addr)

	if err != nil {
		//fmt.Println("HTTP error:", err)
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
	return c.httpClient.Do(req)
}

func (c *RemotePeer) Send(network *Network, tr *Transaction) (err error) {
	addrs := network.GetNodesAddressesByAddress(tr.DestAddressString())
	bs := tr.Marshal()
	for _, a := range addrs {
		go c.httpCall(a, "w", bs)
	}
	return
}

func (c *RemotePeer) Check(frame20 *Transaction, network *Network, remotePublicKeyExists bool) error {
	if remotePublicKeyExists {
		return nil
	}
	go c.checkInternetConnectionPoint(frame20, network)
	return nil
}

func (c *RemotePeer) checkInternetConnectionPoint(frame20 *Transaction, network *Network) (err error) {
	addrs := network.GetNodesAddressesByAddress(frame20.DestAddressString())
	for _, a := range addrs {
		go c.httpCall(a, "w", frame20.Marshal())
	}

	return
}
