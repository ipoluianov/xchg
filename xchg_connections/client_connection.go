package xchg_connections

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_network"
)

type ClientConnection struct {
	mtxClientConnection sync.Mutex
	address             string
	remotePublicKey     *rsa.PublicKey
	localPrivateKey     *rsa.PrivateKey

	aesKey              []byte
	sessionId           uint64
	sessionNonceCounter uint64

	findingConnection bool
	currentConnection *PeerConnection
	currentSID        uint64

	secretBytes []byte

	network *xchg_network.Network
	udpHole *net.UDPAddr

	authData string

	lastestNodeAddress string
	authProcessing     bool

	onEvent FuncOnEvent
}

type FuncOnEvent func(text string)

type ClientConnectionState struct {
	SessionId           uint64
	FindingConnection   bool
	CurrentSID          uint64
	AuthProcessing      bool
	LatestNodeAddress   string
	PeerConnectionState PeerConnectionState
}

func NewClientConnection(network *xchg_network.Network, address string, localPrivateKey32 string, authData string, onEvent FuncOnEvent) *ClientConnection {
	var c ClientConnection
	c.address = address
	c.authData = authData
	c.network = network
	c.remotePublicKey = nil
	localPrivateKeyBS, _ := base32.StdEncoding.DecodeString(localPrivateKey32)
	c.localPrivateKey, _ = crypt_tools.RSAPrivateKeyFromDer(localPrivateKeyBS)
	c.sessionNonceCounter = 1
	c.onEvent = onEvent
	return &c
}

func (c *ClientConnection) Dispose() {
	c.mtxClientConnection.Lock()
	currentConnection := c.currentConnection
	c.mtxClientConnection.Unlock()

	c.onEvent = nil

	if currentConnection != nil {
		currentConnection.Dispose()
		c.mtxClientConnection.Lock()
		c.currentConnection = nil
		c.mtxClientConnection.Unlock()
	}
}

func (c *ClientConnection) Reset() {
	c.mtxClientConnection.Lock()
	c.reset()
	c.mtxClientConnection.Unlock()
}

func (c *ClientConnection) reset() {
	c.currentSID = 0
	c.sessionId = 0
	if c.currentConnection != nil {
		c.currentConnection.Stop()
		c.currentConnection.Dispose()
		c.currentConnection = nil
	}
}

func (c *ClientConnection) CallOnEvent(text string) {
	c.mtxClientConnection.Lock()
	onEvent := c.onEvent
	c.mtxClientConnection.Unlock()
	if onEvent != nil {
		onEvent(text)
	}
}

func (c *ClientConnection) Call(function string, data []byte) (result []byte, err error) {
	c.CallOnEvent("call " + function)

	c.mtxClientConnection.Lock()
	sessionId := c.sessionId
	c.mtxClientConnection.Unlock()

	if sessionId == 0 {
		err = c.auth()
		if err != nil {
			return
		}
	}

	c.mtxClientConnection.Lock()
	sessionId = c.sessionId
	aesKey := make([]byte, len(c.aesKey))
	copy(aesKey, c.aesKey)
	c.mtxClientConnection.Unlock()

	result, err = c.regularCall(function, data, aesKey)

	return
}

func (c *ClientConnection) auth() (err error) {
	c.mtxClientConnection.Lock()
	if c.authProcessing {
		c.mtxClientConnection.Unlock()
		return
	}
	c.authProcessing = true
	c.mtxClientConnection.Unlock()

	defer func() {
		c.mtxClientConnection.Lock()
		c.authProcessing = false
		c.mtxClientConnection.Unlock()
	}()

	var nonce []byte
	nonce, err = c.regularCall("/xchg-get-nonce", nil, nil)
	if err != nil {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_AUTH_GET_NONCE + ":" + err.Error())
		return
	}
	if len(nonce) != 16 {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_AUTH_WRONG_NONCE_LEN)
		return
	}

	c.mtxClientConnection.Lock()
	localPrivateKey := c.localPrivateKey
	remotePublicKey := c.remotePublicKey
	authData := make([]byte, len(c.authData))
	copy(authData, []byte(c.authData))
	c.mtxClientConnection.Unlock()
	if c.localPrivateKey == nil {
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
	result, err = c.regularCall("/xchg-auth", authFrame, nil)
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

	c.mtxClientConnection.Lock()
	c.sessionId = binary.LittleEndian.Uint64(result)
	c.aesKey = make([]byte, 32)
	copy(c.aesKey, result[8:])
	c.mtxClientConnection.Unlock()

	return
}

func (c *ClientConnection) regularCall(function string, data []byte, aesKey []byte) (result []byte, err error) {
	if len(function) > 255 {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_CALL_WRONG_FUNCTION_LEN)
		return
	}

	encrypted := false

	c.mtxClientConnection.Lock()
	address := c.address
	alreadySearching := false
	if c.findingConnection {
		alreadySearching = true
	}
	currentSID := c.currentSID
	if currentSID == 0 && !c.findingConnection {
		c.findingConnection = true
		c.reset()
	}
	localPrivateKey := c.localPrivateKey
	c.mtxClientConnection.Unlock()

	if alreadySearching {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_CALL_SEARCHING_NODE)
		return
	}

	if localPrivateKey == nil {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_CALL_NO_LOCAL_PRIVATE_KEY)
		return
	}

	if currentSID == 0 {
		addresses := c.network.GetNodesAddressesByAddress(address)
		for _, address := range addresses {
			c.lastestNodeAddress = address

			conn := NewPeerConnection(address, localPrivateKey, nil, "client")
			conn.Start()
			if !conn.WaitForConnection(1000 * time.Millisecond) {
				conn.Stop()
				conn.Dispose()
				continue
			}

			var remotePublicKey *rsa.PublicKey
			var udpHole *net.UDPAddr
			currentSID, remotePublicKey, udpHole, err = conn.ResolveAddress(c.address)
			if err != nil || currentSID == 0 || remotePublicKey == nil || xchg.AddressForPublicKey(remotePublicKey) != c.address {
				conn.Stop()
				conn.Dispose()
				continue
			}

			c.mtxClientConnection.Lock()
			c.udpHole = udpHole
			c.currentConnection = conn
			c.currentSID = currentSID
			c.remotePublicKey = remotePublicKey
			c.mtxClientConnection.Unlock()
			break
		}

		c.mtxClientConnection.Lock()
		c.findingConnection = false
		c.mtxClientConnection.Unlock()
	}

	c.mtxClientConnection.Lock()
	connection := c.currentConnection
	sessionId := c.sessionId
	currentSID = c.currentSID
	c.mtxClientConnection.Unlock()

	if connection == nil || currentSID == 0 {
		err = errors.New(xchg.ERR_XCHG_CL_CONN_CALL_NO_ROUTE_TO_PEER)
		return
	}

	c.mtxClientConnection.Lock()
	sessionNonceCounter := c.sessionNonceCounter
	c.sessionNonceCounter++
	c.mtxClientConnection.Unlock()

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

	result, err = connection.Call(currentSID, sessionId, frame, c.udpHole)

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

func (c *ClientConnection) State() ClientConnectionState {
	c.mtxClientConnection.Lock()
	defer c.mtxClientConnection.Unlock()

	var state ClientConnectionState
	state.CurrentSID = c.currentSID
	state.AuthProcessing = c.authProcessing
	state.FindingConnection = c.findingConnection
	state.SessionId = c.sessionId
	state.LatestNodeAddress = c.lastestNodeAddress

	if c.currentConnection != nil {
		state.PeerConnectionState = c.currentConnection.State()
	}

	return state
}
