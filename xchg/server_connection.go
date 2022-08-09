package xchg

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ipoluianov/gomisc/crypt_tools"
)

type Session struct {
	id           uint64
	aesKey       []byte
	lastAccessDT time.Time
}

type ServerConnection struct {
	mtxServerConnection sync.Mutex
	edgeConnections     map[string]*EdgeConnection
	privateKey58        string
	privateKey          *rsa.PrivateKey

	sessionsById          map[uint64]*Session
	nextSessionId         uint64
	lastPurgeSessionsTime time.Time

	nonceGenerator *NonceGenerator

	processor ServerProcessor
}

type ServerProcessor interface {
	ServerProcessorAuth(authData []byte) (err error)
	ServerProcessorCall(function string, parameter []byte) (response []byte, err error)
}

func NewServerConnection(privateKey58 string) *ServerConnection {
	var c ServerConnection
	c.nextSessionId = 1
	c.nonceGenerator = NewNonceGenerator(1024 * 1024)
	c.privateKey58 = privateKey58
	c.privateKey, _ = crypt_tools.RSAPrivateKeyFromDer(base58.Decode(c.privateKey58))
	c.edgeConnections = make(map[string]*EdgeConnection)
	c.sessionsById = make(map[uint64]*Session)
	eConn := NewEdgeConnection("localhost:8484", c.privateKey)
	eConn.SetProcessor(&c)
	c.edgeConnections["localhost:8484"] = eConn
	eConn.Start()
	return &c
}

func (c *ServerConnection) SetProcessor(processor ServerProcessor) {
	c.processor = processor
}

func (c *ServerConnection) Start() {
}

func (c *ServerConnection) getEdgeConnection() *EdgeConnection {
	return c.edgeConnections["localhost:8484"]
}

func (c *ServerConnection) purgeSessions() {
	now := time.Now()
	c.mtxServerConnection.Lock()
	if now.Sub(c.lastPurgeSessionsTime).Seconds() > 5*60 {
		fmt.Println("Purging sessions")
		for sessionId, session := range c.sessionsById {
			if now.Sub(session.lastAccessDT).Seconds() > 30 {
				fmt.Println("Removing session", sessionId)
				delete(c.sessionsById, sessionId)
			}
		}
		c.lastPurgeSessionsTime = time.Now()
	}
	c.mtxServerConnection.Unlock()
}

func (c *ServerConnection) OnEdgeConnected(edgeConnection *EdgeConnection) {
}

func (c *ServerConnection) OnEdgeDissonnected(edgeConnection *EdgeConnection) {
}

func (c *ServerConnection) OnEdgeReceivedCall(edgeConnection *EdgeConnection, sessionId uint64, data []byte) (response []byte) {
	if sessionId != 0 {
	} else {
		// TODO: decrypt by session AES key
	}

	if len(data) < 1 {
		response = c.prepareResponseError(errors.New("EdgeConnection wrong call data (<1)"))
		return
	}

	functionLen := int(data[0])
	if len(data) < 1+functionLen {
		response = c.prepareResponseError(errors.New("EdgeConnection wrong call data (function len)"))
		return
	}
	function := string(data[1 : 1+functionLen])
	functionParameter := data[1+functionLen:]

	var processor ServerProcessor
	c.mtxServerConnection.Lock()
	processor = c.processor
	c.mtxServerConnection.Unlock()

	if processor == nil {
		response = c.prepareResponseError(errors.New("not implemented"))
		return
	}

	var resp []byte
	var err error

	switch function {
	case "/xchg-get-nonce":
		resp = c.nonceGenerator.Get()
	case "/xchg-auth":
		resp, err = c.processAuth(functionParameter)
	default:
		resp, err = c.processor.ServerProcessorCall(function, functionParameter)
	}

	if err != nil {
		response = c.prepareResponseError(err)
	} else {
		response = c.prepareResponse(resp)
	}
	return
}

func (c *ServerConnection) processAuth(functionParameter []byte) (response []byte, err error) {
	if len(functionParameter) < 4 {
		err = errors.New("wrong parameter len (<4)")
		return
	}

	remotePublicKeyBSLen := binary.LittleEndian.Uint32(functionParameter)
	if len(functionParameter) < 4+int(remotePublicKeyBSLen) {
		err = errors.New("wrong parameter len (public key len)")
		return
	}

	remotePublicKeyBS := functionParameter[4 : 4+remotePublicKeyBSLen]
	var remotePublicKey *rsa.PublicKey
	remotePublicKey, err = crypt_tools.RSAPublicKeyFromDer(remotePublicKeyBS)
	if err != nil {
		return
	}

	authFrameSecret := functionParameter[4+remotePublicKeyBSLen:]

	var parameter []byte
	parameter, err = rsa.DecryptPKCS1v15(rand.Reader, c.privateKey, authFrameSecret)
	if err != nil {
		return
	}

	if len(parameter) < 16 {
		err = errors.New("wrong parameter len (<16)")
		return
	}

	nonce := parameter[0:16]
	if !c.nonceGenerator.Check(nonce) {
		return
	}

	authData := parameter[16:]
	err = c.processor.ServerProcessorAuth(authData)
	if err != nil {
		return
	}

	c.mtxServerConnection.Lock()

	sessionId := c.nextSessionId
	c.nextSessionId++
	session := &Session{}
	session.id = sessionId
	session.lastAccessDT = time.Now()
	session.aesKey = make([]byte, 32)
	rand.Read(session.aesKey)
	c.sessionsById[sessionId] = session
	response = make([]byte, 8+32)
	binary.LittleEndian.PutUint64(response, sessionId)
	copy(response[8:], session.aesKey)
	response, err = rsa.EncryptPKCS1v15(rand.Reader, remotePublicKey, response)

	c.mtxServerConnection.Unlock()

	return
}

func (c *ServerConnection) prepareResponse(data []byte) []byte {
	respFrame := make([]byte, 1+len(data))
	respFrame[0] = 0
	copy(respFrame[1:], data)
	return respFrame
}

func (c *ServerConnection) prepareResponseError(err error) []byte {
	errBS := make([]byte, 0)
	if err != nil {
		errBS = []byte(err.Error())
	}
	respFrame := make([]byte, 1+len(errBS))
	respFrame[0] = 1
	copy(respFrame[1:], errBS)
	return respFrame
}
