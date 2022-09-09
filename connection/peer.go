package connection

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/gomisc/nonce_generator"
	"github.com/ipoluianov/gomisc/snake_counter"
	"github.com/ipoluianov/xchg/xchg"
)

type Peer struct {
	mtx        sync.Mutex
	privateKey *rsa.PrivateKey
	started    bool
	stopping   bool
	conn       net.PacketConn

	// Client
	remotePeers map[string]*RemotePeer

	// Server
	incomingTransactions map[string]*Transaction
	sessionsById         map[uint64]*Session
	nonceGenerator       *nonce_generator.NonceGenerator
	nextSessionId        uint64
	processor            ServerProcessor
}

type ServerProcessor interface {
	ServerProcessorAuth(authData []byte) (err error)
	ServerProcessorCall(function string, parameter []byte) (response []byte, err error)
}

type Session struct {
	id           uint64
	aesKey       []byte
	lastAccessDT time.Time
	snakeCounter *snake_counter.SnakeCounter
}

const (
	PEER_UDP_START_PORT = 42000
	PEER_UDP_END_PORT   = 42100
)

func NewPeer(privateKey *rsa.PrivateKey) *Peer {
	var c Peer
	c.remotePeers = make(map[string]*RemotePeer)
	c.incomingTransactions = make(map[string]*Transaction)
	c.nonceGenerator = nonce_generator.NewNonceGenerator(10000)
	c.sessionsById = make(map[uint64]*Session)
	c.nextSessionId = 1

	c.privateKey = privateKey
	if c.privateKey == nil {
		c.privateKey, _ = crypt_tools.GenerateRSAKey()
	}
	go c.thReceive()
	return &c
}

func (c *Peer) Start() (err error) {
	c.mtx.Lock()
	if c.started {
		c.mtx.Unlock()
		err = errors.New("already started")
		return
	}
	c.mtx.Unlock()
	return
}

func (c *Peer) Stop() (err error) {
	c.mtx.Lock()
	if !c.started {
		c.mtx.Unlock()
		err = errors.New("already stopped")
		return
	}
	c.stopping = true
	started := c.started
	c.mtx.Unlock()

	dtBegin := time.Now()
	for started {
		time.Sleep(100 * time.Millisecond)
		c.mtx.Lock()
		started = c.started
		c.mtx.Unlock()
		if time.Now().Sub(dtBegin) > 1000*time.Second {
			break
		}
	}
	c.mtx.Lock()
	started = c.started
	c.mtx.Unlock()

	if started {
		err = errors.New("started")
	}

	return
}

func (c *Peer) SetProcessor(processor ServerProcessor) {
	c.processor = processor
}

func (c *Peer) thReceive() {
	var err error
	var conn net.PacketConn

	c.started = true

	buffer := make([]byte, INPUT_BUFFER_SIZE)

	var n int
	var addr net.Addr

	for {
		// Stopping
		c.mtx.Lock()
		stopping := c.stopping
		conn = c.conn
		c.mtx.Unlock()
		if stopping {
			break
		}

		// UDP port management
		if conn == nil {
			// Open any UDP port in diapason PEER_UDP_START_PORT:PEER_UDP_END_PORT
			for i := PEER_UDP_START_PORT; i < PEER_UDP_END_PORT; i++ {
				conn, err = net.ListenPacket("udp", ":"+fmt.Sprint(i))
				if err == nil {
					c.mtx.Lock()
					c.conn = conn
					c.mtx.Unlock()
					break
				}
			}

			if conn == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		err = conn.SetReadDeadline(time.Now().Add(1000 * time.Millisecond))
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			c.mtx.Lock()
			conn.Close()
			conn = nil
			c.conn = nil
			c.mtx.Unlock()
			continue
		}

		n, addr, err = conn.ReadFrom(buffer)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			// c.backgroundOperations()
			continue
		}

		if err != nil {
			time.Sleep(100 * time.Millisecond)
			c.mtx.Lock()
			conn.Close()
			conn = nil
			c.conn = nil
			c.mtx.Unlock()
			continue
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if ok {
			frame := make([]byte, n)
			copy(frame, buffer[:n])
			go c.processFrame(conn, udpAddr, frame)
		}
	}

	c.mtx.Lock()
	c.stopping = false
	c.started = false
	c.mtx.Unlock()
}

func (c *Peer) processFrame(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	fmt.Println("processFrame from", sourceAddress, frame[0])
	if len(frame) < 8 {
		return
	}

	receivedFromConnectionPoint := RemoteConnectionPointString(sourceAddress)

	frameType := frame[0]

	if frameType == 0x00 {
		c.sendResponse(conn, sourceAddress, frame, make([]byte, 8))
		return
	}

	if frameType == 0x20 {
		c.processFrame20(conn, sourceAddress, frame)
		return
	}

	if frameType == 0x21 {
		c.processFrame21(conn, sourceAddress, frame)
		return
	}

	// Request for server
	if frameType == 0x10 {
		c.processFrame10(conn, sourceAddress, frame)
		return
	}

	// Response received
	if frameType == 0x11 {
		var remotePeer *RemotePeer
		c.mtx.Lock()
		for _, peer := range c.remotePeers {
			if peer.RemoteConnectionPoint() == receivedFromConnectionPoint {
				remotePeer = peer
				break
			}
		}
		c.mtx.Unlock()
		if remotePeer != nil {
			remotePeer.processFrame(conn, sourceAddress, frame)
		}
		return
	}
}

func (c *Peer) sendError(conn net.PacketConn, sourceAddress *net.UDPAddr, originalFrame []byte, errorCode byte) {
	var responseFrame [8]byte
	copy(responseFrame[:], originalFrame[:8])
	responseFrame[1] = errorCode
	_, _ = conn.WriteTo(responseFrame[:], sourceAddress)
}

func (c *Peer) sendResponse(conn net.PacketConn, sourceAddress *net.UDPAddr, originalFrame []byte, responseFrame []byte) {
	copy(responseFrame, originalFrame[:8])
	responseFrame[1] = 0x00
	_, _ = conn.WriteTo(responseFrame, sourceAddress)
}

func (c *Peer) processFrame20(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	c.mtx.Lock()
	localAddress := xchg.AddressForPublicKey(&c.privateKey.PublicKey)
	c.mtx.Unlock()
	requestedAddress := string(frame[8:])
	if requestedAddress != localAddress {
		return
	}

	publicKeyBS := crypt_tools.RSAPublicKeyToDer(&c.privateKey.PublicKey)

	response := make([]byte, 8+len(publicKeyBS))
	copy(response, frame[:8])
	response[0] = 0x21
	copy(response[8:], publicKeyBS)
	_, _ = conn.WriteTo(response, sourceAddress)
}

func (c *Peer) processFrame21(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	receivedPublicKeyBS := frame[8:]
	receivedPublicKey, err := crypt_tools.RSAPublicKeyFromDer([]byte(receivedPublicKeyBS))
	if err != nil {
		return
	}

	receivedAddress := xchg.AddressForPublicKey(receivedPublicKey)

	c.mtx.Lock()

	for _, peer := range c.remotePeers {
		if peer.remoteAddress == receivedAddress {
			peer.setRemoteConnectionPoint(sourceAddress, receivedPublicKey)
			break
		}
	}

	c.mtx.Unlock()
}

func (c *Peer) Call(remoteAddress string, authData string, function string, data []byte, timeout time.Duration) (result []byte, err error) {
	c.mtx.Lock()
	conn := c.conn
	if conn == nil {
		c.mtx.Unlock()
		err = errors.New("no connection")
		return
	}
	remotePeer, remotePeerOk := c.remotePeers[remoteAddress]
	if !remotePeerOk || remotePeer == nil {
		remotePeer = NewRemotePeer(remoteAddress, authData, c.privateKey)
		c.remotePeers[remoteAddress] = remotePeer
	}
	c.mtx.Unlock()
	result, err = remotePeer.Call(conn, function, data, timeout)
	return
}

func (c *Peer) processFrame10(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	fmt.Println("processCall")
	var processor ServerProcessor

	transaction, err := Parse(frame)
	if err != nil {
		return
	}

	c.mtx.Lock()
	processor = c.processor
	var incomingTransaction *Transaction

	for trCode, tr := range c.incomingTransactions {
		now := time.Now()
		if now.Sub(tr.BeginDT) > 10*time.Second {
			delete(c.incomingTransactions, trCode)
		}
	}

	var ok bool
	incomingTransactionCode := fmt.Sprint(sourceAddress.String(), "-", transaction.TransactionId)
	if incomingTransaction, ok = c.incomingTransactions[incomingTransactionCode]; !ok {
		incomingTransaction = NewTransaction(transaction.FrameType, transaction.TransactionId, transaction.SessionId, 0, int(transaction.TotalSize), make([]byte, 0))
		incomingTransaction.BeginDT = time.Now()
		c.incomingTransactions[incomingTransactionCode] = incomingTransaction
	}

	if len(incomingTransaction.Data) != int(incomingTransaction.TotalSize) {
		incomingTransaction.Data = make([]byte, int(incomingTransaction.TotalSize))
	}
	copy(incomingTransaction.Data[transaction.Offset:], transaction.Data)
	incomingTransaction.ReceivedDataLen += len(transaction.Data)

	if incomingTransaction.ReceivedDataLen < int(incomingTransaction.TotalSize) {
		c.mtx.Unlock()
		return
	}
	delete(c.incomingTransactions, incomingTransactionCode)
	c.mtx.Unlock()

	if processor != nil {
		fmt.Println("Received call")
		resp := c.onEdgeReceivedCall(incomingTransaction.SessionId, incomingTransaction.Data)
		trResponse := NewTransaction(0x11, incomingTransaction.TransactionId, incomingTransaction.SessionId, 0, len(resp), resp)

		offset := 0
		blockSize := 1024 - 40
		for offset < len(trResponse.Data) {
			currentBlockSize := blockSize
			restDataLen := len(trResponse.Data) - offset
			if restDataLen < currentBlockSize {
				currentBlockSize = restDataLen
			}

			blockTransaction := NewTransaction(0x11, trResponse.TransactionId, trResponse.SessionId, offset, len(resp), trResponse.Data[offset:offset+currentBlockSize])
			blockTransaction.Offset = uint32(offset)
			blockTransaction.TotalSize = uint32(len(trResponse.Data))

			blockTransactionBS := blockTransaction.Marshal()

			_, err := conn.WriteTo(blockTransactionBS, sourceAddress)
			if err != nil {
				fmt.Println("send error", err)
				break
			}
			offset += currentBlockSize
		}
	}

}

func (c *Peer) onEdgeReceivedCall(sessionId uint64, data []byte) (response []byte) {

	var err error
	// Find the session
	var session *Session
	encryped := false
	if sessionId != 0 {
		c.mtx.Lock()
		var ok bool
		session, ok = c.sessionsById[sessionId]
		if !ok {
			session = nil
		}
		c.mtx.Unlock()
	}

	if sessionId != 0 {
		if session == nil {
			response = prepareResponseError(errors.New(xchg.ERR_XCHG_SRV_CONN_WRONG_SESSION))
			return
		}
		data, err = crypt_tools.DecryptAESGCM(data, session.aesKey)
		if err != nil {
			response = prepareResponseError(errors.New(xchg.ERR_XCHG_SRV_CONN_DECR + ":" + err.Error()))
			return
		}
		data, err = UnpackBytes(data)
		if err != nil {
			response = prepareResponseError(errors.New(xchg.ERR_XCHG_SRV_CONN_UNPACK + ":" + err.Error()))
			return
		}
		if len(data) < 9 {
			response = prepareResponseError(errors.New(xchg.ERR_XCHG_SRV_CONN_WRONG_LEN9))
			return
		}
		encryped = true
		callNonce := binary.LittleEndian.Uint64(data)
		err = session.snakeCounter.TestAndDeclare(int(callNonce))
		if err != nil {
			response = prepareResponseError(errors.New(xchg.ERR_XCHG_SRV_CONN_WRONG_NONCE))
			return
		}
		data = data[8:]
	} else {
		if len(data) < 1 {
			response = prepareResponseError(errors.New(xchg.ERR_XCHG_SRV_CONN_WRONG_LEN1))
			return
		}
	}

	functionLen := int(data[0])
	if len(data) < 1+functionLen {
		response = prepareResponseError(errors.New(xchg.ERR_XCHG_SRV_CONN_WRONG_LEN_FN))
		return
	}
	function := string(data[1 : 1+functionLen])
	functionParameter := data[1+functionLen:]

	var processor ServerProcessor
	c.mtx.Lock()
	processor = c.processor
	c.mtx.Unlock()

	if processor == nil {
		response = prepareResponseError(errors.New(xchg.ERR_XCHG_SRV_CONN_NOT_IMPL))
		return
	}

	var resp []byte

	switch function {
	case "/xchg-get-nonce":
		resp = c.nonceGenerator.Get()
	case "/xchg-auth":
		resp, err = c.processAuth(functionParameter)
	default:
		resp, err = c.processor.ServerProcessorCall(function, functionParameter)
	}

	if err != nil {
		response = prepareResponseError(err)
	} else {
		response = prepareResponse(resp)
	}

	if encryped {
		response = PackBytes(response)
		response, err = crypt_tools.EncryptAESGCM(response, session.aesKey)
		if err != nil {
			return
		}
	}

	return
}

func (c *Peer) processAuth(functionParameter []byte) (response []byte, err error) {
	if len(functionParameter) < 4 {
		err = errors.New(xchg.ERR_XCHG_SRV_CONN_AUTH_DATA_LEN4)
		return
	}

	remotePublicKeyBSLen := binary.LittleEndian.Uint32(functionParameter)
	if len(functionParameter) < 4+int(remotePublicKeyBSLen) {
		err = errors.New(xchg.ERR_XCHG_SRV_CONN_AUTH_DATA_LEN_PK)
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
		err = errors.New(xchg.ERR_XCHG_SRV_CONN_AUTH_DATA_LEN_NONCE)
		return
	}

	nonce := parameter[0:16]
	if !c.nonceGenerator.Check(nonce) {
		err = errors.New(xchg.ERR_XCHG_SRV_CONN_AUTH_WRONG_NONCE)
		return
	}

	authData := parameter[16:]
	err = c.processor.ServerProcessorAuth(authData)
	if err != nil {
		return
	}

	c.mtx.Lock()

	sessionId := c.nextSessionId
	c.nextSessionId++
	session := &Session{}
	session.id = sessionId
	session.lastAccessDT = time.Now()
	session.aesKey = make([]byte, 32)
	session.snakeCounter = snake_counter.NewSnakeCounter(100, 0)
	rand.Read(session.aesKey)
	c.sessionsById[sessionId] = session
	response = make([]byte, 8+32)
	binary.LittleEndian.PutUint64(response, sessionId)
	copy(response[8:], session.aesKey)
	response, err = rsa.EncryptPKCS1v15(rand.Reader, remotePublicKey, response)

	c.mtx.Unlock()

	return
}

func prepareResponse(data []byte) []byte {
	respFrame := make([]byte, 1+len(data))
	respFrame[0] = 0
	copy(respFrame[1:], data)
	return respFrame
}

func prepareResponseError(err error) []byte {
	errBS := make([]byte, 0)
	if err != nil {
		errBS = []byte(err.Error())
	}
	respFrame := make([]byte, 1+len(errBS))
	respFrame[0] = 1
	copy(respFrame[1:], errBS)
	return respFrame
}
