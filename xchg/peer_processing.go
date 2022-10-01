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
	"time"
)

func (c *Peer) processFrame(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	//fmt.Println("processFrame from", sourceAddress, frame[0])
	if len(frame) < 8 {
		return
	}

	frameType := frame[0]

	// Ping Request
	if frameType == 0x00 {
		c.processFrame00(conn, sourceAddress, frame)
		return
	}

	// Ping Response
	if frameType == 0x01 {
		c.processFrame01(conn, sourceAddress, frame)
		return
	}

	// Internet ARP Request
	if frameType == 0x02 {
		c.processFrame02(conn, sourceAddress, frame)
		return
	}

	// Internet ARP Response
	if frameType == 0x03 {
		c.processFrame03(conn, sourceAddress, frame)
		return
	}

	// Call Request
	if frameType == 0x10 {
		c.processFrame10(conn, sourceAddress, frame)
		return
	}

	// Call Response
	if frameType == 0x11 {
		c.processFrame11(conn, sourceAddress, frame)
		return
	}

	// ARP request
	if frameType == 0x20 {
		c.processFrame20(conn, sourceAddress, frame)
		return
	}

	// ARP response
	if frameType == 0x21 {
		c.processFrame21(conn, sourceAddress, frame)
		return
	}

	// Get Public Key
	if frameType == 0x22 {
		c.processFrame22(conn, sourceAddress, frame)
		return
	}

	// Get Public Key Response
	if frameType == 0x23 {
		c.processFrame23(conn, sourceAddress, frame)
		return
	}

}

// ----------------------------------------
// Ping
// ----------------------------------------

func (c *Peer) processFrame00(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	// response to ping request
	frame[0] = 0x01 // Ping response
	frame[1] = 0x00
	conn.WriteTo(frame, sourceAddress)
}

func (c *Peer) processFrame01(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	// nothing to do
}

// ----------------------------------------
// Nonce
// ----------------------------------------

func (c *Peer) processFrame02(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	// nothing to do
}

func (c *Peer) processFrame03(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	if frame[1] != 0 {
		return
	}
	if len(frame) != 8+16 {
		return
	}

	nonce := frame[8:]

	data := make([]byte, 0)
	publicKeyBS := RSAPublicKeyToDer(&c.privateKey.PublicKey)
	request := make([]byte, 8+16+8+256+4+len(publicKeyBS)+len(data))
	request[0] = 0x02

	copy(request[8:], nonce)
	// copy(request[24:], salt) // TODO: salt

	hash := sha256.Sum256(request[8:32])
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return
	}
	copy(request[32:], signature)

	binary.LittleEndian.PutUint32(request[288:], uint32(len(publicKeyBS)))
	copy(request[292:], publicKeyBS)
	copy(request[292+len(publicKeyBS):], data)

	var n int
	n, err = conn.WriteTo(request, sourceAddress)
	if err != nil {
		return
	}
	if n != len(request) {
		err = errors.New("data sent partially")
		return
	}
}

// ----------------------------------------
// Get Data for Native Address
// ----------------------------------------

func (c *Peer) processFrame06(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	// nothing to do
}

func (c *Peer) processFrame07(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	if frame[1] != 0 {
		return
	}

	receivedAddr := ""
	data := make([]byte, 0)

	for i := 8; i < len(frame); i++ {
		if frame[i] == '=' {
			receivedAddr = string(frame[8:i])
			data = frame[i+1:]
			break
		}
	}

	c.mtx.Lock()

	for _, peer := range c.remotePeers {
		if peer.remoteAddress == receivedAddr {
			peer.setInternetConnectionPoint(sourceAddress, data)
			break
		}
	}

	c.mtx.Unlock()
}

// ----------------------------------------
// Resolve Custom Address
// ----------------------------------------

func (c *Peer) processFrame08(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	// nothing to do
}

func (c *Peer) processFrame09(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	// todo: set native address for the custom address
}

// ----------------------------------------
// Resolve Custom Address
// ----------------------------------------

func (c *Peer) processFrame10(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
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
		resp := c.onEdgeReceivedCall(incomingTransaction.SessionId, incomingTransaction.Data)
		trResponse := NewTransaction(0x11, incomingTransaction.TransactionId, incomingTransaction.SessionId, 0, len(resp), resp)

		offset := 0
		blockSize := 1024
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

func (c *Peer) processFrame11(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	receivedFromConnectionPoint := ConnectionPointString(sourceAddress)

	var remotePeer *RemotePeer
	c.mtx.Lock()
	for _, peer := range c.remotePeers {
		if peer.LANConnectionPoint() == receivedFromConnectionPoint {
			remotePeer = peer
			break
		}
		if peer.InternetConnectionPoint() == receivedFromConnectionPoint {
			remotePeer = peer
			break
		}
	}
	c.mtx.Unlock()
	if remotePeer != nil {
		remotePeer.processFrame(conn, sourceAddress, frame)
	}
}

func (c *Peer) processFrame20(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	c.mtx.Lock()
	localAddress := AddressForPublicKey(&c.privateKey.PublicKey)
	c.mtx.Unlock()

	nonce := frame[8 : 8+16]
	nonceHash := sha256.Sum256(nonce)

	requestedAddress := string(frame[8+16:])
	if requestedAddress != localAddress {
		return // This is not my address
	}

	// Send my public key
	publicKeyBS := RSAPublicKeyToDer(&c.privateKey.PublicKey)

	// And signature
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey, crypto.SHA256, nonceHash[:])
	if err != nil {
		return
	}

	response := make([]byte, 8+16+256+len(publicKeyBS))
	copy(response, frame[:8])
	response[0] = 0x21
	copy(response[8:], nonce)
	copy(response[8+16:], signature)
	copy(response[8+16+256:], publicKeyBS)
	_, _ = conn.WriteTo(response, sourceAddress)
}

func (c *Peer) processFrame21(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	receivedPublicKeyBS := frame[8+16+256:]
	receivedPublicKey, err := RSAPublicKeyFromDer([]byte(receivedPublicKeyBS))
	if err != nil {
		return
	}

	receivedAddress := AddressForPublicKey(receivedPublicKey)

	c.mtx.Lock()

	for _, peer := range c.remotePeers {
		if peer.remoteAddress == receivedAddress {
			peer.setLANConnectionPoint(sourceAddress, receivedPublicKey, frame[8:8+16], frame[8+16:8+16+256])
			break
		}
	}

	c.mtx.Unlock()
}

func (c *Peer) processFrame22(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	c.mtx.Lock()
	localAddress := AddressForPublicKey(&c.privateKey.PublicKey)
	c.mtx.Unlock()
	requestedAddress := string(frame[8:])
	if requestedAddress != localAddress {
		return
	}

	publicKeyBS := RSAPublicKeyToDer(&c.privateKey.PublicKey)

	response := make([]byte, 8+len(publicKeyBS))
	copy(response, frame[:8])
	response[0] = 0x23
	copy(response[8:], publicKeyBS)
	_, _ = conn.WriteTo(response, sourceAddress)
}

func (c *Peer) processFrame23(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	receivedPublicKeyBS := frame[8:]
	receivedPublicKey, err := RSAPublicKeyFromDer([]byte(receivedPublicKeyBS))
	if err != nil {
		return
	}

	receivedAddress := AddressForPublicKey(receivedPublicKey)

	c.mtx.Lock()

	for _, peer := range c.remotePeers {
		if peer.remoteAddress == receivedAddress {
			peer.setRemotePublicKey(receivedPublicKey)
			break
		}
	}

	c.mtx.Unlock()
}
