package xchg

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

func (c *Peer) processFrame(conn net.PacketConn, sourceAddress *net.UDPAddr, routerHost string, frame []byte) (responseFrames []*Transaction) {
	if len(frame) < 8 {
		//fmt.Println("processFrame from", sourceAddress, frame)
		return
	}
	//fmt.Println("processFrame from", sourceAddress, frame[8])

	frameType := frame[8]

	// Call Request
	if frameType == 0x10 {
		responseFrames = c.processFrame10(conn, sourceAddress, frame)
		return
	}

	// Call Response
	if frameType == 0x11 {
		c.processFrame11(conn, sourceAddress, frame)
		return
	}

	// ARP request
	if frameType == 0x20 {
		responseFrames = c.processFrame20(conn, sourceAddress, frame)
		return
	}

	// ARP response
	if frameType == 0x21 {
		c.processFrame21(conn, routerHost, sourceAddress, frame)
		return
	}

	return
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

	/*receivedAddr := ""
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

	c.mtx.Unlock()*/
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
// Incoming Call - Server Role
// ----------------------------------------

func (c *Peer) processFrame10(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) (responseFrames []*Transaction) {
	var processor ServerProcessor

	responseFrames = make([]*Transaction, 0)

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
	incomingTransactionCode := fmt.Sprint(transaction.SrcAddress, "-", transaction.TransactionId)
	if incomingTransaction, ok = c.incomingTransactions[incomingTransactionCode]; !ok {
		incomingTransaction = NewTransaction(transaction.FrameType, AddressForPublicKey(&c.privateKey.PublicKey), string(transaction.SrcAddress[:]), transaction.TransactionId, transaction.SessionId, 0, int(transaction.TotalSize), make([]byte, 0))
		incomingTransaction.BeginDT = time.Now()
		c.incomingTransactions[incomingTransactionCode] = incomingTransaction
	}

	incomingTransaction.AppendReceivedData(transaction)

	if incomingTransaction.Complete {
		incomingTransaction.Data = incomingTransaction.Result
		incomingTransaction.Result = nil
	} else {
		c.mtx.Unlock()
		return
	}

	//fmt.Println("RECEIVED TRANSACTION:", incomingTransaction.TransactionId)

	/*if len(incomingTransaction.Data) != int(incomingTransaction.TotalSize) {
		incomingTransaction.Data = make([]byte, int(incomingTransaction.TotalSize))
	}
	copy(incomingTransaction.Data[transaction.Offset:], transaction.Data)
	incomingTransaction.ReceivedDataLen += len(transaction.Data)

	if incomingTransaction.ReceivedDataLen < int(incomingTransaction.TotalSize) {
		c.mtx.Unlock()
		return
	}*/

	delete(c.incomingTransactions, incomingTransactionCode)
	c.mtx.Unlock()

	srcAddress := "#" + base32.StdEncoding.EncodeToString(transaction.SrcAddress[:])

	if processor != nil {
		resp, dontSendResponse := c.onEdgeReceivedCall(incomingTransaction.SessionId, incomingTransaction.Data)
		if !dontSendResponse {
			trResponse := NewTransaction(0x11, AddressForPublicKey(&c.privateKey.PublicKey), srcAddress, incomingTransaction.TransactionId, incomingTransaction.SessionId, 0, len(resp), resp)

			offset := 0
			blockSize := 1024
			for offset < len(trResponse.Data) {
				currentBlockSize := blockSize
				restDataLen := len(trResponse.Data) - offset
				if restDataLen < currentBlockSize {
					currentBlockSize = restDataLen
				}

				blockTransaction := NewTransaction(0x11, AddressForPublicKey(&c.privateKey.PublicKey), srcAddress, trResponse.TransactionId, trResponse.SessionId, offset, len(resp), trResponse.Data[offset:offset+currentBlockSize])
				blockTransaction.Offset = uint32(offset)
				blockTransaction.TotalSize = uint32(len(trResponse.Data))
				responseFrames = append(responseFrames, blockTransaction)
				offset += currentBlockSize
			}
		}
	}
	return
}

func (c *Peer) processFrame11(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) {
	tr, err := Parse(frame)
	if err != nil {
		return
	}

	var remotePeer *RemotePeer
	c.mtx.Lock()
	for _, peer := range c.remotePeers {
		srcAddress := "#" + strings.ToLower(base32.StdEncoding.EncodeToString(tr.SrcAddress[:]))
		if peer.RemoteAddress() == srcAddress {
			remotePeer = peer
			break
		}
	}
	c.mtx.Unlock()
	if remotePeer != nil {
		remotePeer.processFrame(conn, sourceAddress, frame)
	}
}

// ARP LAN request
func (c *Peer) processFrame20(conn net.PacketConn, sourceAddress *net.UDPAddr, frame []byte) (responseFrames []*Transaction) {

	responseFrames = make([]*Transaction, 0)

	c.mtx.Lock()
	localAddress := AddressForPublicKey(&c.privateKey.PublicKey)
	c.mtx.Unlock()

	transaction, err := Parse(frame)
	if err != nil {
		return
	}

	fmt.Println("20 received", transaction)

	nonce := transaction.Data[:16]
	nonceHash := sha256.Sum256(nonce)

	requestedAddress := string(transaction.Data[16:])
	if requestedAddress != localAddress {
		return // This is not my address
	}

	// Send my public key
	publicKeyBS := RSAPublicKeyToDer(&c.privateKey.PublicKey)

	// And signature
	signature, err := rsa.SignPSS(rand.Reader, c.privateKey, crypto.SHA256, nonceHash[:], nil)
	if err != nil {
		return
	}

	srcAddress := "#" + base32.StdEncoding.EncodeToString(transaction.SrcAddress[:])

	response := NewTransaction(0x21, AddressForPublicKey(&c.privateKey.PublicKey), srcAddress, 0, 0, 0, 0, nil)
	response.Data = make([]byte, 16+256+len(publicKeyBS))
	copy(response.Data[0:], nonce)
	copy(response.Data[16:], signature)
	copy(response.Data[16+256:], publicKeyBS)
	responseFrames = append(responseFrames, response)
	return
	//_, _ = conn.WriteTo(response.Marshal(), sourceAddress)
}

func (c *Peer) processFrame21(conn net.PacketConn, routerHost string, sourceAddress *net.UDPAddr, frame []byte) {
	transaction, err := Parse(frame)
	if err != nil {
		return
	}

	if len(transaction.Data) < 16+256 {
		err = errors.New("wrong frame size")
		return
	}

	receivedPublicKeyBS := transaction.Data[16+256:]
	receivedPublicKey, err := RSAPublicKeyFromDer([]byte(receivedPublicKeyBS))
	if err != nil {
		return
	}

	receivedAddress := AddressForPublicKey(receivedPublicKey)

	c.mtx.Lock()

	for _, peer := range c.remotePeers {
		if peer.RemoteAddress() == receivedAddress {
			peer.setConnectionPoint(sourceAddress, routerHost, receivedPublicKey, transaction.Data[0:16], transaction.Data[16:16+256])
			break
		}
	}

	c.mtx.Unlock()
}
