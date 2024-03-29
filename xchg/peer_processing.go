package xchg

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (c *Peer) processFrame(routerHost string, frame []byte) (responseFrames []*Transaction) {
	if len(frame) < 8 {
		return
	}

	frameType := frame[8]

	// Call Request
	if frameType == 0x10 {
		responseFrames = c.processFrame10(routerHost, frame)
		return
	}

	// Call Response
	if frameType == 0x11 {
		c.processFrame11(routerHost, frame)
		return
	}

	// ARP request
	if frameType == 0x20 {
		responseFrames = c.processFrame20(frame)
		return
	}

	// ARP response
	if frameType == 0x21 {
		c.processFrame21(routerHost, frame)
		return
	}

	return
}

// ----------------------------------------
// Incoming Call - Server Role
// ----------------------------------------

func (c *Peer) processFrame10(routerHost string, frame []byte) (responseFrames []*Transaction) {
	var processor ServerProcessor

	responseFrames = make([]*Transaction, 0)

	transaction, err := Parse(frame)
	if err != nil {
		return
	}

	if c.network != nil {
		if c.network.IsLocalNode(routerHost) {
			transaction.FromLocalNode = true
		}
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

	delete(c.incomingTransactions, incomingTransactionCode)
	c.mtx.Unlock()

	srcAddress := "#" + base32.StdEncoding.EncodeToString(transaction.SrcAddress[:])

	if processor != nil {
		resp, dontSendResponse := c.onEdgeReceivedCall(incomingTransaction.SessionId, incomingTransaction.Data)
		if !dontSendResponse {
			trResponse := NewTransaction(0x11, AddressForPublicKey(&c.privateKey.PublicKey), srcAddress, incomingTransaction.TransactionId, incomingTransaction.SessionId, 0, len(resp), resp)

			offset := 0
			blockSize := 4 * 1024
			for offset < len(trResponse.Data) {
				currentBlockSize := blockSize
				restDataLen := len(trResponse.Data) - offset
				if restDataLen < currentBlockSize {
					currentBlockSize = restDataLen
				}

				blockTransaction := NewTransaction(0x11, AddressForPublicKey(&c.privateKey.PublicKey), srcAddress, trResponse.TransactionId, trResponse.SessionId, offset, len(resp), trResponse.Data[offset:offset+currentBlockSize])
				blockTransaction.Offset = uint32(offset)
				blockTransaction.TotalSize = uint32(len(trResponse.Data))
				blockTransaction.FromLocalNode = incomingTransaction.FromLocalNode
				responseFrames = append(responseFrames, blockTransaction)
				offset += currentBlockSize
			}
		}
	}
	return
}

func (c *Peer) processFrame11(routerHost string, frame []byte) {
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
		remotePeer.processFrame(routerHost, frame)
	}
}

// ARP LAN request
func (c *Peer) processFrame20(frame []byte) (responseFrames []*Transaction) {

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
	signature, err := rsa.SignPSS(rand.Reader, c.privateKey, crypto.SHA256, nonceHash[:], &rsa.PSSOptions{
		SaltLength: 32,
	})
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

func (c *Peer) processFrame21(routerHost string, frame []byte) {
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
			peer.setConnectionPoint(routerHost, receivedPublicKey, transaction.Data[0:16], transaction.Data[16:16+256])
			break
		}
	}

	c.mtx.Unlock()
}
