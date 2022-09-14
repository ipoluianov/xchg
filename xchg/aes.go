package xchg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

func DecryptAESGCM(encryptedMessage []byte, key []byte) (decryptedMessage []byte, err error) {
	ch, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(ch)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(encryptedMessage) < nonceSize {
		return nil, errors.New("wrong nonce")
	}
	nonce, ciphertext := encryptedMessage[:nonceSize], encryptedMessage[nonceSize:]
	decryptedMessage, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return
}

func EncryptAESGCM(decryptedMessage []byte, key []byte) (encryptedMessage []byte, err error) {
	var ch cipher.Block
	ch, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var gcm cipher.AEAD
	gcm, err = cipher.NewGCM(ch)
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	encryptedMessage = gcm.Seal(nonce, nonce, decryptedMessage, nil)
	return
}
