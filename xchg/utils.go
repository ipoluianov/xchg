package xchg

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"errors"
	"io"
	"io/fs"
	"io/ioutil"
	"strings"
)

const Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// XCHG:    kqfc2fwogggtlsf7vnh46hhgdjmheiqvqycapj2f2xe2d5jz
// ONIONv2: expyuzz4wqqyqhjn
// ONIONv3: 2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid

const AddressBytesSize = 30
const AddressSize = int((AddressBytesSize * 8) / 5)

func AddressBSForPublicKey(publicKey *rsa.PublicKey) []byte {
	if publicKey == nil {
		return nil
	}
	bs := RSAPublicKeyToDer(publicKey)
	return AddressBSForPublicKeyBS(bs)
}

func AddressForPublicKey(publicKey *rsa.PublicKey) string {
	if publicKey == nil {
		return ""
	}
	bs := RSAPublicKeyToDer(publicKey)
	return AddressForPublicKeyBS(bs)
}

func AddressForPublicKeyBS(publicKeyBS []byte) string {
	if len(publicKeyBS) == 0 {
		return ""
	}

	hash := publicKeyBS
	for i := 0; i < 1; i++ {
		h := sha256.Sum256(hash)
		hash = h[:]
	}

	return "#" + strings.ToLower(base32.StdEncoding.EncodeToString(hash[:AddressBytesSize]))
}

func AddressBSForPublicKeyBS(publicKeyBS []byte) []byte {
	if len(publicKeyBS) == 0 {
		return nil
	}

	hash := publicKeyBS
	for i := 0; i < 1; i++ {
		h := sha256.Sum256(hash)
		hash = h[:]
	}

	return hash[:AddressBytesSize]
}

func NormalizeAddress(address string) string {
	addressBS := []byte(strings.ToUpper(address))
	result := make([]byte, 0, AddressSize)
	for _, b := range addressBS {
		if (b >= 'A' && b <= 'Z') || (b >= '2' && b <= 7) {
			result = append(result, b)
		}
	}
	return strings.ToLower(string(result))
}

func RSAPublicKeyToDer(publicKey *rsa.PublicKey) (publicKeyDer []byte) {
	if publicKey == nil {
		return
	}
	publicKeyDer, _ = x509.MarshalPKIXPublicKey(publicKey)
	return
}

func RSAPublicKeyFromDer(publicKeyDer []byte) (publicKey *rsa.PublicKey, err error) {
	publicKeyAny, err := x509.ParsePKIXPublicKey(publicKeyDer)
	publicKey, ok := publicKeyAny.(*rsa.PublicKey)
	if !ok {
		err = errors.New("wrong public key")
	}
	return
}

func GenerateRSAKey() (privateKey *rsa.PrivateKey, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	return
}

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

func PackBytes(data []byte) []byte {
	var err error
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)
	var zipFile io.Writer
	zipFile, err = zipWriter.Create("data")
	if err == nil {
		_, err = zipFile.Write(data)
	}
	err = zipWriter.Close()
	return buf.Bytes()
}

func UnpackBytes(zippedData []byte) (result []byte, err error) {
	buf := bytes.NewReader(zippedData)
	var zipFile *zip.Reader
	zipFile, err = zip.NewReader(buf, buf.Size())
	if err != nil {
		return
	}
	var file fs.File
	file, err = zipFile.Open("data")
	if err == nil {
		result, err = ioutil.ReadAll(file)
		_ = file.Close()
	}
	return
}
