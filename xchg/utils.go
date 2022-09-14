package xchg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

func RSAPublicKeyToDer(publicKey *rsa.PublicKey) (publicKeyDer []byte) {
	if publicKey == nil {
		return
	}
	publicKeyDer = x509.MarshalPKCS1PublicKey(publicKey)
	return
}

func RSAPublicKeyFromDer(publicKeyDer []byte) (publicKey *rsa.PublicKey, err error) {
	publicKey, err = x509.ParsePKCS1PublicKey(publicKeyDer)
	return
}

func GenerateRSAKey() (privateKey *rsa.PrivateKey, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	return
}
