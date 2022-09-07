package connection

import "crypto/rsa"

type Connection struct {
	privateKey *rsa.PrivateKey
}

func NewConnection() {
}
