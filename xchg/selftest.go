package xchg

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ipoluianov/gomisc/crypt_tools"
)

func GeneratePrivateKey() string {
	privateKey, _ := crypt_tools.GenerateRSAKey()
	privateKeyBS := crypt_tools.RSAPrivateKeyToDer(privateKey)
	return base58.Encode(privateKeyBS)
}

func GetPublicKeyByPrivateKey(privateKey58 string) (result string, err error) {
	privateKeyBS := base58.Decode(privateKey58)
	var privateKey *rsa.PrivateKey
	privateKey, err = crypt_tools.RSAPrivateKeyFromDer(privateKeyBS)
	if err != nil {
		return
	}
	publicKeyBS := crypt_tools.RSAPublicKeyToDer(&privateKey.PublicKey)
	result = base58.Encode(publicKeyBS)
	return
}

func SelfTest() {
	var config RouterConfig
	config.Init()

	var privateKey *rsa.PrivateKey
	privateKey, _ = crypt_tools.GenerateRSAKey()

	router := NewRouter(privateKey, config)

	fmt.Println("-------------- Press Enter to start ROUTERS --------------")
	fmt.Scanln()

	router.Start()

	fmt.Println("------------- Press Enter to start SERVERS --------------")
	fmt.Scanln()

	serverPrivateKey := GeneratePrivateKey()
	serverPublicKey, _ := GetPublicKeyByPrivateKey(serverPrivateKey)
	go Server(serverPrivateKey)
	go Client(serverPublicKey)

	fmt.Println("------------- Press Enter to stop ROUTERS -------------")
	fmt.Scanln()

	router.Stop()

	fmt.Println("------------- Press Enter to stop PROCESS -------------")
	fmt.Scanln()

	fmt.Println("PROCESS was finished")
}

func Server(serverPrivateKey string) {
	ss := NewSimpleServer(serverPrivateKey)
	ss.Start()
}

func Client(serverPublicKey string) {
	time.Sleep(500 * time.Millisecond)
	var err error
	s := NewSimpleClient(serverPublicKey)
	for i := 0; i < 10000; i++ {
		time.Sleep(500 * time.Millisecond)
		var bs string
		bs, err = s.Version()
		if err != nil {
			fmt.Println("ERROR", err)
		} else {
			fmt.Println("RESULT", bs)
		}

	}
	s = nil
}
