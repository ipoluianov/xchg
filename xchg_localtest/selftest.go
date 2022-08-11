package xchg_localtest

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_examples"
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
	fmt.Println("-------------- Press Enter to start ROUTERS --------------")
	fmt.Scanln()

	network := xchg.NewNetwork()
	addrs := make([]string, 0)

	routers := make([]*xchg.Router, 0)
	for i := 0; i < 4; i++ {
		var privateKey *rsa.PrivateKey
		privateKey, _ = crypt_tools.GenerateRSAKey()
		var config xchg.RouterConfig
		config.Init()
		config.BinServerPort = 8484 + i
		config.HttpServerPort = 9800 + i
		router := xchg.NewRouter(privateKey, config)
		router.Start()
		routers = append(routers, router)
		addrs = append(addrs, "127.0.0.1:"+fmt.Sprint(8484+i))
	}
	network.SetRange("", addrs)

	fmt.Println("------------- Press Enter to start SERVERS --------------")
	fmt.Scanln()

	serverPrivateKey := GeneratePrivateKey()
	serverPublicKey, _ := GetPublicKeyByPrivateKey(serverPrivateKey)
	go Server(serverPrivateKey, network)

	go Client(serverPublicKey, network)

	fmt.Println("------------- Press Enter to stop ROUTERS -------------")
	fmt.Scanln()

	for _, router := range routers {
		router.Stop()
	}

	fmt.Println("------------- Press Enter to stop PROCESS -------------")
	fmt.Scanln()

	fmt.Println("PROCESS was finished")
}

func Server(serverPrivateKey string, network *xchg.Network) {
	ss := xchg_examples.NewSimpleServer(serverPrivateKey, network)
	ss.Start()
}

func Client(serverPublicKey string, network *xchg.Network) {
	time.Sleep(500 * time.Millisecond)
	var err error
	s := xchg_examples.NewSimpleClient(serverPublicKey, network)
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
