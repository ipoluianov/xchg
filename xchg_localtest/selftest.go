package xchg_localtest

import (
	"crypto/rsa"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_examples"
	"github.com/ipoluianov/xchg/xchg_network"
	"github.com/ipoluianov/xchg/xchg_router"
)

func SelfTest() {
	fmt.Println("-------------- Press Enter to start ROUTERS --------------")
	fmt.Scanln()

	network := xchg_network.NewNetwork()
	for r := 0; r < 16; r++ {
		rangePrefix := fmt.Sprintf("%X", r)
		for i := 0; i < 1; i++ {
			network.AddHostToRange(rangePrefix, "127.0.0.1:"+fmt.Sprint(8484+i))
		}
	}

	//fmt.Println(network.String())

	routers := make([]*xchg_router.Router, 0)
	for i := 0; i < 1; i++ {
		var privateKey *rsa.PrivateKey
		privateKey, _ = crypt_tools.GenerateRSAKey()
		var config xchg_router.RouterConfig
		config.Init()
		config.BinServerPort = 8484 + i
		config.HttpServerPort = 9800 + i

		router := xchg_router.NewRouter(privateKey, config, network)
		router.Start()
		routers = append(routers, router)
	}

	fmt.Println("------------- Press Enter to start SERVERS --------------")
	fmt.Scanln()

	serverPrivateKey, _ := crypt_tools.GenerateRSAKey()
	serverPrivateKey32 := base32.StdEncoding.EncodeToString(crypt_tools.RSAPrivateKeyToDer(serverPrivateKey))
	serverAddress := xchg.AddressForPublicKey(&serverPrivateKey.PublicKey)

	fmt.Println("Server address:", serverAddress)

	ss := xchg_examples.NewSimpleServer(serverPrivateKey32, network)
	ss.Start()

	go Client(serverAddress, network)

	fmt.Println("------------- Press Enter to stop ROUTERS -------------")
	fmt.Scanln()

	for _, router := range routers {
		router.Stop()
	}

	ss.Stop()

	fmt.Println("------------- Press Enter to stop PROCESS -------------")
	fmt.Scanln()

	fmt.Println("PROCESS was finished")
}

func Client(address string, network *xchg_network.Network) {
	time.Sleep(500 * time.Millisecond)
	var err error
	s := xchg_examples.NewSimpleClient(address, network)
	for i := 0; i < 10; i++ {
		time.Sleep(500 * time.Millisecond)
		var bs string
		fmt.Println("=============== CALLING ==============")
		bs, err = s.Version()
		if err != nil {
			fmt.Println("ERROR", err)
		} else {
			fmt.Println("RESULT", bs)
		}

	}
	s = nil
}

func RunSimpleServer() {
	network := xchg_network.NewNetwork()
	s1 := "54.37.73.160:8484"
	s2 := "54.37.73.229:8484"

	for r := 0; r < 16; r++ {
		rangePrefix := fmt.Sprintf("%X", r)
		network.AddHostToRange(rangePrefix, s1)
		network.AddHostToRange(rangePrefix, s2)
	}

	serverPrivateKey, _ := crypt_tools.GenerateRSAKey()
	serverPrivateKey32 := base32.StdEncoding.EncodeToString(crypt_tools.RSAPrivateKeyToDer(serverPrivateKey))
	serverAddress := xchg.AddressForPublicKey(&serverPrivateKey.PublicKey)

	ss := xchg_examples.NewSimpleServer(serverPrivateKey32, network)
	ss.Start()

	fmt.Println("Server Address", serverAddress)

	fmt.Println("------------- Press Enter to stop Simple Server -------------")
	fmt.Scanln()

	fmt.Println("PROCESS was finished")
}
