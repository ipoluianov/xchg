package xchg

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
)

func SelfTest() {
	var config Config
	config.Init()

	var privateKey *rsa.PrivateKey
	privateKey, _ = crypt_tools.GenerateRSAKey()

	router := NewRouter(privateKey)
	server := NewRouterServer(config, router)
	httpServer := NewHttpServer(config, router)

	fmt.Println("--------------Press any key for start")
	fmt.Scanln()

	var err error

	router.Start()

	err = server.Start()
	if err != nil {
		return
	}

	httpServer.Start()

	fmt.Println("-------------Press any key for connect")
	fmt.Scanln()

	go ServerConnection()

	fmt.Println("----------------Press any key for exit")
	fmt.Scanln()

	server.Stop()
	if err != nil {
		return
	}

	router.Stop()
	if err != nil {
		return
	}

	fmt.Println("Press any key for finish")
	fmt.Scanln()

	fmt.Println("Process was finished")
}

func ServerConnection() {
	var privateKey *rsa.PrivateKey

	_, err := os.Stat("private_key.pem")
	if os.IsNotExist(err) {
		privateKey, err = crypt_tools.GenerateRSAKey()
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile("private_key.pem", []byte(crypt_tools.RSAPrivateKeyToPem(privateKey)), 0666)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile("public_key.pem", []byte(crypt_tools.RSAPublicKeyToPem(&privateKey.PublicKey)), 0666)
		if err != nil {
			panic(err)
		}
		fmt.Println("Key saved to file")
	} else {
		var bs []byte
		bs, err = ioutil.ReadFile("private_key.pem")
		if err != nil {
			panic(err)
		}
		privateKey, err = crypt_tools.RSAPrivateKeyFromPem(string(bs))
		if err != nil {
			panic(err)
		}
		fmt.Println("Key loaded from file")
	}

	s := NewEdgeConnection("127.0.0.1:8484", privateKey, "pass")
	s.Start()
	time.Sleep(3 * time.Second)
	s.Stop()
	s = nil
}
