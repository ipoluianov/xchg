package xchg

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/btcsuite/btcutil/base58"
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

	go ServerConnection("1")
	go ServerConnection("2")

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

func ServerConnection(id string) {
	var privateKey *rsa.PrivateKey

	privateFile := id + "_private_key.pem"
	publicFile := id + "_public_key.pem"

	_, err := os.Stat(privateFile)
	if os.IsNotExist(err) {
		privateKey, err = crypt_tools.GenerateRSAKey()
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(privateFile, []byte(crypt_tools.RSAPrivateKeyToPem(privateKey)), 0666)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(publicFile, []byte(crypt_tools.RSAPublicKeyToPem(&privateKey.PublicKey)), 0666)
		if err != nil {
			panic(err)
		}
		fmt.Println("Key saved to file")
	} else {
		var bs []byte
		bs, err = ioutil.ReadFile(privateFile)
		if err != nil {
			panic(err)
		}
		privateKey, err = crypt_tools.RSAPrivateKeyFromPem(string(bs))
		if err != nil {
			panic(err)
		}
		fmt.Println("Key loaded from file")
		fmt.Println("loaded address", base58.Encode(crypt_tools.RSAPublicKeyToDer(&privateKey.PublicKey)))
	}

	s := NewEdgeConnection("127.0.0.1:8484", privateKey, "pass")
	s.Start()
	if id == "1" {
		for i := 0; i < 10; i++ {
			time.Sleep(100 * time.Millisecond)
			var bs []byte
			bs, err = s.Call("4e1BUTgGBfqVW2FEkDmduPMWQoLrJwrRBg5CLEwPLNBCKj2gxXvBiq1s7S3oTdJpKzu4xWjEXx6WLHM2veikSYNScMNVnkcqQzcd9htSMPy4vW2jtm6TMeEphDdqfPnrrJwvWr3V1t5e6cz2CDF66XPNfZkjEmxFEFdigeJ6h48qcAzYmMzbB9iudoVC1CqX92DzsRcFxY6h8uvKjX77imxWMDTRrU7hmPc9SjBrQZ1oar7WAEYt247cx4UqPmyi9xnfD2Ns7ctJba5VbiKXuVcxx2vtWsB324y2dZCQrduEfLLNr1kxtMe3WimkuxdHX5D74tJ5boF6CJ1HBvzsKUDBy1sGQ3SY6YWhH7b4Pv17Sfu9a",
				[]byte("123"))
			if err != nil {
				fmt.Println("ERROR", err)
			} else {
				fmt.Println("RESULT", string(bs))
			}

		}
	} else {
		time.Sleep(1000 * time.Second)
	}
	s.Stop()
	s = nil
}
