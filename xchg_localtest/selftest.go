package xchg_localtest

import (
	"fmt"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_examples"
)

func SelfTest() {

	serverPrivateKey, _ := crypt_tools.GenerateRSAKey()
	serverAddress := xchg.AddressForPublicKey(&serverPrivateKey.PublicKey)
	fmt.Println("Server address:", serverAddress)

	ss := xchg_examples.NewSimpleServer(serverPrivateKey)
	ss.Start()

	go Client(serverAddress)

	fmt.Println("------------- Press Enter to stop PROCESS -------------")
	fmt.Scanln()

	fmt.Println("PROCESS was finished")
}

func Client(address string) {
	time.Sleep(500 * time.Millisecond)
	var err error
	s := xchg_examples.NewSimpleClient(address)
	for i := 0; i < 1000; i++ {
		time.Sleep(1000 * time.Millisecond)
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

func SimpleClient() {
	var err error

	//network := xchg_network.NewNetworkFromInternet()
	serverPrivateKey, _ := crypt_tools.GenerateRSAKey()
	//serverPrivateKey32 := base32.StdEncoding.EncodeToString(crypt_tools.RSAPrivateKeyToDer(serverPrivateKey))
	serverAddress := xchg.AddressForPublicKey(&serverPrivateKey.PublicKey)
	cl := xchg_examples.NewSimpleClient("bgjjjg3ysqumb66ggivq453t3hl7q7vphnjtibtvaw5atipd")

	for i := 0; i < 1000; i++ {
		var bs string
		fmt.Println("=============== CALLING ==============")
		bs, err = cl.Version()
		if err != nil {
			fmt.Println("ERROR", err)
		} else {
			fmt.Println("RESULT", bs)
		}
		time.Sleep(1000 * time.Millisecond)
	}

	fmt.Println("Client Address", serverAddress)
	fmt.Println("------------- Press Enter to stop Simple Server -------------")
	fmt.Scanln()
	fmt.Println("PROCESS was finished")
}

func SimpleServer() {
	serverPrivateKey, _ := crypt_tools.GenerateRSAKey()
	serverAddress := xchg.AddressForPublicKey(&serverPrivateKey.PublicKey)
	ss := xchg_examples.NewSimpleServer(serverPrivateKey)
	ss.Start()
	fmt.Println("Server Address", serverAddress)
	fmt.Println("------------- Press Enter to stop Simple Server -------------")
	fmt.Scanln()
	fmt.Println("PROCESS was finished")
}
