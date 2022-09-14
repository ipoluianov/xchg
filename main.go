package main

import (
	"fmt"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_examples"
)

func main() {
	serverPrivateKey, _ := crypt_tools.GenerateRSAKey()
	server := xchg_examples.NewSimpleServer(serverPrivateKey)
	server.Start()

	serverAddress := xchg.AddressForPublicKey(&serverPrivateKey.PublicKey)
	client := xchg_examples.NewSimpleClient(serverAddress)

	for {
		res, err := client.Version()
		if err != nil {
			fmt.Println("RESULT: error:", err)
		} else {
			fmt.Println("RESULT:", res)
		}
		time.Sleep(1 * time.Second)
	}
}
