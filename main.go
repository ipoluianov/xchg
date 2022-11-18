package main

import (
	"fmt"
	"io/ioutil"
	"time"

	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_samples"
)

func ttt() {
	/*{
		network := xchg.NewNetworkDefault()
		zipFile, err := xchg.NetworkContainerMake(network, xchg.NetworkContainerEncryptedPrivateKey, "12345")
		if err != nil {
			fmt.Println(err)
			return
		}
		ioutil.WriteFile("d:\\network-container.zip", zipFile, 0777)
		fmt.Println("ok")
	}*/
	{
		bs, err := ioutil.ReadFile("d:\\network-container.zip")
		if err != nil {
			return
		}

		network, err := xchg.NetworkContainerLoadDefault(bs)
		if err != nil {
			fmt.Println("ERROR:", err)
		}
		fmt.Println(network)
	}
}

func main() {
	ttt()
	return
	count := 0
	errs := 0

	fn := func() {
		serverPrivateKey, _ := xchg.GenerateRSAKey()
		server := xchg_samples.NewSimpleServer(serverPrivateKey)
		server.Start()

		serverAddress := xchg.AddressForPublicKey(&serverPrivateKey.PublicKey)
		fmt.Println(serverAddress)
		client := xchg_samples.NewSimpleClient("#zotiazy2i6wulxwhxw3uhf7c6vvk366jfq3ydwxbxcnz7tnk")

		for {
			time.Sleep(50 * time.Millisecond)
			var err error
			fmt.Println("processing ...")
			res, err := client.Version()
			if err != nil {
				fmt.Println("RESULT: error:", err)
				errs++
			} else {
				count++
				fmt.Println(res)
				fmt.Println("================== RESULT OK ================")
			}
		}
	}

	/*go func() {
		for i := 0; i < 1; i++ {
			time.Sleep(200 * time.Millisecond)
			go fn()
		}
	}()*/

	fn()

	for {
		time.Sleep(1 * time.Second)
		fmt.Println("res:", count, errs)
		count = 0
		errs = 0
	}
}
