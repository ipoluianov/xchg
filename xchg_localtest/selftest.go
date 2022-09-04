package xchg_localtest

import (
	"crypto/rsa"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_examples"
	"github.com/ipoluianov/xchg/xchg_network"
	"github.com/ipoluianov/xchg/xchg_router"
)

func GetNetworkDescription(network *xchg_network.Network) {
	result := ""
	for _, r := range network.Ranges {
		rangeBlock := `<div style="font-family: Consolas, 'Courier New', Courier, monospace;font-size: 10pt;">` + "\r\n"
		rangeBlock += "<h1>" + r.Prefix + "...</h1>\r\n"
		for _, h := range r.Hosts {
			httpAddr := strings.ReplaceAll(h.Address, "8484", "8485")

			hostBlock := `<table style="margin-bottom: 10px; border-bottom: 2px solid #4169e1;" >` + "\r\n"
			hostBlock += "<tr><td>Address</td><td>" + h.Address + "</td><tr>\r\n"
			hostBlock += "<tr><td>Name</td><td>" + h.Name + "</td><tr>\r\n"
			hostBlock += "<tr><td>ETH Address</td><td>" + h.EthAddress + "</td><tr>\r\n"
			hostBlock += `<tr><td>State</td><td><a href="http://` + httpAddr + `/state">State</td><tr>` + "\r\n"
			hostBlock += `<tr><td>Performance</td><td><a href="http://` + httpAddr + `/performance">Performance</td><tr>` + "\r\n"
			hostBlock += "</table>\r\n"
			rangeBlock += hostBlock
		}
		rangeBlock += "</div>\r\n"
		result += rangeBlock
	}
	ioutil.WriteFile("network.html", []byte(result), 0666)
}

func GenNetwork() {
	network := xchg_network.NewNetwork()
	s1 := "54.37.73.160:8484"
	s2 := "54.37.73.229:8484"
	s3 := "134.0.115.16:8484"

	for r := 0; r < 16; r++ {
		rangePrefix := fmt.Sprintf("%X", r)
		network.AddHostToRange(rangePrefix, s1)
		network.AddHostToRange(rangePrefix, s2)
		network.AddHostToRange(rangePrefix, s3)
	}

	network.SaveToFile("network.json")
	GetNetworkDescription(network)

}

func GenConfig() {
	var config xchg_router.RouterConfig
	config.Init()
	config.BinServerPort = 8484
	config.HttpServerPort = 8485
	bs, _ := json.MarshalIndent(config, "", " ")
	ioutil.WriteFile("config.json", bs, 0666)
}

func SelfTest() {
	GenNetwork()
	GenConfig()

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

	// TODO: remove for local tests
	network = xchg_network.NewNetwork()
	for r := 0; r < 16; r++ {
		rangePrefix := fmt.Sprintf("%X", r)
		network.AddHostToRange(rangePrefix, "54.37.73.160:8484")
	}

	//network = xchg_network.NewNetworkFromInternet()

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
	for i := 0; i < 1000; i++ {
		time.Sleep(1000 * time.Millisecond)
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

func SimpleClient() {
	network := xchg_network.NewNetworkFromInternet()
	serverPrivateKey, _ := crypt_tools.GenerateRSAKey()
	serverPrivateKey32 := base32.StdEncoding.EncodeToString(crypt_tools.RSAPrivateKeyToDer(serverPrivateKey))
	serverAddress := xchg.AddressForPublicKey(&serverPrivateKey.PublicKey)
	cl := xchg_examples.NewSimpleClient(serverPrivateKey32, network)
	cl.Version()
	fmt.Println("Client Address", serverAddress)
	fmt.Println("------------- Press Enter to stop Simple Server -------------")
	fmt.Scanln()
	fmt.Println("PROCESS was finished")
}

func SimpleServer() {
	network := xchg_network.NewNetworkFromInternet()
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
