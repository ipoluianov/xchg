package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_samples"
)

func ttt() {
	zip64 := "UEsDBAoAAAAAAA14a1XSY0iIAwAAAAMAAAABAAAAZDEyM1BLAQIUAAoAAAAAAA14a1XSY0iIAwAAAAMAAAABAAAAAAAAAAAAAAAAAAAAAABkUEsFBgAAAAABAAEALwAAACIAAAAAAA=="
	zipBS, _ := base64.StdEncoding.DecodeString(zip64)
	ioutil.WriteFile("d:\\qwe.zip", zipBS, 0777)
	return

	var err error
	privateKey64 := "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"
	publicKey64 := "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtUPg002XSwtXEP19yMH1lnxKZkQts/l4ec9CJHhlgbn9Kch9OoBN6/n8UqSHmNYmJQldBIzoHlQ7g666czHlbQcGYMnQCB8KraE4M2LuFSVtVajQKnO1biL6pHVsJNqf1wtgMH+36kJgJpfi8DxXWbC1ECg0Gilfs6gWxKP4TYMWuZL0R1fplRcGAzXqrtKHhhQHBWJoRgTDMYvhm783TpZZjMrjNuVljPAtOcomA7u+Y30JkWxOsCgH2SaXKwmbKDFX4XWib+toAcRPP9IH8npOOfhUZj8h+TkYoCVZ7xa0ySlWQ30kGiHzQJJ/dQy16UIY98w+ILphHvL/nX9u/msft//dXvr+ODZ1O09GcrmXEjL/bE24k38jw2yDLRTB/zeALfu8U4wJkWaup/xMIGBrBKQRcYJr1GyNVbgXzk5D15vIqpCKH+ju5B+8TWLcDd1ncoeqXpi+4bBssngKkp7TJtblq0txV78DRyB/ffmDLIp2Vvic1o1JKg0WRnROkbgue5vw6yd90cVSkDwOQPADm/nJf8NEiS83rEtQBJDZHKMFYyi7JQ9S2JQclO6ZobY3F4P3swnQP7er0t3z7X+HBj5IEySbZ8h1WboLBHSMHg93veK1Vo6Pdi1DycaDcOlaRz4MmZF0VYnvsgqSUCoB5NZ5mkwyKf+zxMFCKgcCAwEAAQ=="
	encryptedData64 := "jVsrXb5EtANCZ0sSajggBHmw5QLfdezka1sBKjkrIiJiXHJUlgK2sqXC6SxDQXXS6u93dQZobKmGWiehS10fGFnzY83GfuqQpS4Nn4BQgK6PKsrvZwqJoHxpAWbdOdKoZB18781I+HlyPs4U8wR/TjqVDBGpIhS3wsUtkf3ReCHUSN8Wxeq6slESU3GpcIiTbU0yaK7PA18hj1c0VtWwDHVrdNswZHUnrNFtiII8nuWb7INPeEbcX1tsqPQpf4PeuL+SwlE2Ky6Hpt79oSzh/eK8N0iN3lfX0W77J4tgPV1RNTM/XrZVljlgXBWgQ/AP/X7RXj6mXXI7803QMnurMq+8M5VTaEgUwaLzlAxiy+V6qgk9+gj0KeGMnVcQ5VbG2VNBKowuIeh3dm1CA9dCXilAYS/fzW7EycRHZyUi9680qvPSbkF1JvEnehF0SFkDEjlohjpZcy5JViox8hf0tlMxoGrA81+3V3i7TNr7KDmfw5qc0dIj0DvIe7N49ofPhAskASjT+e8ePnux6cWDEFv1/rZpYLSFEujJxDF6HVZhnRKxhdmpvQxI4eTrzQT7XgeuWiXUGN5lFQMMNRra2yfDcO3ABzx+pogRpnHtgwnMvDa2liMCFzMdXWTUDb4gMETckHAe4xCB0ldEXKUywPz+mC/AhWFkmmT/+HfO+dQ="
	encryptedDataBS, err := base64.StdEncoding.DecodeString(encryptedData64)
	if err != nil {
		fmt.Println(err)
		return
	}

	privateKeyBS, err := base64.StdEncoding.DecodeString(privateKey64)
	if err != nil {
		fmt.Println(err)
		return
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBS)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("privateKey:", privateKey)

	publicKeyBS, err := base64.StdEncoding.DecodeString(publicKey64)
	if err != nil {
		fmt.Println(err)
		return
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBS)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("publicKey:", publicKey)

	decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey.(*rsa.PrivateKey), encryptedDataBS, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("SUCCESS:", decryptedData)

	e1, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey.(*rsa.PrivateKey).PublicKey, []byte("1221"), nil)
	e2 := base64.StdEncoding.EncodeToString(e1)
	fmt.Println(e2)
}

func main() {
	count := 0
	errs := 0

	fn := func() {
		serverPrivateKey, _ := xchg.GenerateRSAKey()
		server := xchg_samples.NewSimpleServer(serverPrivateKey)
		server.Start()

		serverAddress := xchg.AddressForPublicKey(&serverPrivateKey.PublicKey)
		fmt.Println(serverAddress)
		client := xchg_samples.NewSimpleClient(serverAddress)

		for {
			time.Sleep(500 * time.Millisecond)
			var err error
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

	go func() {
		for i := 0; i < 1; i++ {
			time.Sleep(200 * time.Millisecond)
			go fn()
		}
	}()

	for {
		time.Sleep(1 * time.Second)
		fmt.Println("res:", count, errs)
		count = 0
		errs = 0
	}
}
