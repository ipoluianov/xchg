package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"time"

	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_samples"
)

func ttt() {
	privateKey, _ := xchg.GenerateRSAKey()
	privateKeyBS, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	publicKeyBS, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)

	privateKeyBS64 := base64.StdEncoding.EncodeToString(privateKeyBS)
	fmt.Println("private:", privateKeyBS64)
	publicKeyBS64 := base64.StdEncoding.EncodeToString(publicKeyBS)
	fmt.Println("public:", publicKeyBS64)
}

func encrypt(c *big.Int, pub *rsa.PublicKey, m *big.Int) *big.Int {
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	return c
}

func incCounter(c *[4]byte) {
	if c[3]++; c[3] != 0 {
		return
	}
	if c[2]++; c[2] != 0 {
		return
	}
	if c[1]++; c[1] != 0 {
		return
	}
	c[0]++
}

func mgf1XOR(out []byte, hash hash.Hash, seed []byte) {
	var counter [4]byte
	var digest []byte

	done := 0
	for done < len(out) {
		hash.Write(seed)
		hash.Write(counter[0:4])
		digest = hash.Sum(digest[:0])
		hash.Reset()

		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}
		incCounter(&counter)
	}
}

func emsaPSSVerify(mHash, em []byte, emBits, sLen int, hash hash.Hash) error {
	// See RFC 8017, Section 9.1.2.

	hLen := hash.Size()
	if sLen == rsa.PSSSaltLengthEqualsHash {
		sLen = hLen
	}
	emLen := (emBits + 7) / 8
	if emLen != len(em) {
		return errors.New("rsa: internal error: inconsistent length")
	}

	// 1.  If the length of M is greater than the input limitation for the
	//     hash function (2^61 - 1 octets for SHA-1), output "inconsistent"
	//     and stop.
	//
	// 2.  Let mHash = Hash(M), an octet string of length hLen.
	if hLen != len(mHash) {
		return rsa.ErrVerification
	}

	// 3.  If emLen < hLen + sLen + 2, output "inconsistent" and stop.
	if emLen < hLen+sLen+2 {
		return rsa.ErrVerification
	}

	// 4.  If the rightmost octet of EM does not have hexadecimal value
	//     0xbc, output "inconsistent" and stop.
	if em[emLen-1] != 0xbc {
		return rsa.ErrVerification
	}

	// 5.  Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
	//     let H be the next hLen octets.
	db := em[:emLen-hLen-1]
	h := em[emLen-hLen-1 : emLen-1]

	// 6.  If the leftmost 8 * emLen - emBits bits of the leftmost octet in
	//     maskedDB are not all equal to zero, output "inconsistent" and
	//     stop.
	var bitMask byte = 0xff >> (8*emLen - emBits)
	if em[0] & ^bitMask != 0 {
		return rsa.ErrVerification
	}

	// 7.  Let dbMask = MGF(H, emLen - hLen - 1).
	//
	// 8.  Let DB = maskedDB \xor dbMask.
	mgf1XOR(db, hash, h)

	// 9.  Set the leftmost 8 * emLen - emBits bits of the leftmost octet in DB
	//     to zero.
	db[0] &= bitMask

	// If we don't know the salt length, look for the 0x01 delimiter.
	if sLen == rsa.PSSSaltLengthAuto {
		psLen := bytes.IndexByte(db, 0x01)
		if psLen < 0 {
			return rsa.ErrVerification
		}
		sLen = len(db) - psLen - 1
	}

	// 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
	//     or if the octet at position emLen - hLen - sLen - 1 (the leftmost
	//     position is "position 1") does not have hexadecimal value 0x01,
	//     output "inconsistent" and stop.
	psLen := emLen - hLen - sLen - 2
	for _, e := range db[:psLen] {
		if e != 0x00 {
			return rsa.ErrVerification
		}
	}
	if db[psLen] != 0x01 {
		return rsa.ErrVerification
	}

	// 11.  Let salt be the last sLen octets of DB.
	salt := db[len(db)-sLen:]

	// 12.  Let
	//          M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
	//     M' is an octet string of length 8 + hLen + sLen with eight
	//     initial zero octets.
	//
	// 13. Let H' = Hash(M'), an octet string of length hLen.
	var prefix [8]byte
	hash.Write(prefix[:])
	hash.Write(mHash)
	hash.Write(salt)

	h0 := hash.Sum(nil)

	// 14. If H = H', output "consistent." Otherwise, output "inconsistent."
	if !bytes.Equal(h0, h) { // TODO: constant time?
		return rsa.ErrVerification
	}
	return nil
}

func fillBytes(m big.Int, len int) []byte {
	result := make([]byte, len)
	bytes := (m.BitLen() + 7) >> 3
	offset := len - 1
	for i := 0; i < bytes; i++ {
		var z big.Int
		z = *z.Mod(&m, big.NewInt(256))
		m = *m.Rsh(&m, 8)
		result[offset] = byte(z.Uint64())
		offset--
	}

	return result
}

func rsaBigIntParse(data []byte) (result *big.Int) {
	result = big.NewInt(0)
	for i := 0; i < len(data); i++ {
		//fmt.Println(result)
		result = result.Lsh(result, 8)
		//fmt.Println(result)
		result = result.Add(result, big.NewInt(int64(data[i])))
		//fmt.Println(result)
	}
	return result
}

func rsaEncryptOAEP(hash hash.Hash, random io.Reader, pub *rsa.PublicKey, msg []byte, label []byte) ([]byte, error) {
	hash.Reset()
	k := pub.Size()
	if len(msg) > k-2*hash.Size()-2 {
		return nil, rsa.ErrMessageTooLong
	}

	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	em := make([]byte, k)
	seed := em[1 : 1+hash.Size()]
	db := em[1+hash.Size():]

	copy(db[0:hash.Size()], lHash)
	db[len(db)-len(msg)-1] = 1
	copy(db[len(db)-len(msg):], msg)

	for i := 0; i < 32; i++ {
		seed[i] = 21
	}

	/*_, err := io.ReadFull(random, seed)
	if err != nil {
		return nil, err
	}*/

	fmt.Println("HH:", em)

	mgf1XOR(db, hash, seed)
	mgf1XOR(seed, hash, db)

	m := new(big.Int)
	m.SetBytes(em)
	c := encrypt(new(big.Int), pub, m)

	out := make([]byte, k)
	return c.FillBytes(out), nil
}

func rsaVerify(publicKey *rsa.PublicKey, data []byte, sig []byte) (err error) {
	hash := sha256.Sum256(data)
	digest := hash[:]

	bsTest := make([]byte, 2)
	bsTest[0] = 12
	bsTest[1] = 42
	//sTest := new(big.Int).SetBytes(bsTest)
	//fmt.Println("Test:", sTest, rsaBigIntParse(bsTest))

	//s := new(big.Int).SetBytes(sig)
	s := rsaBigIntParse(sig)

	//fmt.Println("HH:", s)

	m := encrypt(new(big.Int), publicKey, s)
	emBits := publicKey.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	if m.BitLen() > emLen*8 {
		return rsa.ErrVerification
	}
	//em := m.FillBytes(make([]byte, emLen))
	em := fillBytes(*m, emLen)
	err = emsaPSSVerify(digest, em, emBits, 32, crypto.SHA256.New())
	return
}

func rsaVerifyClassic(publicKey *rsa.PublicKey, data []byte, sig []byte) (err error) {
	hash := sha256.Sum256(data)
	err = rsa.VerifyPSS(publicKey, crypto.SHA256, hash[:], sig, &rsa.PSSOptions{
		SaltLength: 32,
	})
	return
}

func ttt2() {
	privateKeyBS64 := "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC4T69E5NAQjf8yZDe1spPizbGkgmqYxr+0ry3NIYNkkpfa4GpwP5FFeg8/Zk22SNHqFy9txMkwVfxATLj2tB/BcqqjhUxq85unQlGxAyYatsy5VcxOronqizNjjd37/MEOHW7V3anK0sHes+BGat/2t10tZFWhP+KNF4l0D2SusmZ+iD/C+Yv8UAFtWAk9zpcUY6MnGm0Tv/FCVkiwbaUDwfz29meQnbse24iRxgRPQ7F1TLiLInir4savKD555hPTAEFIjd0Jetv3RUyF4qaRjko8bfe7F0GSXtQtIimu3+5oaroxKxg3W9RFr3BKVmGc1AD2LHNHYSER3L9NhUR1AgMBAAECggEAJWxwnyGCqcnbRmUY9rjC1GuFpWyhrlG0vUBQoXUrk7E8SkIE+rO9kIjfLbVdFCUnEkwQ4k3xt/HNnVS2vckHJaVdxoQbZx/9u/F4WuPTydrSKNOl/1frQwdusMkuiKrinDYXui8e+cLfgJOvdzzeKt9CeSQFSw+ItbNQwpMZk2rnho6iTMPXiiKj6pfec7I2miNUFHQEWt698fFaLzmKc/qSTAmlBQyiiFQNsP1dieMXboV23gLaH4tVwoRsVgM6V6HAyhIbyNHzqGRXJB6uasytnrcSBLb646WepLnskpgBg+VZjBgE3r7PMoJ7raQBViD9Zyz4DVGZbzB315cVwQKBgQDLyE9GyfB4vqgj863puVjlgnhBFmcZops7yI469UuwGd5WQ9tErn9Tx0LrSk8/PQIkOAHwit8F2UNlQEjq1HWOXWjI0wu67okOs8ax8a5gOIistBKfezK08SyIy2HXi9dKU673pasx5vamDhpm3wis3LP3/KLhrw0Wfjhy+bOF0QKBgQDnihtUXWW4MBbn5dMeUFTKefgw/kmxnTc9FyR9YJDBJ0b4vOsi6I0HuuQzOCFS3qXLdmlmkhfGk8089fBWAQ8rlQZUvMl9XyX3T7EEL8kIKUpnAS1o1jzb/ls1RU5735L/ngSzr0V5fT7Da74WSXhRk3esUkZserpLx0JbXtMpZQKBgQCWrGf5dkyoaogV9RHtE49oO1zA+1iF+tX+kR6g90fcUHQ1onyYvtEEV/vhzxLjNi/EKek9OuEGCQus7Kg9gZPeDLDydCFjOQX76e8LGSCOop5j2809QDFQ2lXMW1zfq9UmbtOa5lK7VgOe6iSZVWWrspAa1yBz8COkMvV4Baq4UQKBgCDuQo7QLcxxgoB+7nTsRfL6P/Nv5zlMu/ODXBw85LmkBXMRI3w2iQBlc1lZjVvE8N2sPLdq5djHYrRd4k3JHsg7DMh2hU3Af5zaB7optbTkcoGN6FB1z/gWCBDeh5gUp0qVxeNsdTwfNRMEOufekS9BAw9OMFfzaJWohGaMaQoFAoGBAMuwwMYAhUuMcAHuhzy52/KBYcSLcqigsrrQzgdj3x8X/CZuFvez1ErBbgn+IjVgx3teZfRVzsvblEOo4yrohkMPfmWTgH1AHNSTDeBnPsw3lzrk+DdWDYCiUWkgRr+tEIJF7KMreNHvR5bK7is7UFowd9FcOGnPe8aN/Ww4H+Px"
	publicKeyBS64 := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuE+vROTQEI3/MmQ3tbKT4s2xpIJqmMa/tK8tzSGDZJKX2uBqcD+RRXoPP2ZNtkjR6hcvbcTJMFX8QEy49rQfwXKqo4VMavObp0JRsQMmGrbMuVXMTq6J6oszY43d+/zBDh1u1d2pytLB3rPgRmrf9rddLWRVoT/ijReJdA9krrJmfog/wvmL/FABbVgJPc6XFGOjJxptE7/xQlZIsG2lA8H89vZnkJ27HtuIkcYET0OxdUy4iyJ4q+LGryg+eeYT0wBBSI3dCXrb90VMheKmkY5KPG33uxdBkl7ULSIprt/uaGq6MSsYN1vURa9wSlZhnNQA9ixzR2EhEdy/TYVEdQIDAQAB"
	privateKeyBS, _ := base64.StdEncoding.DecodeString(privateKeyBS64)
	publicKeyBS, _ := base64.StdEncoding.DecodeString(publicKeyBS64)
	privateKeyAny, _ := x509.ParsePKCS8PrivateKey(privateKeyBS)
	publicKeyAny, _ := x509.ParsePKIXPublicKey(publicKeyBS)
	privateKey := privateKeyAny.(*rsa.PrivateKey)
	publicKey := publicKeyAny.(*rsa.PublicKey)
	//fmt.Println(privateKey)
	fmt.Println(publicKey)

	//privateKeyHash := sha256.Sum256(privateKeyBS)
	//publicKeyHash := sha256.Sum256(publicKeyBS)

	//fmt.Println("privateKeyHash", privateKeyHash)
	//fmt.Println("publicKeyHash", publicKeyHash)

	data := make([]byte, 3)
	data[0] = 42
	data[1] = 43
	data[2] = 44

	/*hash := sha256.Sum256(data)
	signatureBS, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], &rsa.PSSOptions{
		SaltLength: 32,
	})
	//fmt.Println("hash", hash)
	if err != nil {
		fmt.Println("ERROR signature", err)
		return
	}*/

	//signatureBS64 := base64.StdEncoding.EncodeToString(signatureBS)
	//fmt.Println("SIGNATURE:", signatureBS64)

	/*err = rsa.VerifyPSS(publicKey, crypto.SHA256, hash[:], signatureBS, &rsa.PSSOptions{
		SaltLength: 32,
	})*/

	//signatureBS, _ = base64.StdEncoding.DecodeString("ht0rp3bf59TULImpwIZwsodwhhhyxg9Spe3mfAh5zstCSrm8iYMdDZVqEGcW6goIT1NZeacFi3Fndq4vJ9lU6pnyM7Kl32bLgFIeGXp8m8l63k8hMeiq2WaFIQ7HVAz5XslBmJHw8nNoQwss6Rv8s0ktCSvhbKhDSFnAt0Txv0BFPEPFRQyipDJ3c0X7EnRDuLiiqdVibMssnPhf8FtdAEeEPXvN1Z7ACnup/+JaaCYp4fwUVgkhISTge/ikmVVeXsqyquEyBhk3DR2wTvWdol4zD0wmr6PJyuMXHscF0ZUsMB7jNDvvpuRUJRn3lJVwzMIbYB4zo80af2SHkSqnMw==")

	//err = rsaVerify(publicKey, data, signatureBS)

	encData, err := rsaEncryptOAEP(sha256.New(), rand.Reader, publicKey, data, nil)
	if err != nil {
		fmt.Println("ERR:", err)
		return
	}

	decrData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encData, nil)
	if err != nil {
		fmt.Println("ERR:", err)
		return
	}

	fmt.Println("decrypted: ", decrData)

	//fmt.Println("VERIFY:", err)
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

	go fn()

	for {
		time.Sleep(1 * time.Second)
		fmt.Println("res:", count, errs)
		count = 0
		errs = 0
	}
}
