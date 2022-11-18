package xchg

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"io/ioutil"
	"time"
)

const (
	NetworkContainerEncryptedPrivateKey = "U2WN31hU10+NaLgU6sBSYo/ouKnrwSn3z8n0C0hOXxKgDBhgx6ZH62N/VzWpepMQzG1nlJHWVBXUJgCjDismPuNoavijT/pa2bdRGClo9TvKSlLcZbYkLd/isGEMgOMepHgPgHFvt93ERvnVpRFGpWGEKDCU7T+yYgV6li7Y1cdwDg/47nEP8Go/LhTRaFEfnRiHXw3JvT6Cs70xgfGEXZln9Jf4WzJkxOf9B6ox3UqsDE9ASyfqToUnFzXm0zaEfZGWPjU0drfhLanBmnSEy4IwgiyAnnz9As3+oiHW5Z35tvgdqNwz3BcRTLNA9cmBpJbfL3xXQxZ11QwQgYJRO3AgVjfxOxrB1gYZ/Qa+ihjakwztR5Mzgm/HFfeKS4MPVsflgfQVNcABTU3Nv++nXsB6q+7ieX877WGda9zpBDOkveDO089PKkEqRs9zCtWSz9MYbkY3ZxvFNplvblSNNL+mwcfxQeSe6qkmTxJmZ9HKB+uJ6X5bIZjCx6/rhaYUL9h7lctUhvGMY8En5uMI1cl4gRJtL5K/wO4g+YDTlC7kYYlO1Eugyw6I7HTwy6F8sg1GDftXKuJ7Khow4dIqEaRwWH/ukDsSmf0vG+pctdnbBOEU2SabgT9fuMewzprdbCRZ3e8e1sP03it2BVwIz1Oo7eSfaQqLjlvnmXayKLqIY+T+yp4aRRc6zXtZlFGFrbAPPRA+xgouU1gF2NIC3BD0YxFvrNY3QYyjppCdrb1pTdZDTw7wljSQvi2+zuKMlKwN3zH2VyuHmZm0TJBMtx7PUDW9yu1oJwDbbONP2oehklbJMBbDvMrvxoVHBq+CDXtO+xcrF4Ai/rEhUcqQ992LFROF77/fgL82pM1Cbnbg6UGf69nGGBVhpx33ghXognOFY3l1P4AkziZ+wWJAH9ytUstiuvj5MIRhgCCJgORnGSaT/pxMtJWm+jF1iTdovLr9Y9SDhNbWaJp08puMoOa9g1ctBohF9iCf+QAA0t3feUVahldf3D0/MTRQrRSqXrVKu8d3iZcprPKxt6bvb1PUPodinak8jVb+YPjL/6SAczaU5BuiRdJmIXD0+II/G/T3D4itVS1mpr3dWoKH4HAfic3sWG5A+sox1KWG6Ed3FLEHl0cAQ8uqsi3fdsBT+ry29nPNRSBD1HlJA7iqNkD+BUtjXDEvWTb6SW+FCkQmn05NwiMeeVcSl6+n7tdcRdYLInUqP7Dv1uDG5UTAEVHn/l//MoFxcIlah7xLLwbJcozXmNPEoemRga6Eo5Ow8NgE45rDJTVdDyKizY7lCUEJSThYdBP65VVqjY41I5+smbn4OvDEmfyCV8hF8/0AH6wyKVFZxSf/dhMejWR0182/UjPMP/w1LEKJ027vJLYa6MLGd8+lQzOMSammB2/BUzxaO+hRbwa1d2pnoYv3WA/MGfGl1nZgPPcydNrI47gKLRkvvCJzQ7cNvyA8WhCx144xUFLCQniG1TV/rYmfo+0TBnrb+e4d4sGSYMKq9q2lK4jv2KngvEVB0J9e72OjlAh9t9oAVn560NxGC4Wzco4IhF1ip6QIE6iC2dX0qsKKttFwWg8u0uk0jWwbGnrrQqN+ZAWOGBXCScEUESapt+OFJYWQBYO+aLyApHc0dLUR8pc7eDXgs37sWH5O"
	NetworkContainerPublicKey           = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxUeyrJ/FnJWjw/4dd5cbSaYXOOaTzwlq0+NKHof/lIKwyFNXcO1HdRHKlHkwWORtLL5umEHB0ib/K73DPCxQgQq057vi+twSaYgtZQDnZpdrdRphXIjoMNDu980m1rUfGt5aNJDYHElIm8h2MwliFou4uYRsoQlQLyArSXyYGfQn1OHP9JHIpBY30uRmdjKkAakL4oZ1CVhFVSPk9KWeW23U0NErM0IR8jBg92ilRydfqYdQupFCJ+UraNcQfZ1uS4XwjzamZBXkFeXUbDSvo5NCNjBxcUYeYJkysx+FDpoBIVBWg3Ej91sLTAGKV3tM+nX+g+WYY1fIM9gXJCl9wQIDAQAB"
	NetworkContainerFileNetwork         = "network.json"
	NetworkContainerFileSignature       = "signature.base64"
)

func NetworkContainerLoadDefault(zipFileBS []byte) (network *Network, err error) {
	return NetworkContainerLoad(zipFileBS, NetworkContainerPublicKey)
}

func NetworkContainerLoad(zipFileBS []byte, publicKeyBase64 string) (network *Network, err error) {
	var publicKeyBS []byte
	publicKeyBS, err = base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return
	}

	var publicKeyAny any
	publicKeyAny, err = x509.ParsePKIXPublicKey(publicKeyBS)

	var publicKey *rsa.PublicKey
	var ok bool
	publicKey, ok = publicKeyAny.(*rsa.PublicKey)
	if !ok {
		err = errors.New("wrong public key")
	}

	buf := bytes.NewReader(zipFileBS)
	var zipFile *zip.Reader
	zipFile, err = zip.NewReader(buf, buf.Size())
	if err != nil {
		return
	}
	var networkBS []byte
	{
		var file fs.File
		file, err = zipFile.Open(NetworkContainerFileNetwork)
		if err == nil {
			networkBS, err = ioutil.ReadAll(file)
			if err != nil {
				_ = file.Close()
				return
			}
			_ = file.Close()
		} else {
			return
		}
	}
	var signatureBase64BS []byte
	{
		var file fs.File
		file, err = zipFile.Open(NetworkContainerFileSignature)
		if err == nil {
			signatureBase64BS, err = ioutil.ReadAll(file)
			if err != nil {
				_ = file.Close()
				return
			}
			_ = file.Close()
		} else {
			return
		}
	}

	var signature []byte
	signature, err = base64.StdEncoding.DecodeString(string(signatureBase64BS))
	if err != nil {
		return
	}

	hash := sha256.Sum256(networkBS)
	err = rsa.VerifyPSS(publicKey, crypto.SHA256, hash[:], signature, &rsa.PSSOptions{
		SaltLength: 0,
	})
	if err != nil {
		return
	}

	network, err = NewNetworkFromBytes(networkBS)
	return
}

func NetworkContainerCreateKey(privateKeyPassword string) (encryptedPrivateKeyBase64 string, publicKeyBase64 string, err error) {
	var privateKey *rsa.PrivateKey
	privateKey, err = GenerateRSAKey()
	if err != nil {
		return
	}

	var privateKeyBS []byte
	privateKeyBS, err = x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return
	}

	var publicKeyBS []byte
	publicKeyBS, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return
	}

	passwordHash := sha256.Sum256([]byte(privateKeyPassword))
	aesKey := passwordHash[:]
	var encryptedPrivateKeyBS []byte
	encryptedPrivateKeyBS, err = EncryptAESGCM(privateKeyBS, aesKey)
	if err != nil {
		return
	}

	encryptedPrivateKeyBase64 = base64.StdEncoding.EncodeToString(encryptedPrivateKeyBS)
	publicKeyBase64 = base64.StdEncoding.EncodeToString(publicKeyBS)

	return
}

func NetworkContainerMake(network *Network, encryptedPrivateKeyBase64 string, privateKeyPassword string) (resultZipFile []byte, err error) {
	if network == nil {
		err = errors.New("network == nil")
		return
	}

	var encryptedPrivateKeyBS []byte
	encryptedPrivateKeyBS, err = base64.StdEncoding.DecodeString(encryptedPrivateKeyBase64)
	if err != nil {
		return
	}

	passwordHash := sha256.Sum256([]byte(privateKeyPassword))
	aesKey := passwordHash[:]
	var privateKeyBS []byte
	privateKeyBS, err = DecryptAESGCM(encryptedPrivateKeyBS, aesKey)
	if err != nil {
		return
	}

	var privateKeyAny any
	privateKeyAny, err = x509.ParsePKCS8PrivateKey(privateKeyBS)
	if err != nil {
		return
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = privateKeyAny.(*rsa.PrivateKey)
	if !ok {
		err = errors.New("wrong private key")
		return
	}

	if privateKey == nil {
		err = errors.New("privateKey == nil")
		return
	}

	networkBS := network.toBytes()
	hash := sha256.Sum256(networkBS)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], &rsa.PSSOptions{
		SaltLength: 0,
	})
	if err != nil {
		return
	}

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)
	{
		var zipFile io.Writer

		header := &zip.FileHeader{
			Name:     NetworkContainerFileNetwork,
			Method:   zip.Deflate,
			Modified: time.Now(),
		}
		zipFile, err = zipWriter.CreateHeader(header)
		if err == nil {
			_, err = zipFile.Write(networkBS)
			if err != nil {
				zipWriter.Close()
				return
			}
		} else {
			zipWriter.Close()
			return
		}
	}
	{
		var zipFile io.Writer
		header := &zip.FileHeader{
			Name:     NetworkContainerFileSignature,
			Method:   zip.Deflate,
			Modified: time.Now(),
		}
		zipFile, err = zipWriter.CreateHeader(header)
		if err == nil {
			_, err = zipFile.Write([]byte(signatureBase64))
			if err != nil {
				zipWriter.Close()
				return
			}
		} else {
			zipWriter.Close()
			return
		}
	}
	err = zipWriter.Close()
	resultZipFile = buf.Bytes()
	return
}
