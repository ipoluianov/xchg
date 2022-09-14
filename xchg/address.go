package xchg

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

const Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// XCHG:    kqfc2fwogggtlsf7vnh46hhgdjmheiqvqycapj2f2xe2d5jz
// ONIONv2: expyuzz4wqqyqhjn
// ONIONv3: 2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid

const AddressBytesSize = 30
const AddressSize = int((AddressBytesSize * 8) / 5)

func AddressForPublicKey(publicKey *rsa.PublicKey) string {
	if publicKey == nil {
		return ""
	}
	bs := RSAPublicKeyToDer(publicKey)
	return AddressForPublicKeyBS(bs)
}

func AddressForPublicKeyBS(publicKeyBS []byte) string {
	if len(publicKeyBS) == 0 {
		return ""
	}

	hash := publicKeyBS
	for i := 0; i < 1; i++ {
		h := sha256.Sum256(hash)
		hash = h[:]
	}

	return strings.ToLower(base32.StdEncoding.EncodeToString(hash[:AddressBytesSize]))
}

func NormalizeAddress(address string) string {
	addressBS := []byte(strings.ToUpper(address))
	result := make([]byte, 0, AddressSize)
	for _, b := range addressBS {
		if (b >= 'A' && b <= 'Z') || (b >= '2' && b <= 7) {
			result = append(result, b)
		}
	}
	return strings.ToLower(string(result))
}
