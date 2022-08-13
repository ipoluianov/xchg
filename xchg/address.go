package xchg

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base32"
	"strings"

	"github.com/ipoluianov/gomisc/crypt_tools"
)

const Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

func AddressForPublicKey(publicKey *rsa.PublicKey) string {
	bs := crypt_tools.RSAPublicKeyToDer(publicKey)
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

	return strings.ToLower(base32.StdEncoding.EncodeToString(hash[:20]))
}

func NormalizeAddress(address string) string {
	addressBS := []byte(strings.ToUpper(address))
	result := make([]byte, 0, 32)
	for _, b := range addressBS {
		if (b >= 'A' && b <= 'Z') || (b >= '2' && b <= 7) {
			result = append(result, b)
		}
	}
	return strings.ToLower(string(result))
}
