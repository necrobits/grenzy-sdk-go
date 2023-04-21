package griffin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

func base64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func base64urlDecode(data string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(data)
}

func mustHashUsing(method string, data []byte) []byte {
	switch strings.ToLower(method) {
	case "s256":
		hash := sha256.Sum256(data)
		return hash[:]
	}
	panic("unsupported hash method")
}

func generateRandomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	return buf, err
}
