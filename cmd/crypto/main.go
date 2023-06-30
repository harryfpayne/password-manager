package crypto

import (
	"strings"
)

// Dummy encryption and decryption functions
func Encrypt(message string, key string) []byte {
	return []byte(key + message)
}

func Decrypt(message []byte, key string) string {
	_message := string(message)
	for _, k := range key {
		_message = strings.Replace(_message, string(k), "", 1)
	}
	return _message
}

func GetDerivedKey(key string) string {
	return key
}

func RandomString() string {
	return "random-1"
}
