package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
)

// Dummy encryption and decryption functions
func Encrypt(_plaintext string, key string) []byte {
	plaintext, err := pkcs7pad([]byte(_plaintext), aes.BlockSize)
	if err != nil {
		panic(err)
	}

	decodedKey, err := hex.DecodeString(key)
	if err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(decodedKey)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext[aes.BlockSize:], []byte(plaintext))

	return ciphertext
}

func Decrypt(_message []byte, key string) string {
	message := make([]byte, len(_message))
	copy(message, _message)
	var block cipher.Block

	decodedKey, err := hex.DecodeString(key)
	if err != nil {
		panic(err)
	}

	if block, err = aes.NewCipher(decodedKey); err != nil {
		panic(err)
	}

	if len(message) < aes.BlockSize {
		panic("ciphertext too short")
	}

	iv := message[:aes.BlockSize]
	message = message[aes.BlockSize:]

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(message, message)

	fmt.Println("message", string(message))
	stripped, err := pkcs7strip(message, aes.BlockSize)
	if err != nil {
		panic(err)
	}
	return string(stripped)
}

func GetDerivedKey(key string, salt string) string {
	derivedKey := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha512.New)
	return hex.EncodeToString(derivedKey)
}

func RandomString(l int) string {
	b := make([]byte, l)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// pkcs7strip remove pkcs7 padding
func pkcs7strip(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7: Data is empty")
	}
	if length%blockSize != 0 {
		return nil, errors.New("pkcs7: Data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		return nil, errors.New("pkcs7: Invalid padding")
	}
	return data[:length-padLen], nil
}

// pkcs7pad add pkcs7 padding
func pkcs7pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 1 || blockSize >= 256 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	} else {
		padLen := blockSize - len(data)%blockSize
		padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
		return append(data, padding...), nil
	}
}
