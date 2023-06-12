package goid

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

// Encrypt encrypts a string using AES encryption with the provided secret.
func Encrypt(text string, secret string) (string, error) {
	plaintext := []byte(text)
	key := []byte(secret)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts an encrypted string using AES encryption with the provided secret.
func Decrypt(ciphertext string, secret string) (string, error) {
	key := []byte(secret)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	decodedCiphertext, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	if len(decodedCiphertext) < aes.BlockSize {
		return "", err
	}

	iv := decodedCiphertext[:aes.BlockSize]
	decodedCiphertext = decodedCiphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(decodedCiphertext, decodedCiphertext)

	return string(decodedCiphertext), nil
}

func GenerateSecureKey(keyLength int) (string, error) {
	key := make([]byte, keyLength)

	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}

	// Encode the random bytes to a base64 string
	keyString := base64.StdEncoding.EncodeToString(key)

	return keyString, nil
}

// func main() {
// 	// Example usage
// 	plaintext := "Hello, World!"
// 	secret := "MySecretKey123"

// 	encryptedText, err := Encrypt(plaintext, secret)
// 	if err != nil {
// 		panic(err)
// 	}

// 	decryptedText, err := Decrypt(encryptedText, secret)
// 	if err != nil {
// 		panic(err)
// 	}

// 	println("Encrypted text:", encryptedText)
// 	println("Decrypted text:", decryptedText)
// }
