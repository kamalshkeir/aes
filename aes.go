package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/scrypt"
)

var secretInit string

func SetSecret(secret string) {
	secretInit = secret
}

func Encrypt(data string) (string, error) {
	if secretInit == "" {
		secretInit = randomString(19)
	}
	keyByte, salt, err := deriveKey([]byte(secretInit), nil)
	if err != nil {
		return "", err
	}

	blockCipher, err := aes.NewCipher([]byte(keyByte))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)

	ciphertext = append(ciphertext, salt...)
	return hex.EncodeToString(ciphertext), nil
}

func Decrypt(data string) (string, error) {
	if secretInit == "" {
		return "", errors.New("no secret given, set SECRET in env file")
	}
	var salt []byte
	dataByte, _ := hex.DecodeString(data)
	if len(dataByte) > 32 {
		salt, dataByte = dataByte[len(dataByte)-32:], dataByte[:len(dataByte)-32]
	} else {
		return "", errors.New("bad token")
	}

	key, _, err := deriveKey([]byte(secretInit), salt)
	if err != nil {
		return "", err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return "", err
	}

	nonce, ciphertext := dataByte[:gcm.NonceSize()], dataByte[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func deriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}

	key, err := scrypt.Key(password, salt, 1<<10, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

func randomString(s int) string {
	b, _ := randomBytes(s)
	return base64.URLEncoding.EncodeToString(b)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// err == nil only if len(b) == n
	if err != nil {
		return nil, err
	}

	return b, nil
}
