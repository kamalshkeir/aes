package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/kamalshkeir/kmap"
	"golang.org/x/crypto/scrypt"
)

var secretInit string
var aesCache = kmap.New[string, string](false, 50)

// SetSecret sets the secret key for encryption/decryption.
func SetSecret(secret string) {
	secretInit = secret
}

// Encrypt encrypts the given data using the secret key.
func Encrypt(data string) (string, error) {
	if secretInit == "" {
		secretInit = randomString(32)
	}
	if v, ok := aesCache.Get(data); ok {
		return v, nil
	}

	key, salt, err := deriveKey([]byte(secretInit), nil)
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

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)

	ciphertext = append(ciphertext, salt...)
	res := hex.EncodeToString(ciphertext)
	err = aesCache.Set(data, res)
	if err != nil {
		aesCache.Flush()
		_ = aesCache.Set(data, res)
	}
	return res, nil
}

// Decrypt decrypts the given encrypted data using the secret key.
func Decrypt(data string) (string, error) {
	if secretInit == "" {
		return "", errors.New("no secret given, set SECRET in env file")
	}
	if v, ok := aesCache.Get(data); ok {
		return v, nil
	}
	dataByte, err := hex.DecodeString(data)
	if err != nil {
		return "", errors.New("bad token")
	}

	salt, dataByte := dataByte[len(dataByte)-32:], dataByte[:len(dataByte)-32]

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

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	res := string(plaintext)
	err = aesCache.Set(data, res)
	if err != nil {
		aesCache.Flush()
		_ = aesCache.Set(data, res)
	}
	return res, nil
}

func deriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}

	key, err := scrypt.Key(password, salt, 1<<12, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

func randomString(length int) string {
	b, _ := randomBytes(length)
	return base64.URLEncoding.EncodeToString(b)
}

func randomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}
