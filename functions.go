package encrypter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
	"os"
	"strings"
	"syscall"
)

func Encrypt(key, data []byte) ([]byte, error) {
	derivedKey,err := DeriveKey(key, nil)
	if err != nil {
		return nil, err
	}

	return EncryptWithDerivedKey(derivedKey, data)
}

func EncryptWithDerivedKey(derivedKey DerivedKey, data []byte) ([]byte, error) {
	blockCipher, err := aes.NewCipher(derivedKey.Key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	ciphertext = append(ciphertext, derivedKey.Salt...)

	return ciphertext, nil
}

type DerivedKey struct {
	Key []byte
	Salt []byte
}


func Decrypt(key, data []byte) ([]byte, error) {
	if len(data) < 32 {
		return nil, errors.New("bad data detected")
	}
	salt, data := data[len(data)-32:], data[:len(data)-32]

	derivedKey, err := DeriveKey(key, salt)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(derivedKey.Key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func DeriveKey(password, salt []byte) (DerivedKey, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return DerivedKey{}, err
		}
	}

	key, err := scrypt.Key(password, salt, 1048576, 8, 1, 32)
	if err != nil {
		return DerivedKey{}, err
	}

	return DerivedKey{
		Key: key,
		Salt: salt,
	}, nil
}

func GetSecureInput(prefixes ...string) string {
	for _, p := range prefixes {
		os.Stdout.WriteString(p)
	}

	data, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		panic(err)
	}

	return strings.TrimSpace(string(data))
}
