package hybrid_encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"github.com/pkg/errors"
)

type AesKey []byte

type HybridEncryption struct {
	Ciphertext      []byte `json:"ciphertext"`
	EncryptedAesKey []byte `json:"encryptedAesKey"`
}

func Encrypt(data []byte, publicKey *rsa.PublicKey, simKey AesKey) (*HybridEncryption, error) {
	blockCipher, err := aes.NewCipher(simKey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	stream := cipher.NewCTR(blockCipher, iv)
	encryptedData := make([]byte, len(data))
	stream.XORKeyStream(data, encryptedData)

	hash := sha512.New()
	encryptedKey, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, simKey, nil)
	return &HybridEncryption{Ciphertext: encryptedData, EncryptedAesKey: encryptedKey}, nil
}
