package hybrid_encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
)

type AesKey struct {
	Key []byte `json:"key"`
	IV  []byte `json:"iv"`
}

type EncryptedAesKey struct {
	Key []byte `json:"key"`
	IV  []byte `json:"iv"`
}

type HybridEncryption struct {
	CipherText []byte          `json:"ciphertext"`
	EncAesKey  EncryptedAesKey `json:"encryptedAesKey"`
}

func Encrypt(data interface{}, publicKey *rsa.PublicKey, simKey *AesKey) (*HybridEncryption, error) {
	var jsonData []byte
	switch v := data.(type) {
	default:
		fmt.Println(v)
		var err error
		jsonData, err = json.Marshal(data)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	case []byte:
		jsonData = data.([]byte)
	}

	blockCipher, err := aes.NewCipher(simKey.Key)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stream := cipher.NewCTR(blockCipher, simKey.IV)
	encryptedData := make([]byte, len(jsonData))
	stream.XORKeyStream(jsonData, encryptedData)

	hash := sha512.New()
	encryptedKey, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, simKey.Key, nil)
	return &HybridEncryption{
			CipherText: encryptedData,
			EncAesKey: EncryptedAesKey{
				Key: encryptedKey,
				IV:  simKey.IV}},
		nil
}

// dst - pointer to structure
func Decrypt(dst interface{}, encryption *HybridEncryption, key *rsa.PrivateKey) error {
	hash := sha512.New()
	decryptedAesKey, err := rsa.DecryptOAEP(hash, rand.Reader, key, encryption.EncAesKey.Key, nil)
	if err != nil {
		return errors.WithStack(err)
	}

	blockCipher, err := aes.NewCipher(decryptedAesKey)
	if err != nil {
		return errors.WithStack(err)
	}

	stream := cipher.NewCTR(blockCipher, encryption.EncAesKey.IV)
	decryptedData := make([]byte, len(encryption.CipherText))
	stream.XORKeyStream(decryptedData, encryption.CipherText)
	err = json.Unmarshal(decryptedData, dst)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func DecryptStream(dst interface{}, key *rsa.PrivateKey, decoder *json.Decoder) error {
	var encryption HybridEncryption
	err := decoder.Decode(encryption)
	if err != nil {
		return errors.WithStack(err)
	}
	hash := sha512.New()
	decryptedAesKey, err := rsa.DecryptOAEP(hash, rand.Reader, key, encryption.EncAesKey.Key, nil)
	if err != nil {
		return errors.WithStack(err)
	}

	blockCipher, err := aes.NewCipher(decryptedAesKey)
	if err != nil {
		return errors.WithStack(err)
	}

	stream := cipher.NewCTR(blockCipher, encryption.EncAesKey.IV)
	decryptedData := make([]byte, len(encryption.CipherText))
	stream.XORKeyStream(decryptedData, encryption.CipherText)
	err = json.Unmarshal(decryptedData, dst)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
