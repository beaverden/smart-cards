package hybrid_encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/json"
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
	CipherText []byte          `json:"cipher_text"`
	EncAesKey  EncryptedAesKey `json:"encrypted_aes_key"`
}

func NewAesKey() *AesKey {
	key := new(AesKey)
	key.Key = make([]byte, 32)
	key.IV = make([]byte, 16)
	_, _ = rand.Read(key.Key)
	_, _ = rand.Read(key.IV)
	return key
}

// Encrypts data that can be marshaled with json
// If the data interface is already []byte, it won't be marshaled and encrypted as is
// Generates a new AES key for each call
// Encrypts the data with AES and the AES key with RSA (publicKey)
func Encrypt(data interface{}, publicKey *rsa.PublicKey) (*HybridEncryption, error) {
	var jsonData []byte
	switch data.(type) {
	default:
		var err error
		jsonData, err = json.Marshal(data)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	case []byte:
		jsonData = data.([]byte)
	}
	simKey := NewAesKey()
	blockCipher, err := aes.NewCipher(simKey.Key)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stream := cipher.NewCTR(blockCipher, simKey.IV)
	encryptedData := make([]byte, len(jsonData))
	stream.XORKeyStream(encryptedData, jsonData)

	hash := sha512.New()
	encryptedKey, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, simKey.Key, nil)
	return &HybridEncryption{
			CipherText: encryptedData,
			EncAesKey: EncryptedAesKey{
				Key: encryptedKey,
				IV:  simKey.IV}},
		nil
}

// Encrypts data that can be marshaled with json. Encrypts it into a HybridEncryption struct
// The struct is then marshaled to json.Encoder
func EncryptToStream(data interface{}, publicKey *rsa.PublicKey, encoder *json.Encoder) error {
	encryptedChunk, err := Encrypt(data, publicKey)
	if err != nil {
		return errors.WithStack(err)
	}
	return encoder.Encode(encryptedChunk)
}

// Decrypts data that can be unmarshaled with json from the HybridEncryption structure
// Decrypts the AES key with RSA and then the ciphertext with the newly obtained AES key
// Unmarshals the plaintext into the dst interface (supposed to be a pointer to something)
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
	return json.Unmarshal(decryptedData, dst)
}

// Decrypts data that can be unmarshaled with json from the HybridEncryption structure obtained from json.Decoder
// The data is read from the decoder. It reads one HybridEncryption struct
// The structure is sent to the Decrypt function
func DecryptFromStream(dst interface{}, key *rsa.PrivateKey, decoder *json.Decoder) error {
	var encryption HybridEncryption
	err := decoder.Decode(&encryption)
	if err != nil {
		return errors.WithStack(err)
	}
	return Decrypt(dst, &encryption, key)
}
