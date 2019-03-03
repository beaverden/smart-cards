package signature

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"github.com/pkg/errors"
	"math/big"
)

type DSASignature struct {
	Hash   []byte
	R      *big.Int
	S      *big.Int
	PubKey dsa.PublicKey
}

type SignedData struct {
	Data      []byte
	Signature *DSASignature
}

func Sign(data interface{}, key *dsa.PrivateKey) (*DSASignature, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	hashAlgo := sha256.New()
	hashAlgo.Write(jsonData)
	dataChecksum := hashAlgo.Sum(nil)
	r, s, err := dsa.Sign(rand.Reader, key, dataChecksum)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var sig DSASignature
	sig.R = r
	sig.S = s
	sig.PubKey = key.PublicKey
	sig.Hash = dataChecksum
	return &sig, nil
}

func Verify(signature *DSASignature) (bool, error) {
	status := dsa.Verify(&signature.PubKey, signature.Hash, signature.R, signature.S)
	return status, nil
}

func GenerateDSAKeyPair() (*dsa.PrivateKey, error) {
	params := new(dsa.Parameters)

	// see http://golang.org/pkg/crypto/dsa/#ParameterSizes
	if err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160); err != nil {
		return nil, errors.WithStack(err)
	}

	privateKey := new(dsa.PrivateKey)
	privateKey.PublicKey.Parameters = *params
	err := dsa.GenerateKey(privateKey, rand.Reader) // this generates a public & private key pair
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return privateKey, nil
}
