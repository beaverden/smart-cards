package protocol

import (
	"crypto"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/ecrypto/signature"
)

type MerchantData struct {
	Name           string
	MerchantPubKey crypto.PublicKey
}

type WebSegment struct {
	MerchantInfo MerchantData
	Signature    signature.DSASignature
}
