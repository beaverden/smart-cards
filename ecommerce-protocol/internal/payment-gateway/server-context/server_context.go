package server_context

import (
	"crypto/rsa"
	"github.com/beaverden/smart-cards/ecommerce-protocol/config"
	"sync"
)

type PGServerContext struct {
	Config       config.AppConfig
	PGPrivateKey *rsa.PrivateKey
	WaitGroup    *sync.WaitGroup
}
