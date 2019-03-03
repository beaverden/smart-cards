package server_context

import (
	"crypto/dsa"
	"sync"
)

type PGServerContext struct {
	HttpPort     string
	TcpPort      string
	PGPrivateKey *dsa.PrivateKey
	WaitGroup    *sync.WaitGroup
}
