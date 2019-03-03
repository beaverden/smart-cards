package tcp_server

import (
	"encoding/json"
	"fmt"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/payment-gateway/server-context"
	"net"
)

var ServerContext *server_context.PGServerContext

func handleConnection(conn net.Conn) {
	defer conn.Close()
	// 4. Recv {PM, SigM(Sid, PubKC, Amount)}_PubKPG
	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)

}

func StartTCPServer(ctx *server_context.PGServerContext) {
	ServerContext = ctx

	go func() {
		defer fmt.Println("TCP Server Done")
		defer ServerContext.WaitGroup.Done()
		ln, _ := net.Listen("tcp", ctx.TcpPort)
		fmt.Printf("Listening on tcp -> localhost%s\n", ctx.TcpPort)
		for {
			conn, _ := ln.Accept()
			fmt.Printf("Got a tcp connection: %v\n", conn.RemoteAddr())
			go handleConnection(&conn)
		}
	}()

}
