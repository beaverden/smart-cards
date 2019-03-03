package http_api

import (
	"fmt"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/payment-gateway/server-context"
	"net/http"
)

var ServerContext *server_context.PGServerContext

func StartHTTPApiHandler(ctx *server_context.PGServerContext) {
	ServerContext = ctx
	go func() {
		defer fmt.Println("HTTP Api Done")
		defer ctx.WaitGroup.Done()

		http.HandleFunc("/signSegment", signApiHandler)
		fmt.Printf("Listening on http -> http://localhost%s\n", ctx.HttpPort)
		http.ListenAndServe(ctx.HttpPort, nil)
	}()
}
