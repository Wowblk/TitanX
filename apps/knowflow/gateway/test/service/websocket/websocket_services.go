package main

import (
	"log"
	"net/http"

	"github.com/gorilla/websocket"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

var upgrader = websocket.Upgrader{}
var tracer = otel.Tracer("mini-websocket-service")

func main() {
	http.HandleFunc("/ws/chat", handlerWebsocket())
	http.HandleFunc("/health", handlerHealth())
	log.Println("WebSocket Service Started, listening on :8392")
	log.Fatal(http.ListenAndServe(":8392", nil))
}

func handlerHealth() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			_, msgSpan := tracer.Start(r.Context(), "WebSocket.Message",
				trace.WithAttributes(attribute.String("direction", "server")))
			msgType, msg, err := conn.ReadMessage()
			if err != nil {
				msgSpan.RecordError(err)
				msgSpan.SetStatus(codes.Error, "Read failed")
				msgSpan.End()
				return
			}
			err = conn.WriteMessage(msgType, append([]byte("Echo: "), msg...))
			if err != nil {
				msgSpan.RecordError(err)
				msgSpan.SetStatus(codes.Error, "Write failed")
				msgSpan.End()
				return
			}
			msgSpan.SetStatus(codes.Ok, "Message processed")
			msgSpan.End()
		}
	}
}

func handlerWebsocket() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// 提取追踪上下文
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := tracer.Start(ctx, "WebSocket.Connect")
		defer span.End()

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Upgrade failed")
			return
		}
		defer conn.Close()

		for {
			_, msgSpan := tracer.Start(ctx, "WebSocket.Message",
				trace.WithAttributes(attribute.String("direction", "server")))
			msgType, msg, err := conn.ReadMessage()
			if err != nil {
				msgSpan.RecordError(err)
				msgSpan.SetStatus(codes.Error, "Read failed")
				msgSpan.End()
				return
			}
			err = conn.WriteMessage(msgType, append([]byte("Echo: "), msg...))
			if err != nil {
				msgSpan.RecordError(err)
				msgSpan.SetStatus(codes.Error, "Write failed")
				msgSpan.End()
				return
			}
			msgSpan.SetStatus(codes.Ok, "Message processed")
			msgSpan.End()
		}
	}
}
