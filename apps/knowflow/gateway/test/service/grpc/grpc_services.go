package main

import (
	"context"
	"log"
	"net"
	"time"

	"go.opentelemetry.io/otel"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/reflection"

	"github.com/DoraZa/mini-gateway/proto/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

type helloServiceServer struct {
	proto.HelloServiceServer
}

type healthServiceServer struct {
	proto.HealthServer
}

func (s *helloServiceServer) GetHello(ctx context.Context, req *proto.HelloRequest) (*proto.HelloResponse, error) {
	// 模拟返回用户信息
	log.Println("GetHello called with name:", req.Name, ",time:", time.Now())
	tracer := otel.Tracer("mini-grpc-service")
	_, span := tracer.Start(ctx, "GetHello")
	defer span.End()
	return &proto.HelloResponse{
		Message: "GetHello " + req.Name,
	}, nil
}

func (s *helloServiceServer) SayHello(ctx context.Context, req *proto.HelloRequest) (*proto.HelloResponse, error) {
	log.Println("SayHello called with name:", req.Name, ",time:", time.Now())
	tracer := otel.Tracer("mini-grpc-service")
	_, span := tracer.Start(ctx, "SayHello")
	defer span.End()
	// 模拟返回用户信息
	return &proto.HelloResponse{
		Message: "SayHello " + req.Name,
	}, nil
}

func (s *helloServiceServer) ReplyHello(ctx context.Context, req *proto.HelloRequest) (*proto.HelloResponse, error) {
	log.Println("ReplyHello called with name:", req.Name, ",time:", time.Now())
	tracer := otel.Tracer("mini-grpc-service")
	_, span := tracer.Start(ctx, "ReplyHello")
	defer span.End()
	// 模拟返回用户信息
	return &proto.HelloResponse{
		Message: "ReplyHello " + req.Name,
	}, nil
}

func (s *healthServiceServer) Check(context.Context, *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":8391")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer()
	proto.RegisterHelloServiceServer(s, &helloServiceServer{})
	proto.RegisterHealthServer(s, &healthServiceServer{})

	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)             // 整个服务器健康
	healthServer.SetServingStatus("hello.Health", grpc_health_v1.HealthCheckResponse_SERVING) // HelloService 健康
	grpc_health_v1.RegisterHealthServer(s, healthServer)

	reflection.Register(s)

	log.Println("gRPC server listening on :8391")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
