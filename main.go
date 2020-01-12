package main

import (
	"common_service_temp/hello"
	"google.golang.org/grpc"
	"log"
	"net"
)

func main() {
	grpcServer := grpc.NewServer()
	hello.RegisterHelloServiceServer(grpcServer, new(hello.HelloServiceImpl))

	lis, err := net.Listen("tcp", ":1234")
	if err != nil {
		log.Fatal(err)
	}
	grpcServer.Serve(lis)

}
