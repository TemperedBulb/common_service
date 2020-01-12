package main

import (
	"common_service/access_token/logic"
	"common_service/access_token/protos"
	"crypto/tls"
	"crypto/x509"
	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"log"
	"net"
)

const (
	PORT = ":50001"
)

//基于ca验证证书
func checkCred() credentials.TransportCredentials {
	// 通过ca根证书签名,在启动服务器时配置根证书
	certificate, err := tls.LoadX509KeyPair("common/secret/server.crt", "common/secret/server.key")
	if err != nil {
		logrus.Fatal(err)
	}
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile("common/ca/ca.crt")
	if err != nil {
		logrus.Fatal(err)
	}
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		log.Fatal("failed to append certs")
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert, // NOTE: this is optional!
		ClientCAs:    certPool,
	})
	return creds
}

// 验证服务器证书,需要证书的传递
func checkServerCred() credentials.TransportCredentials {
	creds, err := credentials.NewServerTLSFromFile("common_service/secret/server.crt", "common_service/secret/server.key")
	if err != nil {
		logrus.Fatal(err)
	}
	return creds
}

func main() {
	// 验证ca证书
	creds := checkCred()

	// 从文件为服务器构造证书对象
	//creds, err := credentials.NewServerTLSFromFile("common_service/secret/server.crt", "common_service/secret/server.key")
	//if err != nil {
	//	logrus.Fatal(err)
	//}
	db, err := gorm.Open("mysql", "user:password@/dbname?charset=utf8&parseTime=True&loc=Local")
	defer db.Close()
	// 构造一个gRPC服务对象.grpc.Creds()函数把证书包装成选项
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	accessTokenLogic := logic.NewAccessTokenLogic()
	//通过gRPC插件生成的RegisterAccessTokenRpcServer函数注册我们实现的AccessTokenLogic服务
	protos.RegisterAccessTokenRpcServer(grpcServer, accessTokenLogic)
	lis, err := net.Listen("tcp", PORT)
	if err != nil {
		logrus.Fatalf("failed to listen: %v", err)
	}
	logrus.Println("rpc服务已经开启,port", PORT)
	// 通过grpcServer.Serve(lis)在一个监听端口上提供gRPC服务
	err = grpcServer.Serve(lis)
	logrus.Fatal(err)
}

//func main2() {
//
//}
