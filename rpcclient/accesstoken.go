package rpcclient

import (
	"common_service/access_token/protos"
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
)

type AccessTokenRpcClientModel struct {
	AppId  string
	Secret string
}

func (m *AccessTokenRpcClientModel) GetAccessTokenByAppIdAndSecret(appId, secret string) {
	m.AppId = appId
	m.Secret = secret

	// 构造客户端证书对象,第一个参数是服务器的证书文件,第二个参数是签发证书的服务器的名字
	//creds, err := credentials.NewClientTLSFromFile(
	//	"common_service/secret/server.crt", "server.grpc.io",
	//)
	// ---------------------------------基于CA证书对服务器进行证书验证---------------------------------------------
	certificate, err := tls.LoadX509KeyPair("common_service/server/client.crt", "common_service/server/client.key")
	if err != nil {
		logrus.Fatal(err)
	}
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile("common_service/ca/ca.crt")
	if err != nil {
		logrus.Fatal(err)
	}
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		logrus.Fatal("failed to append ca certs")
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		ServerName:   "server.io", // NOTE: this is required!
		RootCAs:      certPool,
	})
	// ---------------------------------------------------------------------------------------------------------

	// grpc.Dial负责和gRPC服务建立链接
	// 无证书使用
	//conn, err := grpc.Dial("localhost:1234", grpc.WithInsecure())
	// 通过grpc.WithTransportCredentials(creds)将证书转为参数选项
	conn, err := grpc.Dial("localhost:1234", grpc.WithTransportCredentials(creds))
	if err != nil {
		logrus.Fatal(err)
	}
	defer conn.Close()
	// 基于建立的连接构造NewAccessTokenRpcClient对象,返回的是NewAccessTokenRpcClient接口对象
	client := protos.NewAccessTokenRpcClient(conn)
	reply, err := client.GetAccessToken(context.Background(), &protos.GetAccessTokenRequest{AppId: "123456", Secret: "123456"})
	if err != nil {
		logrus.Error(err)
	}
	if reply.GetErrcode() != 100000 {
		logrus.Error(reply.Errmsg)
	}
	// 对AccessToken进行保存,留着下次请求使用 TODO
	reply.GetAccessToken()
	reply.GetExpires()
}
