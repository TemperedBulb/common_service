// Code generated by protoc-gen-go. DO NOT EDIT.
// source: accesstoken.proto

package protos

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

//protoc --go_out=plugins=grpc:. xx.proto
type GetAccessTokenRequest struct {
	AppId                string   `protobuf:"bytes,1,opt,name=app_id,json=appId,proto3" json:"app_id,omitempty"`
	Secret               string   `protobuf:"bytes,2,opt,name=secret,proto3" json:"secret,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetAccessTokenRequest) Reset()         { *m = GetAccessTokenRequest{} }
func (m *GetAccessTokenRequest) String() string { return proto.CompactTextString(m) }
func (*GetAccessTokenRequest) ProtoMessage()    {}
func (*GetAccessTokenRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_01310bd4a6761b1e, []int{0}
}

func (m *GetAccessTokenRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetAccessTokenRequest.Unmarshal(m, b)
}
func (m *GetAccessTokenRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetAccessTokenRequest.Marshal(b, m, deterministic)
}
func (m *GetAccessTokenRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetAccessTokenRequest.Merge(m, src)
}
func (m *GetAccessTokenRequest) XXX_Size() int {
	return xxx_messageInfo_GetAccessTokenRequest.Size(m)
}
func (m *GetAccessTokenRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetAccessTokenRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetAccessTokenRequest proto.InternalMessageInfo

func (m *GetAccessTokenRequest) GetAppId() string {
	if m != nil {
		return m.AppId
	}
	return ""
}

func (m *GetAccessTokenRequest) GetSecret() string {
	if m != nil {
		return m.Secret
	}
	return ""
}

type FlushAccessTokenRequest struct {
	AccessToken          string   `protobuf:"bytes,1,opt,name=AccessToken,proto3" json:"AccessToken,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FlushAccessTokenRequest) Reset()         { *m = FlushAccessTokenRequest{} }
func (m *FlushAccessTokenRequest) String() string { return proto.CompactTextString(m) }
func (*FlushAccessTokenRequest) ProtoMessage()    {}
func (*FlushAccessTokenRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_01310bd4a6761b1e, []int{1}
}

func (m *FlushAccessTokenRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FlushAccessTokenRequest.Unmarshal(m, b)
}
func (m *FlushAccessTokenRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FlushAccessTokenRequest.Marshal(b, m, deterministic)
}
func (m *FlushAccessTokenRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FlushAccessTokenRequest.Merge(m, src)
}
func (m *FlushAccessTokenRequest) XXX_Size() int {
	return xxx_messageInfo_FlushAccessTokenRequest.Size(m)
}
func (m *FlushAccessTokenRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_FlushAccessTokenRequest.DiscardUnknown(m)
}

var xxx_messageInfo_FlushAccessTokenRequest proto.InternalMessageInfo

func (m *FlushAccessTokenRequest) GetAccessToken() string {
	if m != nil {
		return m.AccessToken
	}
	return ""
}

type CheckAccessTokenRequest struct {
	AccessToken          string   `protobuf:"bytes,1,opt,name=AccessToken,proto3" json:"AccessToken,omitempty"`
	AppId                string   `protobuf:"bytes,2,opt,name=AppId,proto3" json:"AppId,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CheckAccessTokenRequest) Reset()         { *m = CheckAccessTokenRequest{} }
func (m *CheckAccessTokenRequest) String() string { return proto.CompactTextString(m) }
func (*CheckAccessTokenRequest) ProtoMessage()    {}
func (*CheckAccessTokenRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_01310bd4a6761b1e, []int{2}
}

func (m *CheckAccessTokenRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CheckAccessTokenRequest.Unmarshal(m, b)
}
func (m *CheckAccessTokenRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CheckAccessTokenRequest.Marshal(b, m, deterministic)
}
func (m *CheckAccessTokenRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CheckAccessTokenRequest.Merge(m, src)
}
func (m *CheckAccessTokenRequest) XXX_Size() int {
	return xxx_messageInfo_CheckAccessTokenRequest.Size(m)
}
func (m *CheckAccessTokenRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CheckAccessTokenRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CheckAccessTokenRequest proto.InternalMessageInfo

func (m *CheckAccessTokenRequest) GetAccessToken() string {
	if m != nil {
		return m.AccessToken
	}
	return ""
}

func (m *CheckAccessTokenRequest) GetAppId() string {
	if m != nil {
		return m.AppId
	}
	return ""
}

type AccessTokenResponse struct {
	AccessToken          string   `protobuf:"bytes,1,opt,name=AccessToken,proto3" json:"AccessToken,omitempty"`
	Expires              string   `protobuf:"bytes,2,opt,name=Expires,proto3" json:"Expires,omitempty"`
	Errcode              int64    `protobuf:"varint,3,opt,name=Errcode,proto3" json:"Errcode,omitempty"`
	Errmsg               string   `protobuf:"bytes,4,opt,name=Errmsg,proto3" json:"Errmsg,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AccessTokenResponse) Reset()         { *m = AccessTokenResponse{} }
func (m *AccessTokenResponse) String() string { return proto.CompactTextString(m) }
func (*AccessTokenResponse) ProtoMessage()    {}
func (*AccessTokenResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_01310bd4a6761b1e, []int{3}
}

func (m *AccessTokenResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AccessTokenResponse.Unmarshal(m, b)
}
func (m *AccessTokenResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AccessTokenResponse.Marshal(b, m, deterministic)
}
func (m *AccessTokenResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AccessTokenResponse.Merge(m, src)
}
func (m *AccessTokenResponse) XXX_Size() int {
	return xxx_messageInfo_AccessTokenResponse.Size(m)
}
func (m *AccessTokenResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_AccessTokenResponse.DiscardUnknown(m)
}

var xxx_messageInfo_AccessTokenResponse proto.InternalMessageInfo

func (m *AccessTokenResponse) GetAccessToken() string {
	if m != nil {
		return m.AccessToken
	}
	return ""
}

func (m *AccessTokenResponse) GetExpires() string {
	if m != nil {
		return m.Expires
	}
	return ""
}

func (m *AccessTokenResponse) GetErrcode() int64 {
	if m != nil {
		return m.Errcode
	}
	return 0
}

func (m *AccessTokenResponse) GetErrmsg() string {
	if m != nil {
		return m.Errmsg
	}
	return ""
}

type CheckAccessTokenResponse struct {
	ResultCode           string   `protobuf:"bytes,1,opt,name=ResultCode,proto3" json:"ResultCode,omitempty"`
	ResultMsg            string   `protobuf:"bytes,2,opt,name=ResultMsg,proto3" json:"ResultMsg,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CheckAccessTokenResponse) Reset()         { *m = CheckAccessTokenResponse{} }
func (m *CheckAccessTokenResponse) String() string { return proto.CompactTextString(m) }
func (*CheckAccessTokenResponse) ProtoMessage()    {}
func (*CheckAccessTokenResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_01310bd4a6761b1e, []int{4}
}

func (m *CheckAccessTokenResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CheckAccessTokenResponse.Unmarshal(m, b)
}
func (m *CheckAccessTokenResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CheckAccessTokenResponse.Marshal(b, m, deterministic)
}
func (m *CheckAccessTokenResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CheckAccessTokenResponse.Merge(m, src)
}
func (m *CheckAccessTokenResponse) XXX_Size() int {
	return xxx_messageInfo_CheckAccessTokenResponse.Size(m)
}
func (m *CheckAccessTokenResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_CheckAccessTokenResponse.DiscardUnknown(m)
}

var xxx_messageInfo_CheckAccessTokenResponse proto.InternalMessageInfo

func (m *CheckAccessTokenResponse) GetResultCode() string {
	if m != nil {
		return m.ResultCode
	}
	return ""
}

func (m *CheckAccessTokenResponse) GetResultMsg() string {
	if m != nil {
		return m.ResultMsg
	}
	return ""
}

func init() {
	proto.RegisterType((*GetAccessTokenRequest)(nil), "protos.GetAccessTokenRequest")
	proto.RegisterType((*FlushAccessTokenRequest)(nil), "protos.FlushAccessTokenRequest")
	proto.RegisterType((*CheckAccessTokenRequest)(nil), "protos.CheckAccessTokenRequest")
	proto.RegisterType((*AccessTokenResponse)(nil), "protos.AccessTokenResponse")
	proto.RegisterType((*CheckAccessTokenResponse)(nil), "protos.CheckAccessTokenResponse")
}

func init() { proto.RegisterFile("accesstoken.proto", fileDescriptor_01310bd4a6761b1e) }

var fileDescriptor_01310bd4a6761b1e = []byte{
	// 308 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x92, 0x4f, 0x4b, 0xc3, 0x40,
	0x10, 0xc5, 0x49, 0x6b, 0x23, 0x1d, 0xa1, 0xd4, 0xd5, 0xda, 0xa5, 0xfe, 0x0b, 0x39, 0xf5, 0xd4,
	0x83, 0x1e, 0x3d, 0x95, 0xd2, 0x8a, 0xa0, 0xa0, 0x41, 0xc1, 0x9b, 0xc4, 0xcd, 0xd0, 0x96, 0xd6,
	0x66, 0xdd, 0xd9, 0x80, 0x77, 0x0f, 0x7e, 0x6d, 0x49, 0x76, 0x43, 0xd3, 0x9a, 0x88, 0x78, 0x0a,
	0xef, 0x4d, 0xe6, 0xc7, 0xcb, 0xbc, 0xc0, 0x7e, 0x28, 0x04, 0x12, 0xe9, 0x78, 0x81, 0xab, 0x81,
	0x54, 0xb1, 0x8e, 0x99, 0x9b, 0x3d, 0xc8, 0x9f, 0x40, 0xe7, 0x1a, 0xf5, 0x30, 0x9b, 0x3f, 0xa6,
	0xf3, 0x00, 0xdf, 0x13, 0x24, 0xcd, 0x3a, 0xe0, 0x86, 0x52, 0xbe, 0xcc, 0x23, 0xee, 0x78, 0x4e,
	0xbf, 0x19, 0x34, 0x42, 0x29, 0x6f, 0x22, 0x76, 0x04, 0x2e, 0xa1, 0x50, 0xa8, 0x79, 0x2d, 0xb3,
	0xad, 0xf2, 0xaf, 0xa0, 0x3b, 0x59, 0x26, 0x34, 0x2b, 0x21, 0x79, 0xb0, 0x57, 0x70, 0x2d, 0xae,
	0x68, 0xf9, 0x0f, 0xd0, 0x1d, 0xcd, 0x50, 0x2c, 0xfe, 0xb3, 0xcc, 0x0e, 0xa1, 0x31, 0x4c, 0xa3,
	0xd9, 0x40, 0x46, 0xf8, 0x9f, 0x0e, 0x1c, 0x6c, 0xe0, 0x48, 0xc6, 0x2b, 0xc2, 0x3f, 0xf0, 0x38,
	0xec, 0x8e, 0x3f, 0xe4, 0x5c, 0x21, 0x59, 0x62, 0x2e, 0xb3, 0x89, 0x52, 0x22, 0x8e, 0x90, 0xd7,
	0x3d, 0xa7, 0x5f, 0x0f, 0x72, 0x99, 0x5e, 0x65, 0xac, 0xd4, 0x1b, 0x4d, 0xf9, 0x8e, 0xb9, 0x8a,
	0x51, 0xfe, 0x33, 0xf0, 0x9f, 0x1f, 0x66, 0x93, 0x9c, 0x01, 0x04, 0x48, 0xc9, 0x52, 0x8f, 0x52,
	0xa0, 0x09, 0x52, 0x70, 0xd8, 0x09, 0x34, 0x8d, 0xba, 0xa3, 0xa9, 0x4d, 0xb2, 0x36, 0x2e, 0xbe,
	0x6a, 0xd0, 0x2a, 0x52, 0xa5, 0x60, 0xb7, 0xd0, 0xda, 0xac, 0x92, 0x9d, 0x9a, 0xb2, 0x69, 0x50,
	0x5a, 0x71, 0xef, 0x38, 0x1f, 0x97, 0xc5, 0xbb, 0x87, 0xf6, 0x76, 0xa1, 0xec, 0x3c, 0x5f, 0xa8,
	0xa8, 0xfa, 0x77, 0xe2, 0x13, 0xb4, 0xb7, 0x8f, 0xb1, 0x26, 0x56, 0xf4, 0xdf, 0xf3, 0xaa, 0x5f,
	0x30, 0xd8, 0x57, 0xf3, 0x27, 0x5f, 0x7e, 0x07, 0x00, 0x00, 0xff, 0xff, 0xa8, 0x7e, 0x2d, 0x4d,
	0xe5, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// AccessTokenRpcClient is the client API for AccessTokenRpc service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AccessTokenRpcClient interface {
	GetAccessToken(ctx context.Context, in *GetAccessTokenRequest, opts ...grpc.CallOption) (*AccessTokenResponse, error)
	FlushAccessToken(ctx context.Context, in *FlushAccessTokenRequest, opts ...grpc.CallOption) (*AccessTokenResponse, error)
	CheckAccessToken(ctx context.Context, in *CheckAccessTokenRequest, opts ...grpc.CallOption) (*CheckAccessTokenResponse, error)
}

type accessTokenRpcClient struct {
	cc *grpc.ClientConn
}

func NewAccessTokenRpcClient(cc *grpc.ClientConn) AccessTokenRpcClient {
	return &accessTokenRpcClient{cc}
}

func (c *accessTokenRpcClient) GetAccessToken(ctx context.Context, in *GetAccessTokenRequest, opts ...grpc.CallOption) (*AccessTokenResponse, error) {
	out := new(AccessTokenResponse)
	err := c.cc.Invoke(ctx, "/protos.AccessTokenRpc/GetAccessToken", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accessTokenRpcClient) FlushAccessToken(ctx context.Context, in *FlushAccessTokenRequest, opts ...grpc.CallOption) (*AccessTokenResponse, error) {
	out := new(AccessTokenResponse)
	err := c.cc.Invoke(ctx, "/protos.AccessTokenRpc/FlushAccessToken", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accessTokenRpcClient) CheckAccessToken(ctx context.Context, in *CheckAccessTokenRequest, opts ...grpc.CallOption) (*CheckAccessTokenResponse, error) {
	out := new(CheckAccessTokenResponse)
	err := c.cc.Invoke(ctx, "/protos.AccessTokenRpc/CheckAccessToken", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AccessTokenRpcServer is the server API for AccessTokenRpc service.
type AccessTokenRpcServer interface {
	GetAccessToken(context.Context, *GetAccessTokenRequest) (*AccessTokenResponse, error)
	FlushAccessToken(context.Context, *FlushAccessTokenRequest) (*AccessTokenResponse, error)
	CheckAccessToken(context.Context, *CheckAccessTokenRequest) (*CheckAccessTokenResponse, error)
}

// UnimplementedAccessTokenRpcServer can be embedded to have forward compatible implementations.
type UnimplementedAccessTokenRpcServer struct {
}

func (*UnimplementedAccessTokenRpcServer) GetAccessToken(ctx context.Context, req *GetAccessTokenRequest) (*AccessTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAccessToken not implemented")
}
func (*UnimplementedAccessTokenRpcServer) FlushAccessToken(ctx context.Context, req *FlushAccessTokenRequest) (*AccessTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FlushAccessToken not implemented")
}
func (*UnimplementedAccessTokenRpcServer) CheckAccessToken(ctx context.Context, req *CheckAccessTokenRequest) (*CheckAccessTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckAccessToken not implemented")
}

func RegisterAccessTokenRpcServer(s *grpc.Server, srv AccessTokenRpcServer) {
	s.RegisterService(&_AccessTokenRpc_serviceDesc, srv)
}

func _AccessTokenRpc_GetAccessToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAccessTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccessTokenRpcServer).GetAccessToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protos.AccessTokenRpc/GetAccessToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccessTokenRpcServer).GetAccessToken(ctx, req.(*GetAccessTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AccessTokenRpc_FlushAccessToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FlushAccessTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccessTokenRpcServer).FlushAccessToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protos.AccessTokenRpc/FlushAccessToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccessTokenRpcServer).FlushAccessToken(ctx, req.(*FlushAccessTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AccessTokenRpc_CheckAccessToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CheckAccessTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccessTokenRpcServer).CheckAccessToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protos.AccessTokenRpc/CheckAccessToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccessTokenRpcServer).CheckAccessToken(ctx, req.(*CheckAccessTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _AccessTokenRpc_serviceDesc = grpc.ServiceDesc{
	ServiceName: "protos.AccessTokenRpc",
	HandlerType: (*AccessTokenRpcServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetAccessToken",
			Handler:    _AccessTokenRpc_GetAccessToken_Handler,
		},
		{
			MethodName: "FlushAccessToken",
			Handler:    _AccessTokenRpc_FlushAccessToken_Handler,
		},
		{
			MethodName: "CheckAccessToken",
			Handler:    _AccessTokenRpc_CheckAccessToken_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "accesstoken.proto",
}
