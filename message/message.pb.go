// Code generated by protoc-gen-go. DO NOT EDIT.
// source: message/message.proto

package vkms

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
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

type SignRequest struct {
	KeyUsageToken        []byte   `protobuf:"bytes,1,opt,name=key_usage_token,json=keyUsageToken,proto3" json:"key_usage_token,omitempty"`
	Data                 []byte   `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignRequest) Reset()         { *m = SignRequest{} }
func (m *SignRequest) String() string { return proto.CompactTextString(m) }
func (*SignRequest) ProtoMessage()    {}
func (*SignRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_ebceca9e8703e37f, []int{0}
}

func (m *SignRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignRequest.Unmarshal(m, b)
}
func (m *SignRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignRequest.Marshal(b, m, deterministic)
}
func (m *SignRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignRequest.Merge(m, src)
}
func (m *SignRequest) XXX_Size() int {
	return xxx_messageInfo_SignRequest.Size(m)
}
func (m *SignRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_SignRequest.DiscardUnknown(m)
}

var xxx_messageInfo_SignRequest proto.InternalMessageInfo

func (m *SignRequest) GetKeyUsageToken() []byte {
	if m != nil {
		return m.KeyUsageToken
	}
	return nil
}

func (m *SignRequest) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

type SignResponse struct {
	Code                 int32    `protobuf:"varint,1,opt,name=code,proto3" json:"code,omitempty"`
	Signature            []byte   `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignResponse) Reset()         { *m = SignResponse{} }
func (m *SignResponse) String() string { return proto.CompactTextString(m) }
func (*SignResponse) ProtoMessage()    {}
func (*SignResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_ebceca9e8703e37f, []int{1}
}

func (m *SignResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignResponse.Unmarshal(m, b)
}
func (m *SignResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignResponse.Marshal(b, m, deterministic)
}
func (m *SignResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignResponse.Merge(m, src)
}
func (m *SignResponse) XXX_Size() int {
	return xxx_messageInfo_SignResponse.Size(m)
}
func (m *SignResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_SignResponse.DiscardUnknown(m)
}

var xxx_messageInfo_SignResponse proto.InternalMessageInfo

func (m *SignResponse) GetCode() int32 {
	if m != nil {
		return m.Code
	}
	return 0
}

func (m *SignResponse) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

func init() {
	proto.RegisterType((*SignRequest)(nil), "vkms.SignRequest")
	proto.RegisterType((*SignResponse)(nil), "vkms.SignResponse")
}

func init() { proto.RegisterFile("message/message.proto", fileDescriptor_ebceca9e8703e37f) }

var fileDescriptor_ebceca9e8703e37f = []byte{
	// 195 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x12, 0xcd, 0x4d, 0x2d, 0x2e,
	0x4e, 0x4c, 0x4f, 0xd5, 0x87, 0xd2, 0x7a, 0x05, 0x45, 0xf9, 0x25, 0xf9, 0x42, 0x2c, 0x65, 0xd9,
	0xb9, 0xc5, 0x4a, 0x9e, 0x5c, 0xdc, 0xc1, 0x99, 0xe9, 0x79, 0x41, 0xa9, 0x85, 0xa5, 0xa9, 0xc5,
	0x25, 0x42, 0x6a, 0x5c, 0xfc, 0xd9, 0xa9, 0x95, 0xf1, 0xa5, 0x20, 0x75, 0xf1, 0x25, 0xf9, 0xd9,
	0xa9, 0x79, 0x12, 0x8c, 0x0a, 0x8c, 0x1a, 0x3c, 0x41, 0xbc, 0xd9, 0xa9, 0x95, 0xa1, 0x20, 0xd1,
	0x10, 0x90, 0xa0, 0x90, 0x10, 0x17, 0x4b, 0x4a, 0x62, 0x49, 0xa2, 0x04, 0x13, 0x58, 0x12, 0xcc,
	0x56, 0x72, 0xe0, 0xe2, 0x81, 0x18, 0x55, 0x5c, 0x90, 0x9f, 0x57, 0x9c, 0x0a, 0x52, 0x93, 0x9c,
	0x9f, 0x92, 0x0a, 0x36, 0x80, 0x35, 0x08, 0xcc, 0x16, 0x92, 0xe1, 0xe2, 0x2c, 0xce, 0x4c, 0xcf,
	0x4b, 0x2c, 0x29, 0x2d, 0x4a, 0x85, 0x6a, 0x46, 0x08, 0x18, 0x99, 0x73, 0xb1, 0x84, 0x16, 0xa7,
	0x16, 0x09, 0xe9, 0x73, 0xb1, 0x80, 0x4c, 0x12, 0x12, 0xd4, 0x03, 0xb9, 0x51, 0x0f, 0xc9, 0x81,
	0x52, 0x42, 0xc8, 0x42, 0x10, 0x8b, 0x94, 0x18, 0x9c, 0x38, 0xa2, 0xd8, 0xf4, 0xac, 0x41, 0x12,
	0x49, 0x6c, 0x60, 0xcf, 0x19, 0x03, 0x02, 0x00, 0x00, 0xff, 0xff, 0xcc, 0xc1, 0x71, 0xcb, 0xf5,
	0x00, 0x00, 0x00,
}
