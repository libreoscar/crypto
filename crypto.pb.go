// Code generated by protoc-gen-go.
// source: github.com/libreoscar/crypto/crypto.proto
// DO NOT EDIT!

/*
Package crypto is a generated protocol buffer package.

It is generated from these files:
	github.com/libreoscar/crypto/crypto.proto

It has these top-level messages:
	PublicKey256
	PrivateKey
	Signature
	Digest256
	Digests256
*/
package crypto

import proto "github.com/golang/protobuf/proto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal

type Type int32

const (
	Type_UNKNOWN Type = 0
	Type_P256    Type = 1
)

var Type_name = map[int32]string{
	0: "UNKNOWN",
	1: "P256",
}
var Type_value = map[string]int32{
	"UNKNOWN": 0,
	"P256":    1,
}

func (x Type) String() string {
	return proto.EnumName(Type_name, int32(x))
}

// DO NOT modify its field directly, object of this class is immutable
type PublicKey256 struct {
	Data []byte `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"`
}

func (m *PublicKey256) Reset()         { *m = PublicKey256{} }
func (m *PublicKey256) String() string { return proto.CompactTextString(m) }
func (*PublicKey256) ProtoMessage()    {}

// DO NOT modify its field directly, object of this class is immutable
type PrivateKey struct {
	Type Type   `protobuf:"varint,1,opt,name=type,enum=crypto.Type" json:"type,omitempty"`
	Data []byte `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
}

func (m *PrivateKey) Reset()         { *m = PrivateKey{} }
func (m *PrivateKey) String() string { return proto.CompactTextString(m) }
func (*PrivateKey) ProtoMessage()    {}

// DO NOT modify its field directly, object of this class is immutable
type Signature struct {
	Type Type   `protobuf:"varint,1,opt,name=type,enum=crypto.Type" json:"type,omitempty"`
	Data []byte `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
}

func (m *Signature) Reset()         { *m = Signature{} }
func (m *Signature) String() string { return proto.CompactTextString(m) }
func (*Signature) ProtoMessage()    {}

// DO NOT modify its field directly, object of this class is immutable
type Digest256 struct {
	Data []byte `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"`
}

func (m *Digest256) Reset()         { *m = Digest256{} }
func (m *Digest256) String() string { return proto.CompactTextString(m) }
func (*Digest256) ProtoMessage()    {}

type Digests256 struct {
	Digests []*Digest256 `protobuf:"bytes,1,rep,name=digests" json:"digests,omitempty"`
}

func (m *Digests256) Reset()         { *m = Digests256{} }
func (m *Digests256) String() string { return proto.CompactTextString(m) }
func (*Digests256) ProtoMessage()    {}

func (m *Digests256) GetDigests() []*Digest256 {
	if m != nil {
		return m.Digests
	}
	return nil
}

func init() {
	proto.RegisterEnum("crypto.Type", Type_name, Type_value)
}
