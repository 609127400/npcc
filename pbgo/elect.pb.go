// Copyright the Hyperledger Fabric contributors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.23.0
// source: elect.proto

package pbgo

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Vote struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Node      string `protobuf:"bytes,1,opt,name=node,proto3" json:"node,omitempty"`
	Id        string `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Signature string `protobuf:"bytes,3,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *Vote) Reset() {
	*x = Vote{}
	if protoimpl.UnsafeEnabled {
		mi := &file_elect_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Vote) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Vote) ProtoMessage() {}

func (x *Vote) ProtoReflect() protoreflect.Message {
	mi := &file_elect_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Vote.ProtoReflect.Descriptor instead.
func (*Vote) Descriptor() ([]byte, []int) {
	return file_elect_proto_rawDescGZIP(), []int{0}
}

func (x *Vote) GetNode() string {
	if x != nil {
		return x.Node
	}
	return ""
}

func (x *Vote) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Vote) GetSignature() string {
	if x != nil {
		return x.Signature
	}
	return ""
}

type BallotResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *BallotResponse) Reset() {
	*x = BallotResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_elect_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BallotResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BallotResponse) ProtoMessage() {}

func (x *BallotResponse) ProtoReflect() protoreflect.Message {
	mi := &file_elect_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BallotResponse.ProtoReflect.Descriptor instead.
func (*BallotResponse) Descriptor() ([]byte, []int) {
	return file_elect_proto_rawDescGZIP(), []int{1}
}

var File_elect_proto protoreflect.FileDescriptor

var file_elect_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x04, 0x70,
	0x62, 0x67, 0x6f, 0x22, 0x48, 0x0a, 0x04, 0x56, 0x6f, 0x74, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e,
	0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x6f, 0x64, 0x65, 0x12,
	0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12,
	0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x10, 0x0a,
	0x0e, 0x42, 0x61, 0x6c, 0x6c, 0x6f, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32,
	0x3e, 0x0a, 0x0c, 0x45, 0x6c, 0x65, 0x63, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12,
	0x2e, 0x0a, 0x06, 0x42, 0x61, 0x6c, 0x6c, 0x6f, 0x74, 0x12, 0x0a, 0x2e, 0x70, 0x62, 0x67, 0x6f,
	0x2e, 0x56, 0x6f, 0x74, 0x65, 0x1a, 0x14, 0x2e, 0x70, 0x62, 0x67, 0x6f, 0x2e, 0x42, 0x61, 0x6c,
	0x6c, 0x6f, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x28, 0x01, 0x30, 0x01, 0x42,
	0x16, 0x0a, 0x0c, 0x6e, 0x70, 0x63, 0x63, 0x2e, 0x70, 0x62, 0x2e, 0x6a, 0x61, 0x76, 0x61, 0x5a,
	0x06, 0x2e, 0x2f, 0x70, 0x62, 0x67, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_elect_proto_rawDescOnce sync.Once
	file_elect_proto_rawDescData = file_elect_proto_rawDesc
)

func file_elect_proto_rawDescGZIP() []byte {
	file_elect_proto_rawDescOnce.Do(func() {
		file_elect_proto_rawDescData = protoimpl.X.CompressGZIP(file_elect_proto_rawDescData)
	})
	return file_elect_proto_rawDescData
}

var file_elect_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_elect_proto_goTypes = []interface{}{
	(*Vote)(nil),           // 0: pbgo.Vote
	(*BallotResponse)(nil), // 1: pbgo.BallotResponse
}
var file_elect_proto_depIdxs = []int32{
	0, // 0: pbgo.ElectService.Ballot:input_type -> pbgo.Vote
	1, // 1: pbgo.ElectService.Ballot:output_type -> pbgo.BallotResponse
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_elect_proto_init() }
func file_elect_proto_init() {
	if File_elect_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_elect_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Vote); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_elect_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BallotResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_elect_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_elect_proto_goTypes,
		DependencyIndexes: file_elect_proto_depIdxs,
		MessageInfos:      file_elect_proto_msgTypes,
	}.Build()
	File_elect_proto = out.File
	file_elect_proto_rawDesc = nil
	file_elect_proto_goTypes = nil
	file_elect_proto_depIdxs = nil
}
