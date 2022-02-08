// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.19.3
// source: metadataserver/proto/iam.proto

package api

import (
	reflect "reflect"
	sync "sync"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type AssumeRoleRequest_CredentialUseCase int32

const (
	AssumeRoleRequest_ForTask    AssumeRoleRequest_CredentialUseCase = 0
	AssumeRoleRequest_ForLogging AssumeRoleRequest_CredentialUseCase = 1
)

// Enum value maps for AssumeRoleRequest_CredentialUseCase.
var (
	AssumeRoleRequest_CredentialUseCase_name = map[int32]string{
		0: "ForTask",
		1: "ForLogging",
	}
	AssumeRoleRequest_CredentialUseCase_value = map[string]int32{
		"ForTask":    0,
		"ForLogging": 1,
	}
)

func (x AssumeRoleRequest_CredentialUseCase) Enum() *AssumeRoleRequest_CredentialUseCase {
	p := new(AssumeRoleRequest_CredentialUseCase)
	*p = x
	return p
}

func (x AssumeRoleRequest_CredentialUseCase) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AssumeRoleRequest_CredentialUseCase) Descriptor() protoreflect.EnumDescriptor {
	return file_metadataserver_proto_iam_proto_enumTypes[0].Descriptor()
}

func (AssumeRoleRequest_CredentialUseCase) Type() protoreflect.EnumType {
	return &file_metadataserver_proto_iam_proto_enumTypes[0]
}

func (x AssumeRoleRequest_CredentialUseCase) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AssumeRoleRequest_CredentialUseCase.Descriptor instead.
func (AssumeRoleRequest_CredentialUseCase) EnumDescriptor() ([]byte, []int) {
	return file_metadataserver_proto_iam_proto_rawDescGZIP(), []int{0, 0}
}

type AssumeRoleRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RoleARN           string                              `protobuf:"bytes,1,opt,name=roleARN,proto3" json:"roleARN,omitempty"`
	TaskId            string                              `protobuf:"bytes,2,opt,name=taskId,proto3" json:"taskId,omitempty"`
	CredentialUseCase AssumeRoleRequest_CredentialUseCase `protobuf:"varint,3,opt,name=credentialUseCase,proto3,enum=com.netflix.titus.executor.metadataserver.AssumeRoleRequest_CredentialUseCase" json:"credentialUseCase,omitempty"`
}

func (x *AssumeRoleRequest) Reset() {
	*x = AssumeRoleRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_metadataserver_proto_iam_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AssumeRoleRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AssumeRoleRequest) ProtoMessage() {}

func (x *AssumeRoleRequest) ProtoReflect() protoreflect.Message {
	mi := &file_metadataserver_proto_iam_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AssumeRoleRequest.ProtoReflect.Descriptor instead.
func (*AssumeRoleRequest) Descriptor() ([]byte, []int) {
	return file_metadataserver_proto_iam_proto_rawDescGZIP(), []int{0}
}

func (x *AssumeRoleRequest) GetRoleARN() string {
	if x != nil {
		return x.RoleARN
	}
	return ""
}

func (x *AssumeRoleRequest) GetTaskId() string {
	if x != nil {
		return x.TaskId
	}
	return ""
}

func (x *AssumeRoleRequest) GetCredentialUseCase() AssumeRoleRequest_CredentialUseCase {
	if x != nil {
		return x.CredentialUseCase
	}
	return AssumeRoleRequest_ForTask
}

type AssumeRoleResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AssumedRoleUser *AssumeRoleResponse_AssumedRoleUser `protobuf:"bytes,1,opt,name=assumedRoleUser,proto3" json:"assumedRoleUser,omitempty"`
	Credentials     *AssumeRoleResponse_Credentials     `protobuf:"bytes,2,opt,name=credentials,proto3" json:"credentials,omitempty"`
}

func (x *AssumeRoleResponse) Reset() {
	*x = AssumeRoleResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_metadataserver_proto_iam_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AssumeRoleResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AssumeRoleResponse) ProtoMessage() {}

func (x *AssumeRoleResponse) ProtoReflect() protoreflect.Message {
	mi := &file_metadataserver_proto_iam_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AssumeRoleResponse.ProtoReflect.Descriptor instead.
func (*AssumeRoleResponse) Descriptor() ([]byte, []int) {
	return file_metadataserver_proto_iam_proto_rawDescGZIP(), []int{1}
}

func (x *AssumeRoleResponse) GetAssumedRoleUser() *AssumeRoleResponse_AssumedRoleUser {
	if x != nil {
		return x.AssumedRoleUser
	}
	return nil
}

func (x *AssumeRoleResponse) GetCredentials() *AssumeRoleResponse_Credentials {
	if x != nil {
		return x.Credentials
	}
	return nil
}

type AssumeRoleResponse_AssumedRoleUser struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AssumedRoleId string `protobuf:"bytes,1,opt,name=assumedRoleId,proto3" json:"assumedRoleId,omitempty"`
	Arn           string `protobuf:"bytes,2,opt,name=arn,proto3" json:"arn,omitempty"`
}

func (x *AssumeRoleResponse_AssumedRoleUser) Reset() {
	*x = AssumeRoleResponse_AssumedRoleUser{}
	if protoimpl.UnsafeEnabled {
		mi := &file_metadataserver_proto_iam_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AssumeRoleResponse_AssumedRoleUser) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AssumeRoleResponse_AssumedRoleUser) ProtoMessage() {}

func (x *AssumeRoleResponse_AssumedRoleUser) ProtoReflect() protoreflect.Message {
	mi := &file_metadataserver_proto_iam_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AssumeRoleResponse_AssumedRoleUser.ProtoReflect.Descriptor instead.
func (*AssumeRoleResponse_AssumedRoleUser) Descriptor() ([]byte, []int) {
	return file_metadataserver_proto_iam_proto_rawDescGZIP(), []int{1, 0}
}

func (x *AssumeRoleResponse_AssumedRoleUser) GetAssumedRoleId() string {
	if x != nil {
		return x.AssumedRoleId
	}
	return ""
}

func (x *AssumeRoleResponse_AssumedRoleUser) GetArn() string {
	if x != nil {
		return x.Arn
	}
	return ""
}

type AssumeRoleResponse_Credentials struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SecretAccessKey string                 `protobuf:"bytes,1,opt,name=secretAccessKey,proto3" json:"secretAccessKey,omitempty"`
	SessionToken    string                 `protobuf:"bytes,2,opt,name=sessionToken,proto3" json:"sessionToken,omitempty"`
	Expiration      *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=expiration,proto3" json:"expiration,omitempty"`
	AccessKeyId     string                 `protobuf:"bytes,4,opt,name=accessKeyId,proto3" json:"accessKeyId,omitempty"`
}

func (x *AssumeRoleResponse_Credentials) Reset() {
	*x = AssumeRoleResponse_Credentials{}
	if protoimpl.UnsafeEnabled {
		mi := &file_metadataserver_proto_iam_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AssumeRoleResponse_Credentials) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AssumeRoleResponse_Credentials) ProtoMessage() {}

func (x *AssumeRoleResponse_Credentials) ProtoReflect() protoreflect.Message {
	mi := &file_metadataserver_proto_iam_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AssumeRoleResponse_Credentials.ProtoReflect.Descriptor instead.
func (*AssumeRoleResponse_Credentials) Descriptor() ([]byte, []int) {
	return file_metadataserver_proto_iam_proto_rawDescGZIP(), []int{1, 1}
}

func (x *AssumeRoleResponse_Credentials) GetSecretAccessKey() string {
	if x != nil {
		return x.SecretAccessKey
	}
	return ""
}

func (x *AssumeRoleResponse_Credentials) GetSessionToken() string {
	if x != nil {
		return x.SessionToken
	}
	return ""
}

func (x *AssumeRoleResponse_Credentials) GetExpiration() *timestamppb.Timestamp {
	if x != nil {
		return x.Expiration
	}
	return nil
}

func (x *AssumeRoleResponse_Credentials) GetAccessKeyId() string {
	if x != nil {
		return x.AccessKeyId
	}
	return ""
}

var File_metadataserver_proto_iam_proto protoreflect.FileDescriptor

var file_metadataserver_proto_iam_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x69, 0x61, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x29, 0x63, 0x6f, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x66, 0x6c, 0x69, 0x78, 0x2e, 0x74, 0x69,
	0x74, 0x75, 0x73, 0x2e, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74, 0x6f, 0x72, 0x2e, 0x6d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x1a, 0x1f, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xf5, 0x01, 0x0a,
	0x11, 0x41, 0x73, 0x73, 0x75, 0x6d, 0x65, 0x52, 0x6f, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x6f, 0x6c, 0x65, 0x41, 0x52, 0x4e, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x72, 0x6f, 0x6c, 0x65, 0x41, 0x52, 0x4e, 0x12, 0x16, 0x0a, 0x06,
	0x74, 0x61, 0x73, 0x6b, 0x49, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x61,
	0x73, 0x6b, 0x49, 0x64, 0x12, 0x7c, 0x0a, 0x11, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x61, 0x6c, 0x55, 0x73, 0x65, 0x43, 0x61, 0x73, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x4e, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x66, 0x6c, 0x69, 0x78, 0x2e, 0x74, 0x69,
	0x74, 0x75, 0x73, 0x2e, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74, 0x6f, 0x72, 0x2e, 0x6d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x41, 0x73, 0x73, 0x75,
	0x6d, 0x65, 0x52, 0x6f, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x43, 0x72,
	0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x55, 0x73, 0x65, 0x43, 0x61, 0x73, 0x65, 0x52,
	0x11, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x55, 0x73, 0x65, 0x43, 0x61,
	0x73, 0x65, 0x22, 0x30, 0x0a, 0x11, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c,
	0x55, 0x73, 0x65, 0x43, 0x61, 0x73, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x46, 0x6f, 0x72, 0x54, 0x61,
	0x73, 0x6b, 0x10, 0x00, 0x12, 0x0e, 0x0a, 0x0a, 0x46, 0x6f, 0x72, 0x4c, 0x6f, 0x67, 0x67, 0x69,
	0x6e, 0x67, 0x10, 0x01, 0x22, 0x81, 0x04, 0x0a, 0x12, 0x41, 0x73, 0x73, 0x75, 0x6d, 0x65, 0x52,
	0x6f, 0x6c, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x77, 0x0a, 0x0f, 0x61,
	0x73, 0x73, 0x75, 0x6d, 0x65, 0x64, 0x52, 0x6f, 0x6c, 0x65, 0x55, 0x73, 0x65, 0x72, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x4d, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x66, 0x6c,
	0x69, 0x78, 0x2e, 0x74, 0x69, 0x74, 0x75, 0x73, 0x2e, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74, 0x6f,
	0x72, 0x2e, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
	0x2e, 0x41, 0x73, 0x73, 0x75, 0x6d, 0x65, 0x52, 0x6f, 0x6c, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x2e, 0x41, 0x73, 0x73, 0x75, 0x6d, 0x65, 0x64, 0x52, 0x6f, 0x6c, 0x65, 0x55,
	0x73, 0x65, 0x72, 0x52, 0x0f, 0x61, 0x73, 0x73, 0x75, 0x6d, 0x65, 0x64, 0x52, 0x6f, 0x6c, 0x65,
	0x55, 0x73, 0x65, 0x72, 0x12, 0x6b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x61, 0x6c, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x49, 0x2e, 0x63, 0x6f, 0x6d, 0x2e,
	0x6e, 0x65, 0x74, 0x66, 0x6c, 0x69, 0x78, 0x2e, 0x74, 0x69, 0x74, 0x75, 0x73, 0x2e, 0x65, 0x78,
	0x65, 0x63, 0x75, 0x74, 0x6f, 0x72, 0x2e, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x73,
	0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x41, 0x73, 0x73, 0x75, 0x6d, 0x65, 0x52, 0x6f, 0x6c, 0x65,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x61, 0x6c, 0x73, 0x52, 0x0b, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c,
	0x73, 0x1a, 0x49, 0x0a, 0x0f, 0x41, 0x73, 0x73, 0x75, 0x6d, 0x65, 0x64, 0x52, 0x6f, 0x6c, 0x65,
	0x55, 0x73, 0x65, 0x72, 0x12, 0x24, 0x0a, 0x0d, 0x61, 0x73, 0x73, 0x75, 0x6d, 0x65, 0x64, 0x52,
	0x6f, 0x6c, 0x65, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x61, 0x73, 0x73,
	0x75, 0x6d, 0x65, 0x64, 0x52, 0x6f, 0x6c, 0x65, 0x49, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x61, 0x72,
	0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x61, 0x72, 0x6e, 0x1a, 0xb9, 0x01, 0x0a,
	0x0b, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x12, 0x28, 0x0a, 0x0f,
	0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4b, 0x65, 0x79, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x41, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x4b, 0x65, 0x79, 0x12, 0x22, 0x0a, 0x0c, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x73, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x3a, 0x0a, 0x0a, 0x65, 0x78,
	0x70, 0x69, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x65, 0x78, 0x70, 0x69,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x20, 0x0a, 0x0b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x4b, 0x65, 0x79, 0x49, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x61, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x4b, 0x65, 0x79, 0x49, 0x64, 0x32, 0x91, 0x01, 0x0a, 0x03, 0x49, 0x41, 0x4d,
	0x12, 0x89, 0x01, 0x0a, 0x0a, 0x41, 0x73, 0x73, 0x75, 0x6d, 0x65, 0x52, 0x6f, 0x6c, 0x65, 0x12,
	0x3c, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x66, 0x6c, 0x69, 0x78, 0x2e, 0x74, 0x69,
	0x74, 0x75, 0x73, 0x2e, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74, 0x6f, 0x72, 0x2e, 0x6d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x41, 0x73, 0x73, 0x75,
	0x6d, 0x65, 0x52, 0x6f, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x3d, 0x2e,
	0x63, 0x6f, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x66, 0x6c, 0x69, 0x78, 0x2e, 0x74, 0x69, 0x74, 0x75,
	0x73, 0x2e, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74, 0x6f, 0x72, 0x2e, 0x6d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x41, 0x73, 0x73, 0x75, 0x6d, 0x65,
	0x52, 0x6f, 0x6c, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x36, 0x5a, 0x34,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x4e, 0x65, 0x74, 0x66, 0x6c,
	0x69, 0x78, 0x2f, 0x74, 0x69, 0x74, 0x75, 0x73, 0x2d, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74, 0x6f,
	0x72, 0x2f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
	0x2f, 0x61, 0x70, 0x69, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_metadataserver_proto_iam_proto_rawDescOnce sync.Once
	file_metadataserver_proto_iam_proto_rawDescData = file_metadataserver_proto_iam_proto_rawDesc
)

func file_metadataserver_proto_iam_proto_rawDescGZIP() []byte {
	file_metadataserver_proto_iam_proto_rawDescOnce.Do(func() {
		file_metadataserver_proto_iam_proto_rawDescData = protoimpl.X.CompressGZIP(file_metadataserver_proto_iam_proto_rawDescData)
	})
	return file_metadataserver_proto_iam_proto_rawDescData
}

var file_metadataserver_proto_iam_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_metadataserver_proto_iam_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_metadataserver_proto_iam_proto_goTypes = []interface{}{
	(AssumeRoleRequest_CredentialUseCase)(0),   // 0: com.netflix.titus.executor.metadataserver.AssumeRoleRequest.CredentialUseCase
	(*AssumeRoleRequest)(nil),                  // 1: com.netflix.titus.executor.metadataserver.AssumeRoleRequest
	(*AssumeRoleResponse)(nil),                 // 2: com.netflix.titus.executor.metadataserver.AssumeRoleResponse
	(*AssumeRoleResponse_AssumedRoleUser)(nil), // 3: com.netflix.titus.executor.metadataserver.AssumeRoleResponse.AssumedRoleUser
	(*AssumeRoleResponse_Credentials)(nil),     // 4: com.netflix.titus.executor.metadataserver.AssumeRoleResponse.Credentials
	(*timestamppb.Timestamp)(nil),              // 5: google.protobuf.Timestamp
}
var file_metadataserver_proto_iam_proto_depIdxs = []int32{
	0, // 0: com.netflix.titus.executor.metadataserver.AssumeRoleRequest.credentialUseCase:type_name -> com.netflix.titus.executor.metadataserver.AssumeRoleRequest.CredentialUseCase
	3, // 1: com.netflix.titus.executor.metadataserver.AssumeRoleResponse.assumedRoleUser:type_name -> com.netflix.titus.executor.metadataserver.AssumeRoleResponse.AssumedRoleUser
	4, // 2: com.netflix.titus.executor.metadataserver.AssumeRoleResponse.credentials:type_name -> com.netflix.titus.executor.metadataserver.AssumeRoleResponse.Credentials
	5, // 3: com.netflix.titus.executor.metadataserver.AssumeRoleResponse.Credentials.expiration:type_name -> google.protobuf.Timestamp
	1, // 4: com.netflix.titus.executor.metadataserver.IAM.AssumeRole:input_type -> com.netflix.titus.executor.metadataserver.AssumeRoleRequest
	2, // 5: com.netflix.titus.executor.metadataserver.IAM.AssumeRole:output_type -> com.netflix.titus.executor.metadataserver.AssumeRoleResponse
	5, // [5:6] is the sub-list for method output_type
	4, // [4:5] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_metadataserver_proto_iam_proto_init() }
func file_metadataserver_proto_iam_proto_init() {
	if File_metadataserver_proto_iam_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_metadataserver_proto_iam_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AssumeRoleRequest); i {
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
		file_metadataserver_proto_iam_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AssumeRoleResponse); i {
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
		file_metadataserver_proto_iam_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AssumeRoleResponse_AssumedRoleUser); i {
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
		file_metadataserver_proto_iam_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AssumeRoleResponse_Credentials); i {
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
			RawDescriptor: file_metadataserver_proto_iam_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_metadataserver_proto_iam_proto_goTypes,
		DependencyIndexes: file_metadataserver_proto_iam_proto_depIdxs,
		EnumInfos:         file_metadataserver_proto_iam_proto_enumTypes,
		MessageInfos:      file_metadataserver_proto_iam_proto_msgTypes,
	}.Build()
	File_metadataserver_proto_iam_proto = out.File
	file_metadataserver_proto_iam_proto_rawDesc = nil
	file_metadataserver_proto_iam_proto_goTypes = nil
	file_metadataserver_proto_iam_proto_depIdxs = nil
}
