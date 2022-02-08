// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.19.3
// source: netflix/titus/titus_volumes.proto

package titus

import (
	reflect "reflect"
	sync "sync"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type VolumeMount_MountPropagation int32

const (
	// MountPropagationNone is the default and means that additional mounts
	// inside a volumeMount will *not* be propagated.
	VolumeMount_MountPropagationNone VolumeMount_MountPropagation = 0
	// MountPropagationHostToContainer specifies that mounts get propagated
	// from the source mount to the destination ("rslave" in Linux).
	VolumeMount_MountPropagationHostToContainer VolumeMount_MountPropagation = 1
	// MountPropagationBidirectional specifies that mounts get propagated from
	// the and from the source container to the destination
	// ("rshared" in Linux).
	VolumeMount_MountPropagationBidirectional VolumeMount_MountPropagation = 2
)

// Enum value maps for VolumeMount_MountPropagation.
var (
	VolumeMount_MountPropagation_name = map[int32]string{
		0: "MountPropagationNone",
		1: "MountPropagationHostToContainer",
		2: "MountPropagationBidirectional",
	}
	VolumeMount_MountPropagation_value = map[string]int32{
		"MountPropagationNone":            0,
		"MountPropagationHostToContainer": 1,
		"MountPropagationBidirectional":   2,
	}
)

func (x VolumeMount_MountPropagation) Enum() *VolumeMount_MountPropagation {
	p := new(VolumeMount_MountPropagation)
	*p = x
	return p
}

func (x VolumeMount_MountPropagation) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (VolumeMount_MountPropagation) Descriptor() protoreflect.EnumDescriptor {
	return file_netflix_titus_titus_volumes_proto_enumTypes[0].Descriptor()
}

func (VolumeMount_MountPropagation) Type() protoreflect.EnumType {
	return &file_netflix_titus_titus_volumes_proto_enumTypes[0]
}

func (x VolumeMount_MountPropagation) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use VolumeMount_MountPropagation.Descriptor instead.
func (VolumeMount_MountPropagation) EnumDescriptor() ([]byte, []int) {
	return file_netflix_titus_titus_volumes_proto_rawDescGZIP(), []int{3, 0}
}

type SharedContainerVolumeSource struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The sourceContainer is the name of the container with the
	// path to be shared with other containers. For example:
	//
	//     sourceContainer="main"
	//     sourcePath="/mnt/data"
	//
	// combined with an associated VolumeMount on another container, would
	// be one way to allow the main container to share some of its files
	// (which may be just baked into the image, or provided by another storage
	// system) with some other extraContainer for the task.
	SourceContainer string `protobuf:"bytes,1,opt,name=sourceContainer,proto3" json:"sourceContainer,omitempty"`
	// The path in the container to be shared.
	// This path may contain existing data to share, or it can simply
	// not exist, and it will be created.
	SourcePath string `protobuf:"bytes,2,opt,name=sourcePath,proto3" json:"sourcePath,omitempty"`
}

func (x *SharedContainerVolumeSource) Reset() {
	*x = SharedContainerVolumeSource{}
	if protoimpl.UnsafeEnabled {
		mi := &file_netflix_titus_titus_volumes_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SharedContainerVolumeSource) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SharedContainerVolumeSource) ProtoMessage() {}

func (x *SharedContainerVolumeSource) ProtoReflect() protoreflect.Message {
	mi := &file_netflix_titus_titus_volumes_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SharedContainerVolumeSource.ProtoReflect.Descriptor instead.
func (*SharedContainerVolumeSource) Descriptor() ([]byte, []int) {
	return file_netflix_titus_titus_volumes_proto_rawDescGZIP(), []int{0}
}

func (x *SharedContainerVolumeSource) GetSourceContainer() string {
	if x != nil {
		return x.SourceContainer
	}
	return ""
}

func (x *SharedContainerVolumeSource) GetSourcePath() string {
	if x != nil {
		return x.SourcePath
	}
	return ""
}

// SaaSVolumeSource is a type of volume provided by the SaaS team,
// currently backed by CephFS. It is designed to be very simple for
// users to request, leaving many of the implementation details of
// how it is mounted on the backend.
type SaaSVolumeSource struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// (Required) SaaSVolumeID is the unique identifier to the SaaS
	// volume mount, and uniquely identifies the volume.
	SaaSVolumeID string `protobuf:"bytes,1,opt,name=SaaSVolumeID,proto3" json:"SaaSVolumeID,omitempty"`
}

func (x *SaaSVolumeSource) Reset() {
	*x = SaaSVolumeSource{}
	if protoimpl.UnsafeEnabled {
		mi := &file_netflix_titus_titus_volumes_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SaaSVolumeSource) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SaaSVolumeSource) ProtoMessage() {}

func (x *SaaSVolumeSource) ProtoReflect() protoreflect.Message {
	mi := &file_netflix_titus_titus_volumes_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SaaSVolumeSource.ProtoReflect.Descriptor instead.
func (*SaaSVolumeSource) Descriptor() ([]byte, []int) {
	return file_netflix_titus_titus_volumes_proto_rawDescGZIP(), []int{1}
}

func (x *SaaSVolumeSource) GetSaaSVolumeID() string {
	if x != nil {
		return x.SaaSVolumeID
	}
	return ""
}

// Volumes define some sort of storage for a Task (pod) that is later referenced
// by individual containers via VolumeMount declarations.
// https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#volume-v1-core
// Note that Titus only supports a subset of storage drivers.
type Volume struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// (Required) the name of the volume. This is what is referenced by
	// VolumeMount requests for individual containers.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Types that are assignable to VolumeSource:
	//	*Volume_SharedContainerVolumeSource
	//	*Volume_SaaSVolumeSource
	VolumeSource isVolume_VolumeSource `protobuf_oneof:"VolumeSource"`
}

func (x *Volume) Reset() {
	*x = Volume{}
	if protoimpl.UnsafeEnabled {
		mi := &file_netflix_titus_titus_volumes_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Volume) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Volume) ProtoMessage() {}

func (x *Volume) ProtoReflect() protoreflect.Message {
	mi := &file_netflix_titus_titus_volumes_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Volume.ProtoReflect.Descriptor instead.
func (*Volume) Descriptor() ([]byte, []int) {
	return file_netflix_titus_titus_volumes_proto_rawDescGZIP(), []int{2}
}

func (x *Volume) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (m *Volume) GetVolumeSource() isVolume_VolumeSource {
	if m != nil {
		return m.VolumeSource
	}
	return nil
}

func (x *Volume) GetSharedContainerVolumeSource() *SharedContainerVolumeSource {
	if x, ok := x.GetVolumeSource().(*Volume_SharedContainerVolumeSource); ok {
		return x.SharedContainerVolumeSource
	}
	return nil
}

func (x *Volume) GetSaaSVolumeSource() *SaaSVolumeSource {
	if x, ok := x.GetVolumeSource().(*Volume_SaaSVolumeSource); ok {
		return x.SaaSVolumeSource
	}
	return nil
}

type isVolume_VolumeSource interface {
	isVolume_VolumeSource()
}

type Volume_SharedContainerVolumeSource struct {
	// (Optional) A SharedContainerVolumeSource is a volume that exists on the
	// one container that is exported. Such a volume can be used later via a
	// VolumeMount and shared with other containers in the task (pod)
	SharedContainerVolumeSource *SharedContainerVolumeSource `protobuf:"bytes,2,opt,name=sharedContainerVolumeSource,proto3,oneof"`
}

type Volume_SaaSVolumeSource struct {
	SaaSVolumeSource *SaaSVolumeSource `protobuf:"bytes,3,opt,name=SaaSVolumeSource,proto3,oneof"`
}

func (*Volume_SharedContainerVolumeSource) isVolume_VolumeSource() {}

func (*Volume_SaaSVolumeSource) isVolume_VolumeSource() {}

// VolumeMounts are used to define how to mount a Volume in a container
// Modeled after k8s volumeMounts:
// https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#volumemount-v1-core
type VolumeMount struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// (Required) mountPath is the location inside the container where the volume
	// will be mounted
	MountPath string `protobuf:"bytes,1,opt,name=mountPath,proto3" json:"mountPath,omitempty"`
	// mountPropagation determines how mounts are propagated from the host to
	// container and the other way around. When not set, MountPropagationNone is
	// used.
	MountPropagation VolumeMount_MountPropagation `protobuf:"varint,2,opt,name=mountPropagation,proto3,enum=com.netflix.titus.VolumeMount_MountPropagation" json:"mountPropagation,omitempty"`
	// This must match the Name of a Volume.
	VolumeName string `protobuf:"bytes,3,opt,name=volumeName,proto3" json:"volumeName,omitempty"`
	// Mounted read-only if true, read-write otherwise (false or unspecified).
	// Defaults to false.
	ReadOnly bool `protobuf:"varint,4,opt,name=readOnly,proto3" json:"readOnly,omitempty"`
	// Path within the volume from which the container's volume should be mounted.
	// Defaults to "" (volume's root).
	SubPath string `protobuf:"bytes,5,opt,name=subPath,proto3" json:"subPath,omitempty"`
}

func (x *VolumeMount) Reset() {
	*x = VolumeMount{}
	if protoimpl.UnsafeEnabled {
		mi := &file_netflix_titus_titus_volumes_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VolumeMount) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VolumeMount) ProtoMessage() {}

func (x *VolumeMount) ProtoReflect() protoreflect.Message {
	mi := &file_netflix_titus_titus_volumes_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VolumeMount.ProtoReflect.Descriptor instead.
func (*VolumeMount) Descriptor() ([]byte, []int) {
	return file_netflix_titus_titus_volumes_proto_rawDescGZIP(), []int{3}
}

func (x *VolumeMount) GetMountPath() string {
	if x != nil {
		return x.MountPath
	}
	return ""
}

func (x *VolumeMount) GetMountPropagation() VolumeMount_MountPropagation {
	if x != nil {
		return x.MountPropagation
	}
	return VolumeMount_MountPropagationNone
}

func (x *VolumeMount) GetVolumeName() string {
	if x != nil {
		return x.VolumeName
	}
	return ""
}

func (x *VolumeMount) GetReadOnly() bool {
	if x != nil {
		return x.ReadOnly
	}
	return false
}

func (x *VolumeMount) GetSubPath() string {
	if x != nil {
		return x.SubPath
	}
	return ""
}

var File_netflix_titus_titus_volumes_proto protoreflect.FileDescriptor

var file_netflix_titus_titus_volumes_proto_rawDesc = []byte{
	0x0a, 0x21, 0x6e, 0x65, 0x74, 0x66, 0x6c, 0x69, 0x78, 0x2f, 0x74, 0x69, 0x74, 0x75, 0x73, 0x2f,
	0x74, 0x69, 0x74, 0x75, 0x73, 0x5f, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x73, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x11, 0x63, 0x6f, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x66, 0x6c, 0x69, 0x78,
	0x2e, 0x74, 0x69, 0x74, 0x75, 0x73, 0x22, 0x67, 0x0a, 0x1b, 0x53, 0x68, 0x61, 0x72, 0x65, 0x64,
	0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x56, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x53,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x28, 0x0a, 0x0f, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x43,
	0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x12,
	0x1e, 0x0a, 0x0a, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x50, 0x61, 0x74, 0x68, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0a, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x50, 0x61, 0x74, 0x68, 0x22,
	0x36, 0x0a, 0x10, 0x53, 0x61, 0x61, 0x53, 0x56, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x53, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x12, 0x22, 0x0a, 0x0c, 0x53, 0x61, 0x61, 0x53, 0x56, 0x6f, 0x6c, 0x75, 0x6d,
	0x65, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x53, 0x61, 0x61, 0x53, 0x56,
	0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x49, 0x44, 0x22, 0xf3, 0x01, 0x0a, 0x06, 0x56, 0x6f, 0x6c, 0x75,
	0x6d, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x72, 0x0a, 0x1b, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64,
	0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x56, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x53,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2e, 0x2e, 0x63, 0x6f,
	0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x66, 0x6c, 0x69, 0x78, 0x2e, 0x74, 0x69, 0x74, 0x75, 0x73, 0x2e,
	0x53, 0x68, 0x61, 0x72, 0x65, 0x64, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x56,
	0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x48, 0x00, 0x52, 0x1b, 0x73,
	0x68, 0x61, 0x72, 0x65, 0x64, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x56, 0x6f,
	0x6c, 0x75, 0x6d, 0x65, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x51, 0x0a, 0x10, 0x53, 0x61,
	0x61, 0x53, 0x56, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x66, 0x6c,
	0x69, 0x78, 0x2e, 0x74, 0x69, 0x74, 0x75, 0x73, 0x2e, 0x53, 0x61, 0x61, 0x53, 0x56, 0x6f, 0x6c,
	0x75, 0x6d, 0x65, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x48, 0x00, 0x52, 0x10, 0x53, 0x61, 0x61,
	0x53, 0x56, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x42, 0x0e, 0x0a,
	0x0c, 0x56, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x22, 0xd4, 0x02,
	0x0a, 0x0b, 0x56, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x4d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x1c, 0x0a,
	0x09, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x50, 0x61, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x09, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x50, 0x61, 0x74, 0x68, 0x12, 0x5b, 0x0a, 0x10, 0x6d,
	0x6f, 0x75, 0x6e, 0x74, 0x50, 0x72, 0x6f, 0x70, 0x61, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x2f, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x66,
	0x6c, 0x69, 0x78, 0x2e, 0x74, 0x69, 0x74, 0x75, 0x73, 0x2e, 0x56, 0x6f, 0x6c, 0x75, 0x6d, 0x65,
	0x4d, 0x6f, 0x75, 0x6e, 0x74, 0x2e, 0x4d, 0x6f, 0x75, 0x6e, 0x74, 0x50, 0x72, 0x6f, 0x70, 0x61,
	0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x10, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x50, 0x72, 0x6f,
	0x70, 0x61, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1e, 0x0a, 0x0a, 0x76, 0x6f, 0x6c, 0x75,
	0x6d, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x76, 0x6f,
	0x6c, 0x75, 0x6d, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x72, 0x65, 0x61, 0x64,
	0x4f, 0x6e, 0x6c, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x72, 0x65, 0x61, 0x64,
	0x4f, 0x6e, 0x6c, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x75, 0x62, 0x50, 0x61, 0x74, 0x68, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x75, 0x62, 0x50, 0x61, 0x74, 0x68, 0x22, 0x74,
	0x0a, 0x10, 0x4d, 0x6f, 0x75, 0x6e, 0x74, 0x50, 0x72, 0x6f, 0x70, 0x61, 0x67, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x12, 0x18, 0x0a, 0x14, 0x4d, 0x6f, 0x75, 0x6e, 0x74, 0x50, 0x72, 0x6f, 0x70, 0x61,
	0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4e, 0x6f, 0x6e, 0x65, 0x10, 0x00, 0x12, 0x23, 0x0a, 0x1f,
	0x4d, 0x6f, 0x75, 0x6e, 0x74, 0x50, 0x72, 0x6f, 0x70, 0x61, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x48, 0x6f, 0x73, 0x74, 0x54, 0x6f, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x10,
	0x01, 0x12, 0x21, 0x0a, 0x1d, 0x4d, 0x6f, 0x75, 0x6e, 0x74, 0x50, 0x72, 0x6f, 0x70, 0x61, 0x67,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x69, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x61, 0x6c, 0x10, 0x02, 0x42, 0x42, 0x0a, 0x1f, 0x63, 0x6f, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x66,
	0x6c, 0x69, 0x78, 0x2e, 0x74, 0x69, 0x74, 0x75, 0x73, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x67, 0x65, 0x6e, 0x42, 0x0c, 0x54, 0x69, 0x74, 0x75, 0x73, 0x56, 0x6f,
	0x6c, 0x75, 0x6d, 0x65, 0x73, 0x50, 0x01, 0x5a, 0x0f, 0x2e, 0x2f, 0x6e, 0x65, 0x74, 0x66, 0x6c,
	0x69, 0x78, 0x2f, 0x74, 0x69, 0x74, 0x75, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_netflix_titus_titus_volumes_proto_rawDescOnce sync.Once
	file_netflix_titus_titus_volumes_proto_rawDescData = file_netflix_titus_titus_volumes_proto_rawDesc
)

func file_netflix_titus_titus_volumes_proto_rawDescGZIP() []byte {
	file_netflix_titus_titus_volumes_proto_rawDescOnce.Do(func() {
		file_netflix_titus_titus_volumes_proto_rawDescData = protoimpl.X.CompressGZIP(file_netflix_titus_titus_volumes_proto_rawDescData)
	})
	return file_netflix_titus_titus_volumes_proto_rawDescData
}

var file_netflix_titus_titus_volumes_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_netflix_titus_titus_volumes_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_netflix_titus_titus_volumes_proto_goTypes = []interface{}{
	(VolumeMount_MountPropagation)(0),   // 0: com.netflix.titus.VolumeMount.MountPropagation
	(*SharedContainerVolumeSource)(nil), // 1: com.netflix.titus.SharedContainerVolumeSource
	(*SaaSVolumeSource)(nil),            // 2: com.netflix.titus.SaaSVolumeSource
	(*Volume)(nil),                      // 3: com.netflix.titus.Volume
	(*VolumeMount)(nil),                 // 4: com.netflix.titus.VolumeMount
}
var file_netflix_titus_titus_volumes_proto_depIdxs = []int32{
	1, // 0: com.netflix.titus.Volume.sharedContainerVolumeSource:type_name -> com.netflix.titus.SharedContainerVolumeSource
	2, // 1: com.netflix.titus.Volume.SaaSVolumeSource:type_name -> com.netflix.titus.SaaSVolumeSource
	0, // 2: com.netflix.titus.VolumeMount.mountPropagation:type_name -> com.netflix.titus.VolumeMount.MountPropagation
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_netflix_titus_titus_volumes_proto_init() }
func file_netflix_titus_titus_volumes_proto_init() {
	if File_netflix_titus_titus_volumes_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_netflix_titus_titus_volumes_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SharedContainerVolumeSource); i {
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
		file_netflix_titus_titus_volumes_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SaaSVolumeSource); i {
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
		file_netflix_titus_titus_volumes_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Volume); i {
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
		file_netflix_titus_titus_volumes_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VolumeMount); i {
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
	file_netflix_titus_titus_volumes_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*Volume_SharedContainerVolumeSource)(nil),
		(*Volume_SaaSVolumeSource)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_netflix_titus_titus_volumes_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_netflix_titus_titus_volumes_proto_goTypes,
		DependencyIndexes: file_netflix_titus_titus_volumes_proto_depIdxs,
		EnumInfos:         file_netflix_titus_titus_volumes_proto_enumTypes,
		MessageInfos:      file_netflix_titus_titus_volumes_proto_msgTypes,
	}.Build()
	File_netflix_titus_titus_volumes_proto = out.File
	file_netflix_titus_titus_volumes_proto_rawDesc = nil
	file_netflix_titus_titus_volumes_proto_goTypes = nil
	file_netflix_titus_titus_volumes_proto_depIdxs = nil
}
