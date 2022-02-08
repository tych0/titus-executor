// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.19.3
// source: netflix/titus/titus_containers.proto

package titus

import (
	reflect "reflect"
	sync "sync"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// BasicContainer stores the minimal data required to declare extra containers
// to a job. This is in contrast to the Container message, which has other data
// that are not strictly tied to the main container. For example,
// *resources* (ram/cpu/etc) for the whole *task* are declared in the main
// Container message, not in a basic container.
type BasicContainer struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// (Required) the Name of this container
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// (Required) Image reference.
	Image *BasicImage `protobuf:"bytes,2,opt,name=image,proto3" json:"image,omitempty"`
	// (Optional) Override the entrypoint of the image.
	// If set, the command baked into the image (if any) is always ignored.
	// Interactions between the entrypoint and command are the same as specified
	// by Docker:
	// https://docs.docker.com/engine/reference/builder/#understand-how-cmd-and-entrypoint-interact
	// Note that, unlike the main container, no string splitting occurs.
	EntryPoint []string `protobuf:"bytes,3,rep,name=entryPoint,proto3" json:"entryPoint,omitempty"`
	// (Optional) Additional parameters for the entrypoint defined either here
	// or provided in the container image.
	// Note that, unlike the main container, no string splitting occurs.
	Command []string `protobuf:"bytes,4,rep,name=command,proto3" json:"command,omitempty"`
	// (Optional) A collection of system environment variables passed to the
	// container.
	Env map[string]string `protobuf:"bytes,5,rep,name=env,proto3" json:"env,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// (Optional) An array of VolumeMounts. These VolumeMounts will be mounted in
	// the container, and must reference one of the volumes declared for the Job.
	// See the k8s docs
	// https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#volumemount-v1-core
	// for more technical details.
	VolumeMounts []*VolumeMount `protobuf:"bytes,6,rep,name=volumeMounts,proto3" json:"volumeMounts,omitempty"`
}

func (x *BasicContainer) Reset() {
	*x = BasicContainer{}
	if protoimpl.UnsafeEnabled {
		mi := &file_netflix_titus_titus_containers_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BasicContainer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BasicContainer) ProtoMessage() {}

func (x *BasicContainer) ProtoReflect() protoreflect.Message {
	mi := &file_netflix_titus_titus_containers_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BasicContainer.ProtoReflect.Descriptor instead.
func (*BasicContainer) Descriptor() ([]byte, []int) {
	return file_netflix_titus_titus_containers_proto_rawDescGZIP(), []int{0}
}

func (x *BasicContainer) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *BasicContainer) GetImage() *BasicImage {
	if x != nil {
		return x.Image
	}
	return nil
}

func (x *BasicContainer) GetEntryPoint() []string {
	if x != nil {
		return x.EntryPoint
	}
	return nil
}

func (x *BasicContainer) GetCommand() []string {
	if x != nil {
		return x.Command
	}
	return nil
}

func (x *BasicContainer) GetEnv() map[string]string {
	if x != nil {
		return x.Env
	}
	return nil
}

func (x *BasicContainer) GetVolumeMounts() []*VolumeMount {
	if x != nil {
		return x.VolumeMounts
	}
	return nil
}

// To reference an image, a user has to provide an image name and a version. A
// user may specify a version either with
// a tag value (for example 'latest') or a digest. When submitting a job, a user
// should provide either a tag or a digest value only (not both of them).
//
// For example, docker images can be referenced by {name=titus-examples,
// tag=latest}. A user could also choose to provide only the digest without a
// tag. In this case, the tag value would be empty.
type BasicImage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// (Required) Image name.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// (Required if digest not set) Image tag.
	Tag string `protobuf:"bytes,2,opt,name=tag,proto3" json:"tag,omitempty"`
	// (Required if tag not set) Image digest.
	Digest string `protobuf:"bytes,3,opt,name=digest,proto3" json:"digest,omitempty"`
}

func (x *BasicImage) Reset() {
	*x = BasicImage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_netflix_titus_titus_containers_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BasicImage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BasicImage) ProtoMessage() {}

func (x *BasicImage) ProtoReflect() protoreflect.Message {
	mi := &file_netflix_titus_titus_containers_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BasicImage.ProtoReflect.Descriptor instead.
func (*BasicImage) Descriptor() ([]byte, []int) {
	return file_netflix_titus_titus_containers_proto_rawDescGZIP(), []int{1}
}

func (x *BasicImage) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *BasicImage) GetTag() string {
	if x != nil {
		return x.Tag
	}
	return ""
}

func (x *BasicImage) GetDigest() string {
	if x != nil {
		return x.Digest
	}
	return ""
}

// Definition of a request to add a platform sidecar alongside a task
// Note that this is *not* a user-defined sidecar, that is why it just has a
// name. These platform-sidecars are attached to a task start time, and the
// definition of what the sidecar is is not baked into the job itself, just the
// intent.
type PlatformSidecar struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// (Required) Name of the platform sidecar requested
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// (Optional) Channel representing a pointer to releases of the sidecar
	Channel string `protobuf:"bytes,2,opt,name=channel,proto3" json:"channel,omitempty"`
	// (Optional) Arguments, KV pairs for configuring the sidecar
	Arguments *structpb.Struct `protobuf:"bytes,3,opt,name=arguments,proto3" json:"arguments,omitempty"`
}

func (x *PlatformSidecar) Reset() {
	*x = PlatformSidecar{}
	if protoimpl.UnsafeEnabled {
		mi := &file_netflix_titus_titus_containers_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PlatformSidecar) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PlatformSidecar) ProtoMessage() {}

func (x *PlatformSidecar) ProtoReflect() protoreflect.Message {
	mi := &file_netflix_titus_titus_containers_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PlatformSidecar.ProtoReflect.Descriptor instead.
func (*PlatformSidecar) Descriptor() ([]byte, []int) {
	return file_netflix_titus_titus_containers_proto_rawDescGZIP(), []int{2}
}

func (x *PlatformSidecar) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *PlatformSidecar) GetChannel() string {
	if x != nil {
		return x.Channel
	}
	return ""
}

func (x *PlatformSidecar) GetArguments() *structpb.Struct {
	if x != nil {
		return x.Arguments
	}
	return nil
}

var File_netflix_titus_titus_containers_proto protoreflect.FileDescriptor

var file_netflix_titus_titus_containers_proto_rawDesc = []byte{
	0x0a, 0x24, 0x6e, 0x65, 0x74, 0x66, 0x6c, 0x69, 0x78, 0x2f, 0x74, 0x69, 0x74, 0x75, 0x73, 0x2f,
	0x74, 0x69, 0x74, 0x75, 0x73, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x11, 0x63, 0x6f, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x66,
	0x6c, 0x69, 0x78, 0x2e, 0x74, 0x69, 0x74, 0x75, 0x73, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63,
	0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x6e, 0x65, 0x74, 0x66, 0x6c, 0x69, 0x78,
	0x2f, 0x74, 0x69, 0x74, 0x75, 0x73, 0x2f, 0x74, 0x69, 0x74, 0x75, 0x73, 0x5f, 0x76, 0x6f, 0x6c,
	0x75, 0x6d, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xcd, 0x02, 0x0a, 0x0e, 0x42,
	0x61, 0x73, 0x69, 0x63, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x12, 0x12, 0x0a,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x33, 0x0a, 0x05, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1d, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x66, 0x6c, 0x69, 0x78, 0x2e, 0x74,
	0x69, 0x74, 0x75, 0x73, 0x2e, 0x42, 0x61, 0x73, 0x69, 0x63, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x52,
	0x05, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x50,
	0x6f, 0x69, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0a, 0x65, 0x6e, 0x74, 0x72,
	0x79, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e,
	0x64, 0x18, 0x04, 0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64,
	0x12, 0x3c, 0x0a, 0x03, 0x65, 0x6e, 0x76, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2a, 0x2e,
	0x63, 0x6f, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x66, 0x6c, 0x69, 0x78, 0x2e, 0x74, 0x69, 0x74, 0x75,
	0x73, 0x2e, 0x42, 0x61, 0x73, 0x69, 0x63, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
	0x2e, 0x45, 0x6e, 0x76, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x03, 0x65, 0x6e, 0x76, 0x12, 0x42,
	0x0a, 0x0c, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x4d, 0x6f, 0x75, 0x6e, 0x74, 0x73, 0x18, 0x06,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x66, 0x6c,
	0x69, 0x78, 0x2e, 0x74, 0x69, 0x74, 0x75, 0x73, 0x2e, 0x56, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x4d,
	0x6f, 0x75, 0x6e, 0x74, 0x52, 0x0c, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x4d, 0x6f, 0x75, 0x6e,
	0x74, 0x73, 0x1a, 0x36, 0x0a, 0x08, 0x45, 0x6e, 0x76, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10,
	0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79,
	0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x4a, 0x0a, 0x0a, 0x42, 0x61,
	0x73, 0x69, 0x63, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x10, 0x0a, 0x03,
	0x74, 0x61, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x74, 0x61, 0x67, 0x12, 0x16,
	0x0a, 0x06, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06,
	0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x22, 0x76, 0x0a, 0x0f, 0x50, 0x6c, 0x61, 0x74, 0x66, 0x6f,
	0x72, 0x6d, 0x53, 0x69, 0x64, 0x65, 0x63, 0x61, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x18, 0x0a,
	0x07, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07,
	0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x12, 0x35, 0x0a, 0x09, 0x61, 0x72, 0x67, 0x75, 0x6d,
	0x65, 0x6e, 0x74, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72,
	0x75, 0x63, 0x74, 0x52, 0x09, 0x61, 0x72, 0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x42, 0x45,
	0x0a, 0x1f, 0x63, 0x6f, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x66, 0x6c, 0x69, 0x78, 0x2e, 0x74, 0x69,
	0x74, 0x75, 0x73, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x67, 0x65,
	0x6e, 0x42, 0x0f, 0x54, 0x69, 0x74, 0x75, 0x73, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65,
	0x72, 0x73, 0x50, 0x01, 0x5a, 0x0f, 0x2e, 0x2f, 0x6e, 0x65, 0x74, 0x66, 0x6c, 0x69, 0x78, 0x2f,
	0x74, 0x69, 0x74, 0x75, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_netflix_titus_titus_containers_proto_rawDescOnce sync.Once
	file_netflix_titus_titus_containers_proto_rawDescData = file_netflix_titus_titus_containers_proto_rawDesc
)

func file_netflix_titus_titus_containers_proto_rawDescGZIP() []byte {
	file_netflix_titus_titus_containers_proto_rawDescOnce.Do(func() {
		file_netflix_titus_titus_containers_proto_rawDescData = protoimpl.X.CompressGZIP(file_netflix_titus_titus_containers_proto_rawDescData)
	})
	return file_netflix_titus_titus_containers_proto_rawDescData
}

var file_netflix_titus_titus_containers_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_netflix_titus_titus_containers_proto_goTypes = []interface{}{
	(*BasicContainer)(nil),  // 0: com.netflix.titus.BasicContainer
	(*BasicImage)(nil),      // 1: com.netflix.titus.BasicImage
	(*PlatformSidecar)(nil), // 2: com.netflix.titus.PlatformSidecar
	nil,                     // 3: com.netflix.titus.BasicContainer.EnvEntry
	(*VolumeMount)(nil),     // 4: com.netflix.titus.VolumeMount
	(*structpb.Struct)(nil), // 5: google.protobuf.Struct
}
var file_netflix_titus_titus_containers_proto_depIdxs = []int32{
	1, // 0: com.netflix.titus.BasicContainer.image:type_name -> com.netflix.titus.BasicImage
	3, // 1: com.netflix.titus.BasicContainer.env:type_name -> com.netflix.titus.BasicContainer.EnvEntry
	4, // 2: com.netflix.titus.BasicContainer.volumeMounts:type_name -> com.netflix.titus.VolumeMount
	5, // 3: com.netflix.titus.PlatformSidecar.arguments:type_name -> google.protobuf.Struct
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_netflix_titus_titus_containers_proto_init() }
func file_netflix_titus_titus_containers_proto_init() {
	if File_netflix_titus_titus_containers_proto != nil {
		return
	}
	file_netflix_titus_titus_volumes_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_netflix_titus_titus_containers_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BasicContainer); i {
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
		file_netflix_titus_titus_containers_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BasicImage); i {
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
		file_netflix_titus_titus_containers_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PlatformSidecar); i {
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
			RawDescriptor: file_netflix_titus_titus_containers_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_netflix_titus_titus_containers_proto_goTypes,
		DependencyIndexes: file_netflix_titus_titus_containers_proto_depIdxs,
		MessageInfos:      file_netflix_titus_titus_containers_proto_msgTypes,
	}.Build()
	File_netflix_titus_titus_containers_proto = out.File
	file_netflix_titus_titus_containers_proto_rawDesc = nil
	file_netflix_titus_titus_containers_proto_goTypes = nil
	file_netflix_titus_titus_containers_proto_depIdxs = nil
}
