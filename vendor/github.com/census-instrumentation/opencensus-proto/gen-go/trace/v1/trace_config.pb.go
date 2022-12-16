// Copyright 2018, OpenCensus Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.3
// source: opencensus/proto/trace/v1/trace_config.proto

package v1

import (
	reflect "reflect"
	sync "sync"

	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

// How spans should be sampled:
// - Always off
// - Always on
// - Always follow the parent Span's decision (off if no parent).
type ConstantSampler_ConstantDecision int32

const (
	ConstantSampler_ALWAYS_OFF    ConstantSampler_ConstantDecision = 0
	ConstantSampler_ALWAYS_ON     ConstantSampler_ConstantDecision = 1
	ConstantSampler_ALWAYS_PARENT ConstantSampler_ConstantDecision = 2
)

// Enum value maps for ConstantSampler_ConstantDecision.
var (
	ConstantSampler_ConstantDecision_name = map[int32]string{
		0: "ALWAYS_OFF",
		1: "ALWAYS_ON",
		2: "ALWAYS_PARENT",
	}
	ConstantSampler_ConstantDecision_value = map[string]int32{
		"ALWAYS_OFF":    0,
		"ALWAYS_ON":     1,
		"ALWAYS_PARENT": 2,
	}
)

func (x ConstantSampler_ConstantDecision) Enum() *ConstantSampler_ConstantDecision {
	p := new(ConstantSampler_ConstantDecision)
	*p = x
	return p
}

func (x ConstantSampler_ConstantDecision) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ConstantSampler_ConstantDecision) Descriptor() protoreflect.EnumDescriptor {
	return file_opencensus_proto_trace_v1_trace_config_proto_enumTypes[0].Descriptor()
}

func (ConstantSampler_ConstantDecision) Type() protoreflect.EnumType {
	return &file_opencensus_proto_trace_v1_trace_config_proto_enumTypes[0]
}

func (x ConstantSampler_ConstantDecision) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ConstantSampler_ConstantDecision.Descriptor instead.
func (ConstantSampler_ConstantDecision) EnumDescriptor() ([]byte, []int) {
	return file_opencensus_proto_trace_v1_trace_config_proto_rawDescGZIP(), []int{2, 0}
}

// Global configuration of the trace service. All fields must be specified, or
// the default (zero) values will be used for each type.
type TraceConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The global default sampler used to make decisions on span sampling.
	//
	// Types that are assignable to Sampler:
	//	*TraceConfig_ProbabilitySampler
	//	*TraceConfig_ConstantSampler
	//	*TraceConfig_RateLimitingSampler
	Sampler isTraceConfig_Sampler `protobuf_oneof:"sampler"`
	// The global default max number of attributes per span.
	MaxNumberOfAttributes int64 `protobuf:"varint,4,opt,name=max_number_of_attributes,json=maxNumberOfAttributes,proto3" json:"max_number_of_attributes,omitempty"`
	// The global default max number of annotation events per span.
	MaxNumberOfAnnotations int64 `protobuf:"varint,5,opt,name=max_number_of_annotations,json=maxNumberOfAnnotations,proto3" json:"max_number_of_annotations,omitempty"`
	// The global default max number of message events per span.
	MaxNumberOfMessageEvents int64 `protobuf:"varint,6,opt,name=max_number_of_message_events,json=maxNumberOfMessageEvents,proto3" json:"max_number_of_message_events,omitempty"`
	// The global default max number of link entries per span.
	MaxNumberOfLinks int64 `protobuf:"varint,7,opt,name=max_number_of_links,json=maxNumberOfLinks,proto3" json:"max_number_of_links,omitempty"`
}

func (x *TraceConfig) Reset() {
	*x = TraceConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_opencensus_proto_trace_v1_trace_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TraceConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TraceConfig) ProtoMessage() {}

func (x *TraceConfig) ProtoReflect() protoreflect.Message {
	mi := &file_opencensus_proto_trace_v1_trace_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TraceConfig.ProtoReflect.Descriptor instead.
func (*TraceConfig) Descriptor() ([]byte, []int) {
	return file_opencensus_proto_trace_v1_trace_config_proto_rawDescGZIP(), []int{0}
}

func (m *TraceConfig) GetSampler() isTraceConfig_Sampler {
	if m != nil {
		return m.Sampler
	}
	return nil
}

func (x *TraceConfig) GetProbabilitySampler() *ProbabilitySampler {
	if x, ok := x.GetSampler().(*TraceConfig_ProbabilitySampler); ok {
		return x.ProbabilitySampler
	}
	return nil
}

func (x *TraceConfig) GetConstantSampler() *ConstantSampler {
	if x, ok := x.GetSampler().(*TraceConfig_ConstantSampler); ok {
		return x.ConstantSampler
	}
	return nil
}

func (x *TraceConfig) GetRateLimitingSampler() *RateLimitingSampler {
	if x, ok := x.GetSampler().(*TraceConfig_RateLimitingSampler); ok {
		return x.RateLimitingSampler
	}
	return nil
}

func (x *TraceConfig) GetMaxNumberOfAttributes() int64 {
	if x != nil {
		return x.MaxNumberOfAttributes
	}
	return 0
}

func (x *TraceConfig) GetMaxNumberOfAnnotations() int64 {
	if x != nil {
		return x.MaxNumberOfAnnotations
	}
	return 0
}

func (x *TraceConfig) GetMaxNumberOfMessageEvents() int64 {
	if x != nil {
		return x.MaxNumberOfMessageEvents
	}
	return 0
}

func (x *TraceConfig) GetMaxNumberOfLinks() int64 {
	if x != nil {
		return x.MaxNumberOfLinks
	}
	return 0
}

type isTraceConfig_Sampler interface {
	isTraceConfig_Sampler()
}

type TraceConfig_ProbabilitySampler struct {
	ProbabilitySampler *ProbabilitySampler `protobuf:"bytes,1,opt,name=probability_sampler,json=probabilitySampler,proto3,oneof"`
}

type TraceConfig_ConstantSampler struct {
	ConstantSampler *ConstantSampler `protobuf:"bytes,2,opt,name=constant_sampler,json=constantSampler,proto3,oneof"`
}

type TraceConfig_RateLimitingSampler struct {
	RateLimitingSampler *RateLimitingSampler `protobuf:"bytes,3,opt,name=rate_limiting_sampler,json=rateLimitingSampler,proto3,oneof"`
}

func (*TraceConfig_ProbabilitySampler) isTraceConfig_Sampler() {}

func (*TraceConfig_ConstantSampler) isTraceConfig_Sampler() {}

func (*TraceConfig_RateLimitingSampler) isTraceConfig_Sampler() {}

// Sampler that tries to uniformly sample traces with a given probability.
// The probability of sampling a trace is equal to that of the specified probability.
type ProbabilitySampler struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The desired probability of sampling. Must be within [0.0, 1.0].
	SamplingProbability float64 `protobuf:"fixed64,1,opt,name=samplingProbability,proto3" json:"samplingProbability,omitempty"`
}

func (x *ProbabilitySampler) Reset() {
	*x = ProbabilitySampler{}
	if protoimpl.UnsafeEnabled {
		mi := &file_opencensus_proto_trace_v1_trace_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProbabilitySampler) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProbabilitySampler) ProtoMessage() {}

func (x *ProbabilitySampler) ProtoReflect() protoreflect.Message {
	mi := &file_opencensus_proto_trace_v1_trace_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProbabilitySampler.ProtoReflect.Descriptor instead.
func (*ProbabilitySampler) Descriptor() ([]byte, []int) {
	return file_opencensus_proto_trace_v1_trace_config_proto_rawDescGZIP(), []int{1}
}

func (x *ProbabilitySampler) GetSamplingProbability() float64 {
	if x != nil {
		return x.SamplingProbability
	}
	return 0
}

// Sampler that always makes a constant decision on span sampling.
type ConstantSampler struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Decision ConstantSampler_ConstantDecision `protobuf:"varint,1,opt,name=decision,proto3,enum=opencensus.proto.trace.v1.ConstantSampler_ConstantDecision" json:"decision,omitempty"`
}

func (x *ConstantSampler) Reset() {
	*x = ConstantSampler{}
	if protoimpl.UnsafeEnabled {
		mi := &file_opencensus_proto_trace_v1_trace_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConstantSampler) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConstantSampler) ProtoMessage() {}

func (x *ConstantSampler) ProtoReflect() protoreflect.Message {
	mi := &file_opencensus_proto_trace_v1_trace_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConstantSampler.ProtoReflect.Descriptor instead.
func (*ConstantSampler) Descriptor() ([]byte, []int) {
	return file_opencensus_proto_trace_v1_trace_config_proto_rawDescGZIP(), []int{2}
}

func (x *ConstantSampler) GetDecision() ConstantSampler_ConstantDecision {
	if x != nil {
		return x.Decision
	}
	return ConstantSampler_ALWAYS_OFF
}

// Sampler that tries to sample with a rate per time window.
type RateLimitingSampler struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Rate per second.
	Qps int64 `protobuf:"varint,1,opt,name=qps,proto3" json:"qps,omitempty"`
}

func (x *RateLimitingSampler) Reset() {
	*x = RateLimitingSampler{}
	if protoimpl.UnsafeEnabled {
		mi := &file_opencensus_proto_trace_v1_trace_config_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RateLimitingSampler) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RateLimitingSampler) ProtoMessage() {}

func (x *RateLimitingSampler) ProtoReflect() protoreflect.Message {
	mi := &file_opencensus_proto_trace_v1_trace_config_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RateLimitingSampler.ProtoReflect.Descriptor instead.
func (*RateLimitingSampler) Descriptor() ([]byte, []int) {
	return file_opencensus_proto_trace_v1_trace_config_proto_rawDescGZIP(), []int{3}
}

func (x *RateLimitingSampler) GetQps() int64 {
	if x != nil {
		return x.Qps
	}
	return 0
}

var File_opencensus_proto_trace_v1_trace_config_proto protoreflect.FileDescriptor

var file_opencensus_proto_trace_v1_trace_config_proto_rawDesc = []byte{
	0x0a, 0x2c, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x72, 0x61, 0x63,
	0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x19,
	0x6f, 0x70, 0x65, 0x6e, 0x63, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x76, 0x31, 0x22, 0x9c, 0x04, 0x0a, 0x0b, 0x54, 0x72,
	0x61, 0x63, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x60, 0x0a, 0x13, 0x70, 0x72, 0x6f,
	0x62, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x5f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x72,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x65, 0x6e,
	0x73, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e,
	0x76, 0x31, 0x2e, 0x50, 0x72, 0x6f, 0x62, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x53, 0x61,
	0x6d, 0x70, 0x6c, 0x65, 0x72, 0x48, 0x00, 0x52, 0x12, 0x70, 0x72, 0x6f, 0x62, 0x61, 0x62, 0x69,
	0x6c, 0x69, 0x74, 0x79, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x72, 0x12, 0x57, 0x0a, 0x10, 0x63,
	0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x5f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x72, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x65, 0x6e, 0x73,
	0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x76,
	0x31, 0x2e, 0x43, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65,
	0x72, 0x48, 0x00, 0x52, 0x0f, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x53, 0x61, 0x6d,
	0x70, 0x6c, 0x65, 0x72, 0x12, 0x64, 0x0a, 0x15, 0x72, 0x61, 0x74, 0x65, 0x5f, 0x6c, 0x69, 0x6d,
	0x69, 0x74, 0x69, 0x6e, 0x67, 0x5f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x72, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x2e, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x65, 0x6e, 0x73, 0x75, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x76, 0x31, 0x2e,
	0x52, 0x61, 0x74, 0x65, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x69, 0x6e, 0x67, 0x53, 0x61, 0x6d, 0x70,
	0x6c, 0x65, 0x72, 0x48, 0x00, 0x52, 0x13, 0x72, 0x61, 0x74, 0x65, 0x4c, 0x69, 0x6d, 0x69, 0x74,
	0x69, 0x6e, 0x67, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x72, 0x12, 0x37, 0x0a, 0x18, 0x6d, 0x61,
	0x78, 0x5f, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x5f, 0x6f, 0x66, 0x5f, 0x61, 0x74, 0x74, 0x72,
	0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x15, 0x6d, 0x61,
	0x78, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x4f, 0x66, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x65, 0x73, 0x12, 0x39, 0x0a, 0x19, 0x6d, 0x61, 0x78, 0x5f, 0x6e, 0x75, 0x6d, 0x62, 0x65,
	0x72, 0x5f, 0x6f, 0x66, 0x5f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x16, 0x6d, 0x61, 0x78, 0x4e, 0x75, 0x6d, 0x62, 0x65,
	0x72, 0x4f, 0x66, 0x41, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x3e,
	0x0a, 0x1c, 0x6d, 0x61, 0x78, 0x5f, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x5f, 0x6f, 0x66, 0x5f,
	0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x5f, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x18, 0x6d, 0x61, 0x78, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x4f,
	0x66, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x12, 0x2d,
	0x0a, 0x13, 0x6d, 0x61, 0x78, 0x5f, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x5f, 0x6f, 0x66, 0x5f,
	0x6c, 0x69, 0x6e, 0x6b, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x03, 0x52, 0x10, 0x6d, 0x61, 0x78,
	0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x4f, 0x66, 0x4c, 0x69, 0x6e, 0x6b, 0x73, 0x42, 0x09, 0x0a,
	0x07, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x72, 0x22, 0x46, 0x0a, 0x12, 0x50, 0x72, 0x6f, 0x62,
	0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x72, 0x12, 0x30,
	0x0a, 0x13, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x69, 0x6e, 0x67, 0x50, 0x72, 0x6f, 0x62, 0x61, 0x62,
	0x69, 0x6c, 0x69, 0x74, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x01, 0x52, 0x13, 0x73, 0x61, 0x6d,
	0x70, 0x6c, 0x69, 0x6e, 0x67, 0x50, 0x72, 0x6f, 0x62, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79,
	0x22, 0xb0, 0x01, 0x0a, 0x0f, 0x43, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x53, 0x61, 0x6d,
	0x70, 0x6c, 0x65, 0x72, 0x12, 0x57, 0x0a, 0x08, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x3b, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x65, 0x6e,
	0x73, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e,
	0x76, 0x31, 0x2e, 0x43, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x53, 0x61, 0x6d, 0x70, 0x6c,
	0x65, 0x72, 0x2e, 0x43, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x44, 0x65, 0x63, 0x69, 0x73,
	0x69, 0x6f, 0x6e, 0x52, 0x08, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x44, 0x0a,
	0x10, 0x43, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x44, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f,
	0x6e, 0x12, 0x0e, 0x0a, 0x0a, 0x41, 0x4c, 0x57, 0x41, 0x59, 0x53, 0x5f, 0x4f, 0x46, 0x46, 0x10,
	0x00, 0x12, 0x0d, 0x0a, 0x09, 0x41, 0x4c, 0x57, 0x41, 0x59, 0x53, 0x5f, 0x4f, 0x4e, 0x10, 0x01,
	0x12, 0x11, 0x0a, 0x0d, 0x41, 0x4c, 0x57, 0x41, 0x59, 0x53, 0x5f, 0x50, 0x41, 0x52, 0x45, 0x4e,
	0x54, 0x10, 0x02, 0x22, 0x27, 0x0a, 0x13, 0x52, 0x61, 0x74, 0x65, 0x4c, 0x69, 0x6d, 0x69, 0x74,
	0x69, 0x6e, 0x67, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x72, 0x12, 0x10, 0x0a, 0x03, 0x71, 0x70,
	0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x03, 0x71, 0x70, 0x73, 0x42, 0x92, 0x01, 0x0a,
	0x1c, 0x69, 0x6f, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x76, 0x31, 0x42, 0x10, 0x54,
	0x72, 0x61, 0x63, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50,
	0x01, 0x5a, 0x42, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x65,
	0x6e, 0x73, 0x75, 0x73, 0x2d, 0x69, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x2d,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x65, 0x6e, 0x2d, 0x67, 0x6f, 0x2f, 0x74, 0x72, 0x61,
	0x63, 0x65, 0x2f, 0x76, 0x31, 0xea, 0x02, 0x19, 0x4f, 0x70, 0x65, 0x6e, 0x43, 0x65, 0x6e, 0x73,
	0x75, 0x73, 0x2e, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x54, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x56,
	0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_opencensus_proto_trace_v1_trace_config_proto_rawDescOnce sync.Once
	file_opencensus_proto_trace_v1_trace_config_proto_rawDescData = file_opencensus_proto_trace_v1_trace_config_proto_rawDesc
)

func file_opencensus_proto_trace_v1_trace_config_proto_rawDescGZIP() []byte {
	file_opencensus_proto_trace_v1_trace_config_proto_rawDescOnce.Do(func() {
		file_opencensus_proto_trace_v1_trace_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_opencensus_proto_trace_v1_trace_config_proto_rawDescData)
	})
	return file_opencensus_proto_trace_v1_trace_config_proto_rawDescData
}

var file_opencensus_proto_trace_v1_trace_config_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_opencensus_proto_trace_v1_trace_config_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_opencensus_proto_trace_v1_trace_config_proto_goTypes = []interface{}{
	(ConstantSampler_ConstantDecision)(0), // 0: opencensus.proto.trace.v1.ConstantSampler.ConstantDecision
	(*TraceConfig)(nil),                   // 1: opencensus.proto.trace.v1.TraceConfig
	(*ProbabilitySampler)(nil),            // 2: opencensus.proto.trace.v1.ProbabilitySampler
	(*ConstantSampler)(nil),               // 3: opencensus.proto.trace.v1.ConstantSampler
	(*RateLimitingSampler)(nil),           // 4: opencensus.proto.trace.v1.RateLimitingSampler
}
var file_opencensus_proto_trace_v1_trace_config_proto_depIdxs = []int32{
	2, // 0: opencensus.proto.trace.v1.TraceConfig.probability_sampler:type_name -> opencensus.proto.trace.v1.ProbabilitySampler
	3, // 1: opencensus.proto.trace.v1.TraceConfig.constant_sampler:type_name -> opencensus.proto.trace.v1.ConstantSampler
	4, // 2: opencensus.proto.trace.v1.TraceConfig.rate_limiting_sampler:type_name -> opencensus.proto.trace.v1.RateLimitingSampler
	0, // 3: opencensus.proto.trace.v1.ConstantSampler.decision:type_name -> opencensus.proto.trace.v1.ConstantSampler.ConstantDecision
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_opencensus_proto_trace_v1_trace_config_proto_init() }
func file_opencensus_proto_trace_v1_trace_config_proto_init() {
	if File_opencensus_proto_trace_v1_trace_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_opencensus_proto_trace_v1_trace_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TraceConfig); i {
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
		file_opencensus_proto_trace_v1_trace_config_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProbabilitySampler); i {
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
		file_opencensus_proto_trace_v1_trace_config_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConstantSampler); i {
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
		file_opencensus_proto_trace_v1_trace_config_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RateLimitingSampler); i {
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
	file_opencensus_proto_trace_v1_trace_config_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*TraceConfig_ProbabilitySampler)(nil),
		(*TraceConfig_ConstantSampler)(nil),
		(*TraceConfig_RateLimitingSampler)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_opencensus_proto_trace_v1_trace_config_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_opencensus_proto_trace_v1_trace_config_proto_goTypes,
		DependencyIndexes: file_opencensus_proto_trace_v1_trace_config_proto_depIdxs,
		EnumInfos:         file_opencensus_proto_trace_v1_trace_config_proto_enumTypes,
		MessageInfos:      file_opencensus_proto_trace_v1_trace_config_proto_msgTypes,
	}.Build()
	File_opencensus_proto_trace_v1_trace_config_proto = out.File
	file_opencensus_proto_trace_v1_trace_config_proto_rawDesc = nil
	file_opencensus_proto_trace_v1_trace_config_proto_goTypes = nil
	file_opencensus_proto_trace_v1_trace_config_proto_depIdxs = nil
}
