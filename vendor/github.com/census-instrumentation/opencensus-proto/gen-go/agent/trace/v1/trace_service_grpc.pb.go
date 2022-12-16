// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package v1

import (
	context "context"

	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// TraceServiceClient is the client API for TraceService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TraceServiceClient interface {
	// After initialization, this RPC must be kept alive for the entire life of
	// the application. The agent pushes configs down to applications via a
	// stream.
	Config(ctx context.Context, opts ...grpc.CallOption) (TraceService_ConfigClient, error)
	// For performance reasons, it is recommended to keep this RPC
	// alive for the entire life of the application.
	Export(ctx context.Context, opts ...grpc.CallOption) (TraceService_ExportClient, error)
}

type traceServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTraceServiceClient(cc grpc.ClientConnInterface) TraceServiceClient {
	return &traceServiceClient{cc}
}

func (c *traceServiceClient) Config(ctx context.Context, opts ...grpc.CallOption) (TraceService_ConfigClient, error) {
	stream, err := c.cc.NewStream(ctx, &_TraceService_serviceDesc.Streams[0], "/opencensus.proto.agent.trace.v1.TraceService/Config", opts...)
	if err != nil {
		return nil, err
	}
	x := &traceServiceConfigClient{stream}
	return x, nil
}

type TraceService_ConfigClient interface {
	Send(*CurrentLibraryConfig) error
	Recv() (*UpdatedLibraryConfig, error)
	grpc.ClientStream
}

type traceServiceConfigClient struct {
	grpc.ClientStream
}

func (x *traceServiceConfigClient) Send(m *CurrentLibraryConfig) error {
	return x.ClientStream.SendMsg(m)
}

func (x *traceServiceConfigClient) Recv() (*UpdatedLibraryConfig, error) {
	m := new(UpdatedLibraryConfig)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *traceServiceClient) Export(ctx context.Context, opts ...grpc.CallOption) (TraceService_ExportClient, error) {
	stream, err := c.cc.NewStream(ctx, &_TraceService_serviceDesc.Streams[1], "/opencensus.proto.agent.trace.v1.TraceService/Export", opts...)
	if err != nil {
		return nil, err
	}
	x := &traceServiceExportClient{stream}
	return x, nil
}

type TraceService_ExportClient interface {
	Send(*ExportTraceServiceRequest) error
	Recv() (*ExportTraceServiceResponse, error)
	grpc.ClientStream
}

type traceServiceExportClient struct {
	grpc.ClientStream
}

func (x *traceServiceExportClient) Send(m *ExportTraceServiceRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *traceServiceExportClient) Recv() (*ExportTraceServiceResponse, error) {
	m := new(ExportTraceServiceResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// TraceServiceServer is the server API for TraceService service.
// All implementations must embed UnimplementedTraceServiceServer
// for forward compatibility
type TraceServiceServer interface {
	// After initialization, this RPC must be kept alive for the entire life of
	// the application. The agent pushes configs down to applications via a
	// stream.
	Config(TraceService_ConfigServer) error
	// For performance reasons, it is recommended to keep this RPC
	// alive for the entire life of the application.
	Export(TraceService_ExportServer) error
	mustEmbedUnimplementedTraceServiceServer()
}

// UnimplementedTraceServiceServer must be embedded to have forward compatible implementations.
type UnimplementedTraceServiceServer struct {
}

func (*UnimplementedTraceServiceServer) Config(TraceService_ConfigServer) error {
	return status.Errorf(codes.Unimplemented, "method Config not implemented")
}
func (*UnimplementedTraceServiceServer) Export(TraceService_ExportServer) error {
	return status.Errorf(codes.Unimplemented, "method Export not implemented")
}
func (*UnimplementedTraceServiceServer) mustEmbedUnimplementedTraceServiceServer() {}

func RegisterTraceServiceServer(s *grpc.Server, srv TraceServiceServer) {
	s.RegisterService(&_TraceService_serviceDesc, srv)
}

func _TraceService_Config_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(TraceServiceServer).Config(&traceServiceConfigServer{stream})
}

type TraceService_ConfigServer interface {
	Send(*UpdatedLibraryConfig) error
	Recv() (*CurrentLibraryConfig, error)
	grpc.ServerStream
}

type traceServiceConfigServer struct {
	grpc.ServerStream
}

func (x *traceServiceConfigServer) Send(m *UpdatedLibraryConfig) error {
	return x.ServerStream.SendMsg(m)
}

func (x *traceServiceConfigServer) Recv() (*CurrentLibraryConfig, error) {
	m := new(CurrentLibraryConfig)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _TraceService_Export_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(TraceServiceServer).Export(&traceServiceExportServer{stream})
}

type TraceService_ExportServer interface {
	Send(*ExportTraceServiceResponse) error
	Recv() (*ExportTraceServiceRequest, error)
	grpc.ServerStream
}

type traceServiceExportServer struct {
	grpc.ServerStream
}

func (x *traceServiceExportServer) Send(m *ExportTraceServiceResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *traceServiceExportServer) Recv() (*ExportTraceServiceRequest, error) {
	m := new(ExportTraceServiceRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _TraceService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "opencensus.proto.agent.trace.v1.TraceService",
	HandlerType: (*TraceServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Config",
			Handler:       _TraceService_Config_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "Export",
			Handler:       _TraceService_Export_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "opencensus/proto/agent/trace/v1/trace_service.proto",
}
