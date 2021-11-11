// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.14.0
// source: envoy/extensions/filters/network/tcp_proxy/v3/tcp_proxy.proto

package envoy_extensions_filters_network_tcp_proxy_v3

import (
	v31 "github.com/cilium/proxy/go/envoy/config/accesslog/v3"
	v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	v32 "github.com/cilium/proxy/go/envoy/type/v3"
	_ "github.com/cncf/xds/go/udpa/annotations"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
	reflect "reflect"
	sync "sync"
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

// [#next-free-field: 14]
type TcpProxy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The prefix to use when emitting :ref:`statistics
	// <config_network_filters_tcp_proxy_stats>`.
	StatPrefix string `protobuf:"bytes,1,opt,name=stat_prefix,json=statPrefix,proto3" json:"stat_prefix,omitempty"`
	// Types that are assignable to ClusterSpecifier:
	//	*TcpProxy_Cluster
	//	*TcpProxy_WeightedClusters
	ClusterSpecifier isTcpProxy_ClusterSpecifier `protobuf_oneof:"cluster_specifier"`
	// Optional endpoint metadata match criteria. Only endpoints in the upstream
	// cluster with metadata matching that set in metadata_match will be
	// considered. The filter name should be specified as *envoy.lb*.
	MetadataMatch *v3.Metadata `protobuf:"bytes,9,opt,name=metadata_match,json=metadataMatch,proto3" json:"metadata_match,omitempty"`
	// The idle timeout for connections managed by the TCP proxy filter. The idle timeout
	// is defined as the period in which there are no bytes sent or received on either
	// the upstream or downstream connection. If not set, the default idle timeout is 1 hour. If set
	// to 0s, the timeout will be disabled.
	//
	// .. warning::
	//   Disabling this timeout has a highly likelihood of yielding connection leaks due to lost TCP
	//   FIN packets, etc.
	IdleTimeout *durationpb.Duration `protobuf:"bytes,8,opt,name=idle_timeout,json=idleTimeout,proto3" json:"idle_timeout,omitempty"`
	// [#not-implemented-hide:] The idle timeout for connections managed by the TCP proxy
	// filter. The idle timeout is defined as the period in which there is no
	// active traffic. If not set, there is no idle timeout. When the idle timeout
	// is reached the connection will be closed. The distinction between
	// downstream_idle_timeout/upstream_idle_timeout provides a means to set
	// timeout based on the last byte sent on the downstream/upstream connection.
	DownstreamIdleTimeout *durationpb.Duration `protobuf:"bytes,3,opt,name=downstream_idle_timeout,json=downstreamIdleTimeout,proto3" json:"downstream_idle_timeout,omitempty"`
	// [#not-implemented-hide:]
	UpstreamIdleTimeout *durationpb.Duration `protobuf:"bytes,4,opt,name=upstream_idle_timeout,json=upstreamIdleTimeout,proto3" json:"upstream_idle_timeout,omitempty"`
	// Configuration for :ref:`access logs <arch_overview_access_logs>`
	// emitted by the this tcp_proxy.
	AccessLog []*v31.AccessLog `protobuf:"bytes,5,rep,name=access_log,json=accessLog,proto3" json:"access_log,omitempty"`
	// The maximum number of unsuccessful connection attempts that will be made before
	// giving up. If the parameter is not specified, 1 connection attempt will be made.
	MaxConnectAttempts *wrapperspb.UInt32Value `protobuf:"bytes,7,opt,name=max_connect_attempts,json=maxConnectAttempts,proto3" json:"max_connect_attempts,omitempty"`
	// Optional configuration for TCP proxy hash policy. If hash_policy is not set, the hash-based
	// load balancing algorithms will select a host randomly. Currently the number of hash policies is
	// limited to 1.
	HashPolicy []*v32.HashPolicy `protobuf:"bytes,11,rep,name=hash_policy,json=hashPolicy,proto3" json:"hash_policy,omitempty"`
	// If set, this configures tunneling, e.g. configuration options to tunnel TCP payload over
	// HTTP CONNECT. If this message is absent, the payload will be proxied upstream as per usual.
	TunnelingConfig *TcpProxy_TunnelingConfig `protobuf:"bytes,12,opt,name=tunneling_config,json=tunnelingConfig,proto3" json:"tunneling_config,omitempty"`
	// The maximum duration of a connection. The duration is defined as the period since a connection
	// was established. If not set, there is no max duration. When max_downstream_connection_duration
	// is reached the connection will be closed. Duration must be at least 1ms.
	MaxDownstreamConnectionDuration *durationpb.Duration `protobuf:"bytes,13,opt,name=max_downstream_connection_duration,json=maxDownstreamConnectionDuration,proto3" json:"max_downstream_connection_duration,omitempty"`
}

func (x *TcpProxy) Reset() {
	*x = TcpProxy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TcpProxy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TcpProxy) ProtoMessage() {}

func (x *TcpProxy) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TcpProxy.ProtoReflect.Descriptor instead.
func (*TcpProxy) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_rawDescGZIP(), []int{0}
}

func (x *TcpProxy) GetStatPrefix() string {
	if x != nil {
		return x.StatPrefix
	}
	return ""
}

func (m *TcpProxy) GetClusterSpecifier() isTcpProxy_ClusterSpecifier {
	if m != nil {
		return m.ClusterSpecifier
	}
	return nil
}

func (x *TcpProxy) GetCluster() string {
	if x, ok := x.GetClusterSpecifier().(*TcpProxy_Cluster); ok {
		return x.Cluster
	}
	return ""
}

func (x *TcpProxy) GetWeightedClusters() *TcpProxy_WeightedCluster {
	if x, ok := x.GetClusterSpecifier().(*TcpProxy_WeightedClusters); ok {
		return x.WeightedClusters
	}
	return nil
}

func (x *TcpProxy) GetMetadataMatch() *v3.Metadata {
	if x != nil {
		return x.MetadataMatch
	}
	return nil
}

func (x *TcpProxy) GetIdleTimeout() *durationpb.Duration {
	if x != nil {
		return x.IdleTimeout
	}
	return nil
}

func (x *TcpProxy) GetDownstreamIdleTimeout() *durationpb.Duration {
	if x != nil {
		return x.DownstreamIdleTimeout
	}
	return nil
}

func (x *TcpProxy) GetUpstreamIdleTimeout() *durationpb.Duration {
	if x != nil {
		return x.UpstreamIdleTimeout
	}
	return nil
}

func (x *TcpProxy) GetAccessLog() []*v31.AccessLog {
	if x != nil {
		return x.AccessLog
	}
	return nil
}

func (x *TcpProxy) GetMaxConnectAttempts() *wrapperspb.UInt32Value {
	if x != nil {
		return x.MaxConnectAttempts
	}
	return nil
}

func (x *TcpProxy) GetHashPolicy() []*v32.HashPolicy {
	if x != nil {
		return x.HashPolicy
	}
	return nil
}

func (x *TcpProxy) GetTunnelingConfig() *TcpProxy_TunnelingConfig {
	if x != nil {
		return x.TunnelingConfig
	}
	return nil
}

func (x *TcpProxy) GetMaxDownstreamConnectionDuration() *durationpb.Duration {
	if x != nil {
		return x.MaxDownstreamConnectionDuration
	}
	return nil
}

type isTcpProxy_ClusterSpecifier interface {
	isTcpProxy_ClusterSpecifier()
}

type TcpProxy_Cluster struct {
	// The upstream cluster to connect to.
	Cluster string `protobuf:"bytes,2,opt,name=cluster,proto3,oneof"`
}

type TcpProxy_WeightedClusters struct {
	// Multiple upstream clusters can be specified for a given route. The
	// request is routed to one of the upstream clusters based on weights
	// assigned to each cluster.
	WeightedClusters *TcpProxy_WeightedCluster `protobuf:"bytes,10,opt,name=weighted_clusters,json=weightedClusters,proto3,oneof"`
}

func (*TcpProxy_Cluster) isTcpProxy_ClusterSpecifier() {}

func (*TcpProxy_WeightedClusters) isTcpProxy_ClusterSpecifier() {}

// Allows for specification of multiple upstream clusters along with weights
// that indicate the percentage of traffic to be forwarded to each cluster.
// The router selects an upstream cluster based on these weights.
type TcpProxy_WeightedCluster struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Specifies one or more upstream clusters associated with the route.
	Clusters []*TcpProxy_WeightedCluster_ClusterWeight `protobuf:"bytes,1,rep,name=clusters,proto3" json:"clusters,omitempty"`
}

func (x *TcpProxy_WeightedCluster) Reset() {
	*x = TcpProxy_WeightedCluster{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TcpProxy_WeightedCluster) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TcpProxy_WeightedCluster) ProtoMessage() {}

func (x *TcpProxy_WeightedCluster) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TcpProxy_WeightedCluster.ProtoReflect.Descriptor instead.
func (*TcpProxy_WeightedCluster) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_rawDescGZIP(), []int{0, 0}
}

func (x *TcpProxy_WeightedCluster) GetClusters() []*TcpProxy_WeightedCluster_ClusterWeight {
	if x != nil {
		return x.Clusters
	}
	return nil
}

// Configuration for tunneling TCP over other transports or application layers.
// Tunneling is supported over both HTTP/1.1 and HTTP/2. Upstream protocol is
// determined by the cluster configuration.
type TcpProxy_TunnelingConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The hostname to send in the synthesized CONNECT headers to the upstream proxy.
	Hostname string `protobuf:"bytes,1,opt,name=hostname,proto3" json:"hostname,omitempty"`
	// Use POST method instead of CONNECT method to tunnel the TCP stream.
	// The 'protocol: bytestream' header is also NOT set for HTTP/2 to comply with the spec.
	//
	// The upstream proxy is expected to convert POST payload as raw TCP.
	UsePost bool `protobuf:"varint,2,opt,name=use_post,json=usePost,proto3" json:"use_post,omitempty"`
	// Additional request headers to upstream proxy. This is mainly used to
	// trigger upstream to convert POST requests back to CONNECT requests.
	//
	// Neither *:-prefixed* pseudo-headers nor the Host: header can be overridden.
	HeadersToAdd []*v3.HeaderValueOption `protobuf:"bytes,3,rep,name=headers_to_add,json=headersToAdd,proto3" json:"headers_to_add,omitempty"`
}

func (x *TcpProxy_TunnelingConfig) Reset() {
	*x = TcpProxy_TunnelingConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TcpProxy_TunnelingConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TcpProxy_TunnelingConfig) ProtoMessage() {}

func (x *TcpProxy_TunnelingConfig) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TcpProxy_TunnelingConfig.ProtoReflect.Descriptor instead.
func (*TcpProxy_TunnelingConfig) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_rawDescGZIP(), []int{0, 1}
}

func (x *TcpProxy_TunnelingConfig) GetHostname() string {
	if x != nil {
		return x.Hostname
	}
	return ""
}

func (x *TcpProxy_TunnelingConfig) GetUsePost() bool {
	if x != nil {
		return x.UsePost
	}
	return false
}

func (x *TcpProxy_TunnelingConfig) GetHeadersToAdd() []*v3.HeaderValueOption {
	if x != nil {
		return x.HeadersToAdd
	}
	return nil
}

type TcpProxy_WeightedCluster_ClusterWeight struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Name of the upstream cluster.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// When a request matches the route, the choice of an upstream cluster is
	// determined by its weight. The sum of weights across all entries in the
	// clusters array determines the total weight.
	Weight uint32 `protobuf:"varint,2,opt,name=weight,proto3" json:"weight,omitempty"`
	// Optional endpoint metadata match criteria used by the subset load balancer. Only endpoints
	// in the upstream cluster with metadata matching what is set in this field will be considered
	// for load balancing. Note that this will be merged with what's provided in
	// :ref:`TcpProxy.metadata_match
	// <envoy_api_field_extensions.filters.network.tcp_proxy.v3.TcpProxy.metadata_match>`, with values
	// here taking precedence. The filter name should be specified as *envoy.lb*.
	MetadataMatch *v3.Metadata `protobuf:"bytes,3,opt,name=metadata_match,json=metadataMatch,proto3" json:"metadata_match,omitempty"`
}

func (x *TcpProxy_WeightedCluster_ClusterWeight) Reset() {
	*x = TcpProxy_WeightedCluster_ClusterWeight{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TcpProxy_WeightedCluster_ClusterWeight) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TcpProxy_WeightedCluster_ClusterWeight) ProtoMessage() {}

func (x *TcpProxy_WeightedCluster_ClusterWeight) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TcpProxy_WeightedCluster_ClusterWeight.ProtoReflect.Descriptor instead.
func (*TcpProxy_WeightedCluster_ClusterWeight) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_rawDescGZIP(), []int{0, 0, 0}
}

func (x *TcpProxy_WeightedCluster_ClusterWeight) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *TcpProxy_WeightedCluster_ClusterWeight) GetWeight() uint32 {
	if x != nil {
		return x.Weight
	}
	return 0
}

func (x *TcpProxy_WeightedCluster_ClusterWeight) GetMetadataMatch() *v3.Metadata {
	if x != nil {
		return x.MetadataMatch
	}
	return nil
}

var File_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto protoreflect.FileDescriptor

var file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_rawDesc = []byte{
	0x0a, 0x3d, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f,
	0x72, 0x6b, 0x2f, 0x74, 0x63, 0x70, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x76, 0x33, 0x2f,
	0x74, 0x63, 0x70, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x2d, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e,
	0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72,
	0x6b, 0x2e, 0x74, 0x63, 0x70, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x33, 0x1a, 0x29,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x61, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x6c, 0x6f, 0x67, 0x2f, 0x76, 0x33, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x6c, 0x6f, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x33, 0x2f,
	0x62, 0x61, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x76, 0x33, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x5f, 0x70,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x75, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x77, 0x72, 0x61,
	0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64, 0x70,
	0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x75, 0x64, 0x70, 0x61,
	0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76,
	0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xe8, 0x0d, 0x0a, 0x08, 0x54, 0x63, 0x70, 0x50, 0x72,
	0x6f, 0x78, 0x79, 0x12, 0x28, 0x0a, 0x0b, 0x73, 0x74, 0x61, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x66,
	0x69, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02, 0x10,
	0x01, 0x52, 0x0a, 0x73, 0x74, 0x61, 0x74, 0x50, 0x72, 0x65, 0x66, 0x69, 0x78, 0x12, 0x1a, 0x0a,
	0x07, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00,
	0x52, 0x07, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x12, 0x76, 0x0a, 0x11, 0x77, 0x65, 0x69,
	0x67, 0x68, 0x74, 0x65, 0x64, 0x5f, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x73, 0x18, 0x0a,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x47, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74,
	0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e,
	0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x74, 0x63, 0x70, 0x5f, 0x70, 0x72, 0x6f, 0x78,
	0x79, 0x2e, 0x76, 0x33, 0x2e, 0x54, 0x63, 0x70, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x57, 0x65,
	0x69, 0x67, 0x68, 0x74, 0x65, 0x64, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x48, 0x00, 0x52,
	0x10, 0x77, 0x65, 0x69, 0x67, 0x68, 0x74, 0x65, 0x64, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72,
	0x73, 0x12, 0x45, 0x0a, 0x0e, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x6d, 0x61,
	0x74, 0x63, 0x68, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x33,
	0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x0d, 0x6d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x12, 0x3c, 0x0a, 0x0c, 0x69, 0x64, 0x6c, 0x65,
	0x5f, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x69, 0x64, 0x6c, 0x65, 0x54,
	0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x12, 0x51, 0x0a, 0x17, 0x64, 0x6f, 0x77, 0x6e, 0x73, 0x74,
	0x72, 0x65, 0x61, 0x6d, 0x5f, 0x69, 0x64, 0x6c, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75,
	0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x15, 0x64, 0x6f, 0x77, 0x6e, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x49, 0x64,
	0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x12, 0x4d, 0x0a, 0x15, 0x75, 0x70, 0x73,
	0x74, 0x72, 0x65, 0x61, 0x6d, 0x5f, 0x69, 0x64, 0x6c, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x6f,
	0x75, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x52, 0x13, 0x75, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x49, 0x64, 0x6c,
	0x65, 0x54, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x12, 0x43, 0x0a, 0x0a, 0x61, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x5f, 0x6c, 0x6f, 0x67, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x6c, 0x6f, 0x67, 0x2e, 0x76, 0x33, 0x2e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c,
	0x6f, 0x67, 0x52, 0x09, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x6f, 0x67, 0x12, 0x57, 0x0a,
	0x14, 0x6d, 0x61, 0x78, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x5f, 0x61, 0x74, 0x74,
	0x65, 0x6d, 0x70, 0x74, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x55, 0x49,
	0x6e, 0x74, 0x33, 0x32, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x2a, 0x02,
	0x28, 0x01, 0x52, 0x12, 0x6d, 0x61, 0x78, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x41, 0x74,
	0x74, 0x65, 0x6d, 0x70, 0x74, 0x73, 0x12, 0x44, 0x0a, 0x0b, 0x68, 0x61, 0x73, 0x68, 0x5f, 0x70,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x18, 0x0b, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x76, 0x33, 0x2e, 0x48, 0x61, 0x73, 0x68,
	0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x92, 0x01, 0x02, 0x10, 0x01,
	0x52, 0x0a, 0x68, 0x61, 0x73, 0x68, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x72, 0x0a, 0x10,
	0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x69, 0x6e, 0x67, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x18, 0x0c, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x47, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65,
	0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72,
	0x73, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x74, 0x63, 0x70, 0x5f, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2e, 0x76, 0x33, 0x2e, 0x54, 0x63, 0x70, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x2e,
	0x54, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x69, 0x6e, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52,
	0x0f, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x69, 0x6e, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x12, 0x74, 0x0a, 0x22, 0x6d, 0x61, 0x78, 0x5f, 0x64, 0x6f, 0x77, 0x6e, 0x73, 0x74, 0x72, 0x65,
	0x61, 0x6d, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x64, 0x75,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44,
	0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x0c, 0xfa, 0x42, 0x09, 0xaa, 0x01, 0x06, 0x32,
	0x04, 0x10, 0xc0, 0x84, 0x3d, 0x52, 0x1f, 0x6d, 0x61, 0x78, 0x44, 0x6f, 0x77, 0x6e, 0x73, 0x74,
	0x72, 0x65, 0x61, 0x6d, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x44, 0x75,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x1a, 0xc7, 0x03, 0x0a, 0x0f, 0x57, 0x65, 0x69, 0x67, 0x68,
	0x74, 0x65, 0x64, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x12, 0x7b, 0x0a, 0x08, 0x63, 0x6c,
	0x75, 0x73, 0x74, 0x65, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x55, 0x2e, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e,
	0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e,
	0x74, 0x63, 0x70, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x33, 0x2e, 0x54, 0x63, 0x70,
	0x50, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x57, 0x65, 0x69, 0x67, 0x68, 0x74, 0x65, 0x64, 0x43, 0x6c,
	0x75, 0x73, 0x74, 0x65, 0x72, 0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x57, 0x65, 0x69,
	0x67, 0x68, 0x74, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x92, 0x01, 0x02, 0x08, 0x01, 0x52, 0x08, 0x63,
	0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x73, 0x1a, 0xec, 0x01, 0x0a, 0x0d, 0x43, 0x6c, 0x75, 0x73,
	0x74, 0x65, 0x72, 0x57, 0x65, 0x69, 0x67, 0x68, 0x74, 0x12, 0x1b, 0x0a, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02, 0x10, 0x01,
	0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1f, 0x0a, 0x06, 0x77, 0x65, 0x69, 0x67, 0x68, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x2a, 0x02, 0x28, 0x01, 0x52,
	0x06, 0x77, 0x65, 0x69, 0x67, 0x68, 0x74, 0x12, 0x45, 0x0a, 0x0e, 0x6d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0x5f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1e, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x63,
	0x6f, 0x72, 0x65, 0x2e, 0x76, 0x33, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52,
	0x0d, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x3a, 0x56,
	0x9a, 0xc5, 0x88, 0x1e, 0x51, 0x0a, 0x4f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f,
	0x72, 0x6b, 0x2e, 0x74, 0x63, 0x70, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x32, 0x2e,
	0x54, 0x63, 0x70, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x57, 0x65, 0x69, 0x67, 0x68, 0x74, 0x65,
	0x64, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72,
	0x57, 0x65, 0x69, 0x67, 0x68, 0x74, 0x3a, 0x48, 0x9a, 0xc5, 0x88, 0x1e, 0x43, 0x0a, 0x41, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x66, 0x69, 0x6c, 0x74,
	0x65, 0x72, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x74, 0x63, 0x70, 0x5f, 0x70,
	0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x32, 0x2e, 0x54, 0x63, 0x70, 0x50, 0x72, 0x6f, 0x78, 0x79,
	0x2e, 0x57, 0x65, 0x69, 0x67, 0x68, 0x74, 0x65, 0x64, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72,
	0x1a, 0xf5, 0x01, 0x0a, 0x0f, 0x54, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x69, 0x6e, 0x67, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x12, 0x23, 0x0a, 0x08, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02, 0x10, 0x01, 0x52,
	0x08, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x75, 0x73, 0x65,
	0x5f, 0x70, 0x6f, 0x73, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x75, 0x73, 0x65,
	0x50, 0x6f, 0x73, 0x74, 0x12, 0x58, 0x0a, 0x0e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x5f,
	0x74, 0x6f, 0x5f, 0x61, 0x64, 0x64, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x63, 0x6f, 0x72, 0x65,
	0x2e, 0x76, 0x33, 0x2e, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x4f,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x09, 0xfa, 0x42, 0x06, 0x92, 0x01, 0x03, 0x10, 0xe8, 0x07,
	0x52, 0x0c, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x54, 0x6f, 0x41, 0x64, 0x64, 0x3a, 0x48,
	0x9a, 0xc5, 0x88, 0x1e, 0x43, 0x0a, 0x41, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f,
	0x72, 0x6b, 0x2e, 0x74, 0x63, 0x70, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x32, 0x2e,
	0x54, 0x63, 0x70, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x54, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x69,
	0x6e, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x3a, 0x38, 0x9a, 0xc5, 0x88, 0x1e, 0x33, 0x0a,
	0x31, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x66, 0x69,
	0x6c, 0x74, 0x65, 0x72, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x74, 0x63, 0x70,
	0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x32, 0x2e, 0x54, 0x63, 0x70, 0x50, 0x72, 0x6f,
	0x78, 0x79, 0x42, 0x18, 0x0a, 0x11, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x5f, 0x73, 0x70,
	0x65, 0x63, 0x69, 0x66, 0x69, 0x65, 0x72, 0x12, 0x03, 0xf8, 0x42, 0x01, 0x4a, 0x04, 0x08, 0x06,
	0x10, 0x07, 0x52, 0x0d, 0x64, 0x65, 0x70, 0x72, 0x65, 0x63, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x76,
	0x31, 0x42, 0x56, 0x0a, 0x3b, 0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f,
	0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69,
	0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x77,
	0x6f, 0x72, 0x6b, 0x2e, 0x74, 0x63, 0x70, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x33,
	0x42, 0x0d, 0x54, 0x63, 0x70, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50,
	0x01, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x02, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_rawDescOnce sync.Once
	file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_rawDescData = file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_rawDesc
)

func file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_rawDescGZIP() []byte {
	file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_rawDescData)
	})
	return file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_rawDescData
}

var file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_goTypes = []interface{}{
	(*TcpProxy)(nil),                               // 0: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
	(*TcpProxy_WeightedCluster)(nil),               // 1: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.WeightedCluster
	(*TcpProxy_TunnelingConfig)(nil),               // 2: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.TunnelingConfig
	(*TcpProxy_WeightedCluster_ClusterWeight)(nil), // 3: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.WeightedCluster.ClusterWeight
	(*v3.Metadata)(nil),                            // 4: envoy.config.core.v3.Metadata
	(*durationpb.Duration)(nil),                    // 5: google.protobuf.Duration
	(*v31.AccessLog)(nil),                          // 6: envoy.config.accesslog.v3.AccessLog
	(*wrapperspb.UInt32Value)(nil),                 // 7: google.protobuf.UInt32Value
	(*v32.HashPolicy)(nil),                         // 8: envoy.type.v3.HashPolicy
	(*v3.HeaderValueOption)(nil),                   // 9: envoy.config.core.v3.HeaderValueOption
}
var file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_depIdxs = []int32{
	1,  // 0: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.weighted_clusters:type_name -> envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.WeightedCluster
	4,  // 1: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.metadata_match:type_name -> envoy.config.core.v3.Metadata
	5,  // 2: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.idle_timeout:type_name -> google.protobuf.Duration
	5,  // 3: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.downstream_idle_timeout:type_name -> google.protobuf.Duration
	5,  // 4: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.upstream_idle_timeout:type_name -> google.protobuf.Duration
	6,  // 5: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.access_log:type_name -> envoy.config.accesslog.v3.AccessLog
	7,  // 6: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.max_connect_attempts:type_name -> google.protobuf.UInt32Value
	8,  // 7: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.hash_policy:type_name -> envoy.type.v3.HashPolicy
	2,  // 8: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.tunneling_config:type_name -> envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.TunnelingConfig
	5,  // 9: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.max_downstream_connection_duration:type_name -> google.protobuf.Duration
	3,  // 10: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.WeightedCluster.clusters:type_name -> envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.WeightedCluster.ClusterWeight
	9,  // 11: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.TunnelingConfig.headers_to_add:type_name -> envoy.config.core.v3.HeaderValueOption
	4,  // 12: envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy.WeightedCluster.ClusterWeight.metadata_match:type_name -> envoy.config.core.v3.Metadata
	13, // [13:13] is the sub-list for method output_type
	13, // [13:13] is the sub-list for method input_type
	13, // [13:13] is the sub-list for extension type_name
	13, // [13:13] is the sub-list for extension extendee
	0,  // [0:13] is the sub-list for field type_name
}

func init() { file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_init() }
func file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_init() {
	if File_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TcpProxy); i {
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
		file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TcpProxy_WeightedCluster); i {
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
		file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TcpProxy_TunnelingConfig); i {
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
		file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TcpProxy_WeightedCluster_ClusterWeight); i {
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
	file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*TcpProxy_Cluster)(nil),
		(*TcpProxy_WeightedClusters)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_depIdxs,
		MessageInfos:      file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_msgTypes,
	}.Build()
	File_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto = out.File
	file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_rawDesc = nil
	file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_goTypes = nil
	file_envoy_extensions_filters_network_tcp_proxy_v3_tcp_proxy_proto_depIdxs = nil
}
