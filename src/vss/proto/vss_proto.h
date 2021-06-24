#pragma once

#include "transport/proto/transport.pb.h"
#include "dht/dht_utils.h"
#include "common/bloom_filter.h"

namespace tenon {

namespace vss {

class VssProto {
public:
    static void SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param);
    static void CreateHashMessage(
        const dht::NodePtr& local_node,
        uint64_t random_hash,
        uint64_t tm_height,
        uint64_t elect_height,
        transport::protobuf::Header& msg);
    static void CreateRandomMessage(
        const dht::NodePtr& local_node,
        uint64_t random,
        uint64_t tm_height,
        uint64_t elect_height,
        transport::protobuf::Header& msg);
    static void CreateSplitRandomMessage(
        const dht::NodePtr& local_node,
        uint64_t split_index,
        uint64_t split_random,
        uint64_t tm_height,
        uint64_t elect_height,
        transport::protobuf::Header& msg);

private:
    VssProto() {}
    ~VssProto() {}

    DISALLOW_COPY_AND_ASSIGN(VssProto);
};

}  // namespace vss

}  // namespace tenon
