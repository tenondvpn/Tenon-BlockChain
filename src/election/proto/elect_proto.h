#pragma once

#include "transport/proto/transport.pb.h"
#include "dht/node.h"
#include "common/bloom_filter.h"

namespace tenon {

namespace elect {

class ElectProto {
public:
    static void SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param);
    static void CreateElectBlock(
        const dht::NodePtr& local_node,
        transport::protobuf::Header& msg);
    static void CreateElectWaitingNodes(
        const dht::NodePtr& local_node,
        uint32_t waiting_shard_id,
        const common::BloomFilter& nodes_filter,
        transport::protobuf::Header& msg);

private:
    ElectProto() {}
    ~ElectProto() {}

    DISALLOW_COPY_AND_ASSIGN(ElectProto);
};

}  // namespace elect

}  // namespace tenon
