#pragma once

#include "transport/proto/transport.pb.h"
#include "dht/dht_utils.h"
#include "common/bloom_filter.h"

namespace tenon {

namespace elect {

class ElectProto {
public:
    static void CreateElectWaitingNodes(
        const dht::NodePtr& local_node,
        uint32_t waiting_shard_id,
        const common::BloomFilter& nodes_filter,
        transport::protobuf::Header& msg);
    static void CreateWaitingHeartbeat(
        const dht::NodePtr& local_node,
        uint32_t waiting_shard_id,
        transport::protobuf::Header& msg);
    static void CreateLeaderRotation(
        const dht::NodePtr& local_node,
        const std::string& leader_id,
        uint32_t pool_mod_num,
        transport::protobuf::Header& msg);
    static void GetBlockZeroKnowledgeProof(
        const std::string& id,
        uint64_t random,
        uint32_t net_id,
        uint64_t max_height,
        uint64_t* max_zkp,
        uint64_t* rand_zkp);

private:
    ElectProto() {}
    ~ElectProto() {}

    DISALLOW_COPY_AND_ASSIGN(ElectProto);
};

}  // namespace elect

}  // namespace tenon
