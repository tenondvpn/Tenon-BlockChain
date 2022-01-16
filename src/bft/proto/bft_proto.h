#pragma once

#include "common/utils.h"
#include "dht/dht_utils.h"
#include "transport/proto/transport.pb.h"
#include "bft/proto/bft.pb.h"
#include "bft/bft_interface.h"
#include "bft/tx_pool.h"

namespace tenon {

namespace bft {

class BftProto {
public:
    static void LeaderCreatePrepare(
        const dht::NodePtr& local_node,
        const std::string& data,
        const BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& msg);
    static void BackupCreatePrepare(
        const transport::protobuf::Header& from_header,
        const bft::protobuf::BftMessage& from_bft_msg,
        const dht::NodePtr& local_node,
        const std::string& data,
        const BftInterfacePtr& bft_ptr,
        bool agree,
        transport::protobuf::Header& msg);
    static void LeaderCreatePreCommit(
        const dht::NodePtr& local_node,
        const BftInterfacePtr& bft_ptr,
        bool oppose,
        transport::protobuf::Header& msg);
    static void BackupCreatePreCommit(
        const transport::protobuf::Header& from_header,
        const bft::protobuf::BftMessage& from_bft_msg,
        const BftInterfacePtr& bft_ptr,
        const dht::NodePtr& local_node,
        const std::string& data,
        bool agree,
        const std::string& sign_hash,
        transport::protobuf::Header& msg);
    static void LeaderCreateCommit(
        const dht::NodePtr& local_node,
        const BftInterfacePtr& bft_ptr,
        bool agree,
        transport::protobuf::Header& msg);
    static void CreateLeaderBroadcastToAccount(
        const dht::NodePtr& local_node,
        uint32_t net_id,
        uint32_t message_type,
        uint32_t bft_step,
        bool universal,
        const std::shared_ptr<bft::protobuf::Block>& block_ptr,
        uint32_t local_member_index,
        transport::protobuf::Header& msg);
    static void SetLocalPublicIpPort(
        const dht::NodePtr& local_node,
        bft::protobuf::BftMessage& bft_msg);

    DISALLOW_COPY_AND_ASSIGN(BftProto);
};

}  // namespace bft

}  // namespace tenon
