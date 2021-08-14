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
    static void SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param);
    static void LeaderCreatePrepare(
        const dht::NodePtr& local_node,
        const std::string& data,
        const BftInterfacePtr& bft_ptr,
        const security::Signature& sign,
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
        transport::protobuf::Header& msg);

    // create backup prepare signature: gid + rand + net_id + local_id + status + + secret + agree
    static std::string GetPrepareSignHash(const bft::protobuf::BftMessage& bft_msg) {
        std::string prepare_sign_data = bft_msg.gid() + "_" +
            std::to_string(bft_msg.net_id()) + "_" +
            std::to_string(bft_msg.member_index()) + "_" +
            std::to_string(bft_msg.bft_step()) + "_" +
            bft_msg.secret() + "_" +
            std::to_string(bft_msg.agree());
        return common::Hash::keccak256(prepare_sign_data);
    }

//     static int CreateBackupPrepareSignature(bft::protobuf::BftMessage& bft_msg) {
//         security::Signature sign;
//         std::string sha128 = GetPrepareSignHash(bft_msg);
//         bool sign_res = security::Schnorr::Instance()->Sign(
//             sha128,
//             *(security::Schnorr::Instance()->prikey().get()),
//             *(security::Schnorr::Instance()->pubkey().get()),
//             sign);
//         if (!sign_res) {
//             BFT_ERROR("signature error.");
//             return kBftError;
//         }
// 
//         std::string sign_challenge_str;
//         std::string sign_response_str;
//         sign.Serialize(sign_challenge_str, sign_response_str);
//         bft_msg.set_sign_challenge(sign_challenge_str);
//         bft_msg.set_sign_response(sign_response_str);
//         return kBftSuccess;
//     }

    // create backup prepare signature: gid + rand + net_id + local_id + status + + response + agree
    static std::string GetPrecommitSignHash(const bft::protobuf::BftMessage& bft_msg) {
        std::string prepare_sign_data = bft_msg.gid() + "_" +
            std::to_string(bft_msg.net_id()) + "_" +
            std::to_string(bft_msg.member_index()) + "_" +
            std::to_string(bft_msg.bft_step()) + "_" +
            bft_msg.response() + "_" +
            std::to_string(bft_msg.agree());
        return common::Hash::keccak256(prepare_sign_data);
    }

    static int CreateBackupPrecommitSignature(bft::protobuf::BftMessage& bft_msg) {
        security::Signature sign;
        std::string sha128 = GetPrecommitSignHash(bft_msg);
        bool sign_res = security::Schnorr::Instance()->Sign(
            sha128,
            *(security::Schnorr::Instance()->prikey().get()),
            *(security::Schnorr::Instance()->pubkey().get()),
            sign);
        if (!sign_res) {
            BFT_ERROR("signature error.");
            return kBftError;
        }

        std::string sign_challenge_str;
        std::string sign_response_str;
        sign.Serialize(sign_challenge_str, sign_response_str);
        bft_msg.set_sign_challenge(sign_challenge_str);
        bft_msg.set_sign_response(sign_response_str);
        return kBftSuccess;
    }

private:
    static void SetLocalPublicIpPort(
        const dht::NodePtr& local_node,
        bft::protobuf::BftMessage& bft_msg);

    DISALLOW_COPY_AND_ASSIGN(BftProto);
};

}  // namespace bft

}  // namespace tenon
