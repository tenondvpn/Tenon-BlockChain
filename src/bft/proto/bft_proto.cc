#include "stdafx.h"
#include "bft/proto/bft_proto.h"

#include "common/global_info.h"
#include "security/schnorr.h"
#include "transport/transport_utils.h"
#include "dht/dht_key.h"
#include "network/network_utils.h"
#include "bft/bft_utils.h"

namespace tenon {

namespace bft {

void BftProto::SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param) {
    broad_param->set_layer_left(0);
    broad_param->set_layer_right(((std::numeric_limits<uint64_t>::max))());
    broad_param->set_ign_bloomfilter_hop(kBftBroadcastIgnBloomfilterHop);
    broad_param->set_stop_times(kBftBroadcastStopTimes);
    broad_param->set_hop_limit(kBftHopLimit);
    broad_param->set_hop_to_layer(kBftHopToLayer);
    broad_param->set_neighbor_count(kBftNeighborCount);
}

void BftProto::LeaderCreatePrepare(
        const dht::NodePtr& local_node,
        const std::string& data,
        const BftInterfacePtr& bft_ptr,
        const security::Signature& sign,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    dht::DhtKeyManager dht_key(bft_ptr->network_id(), 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityLow);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_data(data);
    bft_msg.set_leader(false);
    bft_msg.set_gid(bft_ptr->gid());
    bft_msg.set_rand(bft_ptr->rand_num());
    bft_msg.set_net_id(bft_ptr->network_id());
    bft_msg.set_node_id(local_node->id());
    bft_msg.set_bft_step(kBftPrepare);
    bft_msg.set_pool_index(bft_ptr->pool_index());
    bft_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    msg.set_data(bft_msg.SerializeAsString());
}

void BftProto::BackupCreatePrepare(
        const transport::protobuf::Header& from_header,
        const bft::protobuf::BftMessage& from_bft_msg,
        const dht::NodePtr& local_node,
        const std::string& data,
        const security::CommitSecret& secret,
        bool agree,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    msg.set_des_dht_key(from_header.src_dht_key());
    msg.set_des_dht_key_hash(common::Hash::Hash64(from_header.src_dht_key()));
    msg.set_priority(transport::kTransportPriorityLow);
    msg.set_id(from_header.id());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_data(data);
    bft_msg.set_leader(true);
    bft_msg.set_gid(from_bft_msg.gid());
    bft_msg.set_rand(from_bft_msg.rand());
    bft_msg.set_net_id(from_bft_msg.net_id());
    bft_msg.set_node_id(local_node->id());
    bft_msg.set_agree(agree);
    bft_msg.set_bft_step(kBftPrepare);
    bft_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    std::string secret_str;
    secret.Serialize(secret_str);
    bft_msg.set_secret(secret_str);
    if (CreateBackupPrepareSignature(bft_msg) != kBftSuccess) {
        return;
    }

    msg.set_data(bft_msg.SerializeAsString());
}

void BftProto::LeaderCreatePreCommit(
        const dht::NodePtr& local_node,
        const BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    dht::DhtKeyManager dht_key(bft_ptr->network_id(), 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_data(bft_ptr->prepare_hash());
    bft_msg.set_leader(false);
    bft_msg.set_gid(bft_ptr->gid());
    bft_msg.set_rand(bft_ptr->rand_num());
    bft_msg.set_net_id(bft_ptr->network_id());
    bft_msg.set_node_id(local_node->id());
    bft_msg.set_bft_step(kBftPreCommit);
    auto challenge = bft_ptr->challenge();
    std::string challenge_str;
    challenge.Serialize(challenge_str);
    bft_msg.set_challenge(challenge_str);
    security::Signature leader_sign;
    if (!security::Schnorr::Instance()->Sign(
            bft_ptr->prepare_hash(),
            *(security::Schnorr::Instance()->prikey()),
            *(security::Schnorr::Instance()->pubkey()),
            leader_sign)) {
        BFT_ERROR("leader pre commit signature failed!");
        return;
    }
    std::string sign_challenge_str;
    std::string sign_response_str;
    leader_sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    msg.set_data(bft_msg.SerializeAsString());
}

void BftProto::BackupCreatePreCommit(
        const transport::protobuf::Header& from_header,
        const bft::protobuf::BftMessage& from_bft_msg,
        const dht::NodePtr& local_node,
        const std::string& data,
        const security::Response& agg_res,
        bool agree,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    msg.set_des_dht_key(from_header.src_dht_key());
    msg.set_des_dht_key_hash(common::Hash::Hash64(from_header.src_dht_key()));
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(from_header.id());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_data(data);
    bft_msg.set_leader(true);
    bft_msg.set_gid(from_bft_msg.gid());
    bft_msg.set_rand(from_bft_msg.rand());
    bft_msg.set_net_id(from_bft_msg.net_id());
    bft_msg.set_node_id(local_node->id());
    bft_msg.set_agree(agree);
    bft_msg.set_bft_step(kBftPreCommit);
    bft_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    std::string agg_res_str;
    agg_res.Serialize(agg_res_str);
    bft_msg.set_response(agg_res_str);
    if (CreateBackupPrecommitSignature(bft_msg) != kBftSuccess) {
        return;
    }

    msg.set_data(bft_msg.SerializeAsString());
}

void BftProto::LeaderCreateCommit(
        const dht::NodePtr& local_node,
        const BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    dht::DhtKeyManager dht_key(bft_ptr->network_id(), 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_data(bft_ptr->prepare_hash());
    bft_msg.set_leader(false);
    bft_msg.set_gid(bft_ptr->gid());
    bft_msg.set_rand(bft_ptr->rand_num());
    bft_msg.set_net_id(bft_ptr->network_id());
    bft_msg.set_node_id(local_node->id());
    bft_msg.set_bft_step(kBftCommit);
    const auto& bitmap_data = bft_ptr->precommit_bitmap().data();
    std::string msg_hash_src = bft_ptr->prepare_hash();
    for (uint32_t i = 0; i < bitmap_data.size(); ++i) {
        bft_msg.add_bitmap(bitmap_data[i]);
        msg_hash_src += std::to_string(bitmap_data[i]);
    }

    std::string hash_to_sign = common::Hash::Hash256(msg_hash_src);
    security::Signature sign;
    bool sign_res = security::Schnorr::Instance()->Sign(
        hash_to_sign,
        *(security::Schnorr::Instance()->prikey()),
        *(security::Schnorr::Instance()->pubkey()),
        sign);
    if (!sign_res) {
        BFT_ERROR("signature error.");
        return;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    std::string agg_sign_challenge_str;
    std::string agg_sign_response_str;
    bft_ptr->agg_sign()->Serialize(agg_sign_challenge_str, agg_sign_response_str);
    bft_msg.set_agg_sign_challenge(agg_sign_challenge_str);
    bft_msg.set_agg_sign_response(agg_sign_response_str);
    msg.set_data(bft_msg.SerializeAsString());
}

void BftProto::CreateLeaderBroadcastToAccount(
        const dht::NodePtr& local_node,
        uint32_t net_id,
        uint32_t message_type,
        uint32_t bft_step,
        const std::shared_ptr<bft::protobuf::Block>& block_ptr,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    dht::DhtKeyManager dht_key(net_id, common::RandomCountry());
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(message_type);
    msg.set_client(false);
    msg.set_hop_count(0);
    msg.set_universal(true);
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft::protobuf::TxBft tx_bft;
    auto to_tx = tx_bft.mutable_to_tx();
    auto block = to_tx->mutable_block();
    *block = *(block_ptr.get());
    bft_msg.set_data(tx_bft.SerializeAsString());
    bft_msg.set_bft_step(bft_step);
    bft_msg.set_net_id(common::GlobalInfo::Instance()->network_id());
    bft_msg.set_node_id(local_node->id());
    auto block_hash = GetBlockHash(*block);
    block->set_hash(block_hash);
    security::Signature sign;
    bool sign_res = security::Schnorr::Instance()->Sign(
        block_hash,
        *(security::Schnorr::Instance()->prikey()),
        *(security::Schnorr::Instance()->pubkey()),
        sign);
    if (!sign_res) {
        BFT_ERROR("signature error.");
        return;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    msg.set_data(bft_msg.SerializeAsString());
}

}  // namespace bft

}  // namespace tenon
