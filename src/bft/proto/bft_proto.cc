#include "stdafx.h"
#include "bft/proto/bft_proto.h"

#include "bft/bft_utils.h"
#include "bls/bls_manager.h"
#include "common/global_info.h"
#include "common/split.h"
#include "common/string_utils.h"
#include "dht/dht_key.h"
#include "election/elect_manager.h"
#include "network/network_utils.h"
#include "security/schnorr.h"
#include "security/crypto.h"
#include "transport/transport_utils.h"

namespace tenon {

namespace bft {

void BftProto::SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param) {
    broad_param->set_layer_left(0);
    broad_param->set_layer_right(((std::numeric_limits<uint64_t>::max))());
    broad_param->set_ign_bloomfilter_hop(common::kDefaultBroadcastIgnBloomfilterHop);
    broad_param->set_stop_times(common::kDefaultBroadcastStopTimes);
    broad_param->set_hop_limit(common::kDefaultBroadcastHopLimit);
    broad_param->set_hop_to_layer(common::kDefaultBroadcastHopToLayer);
    broad_param->set_neighbor_count(common::kDefaultBroadcastNeighborCount);
}

void BftProto::SetLocalPublicIpPort(
        const dht::NodePtr& local_node,
        bft::protobuf::BftMessage& bft_msg) {
    if (common::GlobalInfo::Instance()->config_first_node()) {
        common::Split<> spliter(
            common::GlobalInfo::Instance()->tcp_spec().c_str(),
            ':',
            common::GlobalInfo::Instance()->tcp_spec().size());
        if (spliter.Count() == 2) {
            bft_msg.set_node_ip(spliter[0]);
            uint16_t port = 0;
            common::StringUtil::ToUint16(spliter[1], &port);
            bft_msg.set_node_port(port);
        }
    } else {
        bft_msg.set_node_ip(local_node->public_ip());
        bft_msg.set_node_port(local_node->public_port + 1);
    }
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
    msg.set_priority(transport::kTransportPriorityHighest);
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
    bft_msg.set_net_id(bft_ptr->network_id());
    bft_msg.set_bft_step(kBftPrepare);
    bft_msg.set_pool_index(bft_ptr->pool_index());
    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    bft_msg.set_prepare_hash(bft_ptr->prepare_hash());
    bft_msg.set_epoch(bft_ptr->GetEpoch());
    bft_msg.set_member_index(elect::ElectManager::Instance()->local_node_member_index());
    bft_msg.set_elect_height(bft_ptr->elect_height());
    SetLocalPublicIpPort(local_node, bft_msg);
//     msg.set_debug(common::StringUtil::Format("msg id: %lu, leader prepare pool index: %d, step: %d, bft gid: %s",
//         msg.id(), bft_ptr->pool_index(), kBftPrepare, common::Encode::HexEncode(bft_ptr->gid()).c_str()));
    msg.set_data(bft_msg.SerializeAsString());
}

void BftProto::BackupCreatePrepare(
        const transport::protobuf::Header& from_header,
        const bft::protobuf::BftMessage& from_bft_msg,
        const dht::NodePtr& local_node,
        const std::string& data,
        const BftInterfacePtr& bft_ptr,
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
    bft_msg.set_net_id(from_bft_msg.net_id());
    bft_msg.set_agree(agree);
    bft_msg.set_bft_step(kBftPrepare);
    bft_msg.set_epoch(from_bft_msg.epoch());
    bft_msg.set_member_index(elect::ElectManager::Instance()->local_node_member_index());
    if (bft_ptr->leader_mem_ptr() == nullptr) {
        return;
    }

    std::string bls_sign_x;
    std::string bls_sign_y;
    if (bls::BlsManager::Instance()->Sign(
            from_bft_msg.prepare_hash(),
            &bls_sign_x,
            &bls_sign_y) != bls::kBlsSuccess) {
        return;
    }

    bft_msg.set_bls_sign_x(bls_sign_x);
    bft_msg.set_bls_sign_y(bls_sign_y);
//     std::string enc_data;
//     if (bft_ptr->leader_mem_ptr()->leader_ecdh_key.empty()) {
//         BFT_ERROR("get leader ecdh key failed [%s]",
//             common::Encode::HexDecode(bft_ptr->leader_mem_ptr()->id).c_str());
//         return;
//     }
// 
//     if (security::Crypto::Instance()->GetEncryptData(
//             bft_ptr->leader_mem_ptr()->leader_ecdh_key,
//             sha128,
//             &enc_data) != security::kSecuritySuccess) {
//         return;
//     }

//     bft_msg.set_backup_enc_data(enc_data);
    SetLocalPublicIpPort(local_node, bft_msg);
//     msg.set_debug(common::StringUtil::Format("msg id: %lu, backup prepare pool index: %d, step: %d, bft gid: %s",
//         msg.id(), from_bft_msg.pool_index(), kBftPrepare, common::Encode::HexEncode(from_bft_msg.gid()).c_str()));
    msg.set_data(bft_msg.SerializeAsString());
}

void BftProto::LeaderCreatePreCommit(
        const dht::NodePtr& local_node,
        const BftInterfacePtr& bft_ptr,
        bool agree,
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
    bft_msg.set_net_id(bft_ptr->network_id());
    bft_msg.set_bft_step(kBftPreCommit);
    bft_msg.set_pool_index(bft_ptr->pool_index());
    bft_msg.set_agree(agree);
    bft_msg.set_elect_height(bft_ptr->elect_height());
    if (agree) {
        bft_msg.set_member_index(elect::ElectManager::Instance()->local_node_member_index());
    }

    const auto& bitmap_data = bft_ptr->prepare_bitmap().data();
    for (uint32_t i = 0; i < bitmap_data.size(); ++i) {
        bft_msg.add_bitmap(bitmap_data[i]);
    }

    auto& bls_precommit_sign = bft_ptr->bls_precommit_agg_sign();
    bft_msg.set_bls_sign_x(BLSutils::ConvertToString<libff::alt_bn128_Fq>(bls_precommit_sign->X));
    bft_msg.set_bls_sign_y(BLSutils::ConvertToString<libff::alt_bn128_Fq>(bls_precommit_sign->Y));
    security::Signature leader_sign;
    if (!security::Schnorr::Instance()->Sign(
            bft_ptr->precommit_hash(),
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
    bft_msg.set_prepare_hash(bft_ptr->prepare_hash());
    bft_msg.set_epoch(bft_ptr->GetEpoch());
    SetLocalPublicIpPort(local_node, bft_msg);
//     msg.set_debug(common::StringUtil::Format("msg id: %lu, leader precommit pool index: %d, step: %d, bft gid: %s",
//         msg.id(), bft_ptr->pool_index(), kBftPreCommit, common::Encode::HexEncode(bft_ptr->gid()).c_str()));
    msg.set_data(bft_msg.SerializeAsString());
}

void BftProto::BackupCreatePreCommit(
        const transport::protobuf::Header& from_header,
        const bft::protobuf::BftMessage& from_bft_msg,
        const dht::NodePtr& local_node,
        const std::string& data,
        bool agree,
        const std::string& sign_hash,
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
    bft_msg.set_net_id(from_bft_msg.net_id());
    bft_msg.set_agree(agree);
    bft_msg.set_bft_step(kBftPreCommit);
    bft_msg.set_epoch(from_bft_msg.epoch());
    bft_msg.set_member_index(elect::ElectManager::Instance()->local_node_member_index());
    std::string bls_sign_x;
    std::string bls_sign_y;
    if (bls::BlsManager::Instance()->Sign(
            sign_hash,
            &bls_sign_x,
            &bls_sign_y) != bls::kBlsSuccess) {
        return;
    }

    bft_msg.set_bls_sign_x(bls_sign_x);
    bft_msg.set_bls_sign_y(bls_sign_y);
    SetLocalPublicIpPort(local_node, bft_msg);
    msg.set_data(bft_msg.SerializeAsString());
}

void BftProto::LeaderCreateCommit(
        const dht::NodePtr& local_node,
        const BftInterfacePtr& bft_ptr,
        bool agree,
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
    bft_msg.set_data(bft_ptr->prepare_hash());
    bft_msg.set_leader(false);
    bft_msg.set_gid(bft_ptr->gid());
    bft_msg.set_net_id(bft_ptr->network_id());
    bft_msg.set_bft_step(kBftCommit);
    bft_msg.set_pool_index(bft_ptr->pool_index());
    bft_msg.set_member_index(elect::ElectManager::Instance()->local_node_member_index());
    bft_msg.set_agree(agree);
    const auto& bitmap_data = bft_ptr->precommit_bitmap().data();
    std::string msg_hash_src = bft_ptr->precommit_hash();
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
    bft_msg.set_prepare_hash(bft_ptr->prepare_hash());
    bft_msg.set_epoch(bft_ptr->GetEpoch());
    SetLocalPublicIpPort(local_node, bft_msg);
//     msg.set_debug(common::StringUtil::Format("msg id: %lu, leader kBftCommit pool index: %d, step: %d, bft gid: %s",
//         msg.id(), bft_ptr->pool_index(), kBftCommit, common::Encode::HexEncode(bft_ptr->gid()).c_str()));
    msg.set_data(bft_msg.SerializeAsString());
}

void BftProto::CreateLeaderBroadcastToAccount(
        const dht::NodePtr& local_node,
        uint32_t net_id,
        uint32_t message_type,
        uint32_t bft_step,
        bool universal,
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
    msg.set_universal(universal);
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
    bft_msg.set_member_index(elect::ElectManager::Instance()->local_node_member_index());
    auto block_hash = GetBlockHash(*block);
    block->set_hash(block_hash);
//     security::Signature sign;
//     bool sign_res = security::Schnorr::Instance()->Sign(
//         block_hash,
//         *(security::Schnorr::Instance()->prikey()),
//         *(security::Schnorr::Instance()->pubkey()),
//         sign);
//     if (!sign_res) {
//         BFT_ERROR("signature error.");
//         return;
//     }
// 
//     std::string sign_challenge_str;
//     std::string sign_response_str;
//     sign.Serialize(sign_challenge_str, sign_response_str);
//     bft_msg.set_sign_challenge(sign_challenge_str);
//     bft_msg.set_sign_response(sign_response_str);
    msg.set_data(bft_msg.SerializeAsString());
}

}  // namespace bft

}  // namespace tenon
