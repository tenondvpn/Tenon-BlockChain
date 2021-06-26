#include "vss/proto/vss_proto.h"

#include "common/user_property_key_define.h"
#include "dht/dht_key.h"
#include "election/elect_manager.h"
#include "network/network_utils.h"
#include "security/schnorr.h"
#include "security/ecdh_create_key.h"
#include "security/crypto.h"
#include "transport/transport_utils.h"
#include "vss/vss_utils.h"

namespace tenon {

namespace vss {

void VssProto::SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param) {
    broad_param->set_layer_left(0);
    broad_param->set_layer_right((std::numeric_limits<uint64_t>::max)());
    broad_param->set_ign_bloomfilter_hop(common::kDefaultBroadcastIgnBloomfilterHop);
    broad_param->set_stop_times(common::kDefaultBroadcastStopTimes);
    broad_param->set_hop_limit(common::kDefaultBroadcastHopLimit);
    broad_param->set_hop_to_layer(common::kDefaultBroadcastHopToLayer);
    broad_param->set_neighbor_count(common::kDefaultBroadcastNeighborCount);
}

void VssProto::CreateHashMessage(
        const dht::NodePtr& local_node,
        uint64_t random_hash,
        uint64_t tm_height,
        uint64_t elect_height,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    dht::DhtKeyManager dht_key(network::kRootCongressNetworkId, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kVssMessage);
    msg.set_client(local_node->client_mode);
    msg.set_universal(false);
    msg.set_hop_count(0);
    vss::protobuf::VssMessage vss_msg;
    vss_msg.set_random_hash(random_hash);
    vss_msg.set_tm_height(tm_height);
    vss_msg.set_elect_height(elect_height);
    vss_msg.set_type(kVssRandomHash);
    std::string hash_str = std::to_string(random_hash) + "_" +
        std::to_string(tm_height) + "_" +
        std::to_string(elect_height) + "_" +
        common::GlobalInfo::Instance()->id();
    auto message_hash = common::Hash::keccak256(hash_str);
    security::Signature sign;
    bool sign_res = security::Schnorr::Instance()->Sign(
        message_hash,
        *(security::Schnorr::Instance()->prikey()),
        *(security::Schnorr::Instance()->pubkey()),
        sign);
    if (!sign_res) {
        VSS_ERROR("signature error.");
        return;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    vss_msg.set_sign_ch(sign_challenge_str);
    vss_msg.set_sign_res(sign_response_str);
    vss_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    msg.set_data(vss_msg.SerializeAsString());
}

void VssProto::CreateRandomMessage(
        const dht::NodePtr& local_node,
        uint64_t random,
        uint64_t tm_height,
        uint64_t elect_height,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    dht::DhtKeyManager dht_key(network::kRootCongressNetworkId, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kVssMessage);
    msg.set_client(local_node->client_mode);
    msg.set_universal(false);
    msg.set_hop_count(0);
    vss::protobuf::VssMessage vss_msg;
    vss_msg.set_random(random);
    vss_msg.set_tm_height(tm_height);
    vss_msg.set_elect_height(elect_height);
    vss_msg.set_type(kVssRandom);
    std::string hash_str = std::to_string(random) + "_" +
        std::to_string(tm_height) + "_" +
        std::to_string(elect_height) + "_" +
        common::GlobalInfo::Instance()->id();
    auto message_hash = common::Hash::keccak256(hash_str);
    security::Signature sign;
    bool sign_res = security::Schnorr::Instance()->Sign(
        message_hash,
        *(security::Schnorr::Instance()->prikey()),
        *(security::Schnorr::Instance()->pubkey()),
        sign);
    if (!sign_res) {
        VSS_ERROR("signature error.");
        return;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    vss_msg.set_sign_ch(sign_challenge_str);
    vss_msg.set_sign_res(sign_response_str);
    vss_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    msg.set_data(vss_msg.SerializeAsString());
}

void VssProto::CreateFirstSplitRandomMessage(
        const dht::NodePtr& local_node,
        uint64_t split_index,
        uint64_t split_random,
        uint64_t tm_height,
        uint64_t elect_height,
        const std::string& des_id,
        transport::protobuf::Header& msg) {
    auto mem_ptr = elect::ElectManager::Instance()->GetMember(
        elect_height,
        network::kRootCongressNetworkId,
        des_id);
    if (mem_ptr == nullptr) {
        return;
    }

    msg.set_src_dht_key(local_node->dht_key());
    dht::DhtKeyManager dht_key(network::kRootCongressNetworkId, 0, des_id);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kVssMessage);
    msg.set_client(local_node->client_mode);
    msg.set_universal(false);
    msg.set_hop_count(0);
    vss::protobuf::VssMessage vss_msg;
    vss_msg.set_split_index(split_index);
    vss_msg.set_split_random(split_random);
    vss_msg.set_tm_height(tm_height);
    vss_msg.set_elect_height(elect_height);
    vss_msg.set_type(kVssFirstRandomSplit);
    std::string hash_str = std::to_string(split_index) + "_" +
        std::to_string(split_random) + "_" +
        std::to_string(tm_height) + "_" +
        std::to_string(elect_height) + "_" +
        common::GlobalInfo::Instance()->id();
    auto message_hash = common::Hash::keccak256(hash_str);
    std::string crypt_data = security::Crypto::Instance()->GetEncryptData(
        mem_ptr->pubkey,
        message_hash);
    if (crypt_data.empty()) {
        return;
    }

    vss_msg.set_crypt_data(crypt_data);
    security::Signature sign;
    bool sign_res = security::Schnorr::Instance()->Sign(
        message_hash,
        *(security::Schnorr::Instance()->prikey()),
        *(security::Schnorr::Instance()->pubkey()),
        sign);
    if (!sign_res) {
        VSS_ERROR("signature error.");
        return;
    }

    std::string test_pubkey;
    mem_ptr->pubkey.Serialize(test_pubkey);
    std::cout << " public key: " << common::Encode::HexEncode(test_pubkey) << ", id: " << common::Encode::HexEncode(des_id) << std::endl;
    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    vss_msg.set_sign_ch(sign_challenge_str);
    vss_msg.set_sign_res(sign_response_str);
    vss_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    msg.set_data(vss_msg.SerializeAsString());
}

void VssProto::CreateThirdSplitRandomMessage(
        const dht::NodePtr& local_node,
        protobuf::VssMessage& vss_msg,
        uint64_t tm_height,
        uint64_t elect_height,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    dht::DhtKeyManager dht_key(network::kRootCongressNetworkId, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kVssMessage);
    msg.set_client(local_node->client_mode);
    msg.set_universal(false);
    msg.set_hop_count(0);
    vss_msg.set_tm_height(tm_height);
    vss_msg.set_elect_height(elect_height);
    vss_msg.set_type(kVssThirdRandomSplit);
    std::string hash_str = std::to_string(tm_height) + "_" +
        std::to_string(elect_height) + "_";
    for (int32_t i = 0; i < vss_msg.all_split_random_size(); ++i) {
        hash_str += vss_msg.all_split_random(i).id() + "_" +
            std::to_string(vss_msg.all_split_random(i).split_index()) + "_" +
            std::to_string(vss_msg.all_split_random(i).split_random()) + "_";
    }

    auto message_hash = common::Hash::keccak256(hash_str);
    security::Signature sign;
    bool sign_res = security::Schnorr::Instance()->Sign(
        message_hash,
        *(security::Schnorr::Instance()->prikey()),
        *(security::Schnorr::Instance()->pubkey()),
        sign);
    if (!sign_res) {
        VSS_ERROR("signature error.");
        return;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    vss_msg.set_sign_ch(sign_challenge_str);
    vss_msg.set_sign_res(sign_response_str);
    vss_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    msg.set_data(vss_msg.SerializeAsString());
}

}  // namespace vss

}  // namespace tenon
