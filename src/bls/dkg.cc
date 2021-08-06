#include "bls/dkg.h"

#include <vector>

#include "bls/bls_utils.h"
#include "common/global_info.h"
#include "dht/dht_key.h"
#include "election/elect_manager.h"
#include "network/route.h"
#include "security/signature.h"
#include "security/crypto_utils.h"
#include "security/schnorr.h"

namespace tenon {

namespace bls {

Dkg* Dkg::Instance() {
    static Dkg ins;
    return &ins;
}

void Dkg::OnNewElectionBlock(uint64_t elect_height, elect::MembersPtr& members) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (elect_height <= elect_hegiht_) {
        return;
    }

    elect_hegiht_ = elect_height;
    members_ = members;
}

Dkg::Dkg() {
    network::Route::Instance()->RegisterMessage(
        common::kBlsMessage,
        std::bind(&Dkg::HandleMessage, this, std::placeholders::_1));
}

Dkg::~Dkg() {}

void Dkg::HandleMessage(const transport::TransportMessagePtr& header_ptr) {
    if (members_ == nullptr) {
        return;
    }

    auto& header = *header_ptr;
    assert(header.type() == common::kBlsMessage);
    // must verify message signature, to avoid evil node
    protobuf::BlsMessage bls_msg;
    if (!bls_msg.ParseFromString(header.data())) {
        BLS_ERROR("bls_msg.ParseFromString ParseFromString failed!");
        return;
    }

    if (bls_msg.index() >= members_->size()) {
        return;
    }

    if (bls_msg.elect_height() != elect_hegiht_) {
        return;
    }
}

bool Dkg::IsSignValid(const protobuf::BlsMessage& bls_msg) {
    if (!security::IsValidSignature(bls_msg.sign_ch(), bls_msg.sign_res())) {
        BLS_ERROR("invalid sign: %s, %s!",
            common::Encode::HexEncode(bls_msg.sign_ch()),
            common::Encode::HexEncode(bls_msg.sign_res()));
        return false;
    }

    std::string content_to_hash;
    if (bls_msg.has_verify_brd()) {
        for (int32_t i = 0; i < bls_msg.verify_brd().verify_vec_size(); ++i) {
            content_to_hash += bls_msg.verify_brd().verify_vec(i).x_c0() +
                bls_msg.verify_brd().verify_vec(i).x_c1() +
                bls_msg.verify_brd().verify_vec(i).y_c0() +
                bls_msg.verify_brd().verify_vec(i).y_c1() +
                bls_msg.verify_brd().verify_vec(i).z_c0() +
                bls_msg.verify_brd().verify_vec(i).z_c1();
        }
    } else if (bls_msg.has_against_req()) {
        content_to_hash = std::to_string(bls_msg.against_req().against_index());
    }

    auto message_hash = common::Hash::keccak256(content_to_hash);
    auto& pubkey = (*members_)[bls_msg.index()]->pubkey;
    auto sign = security::Signature(bls_msg.sign_ch(), bls_msg.sign_res());
    if (!security::Schnorr::Instance()->Verify(message_hash, sign, pubkey)) {
        BLS_ERROR("security::Schnorr::Instance()->Verify failed!");
        return false;
    }

    return true;
}

void Dkg::HandleVerifyBroadcast(
        const transport::TransportMessagePtr& header,
        const protobuf::BlsMessage& bls_msg) {
    if (!IsSignValid(bls_msg)) {
        return;
    }

}

void Dkg::HandleSwapSecKey(
        const transport::TransportMessagePtr& header,
        const protobuf::BlsMessage& bls_msg) {
}

void Dkg::HandleAgainstParticipant(
        const transport::TransportMessagePtr& header,
        const protobuf::BlsMessage& bls_msg) {
    if (!IsSignValid(bls_msg)) {
        return;
    }
}

void Dkg::BroadcastVerfify() {
    std::lock_guard<std::mutex> guard(mutex_);
    CreateContribution();
}

void Dkg::SwapSecKey() {

}

int Dkg::CreateContribution() {
    auto min_aggree_member_count = members_->size() * 2 / 3;
    if ((members_->size() * 2) % 3 > 0) {
        min_aggree_member_count += 1;
    }

    signatures::Dkg dkg_instance = signatures::Dkg(min_aggree_member_count, members_->size());
    std::vector<libff::alt_bn128_Fr> polynomial = dkg_instance.GeneratePolynomial();
    secret_key_contribution_ = dkg_instance.SecretKeyContribution(polynomial);
    verification_vector_ = dkg_instance.VerificationVector(polynomial);
    return 0;
}

void Dkg::SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param) {
    broad_param->set_layer_left(0);
    broad_param->set_layer_right((std::numeric_limits<uint64_t>::max)());
    broad_param->set_ign_bloomfilter_hop(common::kDefaultBroadcastIgnBloomfilterHop);
    broad_param->set_stop_times(common::kDefaultBroadcastStopTimes);
    broad_param->set_hop_limit(common::kDefaultBroadcastHopLimit);
    broad_param->set_hop_to_layer(common::kDefaultBroadcastHopToLayer);
    broad_param->set_neighbor_count(common::kDefaultBroadcastNeighborCount);
}

void Dkg::CreateDkgMessage(
        const dht::NodePtr& local_node,
        protobuf::BlsMessage& bls_msg,
        const std::string& message_hash,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    dht::DhtKeyManager dht_key(common::GlobalInfo::Instance()->network_id(), 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBlsMessage);
    msg.set_client(local_node->client_mode);
    msg.set_universal(false);
    msg.set_hop_count(0);
    security::Signature sign;
    bool sign_res = security::Schnorr::Instance()->Sign(
        message_hash,
        *(security::Schnorr::Instance()->prikey()),
        *(security::Schnorr::Instance()->pubkey()),
        sign);
    if (!sign_res) {
        BLS_ERROR("signature error.");
        return;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bls_msg.set_sign_ch(sign_challenge_str);
    bls_msg.set_sign_res(sign_response_str);
    bls_msg.set_index(elect::ElectManager::Instance()->local_node_member_index());
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    msg.set_data(bls_msg.SerializeAsString());
}

};  // namespace bls

};  // namespace tenon
