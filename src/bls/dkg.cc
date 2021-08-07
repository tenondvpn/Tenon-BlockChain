#include "bls/dkg.h"

#include <vector>

#include <bls/bls_utils.h>

#include "bls/bls_utils.h"
#include "common/global_info.h"
#include "dht/dht_key.h"
#include "election/elect_manager.h"
#include "network/route.h"
#include "security/signature.h"
#include "security/crypto_utils.h"
#include "security/schnorr.h"
#include "security/crypto.h"

namespace tenon {

namespace bls {

Dkg::Dkg() {
    network::Route::Instance()->RegisterMessage(
        common::kBlsMessage,
        std::bind(&Dkg::HandleMessage, this, std::placeholders::_1));
}

Dkg::~Dkg() {}

void Dkg::OnNewElectionBlock(uint64_t elect_height, elect::MembersPtr& members) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (elect_height <= elect_hegiht_) {
        return;
    }

    memset(invalid_node_map_, 0, sizeof(invalid_node_map_));
    min_aggree_member_count_ = members_->size() * 2 / 3;
    if ((members_->size() * 2) % 3 > 0) {
        min_aggree_member_count_ += 1;
    }

    dkg_instance_ = std::make_shared<signatures::Dkg>(min_aggree_member_count_, members_->size());
    elect_hegiht_ = elect_height;
    members_ = members;
    local_member_index_ = elect::ElectManager::Instance()->local_node_member_index();
    all_verification_vector_.resize(members->size());
    all_secret_key_contribution_.resize(members->size());
    auto each_member_offset_us = kDkgPeriodUs / members->size();
    local_offset_us_ = each_member_offset_us * local_member_index_;
    dkg_verify_brd_timer_.CutOff(
        kDkgVerifyBrdBeginUs + local_offset_us_,
        std::bind(&Dkg::BroadcastVerfify, this));
    dkg_swap_seckkey_timer_.CutOff(
        kDkgSwapSecKeyBeginUs + local_offset_us_,
        std::bind(&Dkg::SwapSecKey, this));
    dkg_finish_timer_.CutOff(kDkgFinishBeginUs, std::bind(&Dkg::Finish, this));
}

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

    if (bls_msg.has_verify_brd()) {
        HandleVerifyBroadcast(header, bls_msg);
    }

    if (bls_msg.has_swap_req()) {
        HandleSwapSecKey(header, bls_msg);
    }

    if (bls_msg.has_against_req()) {
        HandleAgainstParticipant(header, bls_msg);
    }

    if (bls_msg.has_verify_res()) {
        HandleVerifyBroadcastRes(header, bls_msg);
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
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg) {
    if (!IsSignValid(bls_msg)) {
        return;
    }

    if (bls_msg.verify_brd().verify_vec_size() != members_->size()) {
        return;
    }

    for (int32_t i = 0; i < bls_msg.verify_brd().verify_vec_size(); ++i) {
        auto x_c0 = libff::alt_bn128_Fq(bls_msg.verify_brd().verify_vec(i).x_c0().c_str());
        auto x_c1 = libff::alt_bn128_Fq(bls_msg.verify_brd().verify_vec(i).x_c1().c_str());
        auto x_coord = libff::alt_bn128_Fq2(x_c0, x_c1);
        auto y_c0 = libff::alt_bn128_Fq(bls_msg.verify_brd().verify_vec(i).y_c0().c_str());
        auto y_c1 = libff::alt_bn128_Fq(bls_msg.verify_brd().verify_vec(i).y_c1().c_str());
        auto y_coord = libff::alt_bn128_Fq2(y_c0, y_c1);
        auto z_c0 = libff::alt_bn128_Fq(bls_msg.verify_brd().verify_vec(i).z_c0().c_str());
        auto z_c1 = libff::alt_bn128_Fq(bls_msg.verify_brd().verify_vec(i).z_c1().c_str());
        auto z_coord = libff::alt_bn128_Fq2(z_c0, z_c1);
        all_verification_vector_[bls_msg.index()][i] = libff::alt_bn128_G2(
            x_coord,
            y_coord,
            z_coord);
    }
}

void Dkg::HandleVerifyBroadcastRes(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg) {
    if (!IsSignValid(bls_msg)) {
        return;
    }

    (*members_)[bls_msg.index()]->public_ip = bls_msg.verify_res().public_ip();
    (*members_)[bls_msg.index()]->public_port = bls_msg.verify_res().public_port();
}

void Dkg::HandleSwapSecKey(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg) {
    auto dec_msg = security::Crypto::Instance()->GetDecryptData(
        (*members_)[bls_msg.index()]->pubkey,
        bls_msg.swap_req().sec_key());
    if (dec_msg.empty()) {
        return;
    }

    // swap
    all_secret_key_contribution_[local_member_index_][bls_msg.index()] =
        libff::alt_bn128_Fr(dec_msg.c_str());
    // verify it valid, if not broadcast against.
    if (!dkg_instance_->Verification(
            local_member_index_,
            all_secret_key_contribution_[local_member_index_][bls_msg.index()],
            all_verification_vector_[bls_msg.index()])) {
        all_secret_key_contribution_[local_member_index_][bls_msg.index()] =
            libff::alt_bn128_Fr::zero();
        // send against
        bls::protobuf::BlsMessage bls_msg;
        auto against_req = bls_msg.mutable_against_req();
        against_req->set_against_index(bls_msg.index());
        auto content_to_hash = std::to_string(bls_msg.index());
        transport::protobuf::Header msg;
        auto dht = network::DhtManager::Instance()->GetDht(
            common::GlobalInfo::Instance()->network_id());
        if (!dht) {
            return;
        }

        auto message_hash = common::Hash::keccak256(content_to_hash);
        CreateDkgMessage(dht->local_node(), bls_msg, message_hash, msg);
        network::Route::Instance()->Send(msg);
    }
}

void Dkg::HandleAgainstParticipant(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg) {
    if (!IsSignValid(bls_msg)) {
        return;
    }

    ++invalid_node_map_[bls_msg.against_req().against_index()];
    if (invalid_node_map_[bls_msg.against_req().against_index()] >= min_aggree_member_count_) {
        all_secret_key_contribution_[local_member_index_][bls_msg.against_req().against_index()] =
            libff::alt_bn128_Fr::zero();
    }
}

void Dkg::BroadcastVerfify() {
    std::lock_guard<std::mutex> guard(mutex_);
    CreateContribution();
    bls::protobuf::BlsMessage bls_msg;
    auto verfiy_brd = bls_msg.mutable_verify_brd();
    std::string content_to_hash;
    for (auto iter = all_verification_vector_[local_member_index_].begin();
            iter != all_verification_vector_[local_member_index_].end(); ++iter) {
        auto verify_item = verfiy_brd->add_verify_vec();
        verify_item->set_x_c0(BLSutils::ConvertToString<libff::alt_bn128_Fq>((*iter).X.c0));
        verify_item->set_x_c1(BLSutils::ConvertToString<libff::alt_bn128_Fq>((*iter).X.c1));
        verify_item->set_y_c0(BLSutils::ConvertToString<libff::alt_bn128_Fq>((*iter).Y.c0));
        verify_item->set_y_c1(BLSutils::ConvertToString<libff::alt_bn128_Fq>((*iter).Y.c1));
        verify_item->set_z_c0(BLSutils::ConvertToString<libff::alt_bn128_Fq>((*iter).Z.c0));
        verify_item->set_z_c1(BLSutils::ConvertToString<libff::alt_bn128_Fq>((*iter).Z.c1));
        content_to_hash += verify_item->x_c0();
        content_to_hash += verify_item->x_c1();
        content_to_hash += verify_item->y_c0();
        content_to_hash += verify_item->y_c1();
        content_to_hash += verify_item->z_c0();
        content_to_hash += verify_item->z_c1();
    }

    transport::protobuf::Header msg;
    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        return;
    }

    auto message_hash = common::Hash::keccak256(content_to_hash);
    CreateDkgMessage(dht->local_node(), bls_msg, message_hash, msg);
    network::Route::Instance()->Send(msg);
}

void Dkg::SwapSecKey() {
    std::lock_guard<std::mutex> guard(mutex_);
    for (uint32_t i = 0; i < members_->size(); ++i) {
        if (i == local_member_index_) {
            continue;
        }

        if ((*members_)[i]->public_ip == 0 || (*members_)[i]->public_port == 0) {
            continue;
        }

        auto sec_key = BLSutils::ConvertToString<libff::alt_bn128_Fr>(
            all_secret_key_contribution_[local_member_index_][i]);
        std::string enc_sec_key = security::Crypto::Instance()->GetEncryptData(
            (*members_)[i]->pubkey,
            sec_key);
        if (enc_sec_key.empty()) {
            continue;
        }

        protobuf::BlsMessage bls_msg;
        auto swap_req = bls_msg.mutable_swap_req();
        swap_req->set_sec_key(enc_sec_key);
        transport::protobuf::Header msg;
        auto dht = network::DhtManager::Instance()->GetDht(
            common::GlobalInfo::Instance()->network_id());
        if (!dht) {
            return;
        }

        CreateDkgMessage(dht->local_node(), bls_msg, "", msg);
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
            common::IpUint32ToString((*members_)[i]->public_ip),
            (*members_)[i]->public_port,
            0,
            msg);
    }
}

void Dkg::Finish() {
    local_sec_key_ = dkg_instance_->SecretKeyShareCreate(
        all_secret_key_contribution_[local_member_index_]);
    public_keys_.clear();
    public_keys_.resize(members_->size());
    common_public_key_ = libff::alt_bn128_G2::zero();
    for (size_t i = 0; i < members_->size(); ++i) {
        if (invalid_node_map_[i] >= min_aggree_member_count_) {
            public_keys_[i] = libff::alt_bn128_G2::zero();
            continue;
        }

        public_keys_[i] = all_verification_vector_[i][0];
        common_public_key_ = common_public_key_ + public_keys_[i];
    }
}

int Dkg::CreateContribution() {
    std::vector<libff::alt_bn128_Fr> polynomial = dkg_instance_->GeneratePolynomial();
    all_secret_key_contribution_[local_member_index_] =
        dkg_instance_->SecretKeyContribution(polynomial);
    all_verification_vector_[local_member_index_] = dkg_instance_->VerificationVector(polynomial);
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
    if (!message_hash.empty()) {
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
        auto broad_param = msg.mutable_broadcast();
        SetDefaultBroadcastParam(broad_param);
    }
    
    bls_msg.set_index(local_member_index_);
    msg.set_data(bls_msg.SerializeAsString());
}

};  // namespace bls

};  // namespace tenon
