#include "bls/bls_dkg.h"

#include <vector>
#include <fstream>

#include <bls/bls_utils.h>
#include <dkg/dkg.h>

#include "bls/bls_utils.h"
#include "common/global_info.h"
#include "common//db_key_prefix.h"
#include "dht/dht_key.h"
#include "db/db.h"
#include "election/elect_manager.h"
#include "network/route.h"
#include "json/json.hpp"
#include "security/signature.h"
#include "security/crypto_utils.h"
#include "security/schnorr.h"
#include "security/crypto.h"
#include "vss/vss_manager.h"

namespace tenon {

namespace bls {

BlsDkg::BlsDkg() {
    network::Route::Instance()->RegisterMessage(
        common::kBlsMessage,
        std::bind(&BlsDkg::HandleMessage, this, std::placeholders::_1));
}

BlsDkg::~BlsDkg() {}

void BlsDkg::OnNewElectionBlock(
        uint64_t elect_height,
        elect::MembersPtr& members) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (elect_height <= elect_hegiht_) {
        return;
    }

    finished_ = false;
    // destroy old timer
    dkg_verify_brd_timer_.Destroy();
    dkg_swap_seckkey_timer_.Destroy();
    dkg_finish_timer_.Destroy();

    valid_sec_key_count_ = 0;
    members_ = members;
    memset(invalid_node_map_, 0, sizeof(invalid_node_map_));
    min_aggree_member_count_ = common::GetSignerCount(members_->size());
    dkg_instance_ = std::make_shared<signatures::Dkg>(min_aggree_member_count_, members_->size());
    elect_hegiht_ = elect_height;
    local_member_index_ = elect::ElectManager::Instance()->local_node_member_index();
    all_verification_vector_.clear();
    all_verification_vector_.resize(members->size());
    for (uint32_t i = 0; i < members->size(); ++i) {
        all_verification_vector_[i] = std::vector<libff::alt_bn128_G2>(
            min_aggree_member_count_,
            libff::alt_bn128_G2::zero());
    }

    all_secret_key_contribution_.clear();
    all_secret_key_contribution_.resize(members->size());
    for (uint32_t i = 0; i < members->size(); ++i) {
        all_secret_key_contribution_[i].push_back(libff::alt_bn128_Fr::zero());
    }

    auto each_member_offset_us = kDkgWorkPeriodUs / members->size();
    local_offset_us_ = each_member_offset_us * local_member_index_;
    dkg_verify_brd_timer_.CutOff(
        kDkgVerifyBrdBeginUs + local_offset_us_,
        std::bind(&BlsDkg::BroadcastVerfify, this));
    dkg_swap_seckkey_timer_.CutOff(
        kDkgSwapSecKeyBeginUs + local_offset_us_,
        std::bind(&BlsDkg::SwapSecKey, this));
    dkg_finish_timer_.CutOff(kDkgFinishBeginUs, std::bind(&BlsDkg::Finish, this));
    BLS_DEBUG("bls OnNewElectionBlock called! verify brd tm: %ld, swap: %ld, finish: %ld,"
        "local_offset_us_: %ld, each_member_offset_us: %ld",
        kDkgVerifyBrdBeginUs + local_offset_us_,
        kDkgSwapSecKeyBeginUs + local_offset_us_,
        kDkgFinishBeginUs,
        local_offset_us_,
        each_member_offset_us);
}

void BlsDkg::HandleMessage(const transport::TransportMessagePtr& header_ptr) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (finished_) {
        return;
    }

    if (members_ == nullptr) {
        BLS_ERROR("members_ == nullptr");
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
        BLS_ERROR("bls_msg.index() >= members_->size()");
        return;
    }

    if (bls_msg.elect_height() != elect_hegiht_) {
        BLS_ERROR("bls_msg.elect_height() != elect_hegiht_: %lu, %lu",
            bls_msg.elect_height(), elect_hegiht_);
        return;
    }

    BLS_DEBUG("HandleMessage comming!has_verify_brd: %d,"
        "has_swap_req: %d, has_against_req: %d, has_verify_res: %d",
        bls_msg.has_verify_brd(),
        bls_msg.has_swap_req(),
        bls_msg.has_against_req(),
        bls_msg.has_verify_res());
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

bool BlsDkg::IsSignValid(const protobuf::BlsMessage& bls_msg) {
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
    } else if (bls_msg.has_verify_res()) {
        content_to_hash = bls_msg.verify_res().public_ip() + "_" +
            std::to_string(bls_msg.verify_res().public_port());
    }

    auto message_hash = common::Hash::keccak256(content_to_hash);
    auto& pubkey = (*members_)[bls_msg.index()]->pubkey;
    auto sign = security::Signature(bls_msg.sign_ch(), bls_msg.sign_res());
    if (!security::Schnorr::Instance()->Verify(message_hash, sign, pubkey)) {
        std::string str_pk;
        pubkey.Serialize(str_pk);
        BLS_ERROR("security::Schnorr::Instance()->Verify failed! hash: %s, index: %d, public key: %s",
            common::Encode::HexEncode(message_hash).c_str(),
            bls_msg.index(),
            common::Encode::HexEncode(str_pk).c_str());
        return false;
    }

    return true;
}

void BlsDkg::HandleVerifyBroadcast(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg) {
    if (!IsSignValid(bls_msg)) {
        BLS_ERROR("sign verify failed!");
        return;
    }

    if (bls_msg.verify_brd().verify_vec_size() < min_aggree_member_count_) {
        BLS_ERROR("bls_msg.verify_brd().verify_vec_size() < min_aggree_member_count_");
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

    SendVerifyBrdResponse(
        bls_msg.verify_brd().public_ip(),
        bls_msg.verify_brd().public_port());
}

void BlsDkg::HandleVerifyBroadcastRes(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg) {
    if (!IsSignValid(bls_msg)) {
        return;
    }

    (*members_)[bls_msg.index()]->public_ip = bls_msg.verify_res().public_ip();
    (*members_)[bls_msg.index()]->public_port = bls_msg.verify_res().public_port();
}

void BlsDkg::HandleSwapSecKey(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg) {
    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        return;
    }

    if (dht->local_node()->dht_key() != header.des_dht_key()) {
        dht->SendToClosestNode(header);
        BLS_ERROR("local dht key: %s, des dht key: %s",
            common::Encode::HexEncode(dht->local_node()->dht_key()).c_str(),
            common::Encode::HexEncode(header.des_dht_key()).c_str());
        return;
    }

    auto dec_msg = security::Crypto::Instance()->GetDecryptData(
        (*members_)[bls_msg.index()]->pubkey,
        bls_msg.swap_req().sec_key());
    if (dec_msg.empty()) {
        BLS_ERROR("dec_msg.empty()");
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
        BLS_ERROR("dkg_instance_->Verification failed!local_member_index_: %d, remote idx: %d",
            local_member_index_,
            bls_msg.index());
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
#ifdef TENON_UNITTEST
        sec_against_msgs_.push_back(msg);
#endif
        return;
    }

    ++valid_sec_key_count_;
    BLS_DEBUG("handle swap sec key success: %d", bls_msg.index());
}

void BlsDkg::HandleAgainstParticipant(
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

void BlsDkg::BroadcastVerfify() {
    std::lock_guard<std::mutex> guard(mutex_);
    if (members_ == nullptr || local_member_index_ >= members_->size()) {
        return;
    }

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

    if (common::GlobalInfo::Instance()->config_first_node()) {
        verfiy_brd->set_public_ip(common::GlobalInfo::Instance()->config_local_ip());
        verfiy_brd->set_public_port(common::GlobalInfo::Instance()->config_local_port() + 1);
    } else {
        verfiy_brd->set_public_ip(dht->local_node()->public_ip());
        verfiy_brd->set_public_port(dht->local_node()->public_port + 1);
    }

    auto message_hash = common::Hash::keccak256(content_to_hash);
    CreateDkgMessage(dht->local_node(), bls_msg, message_hash, msg);
    network::Route::Instance()->Send(msg);
    auto& pubkey = (*members_)[bls_msg.index()]->pubkey;
    std::string tmp_pk_str;
    pubkey.Serialize(tmp_pk_str);
    BLS_DEBUG("bls BroadcastVerfify called hash: %s, index: %d, public key: %s, tmp pk: %s!",
        common::Encode::HexEncode(message_hash).c_str(),
        local_member_index_,
        common::Encode::HexEncode(security::Schnorr::Instance()->str_pubkey()).c_str(),
        common::Encode::HexEncode(tmp_pk_str).c_str());

#ifdef TENON_UNITTEST
    ver_brd_msg_ = msg;
#endif
}

void BlsDkg::SwapSecKey() {
    std::lock_guard<std::mutex> guard(mutex_);
    if (members_ == nullptr || local_member_index_ >= members_->size()) {
        return;
    }

#ifdef TENON_UNITTEST
    sec_swap_msgs_.clear();
#endif
    for (uint32_t i = 0; i < members_->size(); ++i) {
        transport::protobuf::Header msg;
        if (i == local_member_index_) {
#ifdef TENON_UNITTEST
            sec_swap_msgs_.push_back(msg);
#endif
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
        auto dht = network::DhtManager::Instance()->GetDht(
            common::GlobalInfo::Instance()->network_id());
        if (!dht) {
            return;
        }

        CreateDkgMessage(dht->local_node(), bls_msg, "", msg);
        if (transport::MultiThreadHandler::Instance()->tcp_transport() != nullptr) {
            dht::DhtKeyManager dht_key(
                common::GlobalInfo::Instance()->network_id(),
                0,
                (*members_)[i]->id);
            msg.set_des_dht_key(dht_key.StrKey());
            if ((*members_)[i]->public_ip.empty() || (*members_)[i]->public_port == 0) {
                network::Route::Instance()->Send(msg);
            } else {
                transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                    (*members_)[i]->public_ip,
                    (*members_)[i]->public_port,
                    0,
                    msg);
                BLS_DEBUG("bls SwapSecKey called! %s:%d", (*members_)[i]->public_ip.c_str(), (*members_)[i]->public_port);
            }
        }

#ifdef TENON_UNITTEST
        sec_swap_msgs_.push_back(msg);
#endif
    }
}

void BlsDkg::SendVerifyBrdResponse(const std::string& from_ip, uint16_t from_port) {
    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        return;
    }
    
    protobuf::BlsMessage bls_msg;
    auto verify_res = bls_msg.mutable_verify_res();
    verify_res->set_public_ip(dht->local_node()->public_ip());
    verify_res->set_public_port(dht->local_node()->public_port + 1);
    std::string str_to_hash = dht->local_node()->public_ip() + "_" +
        std::to_string(dht->local_node()->public_port + 1);
    auto message_hash = common::Hash::keccak256(str_to_hash);
    transport::protobuf::Header msg;
    CreateDkgMessage(dht->local_node(), bls_msg, message_hash, msg);
    if (transport::MultiThreadHandler::Instance()->tcp_transport() != nullptr) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
            from_ip,
            from_port,
            0,
            msg);
    }
}

void BlsDkg::DumpLocalPrivateKey() {
    // encrypt by private key and save to db
    std::string enc_data;
    std::string sec_key = BLSutils::ConvertToString<libff::alt_bn128_Fr>(local_sec_key_);
    if (security::Crypto::Instance()->GetEncryptData(
            security::Schnorr::Instance()->str_prikey(),
            sec_key,
            &enc_data) != security::kSecuritySuccess) {
        return;
    }

    std::string key = common::kBlsPrivateKeyPrefix +
        std::to_string(elect_hegiht_) + "_" +
        std::to_string(common::GlobalInfo::Instance()->network_id());
    db::Db::Instance()->Put(key, enc_data);
}

void BlsDkg::Finish() {
    std::lock_guard<std::mutex> guard(mutex_);
    std::cout << "bls finish called valid_sec_key_count_: " << valid_sec_key_count_
        << ", min_aggree_member_count_: " << min_aggree_member_count_
        << std::endl;
    if (members_ == nullptr ||
            local_member_index_ >= members_->size() ||
            valid_sec_key_count_ < min_aggree_member_count_) {
        return;
    }

    local_sec_key_ = dkg_instance_->SecretKeyShareCreate(
        all_secret_key_contribution_[local_member_index_]);
    DumpLocalPrivateKey();
    common_public_key_ = libff::alt_bn128_G2::zero();
    for (size_t i = 0; i < members_->size(); ++i) {
        if (invalid_node_map_[i] >= min_aggree_member_count_) {
            continue;
        }

        common_public_key_ = common_public_key_ + all_verification_vector_[i][0];
    }

    local_publick_key_ = dkg_instance_->GetPublicKeyFromSecretKey(local_sec_key_);
    finished_ = true;
    std::string sec_key = BLSutils::ConvertToString<libff::alt_bn128_Fr>(local_sec_key_);
    common_public_key_.to_affine_coordinates();
    std::cout << "bls finish, local sec key: " << sec_key
        << ", common pubkey: "
        << BLSutils::ConvertToString<libff::alt_bn128_Fq>(common_public_key_.X.c0) << ","
        << BLSutils::ConvertToString<libff::alt_bn128_Fq>(common_public_key_.X.c1) << ","
        << BLSutils::ConvertToString<libff::alt_bn128_Fq>(common_public_key_.Y.c0) << ","
        << BLSutils::ConvertToString<libff::alt_bn128_Fq>(common_public_key_.Y.c1)
        << std::endl;
}

void BlsDkg::CreateContribution() {
    std::vector<libff::alt_bn128_Fr> polynomial = dkg_instance_->GeneratePolynomial();
    all_secret_key_contribution_[local_member_index_] =
        dkg_instance_->SecretKeyContribution(polynomial);
    all_verification_vector_[local_member_index_] = dkg_instance_->VerificationVector(polynomial);
    ++valid_sec_key_count_;
}

void BlsDkg::DumpContribution() {
    nlohmann::json data;
    data["idx"] = std::to_string(local_member_index_);
    for (size_t i = 0; i < members_->size(); ++i) {
        data["secret_key_contribution"][std::to_string(i)] =
            BLSutils::ConvertToString< libff::alt_bn128_Fr >(
                all_secret_key_contribution_[local_member_index_][i]);
    }

    for (size_t i = 0; i < min_aggree_member_count_; ++i) {
        data["verification_vector"][std::to_string(i)]["X"]["c0"] =
            BLSutils::ConvertToString< libff::alt_bn128_Fq >(
                all_verification_vector_[local_member_index_][i].X.c0);
        data["verification_vector"][std::to_string(i)]["X"]["c1"] =
            BLSutils::ConvertToString< libff::alt_bn128_Fq >(
                all_verification_vector_[local_member_index_][i].X.c1);
        data["verification_vector"][std::to_string(i)]["Y"]["c0"] =
            BLSutils::ConvertToString< libff::alt_bn128_Fq >(
                all_verification_vector_[local_member_index_][i].Y.c0);
        data["verification_vector"][std::to_string(i)]["Y"]["c1"] =
            BLSutils::ConvertToString< libff::alt_bn128_Fq >(
                all_verification_vector_[local_member_index_][i].Y.c1);
        data["verification_vector"][std::to_string(i)]["Z"]["c0"] =
            BLSutils::ConvertToString< libff::alt_bn128_Fq >(
                all_verification_vector_[local_member_index_][i].Z.c0);
        data["verification_vector"][std::to_string(i)]["Z"]["c1"] =
            BLSutils::ConvertToString< libff::alt_bn128_Fq >(
                all_verification_vector_[local_member_index_][i].Z.c1);
    }

    std::ofstream outfile("data_for_" + std::to_string(local_member_index_) + "-th_participant.json");
    outfile << data.dump(4) << "\n\n";

}

void BlsDkg::SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param) {
    broad_param->set_layer_left(0);
    broad_param->set_layer_right((std::numeric_limits<uint64_t>::max)());
    broad_param->set_ign_bloomfilter_hop(common::kDefaultBroadcastIgnBloomfilterHop);
    broad_param->set_stop_times(common::kDefaultBroadcastStopTimes);
    broad_param->set_hop_limit(common::kDefaultBroadcastHopLimit);
    broad_param->set_hop_to_layer(common::kDefaultBroadcastHopToLayer);
    broad_param->set_neighbor_count(common::kDefaultBroadcastNeighborCount);
}

void BlsDkg::CreateDkgMessage(
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
    
    bls_msg.set_elect_height(elect_hegiht_);
    bls_msg.set_index(local_member_index_);
    msg.set_data(bls_msg.SerializeAsString());
}

};  // namespace bls

};  // namespace tenon
