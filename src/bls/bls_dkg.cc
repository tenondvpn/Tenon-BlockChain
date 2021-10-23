#include "bls/bls_dkg.h"

#include <vector>
#include <fstream>

#include <libbls/tools/utils.h>
#include <dkg/dkg.h>

#include "bls/bls_utils.h"
#include "common/global_info.h"
#include "common/db_key_prefix.h"
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

BlsDkg::BlsDkg(uint32_t t,
        uint32_t n,
        const libff::alt_bn128_Fr& local_sec_key,
        const libff::alt_bn128_G2 local_publick_key,
        const libff::alt_bn128_G2 common_public_key)
        : min_aggree_member_count_(t),
        member_count_(n),
        local_sec_key_(local_sec_key),
        local_publick_key_(local_publick_key),
        common_public_key_(common_public_key){}

BlsDkg::~BlsDkg() {}

void BlsDkg::OnNewElectionBlock(
        uint64_t elect_height,
        elect::MembersPtr& members) try {
//     if (common::GlobalInfo::Instance()->missing_node()) {
//         return;
//     }

//     std::cout << "new election block: " << elect_height << std::endl;
    std::lock_guard<std::mutex> guard(mutex_);
    if (elect_height <= elect_hegiht_) {
        return;
    }

    finished_ = false;
    // destroy old timer
    dkg_verify_brd_timer_.Destroy();
    dkg_swap_seckkey_timer_.Destroy();
    dkg_finish_timer_.Destroy();

    max_finish_count_ = 0;
    max_finish_hash_ = "";
    valid_sec_key_count_ = 0;
    members_ = members;
    memset(invalid_node_map_, 0, sizeof(invalid_node_map_));
    min_aggree_member_count_ = common::GetSignerCount(members_->size());
    member_count_ = members_->size();
    dkg_instance_ = std::make_shared<crypto::Dkg>(min_aggree_member_count_, members_->size());
    elect_hegiht_ = elect_height;
    for (uint32_t i = 0; i < members_->size(); ++i) {
        if ((*members_)[i]->id == common::GlobalInfo::Instance()->id()) {
            local_member_index_ = i;
            break;
        }
    }

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
    if (!common::GlobalInfo::Instance()->missing_node()) {
        dkg_swap_seckkey_timer_.CutOff(
            kDkgSwapSecKeyBeginUs + local_offset_us_,
            std::bind(&BlsDkg::SwapSecKey, this));
        dkg_finish_timer_.CutOff(
            kDkgFinishBeginUs + local_offset_us_,
            std::bind(&BlsDkg::Finish, this));
    }

    BLS_INFO("BlsDkg::OnNewElectionBlock coming: %lu, member size: %u", elect_height, members_->size());
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
}

void BlsDkg::HandleMessage(const transport::TransportMessagePtr& header_ptr) try {
    if (common::GlobalInfo::Instance()->missing_node()) {
        return;
    }

    std::lock_guard<std::mutex> guard(mutex_);
//     if (finished_) {
//         return;
//     }
// 
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
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
}

bool BlsDkg::IsSignValid(const protobuf::BlsMessage& bls_msg, std::string* content_to_hash) {
    if (!security::IsValidSignature(bls_msg.sign_ch(), bls_msg.sign_res())) {
        BLS_ERROR("invalid sign: %s, %s!",
            common::Encode::HexEncode(bls_msg.sign_ch()),
            common::Encode::HexEncode(bls_msg.sign_res()));
        return false;
    }

    if (bls_msg.has_verify_brd()) {
        for (int32_t i = 0; i < bls_msg.verify_brd().verify_vec_size(); ++i) {
            *content_to_hash += bls_msg.verify_brd().verify_vec(i).x_c0() +
                bls_msg.verify_brd().verify_vec(i).x_c1() +
                bls_msg.verify_brd().verify_vec(i).y_c0() +
                bls_msg.verify_brd().verify_vec(i).y_c1() +
                bls_msg.verify_brd().verify_vec(i).z_c0() +
                bls_msg.verify_brd().verify_vec(i).z_c1();
        }
    } else if (bls_msg.has_against_req()) {
        *content_to_hash = std::to_string(bls_msg.against_req().against_index());
    } else if (bls_msg.has_verify_res()) {
        *content_to_hash = bls_msg.verify_res().public_ip() + "_" +
            std::to_string(bls_msg.verify_res().public_port());
    } else if (bls_msg.has_finish_req()) {
        for (int32_t i = 0; i < bls_msg.finish_req().bitmap_size(); ++i) {
            *content_to_hash += std::to_string(bls_msg.finish_req().bitmap(i));
        }
    }

    *content_to_hash = common::Hash::keccak256(*content_to_hash);
    auto& pubkey = (*members_)[bls_msg.index()]->pubkey;
    assert(pubkey.ec_point() != nullptr);
    auto sign = security::Signature(bls_msg.sign_ch(), bls_msg.sign_res());
    if (!security::Schnorr::Instance()->Verify(*content_to_hash, sign, pubkey)) {
        return false;
    }

    return true;
}

void BlsDkg::HandleVerifyBroadcast(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg) try {
    std::string msg_hash;
    if (!IsSignValid(bls_msg, &msg_hash)) {
        BLS_ERROR("sign verify failed!");
        return;
    }

    if (bls_msg.verify_brd().verify_vec_size() < (int32_t)min_aggree_member_count_) {
        BLS_ERROR("bls_msg.verify_brd().verify_vec_size() < min_aggree_member_count_");
        return;
    }

    BLS_DEBUG("receive verify broadcast local: %d, remote: %d, all: %d",
        local_member_index_, bls_msg.index(), members_->size());
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
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
}

void BlsDkg::HandleVerifyBroadcastRes(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg) {
    std::string msg_hash;
    if (!IsSignValid(bls_msg, &msg_hash)) {
        return;
    }

    (*members_)[bls_msg.index()]->public_ip = bls_msg.verify_res().public_ip();
    (*members_)[bls_msg.index()]->public_port = bls_msg.verify_res().public_port();
}

void BlsDkg::HandleSwapSecKey(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg) try {
    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        return;
    }

#ifndef TENON_UNITTEST
    if (dht->local_node()->dht_key() != header.des_dht_key()) {
        dht->SendToClosestNode(header);
        BLS_ERROR("local dht key: %s, des dht key: %s",
            common::Encode::HexEncode(dht->local_node()->dht_key()).c_str(),
            common::Encode::HexEncode(header.des_dht_key()).c_str());
        return;
    }
#endif

    auto dec_msg = security::Crypto::Instance()->GetDecryptData(
        (*members_)[bls_msg.index()]->pubkey,
        bls_msg.swap_req().sec_key());
    if (dec_msg.empty()) {
        BLS_ERROR("dec_msg.empty()");
        return;
    }

    std::string sec_key(dec_msg.substr(0, bls_msg.swap_req().sec_key_len()));
//     std::string peer_pk;
//     (*members_)[bls_msg.index()]->pubkey.Serialize(peer_pk);
//     std::cout << "handle sec_key: " << common::Encode::HexEncode(sec_key)
//         << ", enc_sec_key: " << common::Encode::HexEncode(bls_msg.swap_req().sec_key())
//         << ", local pk: " << common::Encode::HexEncode(security::Schnorr::Instance()->str_pubkey())
//         << ", peer pk: " << common::Encode::HexEncode(peer_pk)
//         << ", local index: " << local_member_index_
//         << ", peer index: " << bls_msg.index()
//         << std::endl;
    if (!IsValidBigInt(sec_key)) {
        BLS_ERROR("invalid big int[%s]", sec_key.c_str());
        assert(false);
        return;
    }

    BLS_DEBUG("bls swaped sec key local: %d, remote: %d, all: %d£¬ valid_sec_key_count_: %u",
        local_member_index_, bls_msg.index(), all_secret_key_contribution_.size(), valid_sec_key_count_);
    // swap
    all_secret_key_contribution_[local_member_index_][bls_msg.index()] =
        libff::alt_bn128_Fr(sec_key.c_str());
    // verify it valid, if not broadcast against.
    if (!dkg_instance_->Verification(
            local_member_index_,
            all_secret_key_contribution_[local_member_index_][bls_msg.index()],
            all_verification_vector_[bls_msg.index()])) {
//         assert(false);
        TENON_DEBUG("dkg_instance_->Verification failed!elect height: %lu,"
            "local_member_index_: %d, remote idx: %d, %s:%d\n",
            elect_hegiht_,
            local_member_index_,
            bls_msg.index(),
            header.from_ip().c_str(),
            header.from_port());
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
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
}

void BlsDkg::HandleAgainstParticipant(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg) {
    std::string msg_hash;
    if (!IsSignValid(bls_msg, &msg_hash)) {
        return;
    }

    ++invalid_node_map_[bls_msg.against_req().against_index()];
    if (invalid_node_map_[bls_msg.against_req().against_index()] >= min_aggree_member_count_) {
        all_secret_key_contribution_[local_member_index_][bls_msg.against_req().against_index()] =
            libff::alt_bn128_Fr::zero();
    }
}

void BlsDkg::BroadcastVerfify() try {
//     if (common::GlobalInfo::Instance()->network_id() < network::kRootCongressNetworkId ||
//             common::GlobalInfo::Instance()->network_id() >= network::kConsensusShardEndNetworkId) {
//         return;
//     }

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
        verify_item->set_x_c0(crypto::ThresholdUtils::fieldElementToString((*iter).X.c0));
        verify_item->set_x_c1(crypto::ThresholdUtils::fieldElementToString((*iter).X.c1));
        verify_item->set_y_c0(crypto::ThresholdUtils::fieldElementToString((*iter).Y.c0));
        verify_item->set_y_c1(crypto::ThresholdUtils::fieldElementToString((*iter).Y.c1));
        verify_item->set_z_c0(crypto::ThresholdUtils::fieldElementToString((*iter).Z.c0));
        verify_item->set_z_c1(crypto::ThresholdUtils::fieldElementToString((*iter).Z.c1));
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
#ifdef TENON_UNITTEST
    ver_brd_msg_ = msg;
#endif
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
}

void BlsDkg::SwapSecKey() try {
//     if (common::GlobalInfo::Instance()->network_id() < network::kRootCongressNetworkId ||
//             common::GlobalInfo::Instance()->network_id() >= network::kConsensusShardEndNetworkId) {
//         return;
//     }
    std::lock_guard<std::mutex> guard(mutex_);
//     for (uint32_t i = 0; i < all_verification_vector_.size(); ++i) {
//         if (all_verification_vector_[i][0] == libff::alt_bn128_G2::zero()) {
//             return;
//         }
//     }

    if (members_ == nullptr || local_member_index_ >= members_->size()) {
        return;
    }

    if (local_src_secret_key_contribution_.size() != members_->size()) {
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

        auto sec_key = crypto::ThresholdUtils::fieldElementToString(
            local_src_secret_key_contribution_[i]);
        std::string enc_sec_key = security::Crypto::Instance()->GetEncryptData(
            (*members_)[i]->pubkey,
            sec_key);
        if (enc_sec_key.empty()) {
            continue;
        }

//         std::string peer_pk;
//         (*members_)[i]->pubkey.Serialize(peer_pk);
//         std::cout << "sec_key: " << common::Encode::HexEncode(sec_key)
//             << ", enc_sec_key: " << common::Encode::HexEncode(enc_sec_key)
//             << ", local pk: " << common::Encode::HexEncode(security::Schnorr::Instance()->str_pubkey())
//             << ", peer pk: " << common::Encode::HexEncode(peer_pk)
//             << ", local index: " << local_member_index_
//             << ", peer index: " << i
//             << std::endl;

        protobuf::BlsMessage bls_msg;
        auto swap_req = bls_msg.mutable_swap_req();
        swap_req->set_sec_key(enc_sec_key);
        swap_req->set_sec_key_len(sec_key.size());
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
            }
        }

#ifdef TENON_UNITTEST
        sec_swap_msgs_.push_back(msg);
#endif
    }
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
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
    std::string sec_key = crypto::ThresholdUtils::fieldElementToString(local_sec_key_);
    if (security::Crypto::Instance()->GetEncryptData(
            security::Schnorr::Instance()->str_prikey(),
            sec_key,
            &enc_data) != security::kSecuritySuccess) {
        return;
    }

    std::string key = common::kBlsPrivateKeyPrefix +
        std::to_string(elect_hegiht_) + "_" +
        std::to_string(common::GlobalInfo::Instance()->network_id()) + "_" +
        common::GlobalInfo::Instance()->id();
    db::Db::Instance()->Put(key, enc_data);
}

void BlsDkg::Finish() try {
//     if (common::GlobalInfo::Instance()->network_id() < network::kRootCongressNetworkId ||
//             common::GlobalInfo::Instance()->network_id() >= network::kConsensusShardEndNetworkId) {
//         return;
//     }
// 
    std::lock_guard<std::mutex> guard(mutex_);
//     for (uint32_t i = 0; i < all_verification_vector_.size(); ++i) {
//         if (all_verification_vector_[i][0] == libff::alt_bn128_G2::zero()) {
//             return;
//         }
//     }

    if (members_ == nullptr ||
            local_member_index_ >= members_->size() ||
            valid_sec_key_count_ < min_aggree_member_count_) {
        return;
    }

    uint32_t bitmap_size = members_->size() / 64 * 64;
    if (members_->size() % 64 > 0) {
        bitmap_size += 64;
    }

    common::Bitmap bitmap(bitmap_size);
    common_public_key_ = libff::alt_bn128_G2::zero();
    std::vector<libff::alt_bn128_Fr> valid_seck_keys;
    for (size_t i = 0; i < members_->size(); ++i) {
        if (all_secret_key_contribution_[local_member_index_][i] == libff::alt_bn128_Fr::zero() ||
                all_verification_vector_[i][0] == libff::alt_bn128_G2::zero()) {
            valid_seck_keys.push_back(libff::alt_bn128_Fr::zero());
            common_public_key_ = common_public_key_ + libff::alt_bn128_G2::zero();
        } else {
            valid_seck_keys.push_back(all_secret_key_contribution_[local_member_index_][i]);
            common_public_key_ = common_public_key_ + all_verification_vector_[i][0];
            bitmap.Set(i);
        }
    }

    if (bitmap.valid_count() < members_->size() * kBlsMaxExchangeMembersRatio) {
        return;
    }

    crypto::Dkg dkg(min_aggree_member_count_, members_->size());
    local_sec_key_ = dkg.SecretKeyShareCreate(
        valid_seck_keys);
    local_publick_key_ = dkg.GetPublicKeyFromSecretKey(local_sec_key_);
    DumpLocalPrivateKey();
    BroadcastFinish(bitmap);
    finished_ = true;
} catch (std::exception& e) {
    local_sec_key_ = libff::alt_bn128_Fr::zero();
    BLS_ERROR("catch error: %s", e.what());
}

void BlsDkg::BroadcastFinish(const common::Bitmap& bitmap) {
    protobuf::BlsMessage bls_msg;
    auto finish_msg = bls_msg.mutable_finish_req();
    auto& data = bitmap.data();
    std::string msg_for_hash;
    for (auto iter = data.begin(); iter != data.end(); ++iter) {
        finish_msg->add_bitmap(*iter);
        msg_for_hash += std::to_string(*iter);
    }

    msg_for_hash += std::string("_") +
        std::to_string(common::GlobalInfo::Instance()->network_id());
    auto message_hash = common::Hash::keccak256(msg_for_hash);
    transport::protobuf::Header msg;
    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        return;
    }

    local_publick_key_.to_affine_coordinates();
    auto local_pk = finish_msg->mutable_pubkey();
    local_pk->set_x_c0(
        crypto::ThresholdUtils::fieldElementToString(local_publick_key_.X.c0));
    local_pk->set_x_c1(
        crypto::ThresholdUtils::fieldElementToString(local_publick_key_.X.c1));
    local_pk->set_y_c0(
        crypto::ThresholdUtils::fieldElementToString(local_publick_key_.Y.c0));
    local_pk->set_y_c1(
        crypto::ThresholdUtils::fieldElementToString(local_publick_key_.Y.c1));
    finish_msg->set_network_id(common::GlobalInfo::Instance()->network_id());
    auto common_pk = finish_msg->mutable_common_pubkey();
    common_public_key_.to_affine_coordinates();
    common_pk->set_x_c0(
        crypto::ThresholdUtils::fieldElementToString(common_public_key_.X.c0));
    common_pk->set_x_c1(
        crypto::ThresholdUtils::fieldElementToString(common_public_key_.X.c1));
    common_pk->set_y_c0(
        crypto::ThresholdUtils::fieldElementToString(common_public_key_.Y.c0));
    common_pk->set_y_c1(
        crypto::ThresholdUtils::fieldElementToString(common_public_key_.Y.c1));
    CreateDkgMessage(dht->local_node(), bls_msg, message_hash, msg);

#ifndef TENON_UNITTEST
    network::Route::Instance()->Send(msg);
    network::Route::Instance()->SendToLocal(msg);
#endif

    {
        std::string sec_key = crypto::ThresholdUtils::fieldElementToString(local_sec_key_);
        TENON_DEBUG("local bls info sec key: %s, "
            "local public key: %s, %s, %s, %s, "
            "common public key: %s, %s, %s, %s\n",
            sec_key.c_str(),
            local_pk->x_c0().c_str(),
            local_pk->x_c1().c_str(),
            local_pk->y_c0().c_str(),
            local_pk->y_c1().c_str(),
            common_pk->x_c0().c_str(),
            common_pk->x_c1().c_str(),
            common_pk->y_c0().c_str(),
            common_pk->y_c1().c_str());
    }

}

void BlsDkg::CreateContribution() {
    std::vector<libff::alt_bn128_Fr> polynomial = dkg_instance_->GeneratePolynomial();
    all_secret_key_contribution_[local_member_index_] =
        dkg_instance_->SecretKeyContribution(polynomial);
    local_src_secret_key_contribution_ = all_secret_key_contribution_[local_member_index_];
    all_verification_vector_[local_member_index_] = dkg_instance_->VerificationVector(polynomial);
    ++valid_sec_key_count_;
}

void BlsDkg::DumpContribution() {
    nlohmann::json data;
    data["idx"] = std::to_string(local_member_index_);
    for (size_t i = 0; i < members_->size(); ++i) {
        data["secret_key_contribution"][std::to_string(i)] =
            crypto::ThresholdUtils::fieldElementToString(
                all_secret_key_contribution_[local_member_index_][i]);
    }

    for (size_t i = 0; i < min_aggree_member_count_; ++i) {
        data["verification_vector"][std::to_string(i)]["X"]["c0"] =
            crypto::ThresholdUtils::fieldElementToString(
                all_verification_vector_[local_member_index_][i].X.c0);
        data["verification_vector"][std::to_string(i)]["X"]["c1"] =
            crypto::ThresholdUtils::fieldElementToString(
                all_verification_vector_[local_member_index_][i].X.c1);
        data["verification_vector"][std::to_string(i)]["Y"]["c0"] =
            crypto::ThresholdUtils::fieldElementToString(
                all_verification_vector_[local_member_index_][i].Y.c0);
        data["verification_vector"][std::to_string(i)]["Y"]["c1"] =
            crypto::ThresholdUtils::fieldElementToString(
                all_verification_vector_[local_member_index_][i].Y.c1);
        data["verification_vector"][std::to_string(i)]["Z"]["c0"] =
            crypto::ThresholdUtils::fieldElementToString(
                all_verification_vector_[local_member_index_][i].Z.c0);
        data["verification_vector"][std::to_string(i)]["Z"]["c1"] =
            crypto::ThresholdUtils::fieldElementToString(
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
    if (bls_msg.has_finish_req()) {
        dht::DhtKeyManager dht_key(network::kRootCongressNetworkId, 0);
        msg.set_des_dht_key(dht_key.StrKey());
    } else {
        dht::DhtKeyManager dht_key(common::GlobalInfo::Instance()->network_id(), 0);
        msg.set_des_dht_key(dht_key.StrKey());
    }

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
