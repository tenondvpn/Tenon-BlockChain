#include "bls/bls_dkg.h"

#include <vector>
#include <fstream>

#include <libbls/tools/utils.h>
#include <dkg/dkg.h>

#include "bls/bls_utils.h"
#include "bls/bls_manager.h"
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
#include "timeblock/time_block_manager.h"
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

void BlsDkg::Destroy() {
    dkg_verify_brd_timer_.Destroy();
    dkg_swap_seckkey_timer_.Destroy();
    dkg_finish_timer_.Destroy();
}

void BlsDkg::OnNewElectionBlock(
        uint64_t elect_height,
        elect::MembersPtr& members) try {
    std::lock_guard<std::mutex> guard(mutex_);
    if (elect_height <= elect_hegiht_) {
        return;
    }

    memset(valid_swaped_keys_, 0, sizeof(valid_swaped_keys_));
    memset(has_swaped_keys_, 0, sizeof(has_swaped_keys_));
    finished_ = false;
    // destroy old timer
    dkg_verify_brd_timer_.Destroy();
    dkg_swap_seckkey_timer_.Destroy();
    dkg_finish_timer_.Destroy();
    max_finish_count_ = 0;
    max_finish_hash_ = "";
    valid_sec_key_count_ = 0;
    members_ = members;
    valid_swapkey_set_.clear();
//     memset(invalid_node_map_, 0, sizeof(invalid_node_map_));
    min_aggree_member_count_ = common::GetSignerCount(members_->size());
    member_count_ = members_->size();
    dkg_instance_ = std::make_shared<libBLS::Dkg>(min_aggree_member_count_, members_->size());
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

    auto tmblock_tm = tmblock::TimeBlockManager::Instance()->LatestTimestamp() * 1000l * 1000l;
    begin_time_us_ = common::TimeUtils::TimestampUs();
    auto ver_offset = kDkgPeriodUs;
    auto swap_offset = kDkgPeriodUs * 4;
    auto finish_offset = kDkgPeriodUs * 8;
    auto timeblock_period = common::kTimeBlockCreatePeriodSeconds * 1000l * 1000l;
    auto offset_period = timeblock_period / 3l;
    if (begin_time_us_ < tmblock_tm + offset_period) {
        kDkgPeriodUs = (timeblock_period - offset_period) / 10l;
        ver_offset = tmblock_tm + offset_period - begin_time_us_;
        begin_time_us_ = tmblock_tm + offset_period - kDkgPeriodUs;
        swap_offset = ver_offset + kDkgPeriodUs * 3;
        finish_offset = ver_offset + kDkgPeriodUs * 7;
    }

    ver_offset += rand() % (kDkgPeriodUs * 2);
    swap_offset += rand() % (kDkgPeriodUs * 2);
    finish_offset += rand() % kDkgPeriodUs;
    swapkey_valid_ = true;
    dkg_verify_brd_timer_.CutOff(
        ver_offset,
        std::bind(&BlsDkg::BroadcastVerfify, this));
    dkg_swap_seckkey_timer_.CutOff(
        swap_offset,
        std::bind(&BlsDkg::SwapSecKey, this));
    dkg_finish_timer_.CutOff(
        finish_offset,
        std::bind(&BlsDkg::Finish, this));
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
}

void BlsDkg::HandleMessage(const transport::TransportMessagePtr& header_ptr) try {
    std::lock_guard<std::mutex> guard(mutex_);
    if (members_ == nullptr) {
        BLS_ERROR("members_ == nullptr");
        return;
    }

    if (local_member_index_ == common::kInvalidUint32) {
        BLS_INFO("bls create HandleSwapSecKey block elect_height: %lu", elect_hegiht_);
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

    if (members_->size() <= bls_msg.index()) {
        BLS_ERROR("members_->size() <= bls_msg.index(): %d, %d",
            members_->size(), bls_msg.index());
        return;
    }

    if (bls_msg.index() >= members_->size()) {
        BLS_ERROR("bls_msg.index() >= members_->size()");
        return;
    }

    if (bls_msg.elect_height() == 0 || bls_msg.elect_height() != elect_hegiht_) {
        BLS_ERROR("bls_msg.elect_height() != elect_height: %lu, %lu",
            bls_msg.elect_height(), elect_hegiht_);
        return;
    }

    if (bls_msg.has_verify_brd()) {
        HandleVerifyBroadcast(header, bls_msg);
    }

    if (bls_msg.has_swap_req()) {
        HandleSwapSecKey(header, bls_msg);
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
    } else if (bls_msg.has_swap_req()) {
        for (int32_t i = 0; i < bls_msg.swap_req().keys_size(); ++i) {
            *content_to_hash += bls_msg.swap_req().keys(i).sec_key();
        }
    } else {
        return false;
    }

    *content_to_hash = common::Hash::keccak256(*content_to_hash);
    auto& pubkey = (*members_)[bls_msg.index()]->pubkey;
    assert(pubkey.ec_point() != nullptr);
    auto sign = security::Signature(bls_msg.sign_ch(), bls_msg.sign_res());
    if (!security::Schnorr::Instance()->Verify(*content_to_hash, sign, pubkey)) {
        BLS_INFO("bls create IsSignValid error block elect_height: %lu", elect_hegiht_);
        return false;
    }

    return true;
}

void BlsDkg::HandleVerifyBroadcast(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg) try {
    if (!IsVerifyBrdPeriod()) {
        return;
    }

    std::string msg_hash;
    if (!IsSignValid(bls_msg, &msg_hash)) {
        BLS_ERROR("sign verify failed!");
        return;
    }

    if (bls_msg.verify_brd().verify_vec_size() < (int32_t)min_aggree_member_count_) {
        BLS_ERROR("bls_msg.verify_brd().verify_vec_size() < min_aggree_member_count_");
        return;
    }

    if (all_verification_vector_.size() <= bls_msg.index()) {
        return;
    }

    if (all_verification_vector_[bls_msg.index()].size() !=
            (uint32_t)bls_msg.verify_brd().verify_vec_size()) {
        BLS_ERROR("all_verification_vector_[bls_msg.index()].size() != "
            "bls_msg.verify_brd().verify_vec_size()[%d: %d]",
            all_verification_vector_[bls_msg.index()].size(),
            bls_msg.verify_brd().verify_vec_size());
        assert(false);
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

    BLS_DEBUG("success hanlde verify broadcast: %d, elect_height: %lu",
        bls_msg.index(), bls_msg.elect_height());
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
}

void BlsDkg::HandleSwapSecKey(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg) try {
    if (!IsSwapKeyPeriod()) {
        return;
    }

    if (all_secret_key_contribution_.size() <= local_member_index_) {
        return;
    }

    if (all_secret_key_contribution_[local_member_index_].size() <= bls_msg.index()) {
        BLS_ERROR("all_secret_key_contribution_[local_member_index_].size() <= bls_msg.index(): %d, %d",
            all_secret_key_contribution_[local_member_index_].size(), bls_msg.index());
        return;
    }

    if (bls_msg.swap_req().keys_size() <= local_member_index_) {
        return;
    }

    std::string msg_hash;
    if (!IsSignValid(bls_msg, &msg_hash)) {
        BLS_ERROR("sign verify failed!");
        return;
    }

    auto dec_msg = security::Crypto::Instance()->GetDecryptData(
        (*members_)[bls_msg.index()]->pubkey,
        bls_msg.swap_req().keys(local_member_index_).sec_key());
    if (dec_msg.empty()) {
        BLS_ERROR("dec_msg.empty()");
        return;
    }

    std::string sec_key(dec_msg.substr(
        0,
        bls_msg.swap_req().keys(local_member_index_).sec_key_len()));
    if (!IsValidBigInt(sec_key)) {
        BLS_ERROR("invalid big int[%s]", sec_key.c_str());
        assert(false);
        return;
    }

    if (has_swaped_keys_[bls_msg.index()]) {
        return;
    }

    // swap
    all_secret_key_contribution_[local_member_index_][bls_msg.index()] =
        libff::alt_bn128_Fr(sec_key.c_str());
    // verify it valid, if not broadcast against.
    if (!dkg_instance_->Verification(
            local_member_index_,
            all_secret_key_contribution_[local_member_index_][bls_msg.index()],
            all_verification_vector_[bls_msg.index()])) {
        TENON_WARN("dkg_instance_->Verification failed!elect_height: %lu,"
            "local_member_index_: %d, remote idx: %d, %s:%d\n",
            elect_hegiht_,
            local_member_index_,
            bls_msg.index(),
            header.from_ip().c_str(),
            header.from_port());
        all_secret_key_contribution_[local_member_index_][bls_msg.index()] =
            libff::alt_bn128_Fr::zero();
        return;
    }

    valid_swapkey_set_.insert(bls_msg.index());
    ++valid_sec_key_count_;
    BLS_DEBUG("HandleSwapSecKey success, index: %d, elect_height: %lu",
        bls_msg.index(), bls_msg.elect_height());
    has_swaped_keys_[bls_msg.index()] = true;
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
}

void BlsDkg::BroadcastVerfify() try {
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
        verify_item->set_x_c0(libBLS::ThresholdUtils::fieldElementToString((*iter).X.c0));
        verify_item->set_x_c1(libBLS::ThresholdUtils::fieldElementToString((*iter).X.c1));
        verify_item->set_y_c0(libBLS::ThresholdUtils::fieldElementToString((*iter).Y.c0));
        verify_item->set_y_c1(libBLS::ThresholdUtils::fieldElementToString((*iter).Y.c1));
        verify_item->set_z_c0(libBLS::ThresholdUtils::fieldElementToString((*iter).Z.c0));
        verify_item->set_z_c1(libBLS::ThresholdUtils::fieldElementToString((*iter).Z.c1));
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
    auto broad_param = msg.mutable_broadcast();
    transport::SetDefaultBroadcastParam(broad_param);
    network::Route::Instance()->Send(msg);
    BLS_DEBUG("BroadcastVerfify new election block elect_height: %lu, local_member_index_: %d", elect_hegiht_, local_member_index_);
#ifdef TENON_UNITTEST
    ver_brd_msg_ = msg;
#endif
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
}

void BlsDkg::SwapSecKey() try {
    std::lock_guard<std::mutex> guard(mutex_);
    if (members_ == nullptr || local_member_index_ >= members_->size()) {
        return;
    }

    if (local_src_secret_key_contribution_.size() != members_->size()) {
        return;
    }

    std::string content_to_hash;
    protobuf::BlsMessage bls_msg;
    auto swap_req = bls_msg.mutable_swap_req();
    for (uint32_t i = 0; i < members_->size(); ++i) {
        auto swap_item = swap_req->add_keys();
        swap_item->set_sec_key("");
        swap_item->set_sec_key_len(0);
        if (valid_swaped_keys_[i]) {
            BLS_DEBUG("valid_swaped_keys_: %d", i);
            continue;
        }

        if (i == local_member_index_) {
            continue;
        }

        std::string seckey;
        int32_t seckey_len = 0;
        CreateSwapKey(i, &seckey, &seckey_len);
        if (seckey_len == 0) {
            continue;
        }

        swap_item->set_sec_key(seckey);
        swap_item->set_sec_key_len(seckey_len);
        content_to_hash += seckey;
    }

    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        return;
    }

    auto message_hash = common::Hash::keccak256(content_to_hash);
    transport::protobuf::Header msg;
    CreateDkgMessage(dht->local_node(), bls_msg, message_hash, msg);
    dht::DhtKeyManager dht_key(common::GlobalInfo::Instance()->network_id(), 0);
    msg.set_des_dht_key(dht_key.StrKey());
    auto broad_param = msg.mutable_broadcast();
    transport::SetDefaultBroadcastParam(broad_param);
    network::Route::Instance()->Send(msg);
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
}

void BlsDkg::CreateSwapKey(uint32_t member_idx, std::string* seckey, int32_t* seckey_len) {
    if (members_ == nullptr || local_member_index_ >= members_->size()) {
        return;
    }

    if (local_src_secret_key_contribution_.size() != members_->size()) {
        return;
    }

    auto sec_key = libBLS::ThresholdUtils::fieldElementToString(
        local_src_secret_key_contribution_[member_idx]);
    *seckey = security::Crypto::Instance()->GetEncryptData(
        (*members_)[member_idx]->pubkey,
        sec_key);
    *seckey_len = sec_key.size();
}

void BlsDkg::DumpLocalPrivateKey() {
    // encrypt by private key and save to db
    std::string enc_data;
    std::string sec_key = libBLS::ThresholdUtils::fieldElementToString(local_sec_key_);
    BLS_DEBUG("DumpLocalPrivateKey sec_key: %s, size: %d", sec_key.c_str(), sec_key.size());
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

void BlsDkg::Finish() {
    std::lock_guard<std::mutex> guard(mutex_);
    FinishNoLock();
}

void BlsDkg::FinishNoLock() try {
    swapkey_valid_ = false;
    if (members_ == nullptr ||
            local_member_index_ >= members_->size() ||
            valid_sec_key_count_ < min_aggree_member_count_) {
        BLS_ERROR("valid count error.valid_sec_key_count_: %d, min_aggree_member_count_: %d, members_ == nullptr: %d, local_member_index_: %d, members_->size(): %d",
            valid_sec_key_count_, min_aggree_member_count_, (members_ == nullptr), local_member_index_, members_->size());
        BLS_INFO("bls create Finish error block elect_height: %lu", elect_hegiht_);
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
        auto iter = valid_swapkey_set_.find(i);
        if (iter == valid_swapkey_set_.end()) {
            valid_seck_keys.push_back(libff::alt_bn128_Fr::zero());
            common_public_key_ = common_public_key_ + libff::alt_bn128_G2::zero();
            BLS_DEBUG("elect_height: %d, invalid swapkey index: %d", elect_hegiht_, i);
            continue;
        }

        if (all_verification_vector_[i][0] == libff::alt_bn128_G2::zero()) {
            valid_seck_keys.push_back(libff::alt_bn128_Fr::zero());
            common_public_key_ = common_public_key_ + libff::alt_bn128_G2::zero();
            BLS_DEBUG("elect_height: %d, invalid all_verification_vector_ index: %d", elect_hegiht_, i);
            continue;
        }

        if (all_secret_key_contribution_[local_member_index_][i] == libff::alt_bn128_Fr::zero()) {
            valid_seck_keys.push_back(libff::alt_bn128_Fr::zero());
            common_public_key_ = common_public_key_ + libff::alt_bn128_G2::zero();
            BLS_DEBUG("elect_height: %d, invalid all_secret_key_contribution_ index: %d", elect_hegiht_, i);
            continue;
        }

        valid_seck_keys.push_back(all_secret_key_contribution_[local_member_index_][i]);
        common_public_key_ = common_public_key_ + all_verification_vector_[i][0];
        bitmap.Set(i);
    }

    uint32_t valid_count = static_cast<uint32_t>((float)members_->size() * kBlsMaxExchangeMembersRatio);
    if (bitmap.valid_count() < valid_count) {
        BLS_ERROR("elect_height: %d, bitmap.valid_count: %u < %u,  members_->size(): %u, kBlsMaxExchangeMembersRatio: %f",
            elect_hegiht_, bitmap.valid_count(), valid_count, members_->size(), kBlsMaxExchangeMembersRatio);
        return;
    }

    libBLS::Dkg dkg(min_aggree_member_count_, members_->size());
    local_sec_key_ = dkg.SecretKeyShareCreate(valid_seck_keys);
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
    BLS_DEBUG("BroadcastFinish: %s", msg_for_hash.c_str());
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
        libBLS::ThresholdUtils::fieldElementToString(local_publick_key_.X.c0));
    local_pk->set_x_c1(
        libBLS::ThresholdUtils::fieldElementToString(local_publick_key_.X.c1));
    local_pk->set_y_c0(
        libBLS::ThresholdUtils::fieldElementToString(local_publick_key_.Y.c0));
    local_pk->set_y_c1(
        libBLS::ThresholdUtils::fieldElementToString(local_publick_key_.Y.c1));
    finish_msg->set_network_id(common::GlobalInfo::Instance()->network_id());
    auto common_pk = finish_msg->mutable_common_pubkey();
    common_public_key_.to_affine_coordinates();
    common_pk->set_x_c0(
        libBLS::ThresholdUtils::fieldElementToString(common_public_key_.X.c0));
    common_pk->set_x_c1(
        libBLS::ThresholdUtils::fieldElementToString(common_public_key_.X.c1));
    common_pk->set_y_c0(
        libBLS::ThresholdUtils::fieldElementToString(common_public_key_.Y.c0));
    common_pk->set_y_c1(
        libBLS::ThresholdUtils::fieldElementToString(common_public_key_.Y.c1));
    std::string sign_x;
    std::string sign_y;
    if (BlsManager::Instance()->Sign(
            min_aggree_member_count_,
            member_count_,
            local_sec_key_,
            message_hash,
            &sign_x,
            &sign_y) != kBlsSuccess) {
        return;
    }

    finish_msg->set_bls_sign_x(sign_x);
    finish_msg->set_bls_sign_y(sign_y);
    CreateDkgMessage(dht->local_node(), bls_msg, message_hash, msg);
    auto broad_param = msg.mutable_broadcast();
    transport::SetDefaultBroadcastParam(broad_param);
    local_publick_key_.to_affine_coordinates();
    std::string sec_key = libBLS::ThresholdUtils::fieldElementToString(local_sec_key_);
    BLS_DEBUG("Finish new election block elect_height: %lu, local_member_index_: %d, sec_key: %s, cpk: %s, %s, %s, %s, pk: %s, %s, %s, %s, msg_hash: %s, signxy: %s, %s",
        elect_hegiht_, local_member_index_, sec_key.c_str(), 
        (common_pk->x_c0()).c_str(),
        (common_pk->x_c1()).c_str(),
        (common_pk->y_c0()).c_str(),
        (common_pk->y_c1()).c_str(),
        (local_pk->x_c0()).c_str(),
        (local_pk->x_c1()).c_str(),
        (local_pk->y_c0()).c_str(),
        (local_pk->y_c1()).c_str(),
        common::Encode::HexEncode(message_hash).c_str(),
        sign_x.c_str(),
        sign_y.c_str());

//     BLS_INFO("broadcast finish network: %d, valid_sec_key_count_: %d, bitmap.valid_count: %d, elect_height: %lu,"
//         "cpk: %s,%s,%s,%s, pk: %s,%s,%s,%s",
//         common::GlobalInfo::Instance()->network_id(), valid_sec_key_count_, bitmap.valid_count(), elect_hegiht_,
//         common_pk->x_c0().c_str(),
//         common_pk->x_c1().c_str(),
//         common_pk->y_c0().c_str(),
//         common_pk->y_c1().c_str(),
//         local_pk->x_c0().c_str(),
//         local_pk->x_c1().c_str(),
//         local_pk->y_c0().c_str(),
//         local_pk->y_c1().c_str());
#ifndef TENON_UNITTEST
    network::Route::Instance()->Send(msg);
    network::Route::Instance()->SendToLocal(msg);
#endif
}

void BlsDkg::CreateContribution() {
    std::vector<libff::alt_bn128_Fr> polynomial = dkg_instance_->GeneratePolynomial();
    all_secret_key_contribution_[local_member_index_] =
        dkg_instance_->SecretKeyContribution(polynomial);
    local_src_secret_key_contribution_ = all_secret_key_contribution_[local_member_index_];
    all_verification_vector_[local_member_index_] = dkg_instance_->VerificationVector(polynomial);
    valid_swapkey_set_.insert(local_member_index_);
    ++valid_sec_key_count_;
}

void BlsDkg::DumpContribution() {
    nlohmann::json data;
    data["idx"] = std::to_string(local_member_index_);
    for (size_t i = 0; i < members_->size(); ++i) {
        data["secret_key_contribution"][std::to_string(i)] =
            libBLS::ThresholdUtils::fieldElementToString(
                all_secret_key_contribution_[local_member_index_][i]);
    }

    for (size_t i = 0; i < min_aggree_member_count_; ++i) {
        data["verification_vector"][std::to_string(i)]["X"]["c0"] =
            libBLS::ThresholdUtils::fieldElementToString(
                all_verification_vector_[local_member_index_][i].X.c0);
        data["verification_vector"][std::to_string(i)]["X"]["c1"] =
            libBLS::ThresholdUtils::fieldElementToString(
                all_verification_vector_[local_member_index_][i].X.c1);
        data["verification_vector"][std::to_string(i)]["Y"]["c0"] =
            libBLS::ThresholdUtils::fieldElementToString(
                all_verification_vector_[local_member_index_][i].Y.c0);
        data["verification_vector"][std::to_string(i)]["Y"]["c1"] =
            libBLS::ThresholdUtils::fieldElementToString(
                all_verification_vector_[local_member_index_][i].Y.c1);
        data["verification_vector"][std::to_string(i)]["Z"]["c0"] =
            libBLS::ThresholdUtils::fieldElementToString(
                all_verification_vector_[local_member_index_][i].Z.c0);
        data["verification_vector"][std::to_string(i)]["Z"]["c1"] =
            libBLS::ThresholdUtils::fieldElementToString(
                all_verification_vector_[local_member_index_][i].Z.c1);
    }

    std::ofstream outfile("data_for_" + std::to_string(local_member_index_) + "-th_participant.json");
    outfile << data.dump(4) << "\n\n";
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
    msg.set_debug("dkg_msg_debug");
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
    }
    
    bls_msg.set_elect_height(elect_hegiht_);
    bls_msg.set_index(local_member_index_);
    msg.set_data(bls_msg.SerializeAsString());
}

};  // namespace bls

};  // namespace tenon
