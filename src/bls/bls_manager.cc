#include "bls/bls_manager.h"

#include <dkg/dkg.h>
#include <bls/BLSPrivateKey.h>
#include <bls/BLSPrivateKeyShare.h>
#include <bls/BLSPublicKey.h>
#include <bls/BLSPublicKeyShare.h>
#include <bls/BLSutils.h>
#include <libff/common/profiling.hpp>

#include "bls/bls_sign.h"
#include "common/db_key_prefix.h"
#include "db/db.h"
#include "election/elect_manager.h"
#include "init/init_utils.h"
#include "network/route.h"
#include "security/crypto.h"
#include "security/schnorr.h"

namespace tenon {

namespace bls {

void initLibSnark() noexcept {
    static bool s_initialized = []() noexcept
    {
        libff::inhibit_profiling_info = true;
        libff::inhibit_profiling_counters = true;
        libff::alt_bn128_pp::init_public_params();
        return true;
    }();
    (void)s_initialized;
}

BlsManager* BlsManager::Instance() {
    static BlsManager ins;
    return &ins;
}

void BlsManager::ProcessNewElectBlock(
        uint64_t elect_height,
        elect::MembersPtr& new_members) {
    std::lock_guard<std::mutex> guard(mutex_);
    waiting_bls_ = std::make_shared<bls::BlsDkg>();
    waiting_bls_->OnNewElectionBlock(elect_height, new_members);
}

void BlsManager::SetUsedElectionBlock(
        uint64_t elect_height,
        uint32_t network_id,
        uint32_t member_count,
        const libff::alt_bn128_G2& common_public_key) try {
    std::lock_guard<std::mutex> guard(mutex_);
    if (max_height_ != common::kInvalidUint64 && elect_height <= max_height_) {
        BLS_ERROR("elect_height error: %lu, %lu", elect_height, max_height_);
        return;
    }

    max_height_ = elect_height;
    std::string key = common::kBlsPrivateKeyPrefix +
        std::to_string(elect_height) + "_" +
        std::to_string(network_id) + "_" +
        common::GlobalInfo::Instance()->id();
    std::cout << "get prikey from db: " << common::Encode::HexEncode(key) << std::endl;
    std::string val;
    auto st = db::Db::Instance()->Get(key, &val);
    if (!st.ok()) {
        BLS_ERROR("get bls private key failed![%s]", key.c_str());
        return;
    }

    std::string dec_data;
    if (elect_height <= 4) {
        // for genesis block with sure encrypt key
        if (security::Crypto::Instance()->GetDecryptData(
                init::kGenesisElectPrikeyEncryptKey,
                val,
                &dec_data) != security::kSecuritySuccess) {
            return;
        }
    } else {
        if (security::Crypto::Instance()->GetDecryptData(
                security::Schnorr::Instance()->str_prikey(),
                val,
                &dec_data) != security::kSecuritySuccess) {
            return;
        }
    }
    
    libff::alt_bn128_Fr local_sec_key = libff::alt_bn128_Fr(dec_data.c_str());
    auto t = common::GetSignerCount(member_count);
    signatures::Dkg dkg(t, member_count);
    libff::alt_bn128_G2 local_publick_key = dkg.GetPublicKeyFromSecretKey(local_sec_key);
    used_bls_ = std::make_shared<bls::BlsDkg>();
    used_bls_->SetInitElectionBlock(
        t,
        member_count,
        local_sec_key,
        local_publick_key,
        common_public_key);
    std::cout << "used_bls_->n(): " << used_bls_->n() << std::endl;
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
}

int BlsManager::Sign(
        const std::string& sign_msg,
        libff::alt_bn128_G1* bn_sign) {
    if (used_bls_ == nullptr || used_bls_->n() == 0) {
        return kBlsError;
    }

    BlsSign::Sign(used_bls_->t(), used_bls_->n(), used_bls_->local_sec_key(), sign_msg, bn_sign);
    return kBlsSuccess;
}

int BlsManager::Sign(
        const std::string& sign_msg,
        std::string* sign_x,
        std::string* sign_y) try {
//     std::lock_guard<std::mutex> guard(sign_mutex_);
    if (used_bls_ == nullptr || used_bls_->n() == 0) {
        return kBlsError;
    }

    libff::alt_bn128_G1 bn_sign;
    BlsSign::Sign(used_bls_->t(), used_bls_->n(), used_bls_->local_sec_key(), sign_msg, &bn_sign);
    bn_sign.to_affine_coordinates();
    *sign_x = BLSutils::ConvertToString<libff::alt_bn128_Fq>(bn_sign.X);
    *sign_y = BLSutils::ConvertToString<libff::alt_bn128_Fq>(bn_sign.Y);

    BLSPublicKeyShare pkey(used_bls_->local_sec_key(), used_bls_->t(), used_bls_->n());
    std::shared_ptr< std::vector< std::string > > strs = pkey.toString();
    std::cout << "sign t: " << used_bls_->t() << ", n: " << used_bls_->n()
        << ", pk: " << strs->at(0) << ", " << strs->at(1) << ", " << strs->at(2) << ", " << strs->at(3)
        << ", sign x: " << *sign_x
        << ", sign y: " << *sign_y
        << ", sign msg: " << common::Encode::HexEncode(sign_msg)
        << std::endl;

    return kBlsSuccess;
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
    return kBlsError;
}

int BlsManager::Verify(
        uint32_t t,
        uint32_t n,
        const libff::alt_bn128_G2& pubkey,
        const libff::alt_bn128_G1& sign,
        const std::string& sign_msg) try {
//     std::lock_guard<std::mutex> guard(sign_mutex_);
    if (sign_msg.size() != 32) {
        BLS_ERROR("sign message error: %s", common::Encode::HexEncode(sign_msg));
        return kBlsError;
    }
// 
    auto sign_ptr = const_cast<libff::alt_bn128_G1*>(&sign);
    sign_ptr->to_affine_coordinates();
    auto sign_x = BLSutils::ConvertToString<libff::alt_bn128_Fq>(sign_ptr->X);
    auto sign_y = BLSutils::ConvertToString<libff::alt_bn128_Fq>(sign_ptr->Y);
    auto pk = const_cast<libff::alt_bn128_G2*>(&pubkey);
    pk->to_affine_coordinates();
    auto pk_ptr = std::make_shared< BLSPublicKey >(*pk, t, n);
    auto strs = pk_ptr->toString();
    std::cout << "verify t: " << t << ", n: " << n
        << ", pk: " << strs->at(0) << ", " << strs->at(1) << ", " << strs->at(2) << ", " << strs->at(3)
        << ", sign x: " << sign_x
        << ", sign y: " << sign_y
        << ", sign msg: " << common::Encode::HexEncode(sign_msg)
        << std::endl;
    return BlsSign::Verify(t, n, sign, sign_msg, pubkey);
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
    return kBlsError;
}

void BlsManager::HandleMessage(const transport::TransportMessagePtr& header) {
    protobuf::BlsMessage bls_msg;
    if (!bls_msg.ParseFromString(header->data())) {
        BLS_ERROR("bls_msg.ParseFromString ParseFromString failed!");
        return;
    }

    if (bls_msg.has_finish_req()) {
        HandleFinish(*header, bls_msg);
        return;
    }

    if (waiting_bls_ != nullptr) {
        waiting_bls_->HandleMessage(header);
    }
}

bool BlsManager::IsSignValid(
        const elect::MembersPtr& members,
        const protobuf::BlsMessage& bls_msg,
        std::string* content_to_hash) {
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
            *content_to_hash += std::to_string(bls_msg.finish_req().bitmap(i)) + "_"  +
                std::to_string(bls_msg.finish_req().network_id());
        }
    }

    *content_to_hash = common::Hash::keccak256(*content_to_hash);
    auto& pubkey = (*members)[bls_msg.index()]->pubkey;
    auto sign = security::Signature(bls_msg.sign_ch(), bls_msg.sign_res());
    if (!security::Schnorr::Instance()->Verify(*content_to_hash, sign, pubkey)) {
        return false;
    }

    return true;
}

void BlsManager::HandleFinish(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg) {
    auto members = elect::ElectManager::Instance()->GetNetworkMembers(
        bls_msg.finish_req().network_id());
    if (members == nullptr) {
        return;
    }

    std::string msg_hash;
    if (!IsSignValid(members, bls_msg, &msg_hash)) {
        return;
    }

    std::vector<std::string> pkey_str = {
            bls_msg.finish_req().pubkey().x_c0(),
            bls_msg.finish_req().pubkey().x_c1(),
            bls_msg.finish_req().pubkey().y_c0(),
            bls_msg.finish_req().pubkey().y_c1()
    };
    auto t = common::GetSignerCount(members->size());
    BLSPublicKey pkey(
        std::make_shared<std::vector<std::string>>(pkey_str),
        t,
        members->size());
    std::vector<std::string> common_pkey_str = {
            bls_msg.finish_req().common_pubkey().x_c0(),
            bls_msg.finish_req().common_pubkey().x_c1(),
            bls_msg.finish_req().common_pubkey().y_c0(),
            bls_msg.finish_req().common_pubkey().y_c1()
    };
    BLSPublicKey common_pkey(
        std::make_shared<std::vector<std::string>>(common_pkey_str),
        t,
        members->size());
    std::string common_pk_str;
    for (uint32_t i = 0; i < common_pkey_str.size(); ++i) {
        common_pk_str += common_pkey_str[i];
    }

    std::string cpk_hash = common::Hash::Hash256(common_pk_str);

    all_public_keys_[bls_msg.index()] = *pkey.getPublicKey();
    auto iter = max_bls_members_.find(msg_hash);
    if (iter != max_bls_members_.end()) {
        ++iter->second->count;
        if (iter->second->count > max_finish_count_) {
            max_finish_count_ = iter->second->count;
            max_finish_hash_ = msg_hash;
            std::cout << "finsh called: " << common::Encode::HexEncode(max_finish_hash_) << ", count: " << max_finish_count_ << std::endl;
        }

        return;
    }

    std::vector<uint64_t> bitmap_data;
    for (int32_t i = 0; i < bls_msg.finish_req().bitmap_size(); ++i) {
        bitmap_data.push_back(bls_msg.finish_req().bitmap(i));
    }

    common::Bitmap bitmap(bitmap_data);
    auto item = std::make_shared<MaxBlsMemberItem>(1, bitmap);
    max_bls_members_[msg_hash] = item;
    if (max_finish_count_ == 0) {
        max_finish_count_ = 1;
        max_finish_hash_ = msg_hash;
    }
}

void BlsManager::AddBlsConsensusInfo(elect::protobuf::ElectBlock& ec_block) {
    if (waiting_bls_ != nullptr) {
        waiting_bls_->AddBlsConsensusInfo(ec_block);
    }
}

BlsManager::BlsManager() {
    initLibSnark();
    network::Route::Instance()->RegisterMessage(
        common::kBlsMessage,
        std::bind(&BlsManager::HandleMessage, this, std::placeholders::_1));
}

BlsManager::~BlsManager() {}

};  // namespace bls

};  // namespace tenon
