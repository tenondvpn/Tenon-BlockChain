#include "bls/bls_manager.h"

#include <dkg/dkg.h>

#include "bls/bls_sign.h"
#include "common/db_key_prefix.h"
#include "db/db.h"
#include "election/elect_manager.h"
#include "security/crypto.h"
#include "security/schnorr.h"

namespace tenon {

namespace bls {

BlsManager* BlsManager::Instance() {
    static BlsManager ins;
    return &ins;
}

void BlsManager::ProcessNewElectBlock(
        uint64_t elect_height,
        elect::protobuf::ElectBlock& elect_block,
        elect::MembersPtr& new_members) {
    std::lock_guard<std::mutex> guard(mutex_);
    waiting_bls_ = std::make_shared<bls::BlsDkg>();
    waiting_bls_->OnNewElectionBlock(elect_height, new_members);
}

void BlsManager::SetUsedElectionBlock(
        uint64_t elect_height,
        const libff::alt_bn128_G2& common_public_key) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (max_height_ != common::kInvalidUint64 && elect_height <= max_height_) {
        return;
    }

    max_height_ = elect_height;
    std::string key = common::kBlsPrivateKeyPrefix +
        std::to_string(elect_height) + "_" +
        std::to_string(common::GlobalInfo::Instance()->network_id());
    std::string val;
    auto st = db::Db::Instance()->Get(key, &val);
    if (!st.ok()) {
        return;
    }

    std::string dec_data;
    if (security::Crypto::Instance()->GetDecryptData(
            security::Schnorr::Instance()->str_prikey(),
            val,
            &dec_data) != security::kSecuritySuccess) {
        return;
    }

    libff::alt_bn128_Fr local_sec_key = libff::alt_bn128_Fr(dec_data.c_str());
    auto member_count = elect::ElectManager::Instance()->GetMemberCountWithHeight(
        elect_height,
        common::GlobalInfo::Instance()->network_id());
    auto t = common::GetSignerCount(member_count);
    signatures::Dkg dkg(t, member_count);
    libff::alt_bn128_G2 local_publick_key = dkg.GetPublicKeyFromSecretKey(local_sec_key);
    used_bls_ = std::make_shared<bls::BlsDkg>();
    used_bls_->SetInitElectionBlock(local_sec_key, local_publick_key, common_public_key);
}

int BlsManager::Sign(
        const std::string& sign_msg,
        std::string* sign_x,
        std::string* sign_y) {
    if (used_bls_ == nullptr || used_bls_->n() == 0) {
        return kBlsError;
    }

    libff::alt_bn128_G1 bn_sign;
    BlsSign::Sign(used_bls_->t(), used_bls_->n(), used_bls_->local_sec_key(), sign_msg, &bn_sign);
    bn_sign.to_affine_coordinates();
    *sign_x = BLSutils::ConvertToString<libff::alt_bn128_Fq>(bn_sign.X);
    *sign_y = BLSutils::ConvertToString<libff::alt_bn128_Fq>(bn_sign.Y);
    return kBlsSuccess;
}

int BlsManager::Verify(
        uint32_t t,
        uint32_t n,
        const libff::alt_bn128_G2& pubkey,
        const std::string& sign_x,
        const std::string& sign_y,
        const std::string& sign_msg) {
    libff::alt_bn128_G1 sign;
    sign.X = libff::alt_bn128_Fq(sign_x.c_str());
    sign.Y = libff::alt_bn128_Fq(sign_y.c_str());
    sign.Z = libff::alt_bn128_Fq::one();
    return BlsSign::Verify(t, n, sign, sign_msg, pubkey);
}

BlsManager::BlsManager() {}

BlsManager::~BlsManager() {}

};  // namespace bls

};  // namespace tenon