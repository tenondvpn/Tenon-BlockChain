#include "bls/bls_manager.h"

#include <dkg/dkg.h>
#include <bls/BLSPrivateKey.h>
#include <bls/BLSPrivateKeyShare.h>
#include <bls/BLSPublicKey.h>
#include <bls/BLSPublicKeyShare.h>
#include <bls/BLSutils.h>

#include "bls/bls_sign.h"
#include "common/db_key_prefix.h"
#include "db/db.h"
#include "election/elect_manager.h"
#include "init/init_utils.h"
#include "security/crypto.h"
#include "security/schnorr.h"

namespace tenon {

namespace bls {

void initLibSnark() noexcept {
    static bool s_initialized = []() noexcept
    {
        libff::inhibit_profiling_info = false;
        libff::inhibit_profiling_counters = false;
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
        std::string* sign_x,
        std::string* sign_y) try {
    std::lock_guard<std::mutex> guard(sign_mutex_);
    if (used_bls_ == nullptr || used_bls_->n() == 0) {
        return kBlsError;
    }

    libff::alt_bn128_G1 bn_sign;
    BlsSign::Sign(used_bls_->t(), used_bls_->n(), used_bls_->local_sec_key(), sign_msg, &bn_sign);
    bn_sign.to_affine_coordinates();
    *sign_x = BLSutils::ConvertToString<libff::alt_bn128_Fq>(bn_sign.X);
    *sign_y = BLSutils::ConvertToString<libff::alt_bn128_Fq>(bn_sign.Y);

//     BLSPublicKeyShare pkey(used_bls_->local_sec_key(), used_bls_->t(), used_bls_->n());
//     std::shared_ptr< std::vector< std::string > > strs = pkey.toString();
//     std::cout << "sign t: " << used_bls_->t() << ", n: " << used_bls_->n()
//         << ", pk: " << strs->at(0) << ", " << strs->at(1) << ", " << strs->at(2) << ", " << strs->at(3)
//         << ", sign x: " << *sign_x
//         << ", sign y: " << *sign_y
//         << ", sign msg: " << common::Encode::HexEncode(sign_msg)
//         << std::endl;

    return kBlsSuccess;
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
    return kBlsError;
}

int BlsManager::Verify(
        uint32_t t,
        uint32_t n,
        const libff::alt_bn128_G2& pubkey,
        const std::string& sign_x,
        const std::string& sign_y,
        const std::string& sign_msg) try {
    std::lock_guard<std::mutex> guard(sign_mutex_);
    if (sign_msg.size() != 32) {
        BLS_ERROR("sign message error: %s", common::Encode::HexEncode(sign_msg));
        return kBlsError;
    }

    libff::alt_bn128_G1 sign;
    sign.X = libff::alt_bn128_Fq(sign_x.c_str());
    sign.Y = libff::alt_bn128_Fq(sign_y.c_str());
    sign.Z = libff::alt_bn128_Fq::one();

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

BlsManager::BlsManager() {
    initLibSnark();
}

BlsManager::~BlsManager() {}

};  // namespace bls

};  // namespace tenon
