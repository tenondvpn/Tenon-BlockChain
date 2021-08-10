#include "bls/bls_manager.h"

#include "bls/bls_sign.h"
#include "election/elect_manager.h"

namespace tenon {

namespace bls {

BlsManager* BlsManager::Instance() {
    static BlsManager ins;
    return &ins;
}

void BlsManager::ProcessNewElectBlock(
        elect::protobuf::ElectBlock& elect_block,
        elect::MembersPtr& new_members) {
    std::lock_guard<std::mutex> guard(mutex_);
    waiting_bls_ = std::make_shared<bls::BlsDkg>();
    waiting_bls_->OnNewElectionBlock(elect_block.elect_height(), new_members);
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
