#pragma once

#include <memory>
#include <unordered_map>

#include "bls/bls_dkg.h"
#include "bls/bls_utils.h"
#include "election/proto/elect.pb.h"

namespace tenon {

namespace bls {

class BlsManager {
public:
    static BlsManager* Instance();
    void ProcessNewElectBlock(
        elect::protobuf::ElectBlock& elect_block,
        elect::MembersPtr& new_members);

    void SetUsedElectionBlock(
            uint64_t elect_height,
            const libff::alt_bn128_G2& common_public_key) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (max_height_ != common::kInvalidUint64 && elect_height <= max_height_) {
            return;
        }

        max_height_ = elect_height;
        libff::alt_bn128_Fr local_sec_key;
        libff::alt_bn128_G2 local_publick_key;
        used_bls_ = std::make_shared<bls::BlsDkg>();
        used_bls_->SetInitElectionBlock(local_sec_key, local_publick_key, common_public_key);
    }

    int Sign(
        const std::string& sign_msg,
        std::string* sign_x,
        std::string* sign_y);
    int Verify(
        uint32_t t,
        uint32_t n,
        const libff::alt_bn128_G2& pubkey,
        const std::string& sign_x,
        const std::string& sign_y,
        const std::string& sign_msg);

private:
    BlsManager();
    ~BlsManager();

    std::shared_ptr<bls::BlsDkg> used_bls_{ nullptr };
    std::shared_ptr<bls::BlsDkg> waiting_bls_{ nullptr };
    uint64_t max_height_{ common::kInvalidUint64 };
    std::mutex mutex_;

    DISALLOW_COPY_AND_ASSIGN(BlsManager);
};


};  // namespace bls

};  // namespace tenon
