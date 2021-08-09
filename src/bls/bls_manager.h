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
    std::mutex mutex_;
    std::unordered_map<uint64_t, libff::alt_bn128_G2> common_public_key_with_height_;
    std::mutex common_public_key_with_height_mutex_;

    DISALLOW_COPY_AND_ASSIGN(BlsManager);
};


};  // namespace bls

};  // namespace tenon
