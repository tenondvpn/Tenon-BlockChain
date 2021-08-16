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
        uint64_t elect_height,
        elect::MembersPtr& new_members);
    void SetUsedElectionBlock(
        uint64_t elect_height,
        uint32_t network_id,
        uint32_t member_count,
        const libff::alt_bn128_G2& common_public_key);
    int Sign(
        const std::string& sign_msg,
        std::string* sign_x,
        std::string* sign_y);
    int Sign(
        const std::string& sign_msg,
        libff::alt_bn128_G1* bn_sign);
    int Verify(
        uint32_t t,
        uint32_t n,
        const libff::alt_bn128_G2& pubkey,
        const libff::alt_bn128_G1& sign,
        const std::string& sign_msg);
    void AddBlsConsensusInfo(elect::protobuf::ElectBlock& ec_block);

private:
    BlsManager();
    ~BlsManager();
    void HandleMessage(const transport::TransportMessagePtr& header);

    std::shared_ptr<bls::BlsDkg> used_bls_{ nullptr };
    std::shared_ptr<bls::BlsDkg> waiting_bls_{ nullptr };
    uint64_t max_height_{ common::kInvalidUint64 };
    std::mutex mutex_;
    std::mutex sign_mutex_;

    DISALLOW_COPY_AND_ASSIGN(BlsManager);
};


};  // namespace bls

};  // namespace tenon
